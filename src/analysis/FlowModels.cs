using System;
using System.Collections.Generic;
using System.Linq;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        // Models track provenance, not live objects or compressed bytes. Analysis never invokes script methods.
        enum ModelKind { Characters, PackedBytes, Base64Text }
        sealed class ModelValue
        {
            internal ModelValue(ModelKind kind, Mark[] marks)
            { Kind = kind; Marks = marks; }
            internal readonly ModelKind Kind;
            internal Mark[] Marks;
            internal string? Exact;
        }

        sealed partial class AdapterContext
        {
            static readonly string[] CompressionTypes = { "gzipstream", "deflatestream", "brotlistream" };
            static Payload Symbol(ModelValue model, string step) => new Payload {
                Model = model, SourceRef = step, IsString = model.Kind == ModelKind.Base64Text,
                Tags = model.Marks.Select(m => m.Via(step)).ToArray(), Issue = "symbolic-payload-value"
            };
            static bool BareVariable(string name) => SafeName(name) && !name.Contains(":");
            static object? SingleElement(object? node)
            {
                if (Kind(node) == "CommandExpressionAst")
                    return Items(Prop(node, "Redirections")).Any() ? null : node;
                if (Kind(node) != "PipelineAst" || !Equals(Prop(node, "Background"), false)) return null;
                var list = Items(Prop(node, "PipelineElements")).Take(2).ToArray();
                return list.Length == 1 && !Items(Prop(list[0], "Redirections")).Any() ? list[0] : null;
            }
            static object[] ListItems(object? ast, int max)
            {
                if (ast is Payload binding) return binding.Elements?.Take(ProbeCount(max)).Cast<object>().ToArray() ?? new object[] { binding };
                if (Kind(ast) == "ArrayExpressionAst")
                {
                    var block = Prop(ast, "SubExpression");
                    if (Items(Prop(block, "Traps")).Any()) return Array.Empty<object>();
                    var statements = Items(Prop(block, "Statements")).Take(2).ToArray();
                    if (statements.Length != 1) return Array.Empty<object>();
                    ast = Prop(SingleElement(statements[0]), "Expression");
                }
                return Kind(ast) == "ArrayLiteralAst" ? Items(Prop(ast, "Elements")).Take(ProbeCount(max)).ToArray() :
                    ast == null ? Array.Empty<object>() : new[] { ast };
            }
            static bool CompressionType(string type, out string codec)
            {
                codec = "";
                const string prefix = "io.compression.";
                if (type.StartsWith("system.", StringComparison.Ordinal)) type = type.Substring(7);
                if (!type.StartsWith(prefix, StringComparison.Ordinal)) return false;
                codec = type.Substring(prefix.Length);
                return CompressionTypes.Contains(codec);
            }
            string? CodecName(object? ast)
            {
                if (ast is Payload binding) return binding.Complete ? binding.Text?.ToLowerInvariant() : null;
                if (Literal(ast) is string literal) return literal.ToLowerInvariant();
                if (Kind(ast) != "ExpandableStringExpressionAst") return null;
                var nested = Items(Prop(ast, "NestedExpressions")).Take(2).ToArray();
                if (nested.Length != 1 || !BareVariable(VarName(nested[0]))) return null;
                var name = VarName(nested[0]);
                var pattern = Str(Prop(ast, "Value"));
                var suffix = "$" + name;
                if (!pattern.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) return null;
                var prefix = pattern.Substring(0, pattern.Length - suffix.Length).ToLowerInvariant();
                if (prefix is not ("system.io.compression." or "io.compression.")) return null;
                var value = Variable(name);
                return value.Complete && value.IsString ? prefix + value.Text?.ToLowerInvariant() : null;
            }
            Payload? NewCompressionObject(object command, int depth)
            {
                using var args = new Args(this, command, new[] { "TypeName", "ArgumentList" }, Empty);
                var typeArg = args.Get("TypeName") ?? args.Plain.FirstOrDefault();
                int pos = args.Has("TypeName") ? 0 : 1;
                if (!args.Valid || args.Plain.Count > pos + (args.Has("ArgumentList") ? 0 : 1) || CodecName(typeArg) is not string type) return null;
                return ConstructHttpObject(type, ListItems(args.Get("ArgumentList") ?? args.Plain.ElementAtOrDefault(pos), 5), depth);
            }
            Payload? ModelExpression(object? node, int depth)
            {
                if (Kind(node) == "UnaryExpressionAst" && Str(Prop(node, "TokenKind")) == "Join")
                {
                    var chars = Value(Prop(node, "Child"), depth + 1).Model;
                    if (chars?.Kind != ModelKind.Characters) return null;
                    var tags = chars.Marks.Select(m => m.Via("join characters")).ToArray();
                    if (chars.Exact != null) return Text(chars.Exact, "join characters", tags);
                    return Symbol(new ModelValue(ModelKind.Base64Text, tags), "join characters");
                }
                if (Kind(node) != "InvokeMemberExpressionAst") return null;
                var recv = Prop(node, "Expression");
                var member = Literal(Prop(node, "Member"))?.ToLowerInvariant();
                var args = Items(Prop(node, "Arguments")).Take(4).ToArray();
                if (Equals(Prop(node, "Static"), true)) return null;
                if (!BareVariable(VarName(recv)) || args.Length != 0) return null;
                var input = Value(recv, depth + 1);
                if (member == "tochararray" && (input.Model?.Kind == ModelKind.Base64Text ||
                    (input.Complete && input.IsString && input.Text != null)))
                    return Symbol(new ModelValue(ModelKind.Characters, input.Tags) { Exact = input.Text }, "character array");
                return null;
            }
            bool ApplyMutation(object? node)
            {
                if (barrier || Kind(node) != "InvokeMemberExpressionAst") return false;
                var recv = Prop(node, "Expression");
                var member = Literal(Prop(node, "Member"))?.ToLowerInvariant();
                var args = Items(Prop(node, "Arguments")).Take(4).ToArray();
                if (Equals(Prop(node, "Static"), true))
                {
                    if (Kind(recv) != "TypeExpressionAst" || TypeName(recv) is not ("array" or "system.array") ||
                        member != "reverse" || args.Length != 1 || !BareVariable(VarName(args[0])) ||
                        Variable(VarName(args[0])).Model is not { Kind: ModelKind.Characters } chars) return false;
                    if (chars.Exact != null) chars.Exact = new string(chars.Exact.Reverse().ToArray());
                    chars.Marks = chars.Marks.Select(m => m.Via("array reorder")).ToArray();
                    return true;
                }
                return false;
            }
        }
    }
}

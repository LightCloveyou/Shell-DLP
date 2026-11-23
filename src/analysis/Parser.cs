using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        [StructLayout(LayoutKind.Sequential)]
        struct Request { public IntPtr Source, Output; public int Length, Capacity, Decision; }
        static int MaxReportNodes => Limits.MaxReportNodes;
        static int MaxPolicyNodes => Limits.MaxPolicyNodes;
        static readonly string[] Kinds = {
            "CommandAst", "PipelineAst", "VariableExpressionAst", "StringConstantExpressionAst",
            "ExpandableStringExpressionAst", "InvokeMemberExpressionAst", "AssignmentStatementAst"
        };
        static readonly HashSet<string> ParameterValues = new HashSet<string>(
            new[] { "Uri", "Body", "Method", "Path", "LiteralPath", "InFile", "OutFile", "FilePath", "Destination" },
            StringComparer.OrdinalIgnoreCase);
        static readonly HashSet<string> PathParameters = new HashSet<string>(
            new[] { "Path", "LiteralPath", "InFile", "OutFile", "FilePath", "Destination" },
            StringComparer.OrdinalIgnoreCase);
        static readonly HashSet<string> FileCommands = new HashSet<string>(
            new[] { "Get-Content", "Set-Content", "Add-Content", "Copy-Item", "Move-Item", "Remove-Item", "gc", "cat", "type" },
            StringComparer.OrdinalIgnoreCase);

        static object? Prop(object? o, string name)
        {
            for (var type = o?.GetType(); type != null; type = type.BaseType)
            {
                var property = type.GetProperty(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly);
                if (property != null) return property.GetValue(o);
            }
            return null;
        }
        static string Str(object? o) => o?.ToString() ?? "";
        static string Kind(object? o) => o?.GetType().Name ?? "";
        static IEnumerable<object> Items(object? o) => (o as IEnumerable)?.Cast<object>() ?? Enumerable.Empty<object>();
        static string Command(object o) => Str(o.GetType().GetMethod("GetCommandName")?.Invoke(o, null));
        static bool Interesting(object o) => Array.IndexOf(Kinds, Kind(o)) >= 0;
        static string? Literal(object? o) => Kind(o) == "StringConstantExpressionAst" ? Str(Prop(o, "Value")) : null;
        static string Small(string s) => s.Length <= Limits.MaxReportChars ? s : s.Substring(0, Limits.MaxReportChars) + "…";
        static Dictionary<string, object?> Data(params object?[] entries) {
            var result = new Dictionary<string, object?>();
            for (int i = 0; i < entries.Length; i += 2) result.Add((string)entries[i]!, entries[i + 1]);
            return result;
        }

        static bool PreparePolicySource(Type parser, string source, out string policySource)
        {
            policySource = source;
            if (source.IndexOf("using", StringComparison.OrdinalIgnoreCase) < 0) return true;
            // Tokenize before ParseInput: external using directives can trigger resolution.
            // Mask only recognized directive forms; never resolve their arguments here.
            try
            {
                var type = parser.Assembly.GetType("System.Management.Automation.Language.Tokenizer", true)!;
                var scanner = type.GetConstructor(Instance, null, new[] { parser }, null)!
                    .Invoke(new[] { Activator.CreateInstance(parser, true) });
                type.GetMethod("Initialize", Instance)!.Invoke(scanner, new object?[] { null, source, null });
                var next = type.GetMethod("NextToken", Instance)!;
                char[]? cleaned = null;
                for (int i = 0; i <= source.Length; i++)
                {
                    var token = next.Invoke(scanner, null);
                    var kind = Str(Prop(token, "Kind"));
                    if (kind == "EndOfInput")
                    {
                        if (cleaned != null) policySource = new string(cleaned);
                        return true;
                    }
                    if (kind == "Using")
                    {
                        var qualifier = Str(Prop(next.Invoke(scanner, null), "Text"));
                        if (qualifier.Equals("namespace", StringComparison.OrdinalIgnoreCase)) continue;
                        if (!qualifier.Equals("module", StringComparison.OrdinalIgnoreCase) &&
                            !qualifier.Equals("assembly", StringComparison.OrdinalIgnoreCase)) return false;
                        var arg = next.Invoke(scanner, null);
                        var argKind = Str(Prop(arg, "Kind"));
                        if (argKind == "AtCurly" && qualifier.Equals("module", StringComparison.OrdinalIgnoreCase))
                        {
                            // Module specifications can be hashtables. Consume their tokens,
                            // but never ask PowerShell to parse or resolve the specification.
                            int braces = 1;
                            for (int j = 0; j < Limits.MaxUsingTokens && braces > 0; j++)
                            {
                                arg = next.Invoke(scanner, null);
                                var part = Str(Prop(arg, "Kind"));
                                if (part == "EndOfInput" || Items(Prop(arg, "NestedTokens")).Any()) return false;
                                if (part is "AtCurly" or "LCurly") braces++;
                                else if (part == "RCurly") braces--;
                            }
                            if (braces != 0) return false;
                        }
                        else if (argKind is not ("StringLiteral" or "Generic" or "Identifier" or "StringExpandable") ||
                                 Items(Prop(arg, "NestedTokens")).Any()) return false;
                        var separator = next.Invoke(scanner, null);
                        var separatorKind = Str(Prop(separator, "Kind"));
                        if (separatorKind == "Comment")
                        {
                            separator = next.Invoke(scanner, null);
                            separatorKind = Str(Prop(separator, "Kind"));
                        }
                        if (separatorKind is not ("NewLine" or "Semi" or "EndOfInput") ||
                            Prop(Prop(token, "Extent"), "StartOffset") is not int begin ||
                            Prop(Prop(arg, "Extent"), "EndOffset") is not int end ||
                            begin < 0 || end <= begin || end > source.Length) return false;
                        cleaned ??= source.ToCharArray();
                        for (int offset = begin; offset < end; offset++)
                            if (cleaned[offset] != '\r' && cleaned[offset] != '\n') cleaned[offset] = ' ';
                        if (separatorKind == "EndOfInput") { policySource = new string(cleaned); return true; }
                        continue;
                    }
                    if (Items(Prop(token, "NestedTokens")).Any(t => Str(Prop(t, "Text"))
                        .IndexOf("using", StringComparison.OrdinalIgnoreCase) >= 0)) return false;
                }
            }
            catch { }
            return false;
        }

        public static int Analyze(IntPtr data, int size)
        {
            try
            {
                if (size != Marshal.SizeOf<Request>()) return -1;
                var req = Marshal.PtrToStructure<Request>(data);
                var policy = Store.Current(out _);
                if (req.Length == 0 && req.Source == IntPtr.Zero)
                    return req.Capacity == -1 ? (policy ?? Limits).MaxReportBytes : (policy ?? Limits).MaxAmsiBytes;
                if (req.Length < 1) return -1;
                if ((long)req.Length * sizeof(char) > (policy ?? Limits).MaxScriptBytes)
                {
                    req.Decision = 3;
                    Marshal.StructureToPtr(req, data, false);
                    return -4;
                }
                var elapsed = System.Diagnostics.Stopwatch.StartNew();
                var source = Marshal.PtrToStringUni(req.Source, req.Length)!;
                var parser = Type.GetType("System.Management.Automation.Language.Parser, System.Management.Automation", false) ??
                    AppDomain.CurrentDomain.GetAssemblies().Select(a => a.GetType("System.Management.Automation.Language.Parser")).FirstOrDefault(t => t != null);
                if (parser == null) return -1;
                if (!PreparePolicySource(parser, source, out var policySource))
                {
                    req.Decision = 3;
                    Marshal.StructureToPtr(req, data, false);
                    return -2;
                }
                var parse = parser.GetMethods().Single(m => m.Name == "ParseInput" && m.GetParameters().Length == 3);
                var args = new object?[] { policySource, null, null };
                var ast = parse.Invoke(null, args);
                if (ast == null) return -1;
                var walk = ast.GetType().GetMethod("FindAll")!;
                var filter = Delegate.CreateDelegate(walk.GetParameters()[0].ParameterType,
                    typeof(AstBridge).GetMethod(nameof(Interesting), BindingFlags.Static | BindingFlags.NonPublic)!);
                var nodes = Items(walk.Invoke(ast, new object[] { filter, true })).Take(ProbeCount(MaxPolicyNodes)).ToArray();
                var errors = Items(args[2]).Take(Limits.MaxParseErrors).Select(e => Data("id", Prop(e, "ErrorId"),
                    "line", Prop(Prop(e, "Extent"), "StartLineNumber"))).ToArray();
                var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var urls = new HashSet<string>(StringComparer.Ordinal);
                var ips = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var commands = new List<object>();
                var pipelines = new List<object>();
                var variables = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var strings = new HashSet<string>(StringComparer.Ordinal);
                var expandable = new HashSet<string>(StringComparer.Ordinal);
                var dynamic = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var external = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var encoding = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var root = Items(Prop(Prop(ast, "EndBlock"), "Statements")).Take(ProbeCount((policy ?? Limits).MaxStatements)).ToArray();
                var flow = Flow.Create(parser.Assembly, nodes.Take(MaxReportNodes), root);
                req.Decision = errors.Length > 0 ? 4 : 0;
                foreach (var node in nodes.Take(MaxReportNodes))
                {
                    if (elapsed.ElapsedMilliseconds > (policy ?? Limits).FileScanBudgetMs) break;
                    switch (Kind(node))
                    {
                        case "CommandAst":
                            var name = Command(node);
                            flow.IsShadowed(name);
                            var op = Str(Prop(node, "InvocationOperator"));
                            var elements = Items(Prop(node, "CommandElements")).ToArray();
                            var parameters = new List<object>();
                            for (int i = 1; i < elements.Length; i++)
                            {
                                var el = elements[i];
                                if (Kind(el) != "CommandParameterAst") continue;
                                var key = Str(Prop(el, "ParameterName"));
                                var arg = Prop(el, "Argument");
                                if (arg == null && ParameterValues.Contains(key) && i + 1 < elements.Length) arg = elements[i + 1];
                                var val = Literal(arg);
                                var resolved = val == null && arg != null ? flow.Resolve(arg) : null;
                                parameters.Add(Data("name", key, "literal", val == null ? null : Small(val),
                                    "valueSource", resolved?.Source, "valueKnown", resolved?.Known));
                                if (val != null && PathParameters.Contains(key)) paths.Add(Small(val));
                            }
                            if (FileCommands.Contains(name) && elements.Length > 1 && Literal(elements[1]) is string path) paths.Add(Small(path));
                            commands.Add(Data("name", name, "invocationOperator", op,
                                "line", Prop(Prop(node, "Extent"), "StartLineNumber"), "parameters", parameters));
                            if (op == "Ampersand" || op == "Dot" || Regex.IsMatch(name, @"^(?:Invoke-Expression|iex)$", RegexOptions.IgnoreCase)) dynamic.Add(name.Length > 0 ? name : op);
                            if (Regex.IsMatch(name, @"(?:\.(?:exe|cmd|bat|com)$|^(?:curl|ncat|scp|ssh|git|wget)$)", RegexOptions.IgnoreCase)) external.Add(name);
                            break;
                        case "PipelineAst":
                            var pipe = Items(Prop(node, "PipelineElements")).ToArray();
                            if (pipe.Length > 1) pipelines.Add(pipe.Select(e => Kind(e) == "CommandAst" ? Command(e) : Kind(e)).ToArray());
                            break;
                        case "VariableExpressionAst": variables.Add(Str(Prop(Prop(node, "VariablePath"), "UserPath"))); break;
                        case "ExpandableStringExpressionAst": expandable.Add(Small(Str(Prop(Prop(node, "Extent"), "Text")))); break;
                        case "StringConstantExpressionAst":
                            var literal = Str(Prop(node, "Value"));
                            if (Str(Prop(node, "StringConstantType")) != "BareWord") strings.Add(Small(literal));
                            if (Regex.IsMatch(literal, @"^(?:[A-Za-z]:[\\/]|\\\\|\.\.?[\\/]|/(?!/))")) paths.Add(Small(literal));
                            var host = literal;
                            if (Regex.IsMatch(literal, @"^[a-z][a-z0-9+.-]*://", RegexOptions.IgnoreCase) &&
                                Uri.TryCreate(literal, UriKind.Absolute, out var target) && target.Host.Length > 0)
                            { urls.Add(Small(literal)); host = target.DnsSafeHost; }
                            if ((host.Contains(".") || host.Contains(":")) && IPAddress.TryParse(host, out var ip)) ips.Add(ip.ToString());
                            else if (host.Length <= 253 && Regex.IsMatch(host, @"^(?:[a-z0-9][a-z0-9-]*\.)+[a-z][a-z0-9-]*$", RegexOptions.IgnoreCase) &&
                                !Regex.IsMatch(host, @"\.(?:exe|cmd|dll|ps1|txt|json|csv|zip|log)$", RegexOptions.IgnoreCase)) domains.Add(host);
                            break;
                        case "InvokeMemberExpressionAst":
                            var member = Literal(Prop(node, "Member"));
                            if (member != null && Regex.IsMatch(member, @"^(?:FromBase64String|ToBase64String|FromBase64CharArray|ToBase64CharArray|GetBytes|GetString|UrlEncode|UrlDecode)$", RegexOptions.IgnoreCase)) encoding.Add(member);
                            break;
                    }
                }
                var plan = req.Decision == 4 ? new RulePlan() :
                    new AdapterContext(flow, elapsed).Build(ast, root, nodes.Take(MaxPolicyNodes), nodes.Length > MaxPolicyNodes, policySource != source);
                if (req.Decision != 4) req.Decision = plan.Decision;
                if (req.Decision != 1 && req.Decision != 4 && policySource == source) flow.Schedule(plan);
                Marshal.StructureToPtr(req, data, false);
                var report = Data("status", errors.Length == 0 ? policySource == source ? "parsed" : "external-using-isolated" : "syntax-error", "truncated", nodes.Length > MaxReportNodes,
                    "commands", commands, "filePaths", paths, "urls", urls, "ipAddresses", ips, "domains", domains,
                    "pipelines", pipelines, "variables", variables, "stringLiterals", strings, "expandableStrings", expandable,
                    "dynamicExecution", dynamic, "externalCommands", external, "encodingCalls", encoding, "parseErrors", errors,
                    "dataFlow", flow.Report(), "policy", Data("decision", plan.Reason, "configuration", plan.Configuration,
                        "evidence", plan.Evidence, "sensitiveSources", plan.Sources,
                        "omittedEvidence", plan.OmittedEvidence, "omittedSources", plan.OmittedSources, "pending", plan.Work.Select(w => Data("kind", w.Journal != null ? "git-observation" : w.File ? "copy" : "persistent-variable",
                            "target", w.File || w.Journal != null ? w.Target : w.Name, "scope", w.Scope)).ToArray()));
                var serializer = Type.GetType("System.Text.Json.JsonSerializer, System.Text.Json", true)!;
                var serialize = serializer.GetMethods().First(m => m.Name == "Serialize" && m.IsGenericMethodDefinition &&
                    m.ReturnType == typeof(string) && m.GetParameters().Length == 2 && m.GetParameters()[1].ParameterType.Name == "JsonSerializerOptions");
                var writeJson = serialize.MakeGenericMethod(report.GetType());
                byte[] Encode(Dictionary<string, object?> record) =>
                    Encoding.UTF8.GetBytes((string)writeJson.Invoke(null, new object?[] { record, null })!);
                var bytes = Encode(report);
                if (bytes.Length > req.Capacity)
                {
                    // AST detail may overflow independently of the policy decision. Keep the
                    // decisive evidence instead of replacing the entire event with a status.
                    bytes = Encode(Data("status", errors.Length == 0 ? policySource == source ? "parsed" : "external-using-isolated" : "syntax-error", "truncated", true,
                        "truncation", "report-output-limit", "policy", Data("decision", plan.Reason,
                            "configuration", plan.Configuration, "evidence",
                            plan.PrimaryEvidence == null ? Array.Empty<object>() : new[] { plan.PrimaryEvidence })));
                }
                if (bytes.Length > req.Capacity)
                    bytes = Encode(Data("status", errors.Length == 0 ? policySource == source ? "parsed" : "external-using-isolated" : "syntax-error", "truncated", true,
                        "truncation", "report-output-limit", "policy", Data("decision", plan.Reason)));
                if (bytes.Length > req.Capacity) return -3;
                Marshal.Copy(bytes, 0, req.Output, bytes.Length);
                return bytes.Length;
            }
            catch { return -1; }
        }
    }
}

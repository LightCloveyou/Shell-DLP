using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            readonly Dictionary<string, object?[]> functions = new Dictionary<string, object?[]>(StringComparer.OrdinalIgnoreCase);
            readonly Stack<string> functionScopes = new Stack<string>();

            Payload? CallFunctions(object?[] definitions, object command, Payload? input, int depth)
            {
                if (!StackAvailable || depth > MaxExpressionDepth || functionScopes.Count >= MaxExpressionDepth || !Budget())
                { ReportMissing("function-call-limit"); return Missing("function-call-limit"); }
                if (definitions.Length == 1 && definitions[0] != null)
                    return CallFunction(definitions[0]!, command, input, depth);
                var entry = new StatementState(this);
                var paths = new List<(StatementState State, StatementExit Exit)>();
                var results = new List<Payload?>();
                foreach (var definition in definitions)
                {
                    RestoreStatementState(entry);
                    if (definition == null) results.Add(Missing("conditional-command-definition"));
                    else
                    {
                        var result = CallFunction(definition, command, input, depth);
                        if (capture?.Destination is Payload destination)
                        {
                            WriteOutVariable(destination, result, capture.NoEnumerate);
                            capture.Destination = null;
                        }
                        results.Add(result);
                    }
                    paths.Add((new StatementState(this), StatementExit.None));
                }
                MergeStatementPaths(paths);
                return UnknownValue("conditional-function-output", results.ToArray());
            }

            static string AttributeName(object attribute)
            {
                var name = TypeName(attribute);
                const string automation = "system.management.automation.";
                if (name.StartsWith(automation, StringComparison.Ordinal)) name = name.Substring(automation.Length);
                return name.EndsWith("attribute", StringComparison.Ordinal) ? name.Substring(0, name.Length - 9) : name;
            }

            static bool? AttributeSwitch(object option)
            {
                if (Equals(Prop(option, "ExpressionOmitted"), true)) return true;
                return VarName(Prop(option, "Argument")).ToLowerInvariant() switch { "true" => true, "false" => false, _ => null };
            }

            // Conversions operate on analyzer-owned primitives. Never resolve a script-defined
            // type, instantiate an attribute, or execute a validation script during AMSI inspection.
            Payload BindFunctionValue(string type, Payload value, out bool? success)
            {
                if (type.StartsWith("system.", StringComparison.Ordinal)) type = type.Substring(7);
                success = true;
                if (type is "" or "object" or "switch" or "switchparameter" or "management.automation.switchparameter") return value;
                if (IsStreamValue(value) && StreamReferenceType(HttpType(type))) return value;
                if (value.ReadType is "io.compression.compressionmode" or "io.compression.compressionlevel" &&
                    value.ReadType == HttpType(type)) return value;
                if (type == "string" && value.IsString || type == "byte[]" && (value.Bytes != null || value.Issue == "file-bytes-unavailable")) return value;
                if (type is "string[]" or "object[]")
                {
                    if (value.Elements == null && !value.Complete) { success = null; return UnknownValue("function-array-conversion", value); }
                    if (type == "object[]") return value.Elements != null ? value : CollectElements(new[] { value });
                    var converted = new List<Payload>();
                    bool exact = !value.InspectionPartial;
                    foreach (var item in value.Elements ?? new[] { value })
                    {
                        converted.Add(BindFunctionValue("string", item, out var ok));
                        exact &= ok == true;
                    }
                    var array = CollectElements(converted);
                    if (!exact) { success = null; array = Partial(array, "function-array-conversion"); }
                    return array;
                }
                if (value.Complete && !value.InspectionPartial)
                {
                    if (type == "byte[]")
                    {
                        var items = value.Elements ?? new[] { value };
                        if (items.Length <= MaxContent)
                        {
                            var bytes = new byte[items.Length];
                            for (int i = 0; i < items.Length; i++)
                            {
                                var item = BindFunctionValue("byte", items[i], out success);
                                if (success != true) return UnknownValue("function-byte-conversion", value);
                                bytes[i] = byte.Parse(item.Text!, CultureInfo.InvariantCulture);
                            }
                            return Bytes(bytes, "function byte array", Merge(KnownMarks(new[] { value })));
                        }
                    }
                    if (type == "string" && value.Text != null && value.Elements == null)
                        return Text(value.Text, "function string parameter", value.Tags);
                    var integer = type switch
                    {
                        "int" or "int32" => typeof(int), "long" or "int64" => typeof(long),
                        "short" or "int16" => typeof(short), "byte" => typeof(byte), "sbyte" => typeof(sbyte),
                        "uint" or "uint32" => typeof(uint), "ulong" or "uint64" => typeof(ulong),
                        "ushort" or "uint16" => typeof(ushort), _ => null
                    };
                    if (integer != null && value.Text is string raw && value.Elements == null)
                    {
                        var text = !value.IsString && value.NumericType == null && value.ScalarTruth is bool boolean ?
                            (boolean ? "1" : "0") : raw.Trim();
                        if (text.Length == 0) text = "0";
                        if (decimal.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number))
                        {
                            try
                            {
                                var converted = Convert.ChangeType(number, integer, CultureInfo.InvariantCulture);
                                var result = Text(Convert.ToString(converted, CultureInfo.InvariantCulture), "function numeric parameter", FileRecordMarks(value));
                                result.NumericType = integer.Name;
                                result.IsString = false;
                                result.ScalarTruth = number != 0;
                                return result;
                            }
                            catch (OverflowException) { success = false; return Missing("function-parameter-conversion"); }
                        }
                        if (value.IsString && text.All(char.IsLetter) &&
                            !text.Equals("nan", StringComparison.OrdinalIgnoreCase) && !text.Equals("infinity", StringComparison.OrdinalIgnoreCase))
                        { success = false; return Missing("function-parameter-conversion"); }
                    }
                    if (value.Text != null && value.Elements == null)
                    {
                        object? number = null;
                        const NumberStyles format = NumberStyles.Float | NumberStyles.AllowThousands;
                        if (type == "double" && double.TryParse(value.Text, format, CultureInfo.InvariantCulture, out var real)) number = real;
                        if (type is "single" or "float" && float.TryParse(value.Text, format, CultureInfo.InvariantCulture, out var single)) number = single;
                        if (type == "decimal" && decimal.TryParse(value.Text, format, CultureInfo.InvariantCulture, out var fixedPoint)) number = fixedPoint;
                        if (number != null)
                        {
                            var converted = Text(Convert.ToString(number, CultureInfo.InvariantCulture), "function numeric parameter", FileRecordMarks(value));
                            converted.IsString = false;
                            converted.NumericType = number.GetType().Name;
                            converted.ScalarTruth = Convert.ToDouble(number, CultureInfo.InvariantCulture) != 0;
                            return converted;
                        }
                    }
                    if (type is "bool" or "boolean" && !value.IsString && value.ScalarTruth is bool truth)
                        return new Payload { Complete = true, ScalarTruth = truth, Text = truth ? "True" : "False", Tags = FileRecordMarks(value) };
                }
                success = null;
                return new Payload { Issue = "function-parameter-conversion", InspectionPartial = true, Tags = FileRecordMarks(value) };
            }

            bool? ValidateFunctionValue(object attribute, Payload value)
            {
                if (!value.Complete || value.InspectionPartial) return null;
                var items = value.Elements ?? new[] { value };
                var arguments = Items(Prop(attribute, "PositionalArguments")).ToArray();
                var options = Items(Prop(attribute, "NamedArguments")).ToArray();
                switch (AttributeName(attribute))
                {
                    case "validateset":
                        var choices = arguments.Select(Literal).ToArray();
                        if (choices.Length == 0 || choices.Any(c => c == null) || items.Any(v => v.Text == null)) return null;
                        var ignore = options.FirstOrDefault(o => Str(Prop(o, "ArgumentName")).Equals("IgnoreCase", StringComparison.OrdinalIgnoreCase));
                        var ignoreCase = ignore == null ? true : AttributeSwitch(ignore);
                        if (!ignoreCase.HasValue) return null;
                        return items.All(v => choices.Contains(v.Text, ignoreCase.Value ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal));
                    case "validaterange":
                        if (arguments.Length != 2 || arguments.Any(a => Kind(a) is not ("ConstantExpressionAst" or "StringConstantExpressionAst")) ||
                            !decimal.TryParse(Value(arguments[0]).Text, NumberStyles.Number, CultureInfo.InvariantCulture, out var low) ||
                            !decimal.TryParse(Value(arguments[1]).Text, NumberStyles.Number, CultureInfo.InvariantCulture, out var high)) return null;
                        foreach (var item in items)
                        {
                            if (item.NumericType is null or "Double" or "Single" || !decimal.TryParse(item.Text, NumberStyles.Number, CultureInfo.InvariantCulture, out var n)) return null;
                            if (n < low || n > high) return false;
                        }
                        return true;
                    case "validatenotnull": return items.All(v => v.Text != null || v.Bytes != null || v.Map != null) ? true : (bool?)null;
                    case "validatenotnullorempty":
                        if (items.Length == 0 || value.Bytes?.Length == 0 || items.Any(v => v.IsString && v.Text == "")) return false;
                        return items.All(v => v.Text != null || v.Bytes != null) ? true : (bool?)null;
                    default: return null;
                }
            }

            Payload? CallFunction(object definition, object command, Payload? input, int depth)
            {
                var body = Prop(definition, "Body");
                var paramBlock = Prop(body, "ParamBlock");
                var parameters = Items(Prop(definition, "Parameters")).Concat(Items(Prop(paramBlock, "Parameters"))).ToArray();
                var names = parameters.Select(p => VarName(Prop(p, "Name"))).ToArray();
                Payload Opaque(string issue) { ReportMissing(issue); return Missing(issue); }
                var attributes = Items(Prop(paramBlock, "Attributes")).ToArray();
                bool uncertain = Prop(body, "DynamicParamBlock") != null;
                if (parameters.Length > Limits.MaxArguments) return Opaque("function-parameter-limit");
                bool positionalBinding = true, shouldProcess = false;
                foreach (var attribute in attributes)
                {
                    if (AttributeName(attribute) != "cmdletbinding") { uncertain = true; continue; }
                    foreach (var option in Items(Prop(attribute, "NamedArguments")))
                    {
                        var setting = Str(Prop(option, "ArgumentName")).ToLowerInvariant();
                        if (setting is "positionalbinding" or "supportsshouldprocess")
                        {
                            var flag = AttributeSwitch(option);
                            if (!flag.HasValue) uncertain = true;
                            else if (setting == "positionalbinding") positionalBinding = flag.Value;
                            else shouldProcess = flag.Value;
                        }
                    }
                }
                var switches = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var pipelineParameters = new List<string>();
                var mandatory = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var positions = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                var aliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                var types = new string[parameters.Length];
                var validations = parameters.Select(_ => new List<object>()).ToArray();
                var allowEmpty = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                bool advanced = attributes.Any(a => AttributeName(a) == "cmdletbinding");
                for (int i = 0; i < parameters.Length; i++)
                {
                    var metadata = Items(Prop(parameters[i], "Attributes")).ToArray();
                    foreach (var attribute in metadata.Where(a => Kind(a) == "AttributeAst"))
                    {
                        var name = AttributeName(attribute);
                        if (name == "alias")
                        {
                            foreach (var arg in Items(Prop(attribute, "PositionalArguments")))
                                if (Literal(arg) is string alias) aliases[alias] = names[i]; else uncertain = true;
                            continue;
                        }
                        if (name.StartsWith("validate", StringComparison.Ordinal)) { validations[i].Add(attribute); continue; }
                        if (name == "allowemptystring") { allowEmpty.Add(names[i]); continue; }
                        if (name is "allowemptycollection" or "allownull") continue;
                        if (name != "parameter") { uncertain = true; continue; }
                        advanced = true;
                        foreach (var option in Items(Prop(attribute, "NamedArguments")))
                        {
                            var setting = Str(Prop(option, "ArgumentName")).ToLowerInvariant();
                            if (setting == "position" && Prop(Prop(option, "Argument"), "Value") is int pos && pos >= 0)
                            { positions[names[i]] = pos; continue; }
                            if (setting is "mandatory" or "valuefrompipeline")
                            {
                                if (AttributeSwitch(option) is not bool enabled) uncertain = true;
                                else if (enabled && setting == "mandatory") mandatory.Add(names[i]);
                                else if (enabled) pipelineParameters.Add(names[i]);
                            }
                            else uncertain = true;
                        }
                    }
                    var constraints = metadata.Where(a => Kind(a) == "TypeConstraintAst").ToArray();
                    types[i] = constraints.Length == 0 ? "" : constraints.Length == 1 ? TypeName(constraints[0]) : "?";
                    if (types[i] is "switch" or "switchparameter" or "system.management.automation.switchparameter") switches.Add(names[i]);
                }
                uncertain |= pipelineParameters.Count > 1 || positions.Values.Distinct().Count() != positions.Count;
                var named = names.Except(switches, StringComparer.OrdinalIgnoreCase);
                var flags = switches.AsEnumerable();
                if (advanced)
                {
                    flags = flags.Concat(CommonFlags);
                    foreach (var alias in ParameterAliases.Where(a => CommonNames.Contains(a.Value) ||
                        shouldProcess && a.Value is ("WhatIf" or "Confirm")))
                        if (!aliases.ContainsKey(alias.Key)) aliases.Add(alias.Key, alias.Value);
                }
                if (shouldProcess) flags = flags.Concat(new[] { "WhatIf", "Confirm" });
                using var args = new Args(this, command, named.ToArray(), flags.ToArray(), commonParameters: advanced, aliases: aliases, allowExtraNamed: !advanced);
                if (!args.Valid && !args.Uncertain && !uncertain && advanced) return Opaque("function-arguments");
                uncertain |= !args.Valid || args.Uncertain;
                var bound = new Dictionary<string, Payload>(StringComparer.OrdinalIgnoreCase);
                foreach (var pair in args.Named)
                    bound[pair.Key] = flags.Contains(pair.Key, StringComparer.OrdinalIgnoreCase) ?
                        new Payload { Complete = true, ScalarTruth = true, Text = "True" } : Value(pair.Value, depth + 1);
                foreach (var disabled in args.Disabled)
                    bound[disabled] = new Payload { Complete = true, ScalarTruth = false, Text = "False" };
                var positional = new Queue<Payload>(args.Plain.Select(arg => Value(arg, depth + 1)));
                foreach (var param in names.Where(n => !bound.ContainsKey(n) && !switches.Contains(n) && (positionalBinding && positions.Count == 0 || positions.ContainsKey(n)))
                    .OrderBy(n => positions.TryGetValue(n, out var order) ? order : Array.IndexOf(names, n)))
                    if (positional.Count != 0) bound[param] = positional.Dequeue();
                if (!uncertain && (mandatory.Any(n => !bound.ContainsKey(n) && !(input != null && pipelineParameters.Contains(n))) ||
                    positional.Count != 0 && advanced))
                    return Opaque("function-argument-binding");
                var extra = CollectElements(args.Extras.Concat(positional));
                if (args.Uncertain) extra = UnknownValue("function-extra-arguments", extra);
                var end = Prop(body, "EndBlock");
                var process = Prop(body, "ProcessBlock");
                if (process == null && Equals(Prop(definition, "IsFilter"), true)) { process = end; end = null; }
                var pipelineParameter = pipelineParameters.FirstOrDefault(n => !bound.ContainsKey(n));
                var records = process == null && pipelineParameter == null ? null : IterationItems(input);
                if (pipelineParameter != null && input != null)
                    bound[pipelineParameter] = records?.LastOrDefault() ?? input;
                var scope = "@function" + functionScopes.Count.ToString(CultureInfo.InvariantCulture) + "/";
                var outerDefinitions = new Dictionary<string, object?[]>(functions, functions.Comparer);
                var shadowed = scriptDefinitions.ToArray();
                var outerExit = observeAlternateExit;
                var outerObserver = observeStatement;
                var outcomes = new List<(StatementState State, StatementExit Exit)>();
                observeAlternateExit = (state, exit) => outcomes.Add((state, exit));
                observeStatement = null;
                var entryState = new StatementState(this, preserveMutableValues: true);
                functionScopes.Push(scope);
                var output = new List<Payload>();
                try
                {
                    values[Key("args")] = extra;
                    values[Key("input")] = input ?? CollectElements(Array.Empty<Payload>());
                    for (int i = 0; i < names.Length; i++)
                    {
                        string param = names[i];
                        if (!bound.TryGetValue(param, out var val))
                        {
                            var fallback = Prop(parameters[i], "DefaultValue");
                            val = fallback != null ? Value(fallback, depth + 1) : switches.Contains(param) ?
                                new Payload { Complete = true, Text = "False", ScalarTruth = false } : new Payload { Complete = true, ScalarTruth = false, SourceRef = "unbound parameter" };
                        }
                        bool provided = bound.ContainsKey(param);
                        if (!args.Valid && !provided) val = Missing("function-argument-binding");
                        if (provided || Prop(parameters[i], "DefaultValue") != null)
                        {
                            val = BindFunctionValue(types[i], val, out var converted);
                            if (!uncertain && converted == false && param != pipelineParameter) return Opaque("function-parameter-conversion");
                            uncertain |= converted != true;
                            foreach (var validation in validations[i])
                            {
                                var valid = ValidateFunctionValue(validation, val);
                                if (!uncertain && valid == false && param != pipelineParameter) return Opaque("function-validation");
                                uncertain |= valid != true;
                            }
                        }
                        if (!uncertain && provided && mandatory.Contains(param) && !allowEmpty.Contains(param) &&
                            val.IsString && val.Complete && val.Text == "") return Opaque("function-mandatory-parameter");
                        if (provided) bound[param] = val;
                        values[Key(param)] = val;
                    }
                    values[Key("PSBoundParameters")] = new Payload { Map = bound, Complete = !uncertain, InspectionPartial = uncertain };
                    ReachBranch(body);
                    if (uncertain) ReportMissing("function-parameter-binding");
                    StatementExit Run(object? block) => AnalyzeStatements(Items(Prop(block, "Statements")), depth + 1, output);
                    var exit = Run(Prop(body, "BeginBlock"));
                    if (process != null && exit == StatementExit.None)
                    {
                        var items = records ?? (currentStage > 1 && input == null ? Array.Empty<Payload>() :
                            new[] { input ?? Missing("no-pipeline-object") });
                        if (items.Length == 0) SkipBranch(process);
                        foreach (var item in items.Take(MaxForEachIterations))
                        {
                            values[Key("_")] = values[Key("PSItem")] = item;
                            if (pipelineParameter != null)
                            {
                                int index = Array.IndexOf(names, pipelineParameter);
                                var converted = BindFunctionValue(types[index], values[Key("_")], out var ok);
                                if (ok == false || validations[index].Any(v => ValidateFunctionValue(v, converted) == false)) continue;
                                bound[pipelineParameter] = values[Key(pipelineParameter)] = converted;
                            }
                            exit = Run(process);
                            if (exit != StatementExit.None) break;
                        }
                        if (exit == StatementExit.None && items.Length > MaxForEachIterations)
                        {
                            values[Key("_")] = values[Key("PSItem")] = UnknownValue("function-pipeline-limit", items.Skip(MaxForEachIterations).ToArray());
                            if (pipelineParameter != null) values[Key(pipelineParameter)] = values[Key("_")];
                            exit = Run(process);
                            ReportMissing("function-pipeline-limit");
                        }
                    }
                    if (exit == StatementExit.None) exit = Run(end);
                    if (outcomes.Count != 0)
                    {
                        outcomes.Add((new StatementState(this), exit));
                        MergeStatementPaths(outcomes.Select(o => (o.State, StatementExit.None)).ToList());
                    }
                    AnalyzeStatements(Items(Prop(Prop(body, "CleanBlock"), "Statements")), depth + 1);
                    if (uncertain)
                    {
                        var after = new StatementState(this, preserveMutableValues: true);
                        after.Join(entryState);
                        RestoreStatementState(after);
                        return output.Count == 0 ? null : UnknownValue("conditional-function-output", output.ToArray());
                    }
                    return output.Count == 0 ? null : output.Count == 1 ? output[0] : CollectElements(output);
                }
                finally
                {
                    functionScopes.Pop();
                    foreach (var key in values.Keys.Where(k => k.StartsWith(scope, StringComparison.Ordinal)).ToArray()) values.Remove(key);
                    foreach (var key in plan.Assignments.Keys.Where(k => k.StartsWith(scope, StringComparison.Ordinal)).ToArray()) plan.Assignments.Remove(key);
                    functions.Clear();
                    foreach (var pair in outerDefinitions) functions.Add(pair.Key, pair.Value);
                    scriptDefinitions.Clear();
                    scriptDefinitions.UnionWith(shadowed);
                    observeStatement = outerObserver;
                    observeAlternateExit = outerExit;
                }
            }
        }
    }
}

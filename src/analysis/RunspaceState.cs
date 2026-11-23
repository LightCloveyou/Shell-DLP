using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        const BindingFlags Instance = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
        static int MaxVars => Limits.MaxVars;
        static readonly ConditionalWeakTable<object, State> Sessions = new ConditionalWeakTable<object, State>();
        static readonly ConditionalWeakTable<object, Pending> Pipelines = new ConditionalWeakTable<object, Pending>();

        static object? InternalProp(object? o, string name)
        {
            for (var type = o?.GetType(); type != null; type = type.BaseType)
            {
                var prop = type.GetProperty(name, Instance | BindingFlags.DeclaredOnly);
                if (prop != null) return prop.GetValue(o);
            }
            return null;
        }

        static object? Method(object? o, string name, Type[] signature, params object[] args) =>
            o?.GetType().GetMethod(name, Instance, null, signature, null)?.Invoke(o, args);

        static string VarName(object? node) => Kind(node) == "VariableExpressionAst"
            ? Str(Prop(Prop(node, "VariablePath"), "UserPath")) : "";
        static bool SafeName(string name) => name.Length <= Limits.MaxVariableName &&
            Regex.IsMatch(name, @"^(?:(?:global|local|env):)?[a-z0-9_][a-z0-9_.-]*$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        static bool EnvName(string s) => s.StartsWith("env:", StringComparison.OrdinalIgnoreCase);
        static bool GlobalName(string s) => s.StartsWith("global:", StringComparison.OrdinalIgnoreCase);
        static string BaseName(string s) => s.Substring(s.IndexOf(':') + 1);
        static string Canonical(string s) => EnvName(s) ? "env:" + BaseName(s) : "global:" + BaseName(s);
        static bool SafeStableVariable(string name)
        {
            return !EnvName(name) && !Regex.IsMatch(BaseName(name),
                @"^(?:\d+|null|true|false|args|input|error|host|pwd|home|pid|pscmdlet|psitem|myinvocation|executioncontext|lastexitcode|matches|_)$",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }

        sealed class Observed
        {
            public readonly bool Known;
            public readonly string? Text;
            public readonly string Source;
            public readonly string Type;
            public readonly string? Origin;
            public readonly string[]? Dependencies;
            public readonly Mark[] Marks;
            public readonly object? Structured;
            public Observed(bool known, string? text, string source, string type, string? origin = null,
                string[]? dependencies = null, Mark[]? marks = null, object? structured = null)
            { Known = known; Text = text; Source = source; Type = type; Origin = origin; Dependencies = dependencies; Marks = marks ?? Array.Empty<Mark>(); Structured = structured; }
            public bool? Sensitive => Known ? Marks.Length != 0 || (Text != null && Store.Current(out _)?.Rules.Any(
                r => r.Texts.Any(t => Text.IndexOf(t, StringComparison.Ordinal) >= 0)) == true) : (bool?)null;
            public Observed At(string source) => new Observed(Known, Text, source, Type, Origin, Dependencies, Marks, Structured);
            public Observed From(Assignment assignment, Mark[]? marks = null) =>
                new Observed(Known, Text, Source, Type, assignment.Origin, assignment.DependsOn, marks, Structured);
            public object Report(string name) => Data("name", name, "known", Known, "valueType", Type,
                "valueLength", Text?.Length, "sensitive", Sensitive, "valueSource", Source,
                "candidateOrigin", Origin, "dependsOn", Dependencies, "flow", Marks.Select(m => m.Report()).ToArray());
            public bool Same(Observed other) => Known && other.Known &&
                Structured == null && other.Structured == null && Type == other.Type && string.Equals(Text, other.Text, StringComparison.Ordinal);
        }

        static Observed Unknown(string source) => new Observed(false, null, source, "");
        static object? UnwrapHostValue(object? value)
        {
            // Cmdlet output can carry a built-in PSObject wrapper. Unwrap only
            // the built-in carrier before checking the allowed base types.
            for (int i = 0; i < 3 && value != null &&
                value.GetType().FullName == "System.Management.Automation.PSObject" &&
                value.GetType().Assembly.GetName().Name == "System.Management.Automation"; i++)
            {
                var inner = Prop(value, "ImmediateBaseObject");
                if (ReferenceEquals(inner, value)) break;
                value = inner;
            }
            return value;
        }

        static Observed Scalar(object? value, string source)
        {
            value = UnwrapHostValue(value);
            if (value == null) return new Observed(true, null, source, "null");
            string? text;
            switch (value)
            {
                case string s: text = s; break;
                case bool b: text = b ? "True" : "False"; break;
                case byte _: case sbyte _: case short _: case ushort _: case int _: case uint _:
                case long _: case ulong _: case float _: case double _: case decimal _: case char _:
                    text = Convert.ToString(value, CultureInfo.InvariantCulture); break;
                default:
                    int budget = Limits.MaxCollection;
                    var snapshot = Snapshot(value, 0, ref budget);
                    return snapshot == null ? Unknown("unsupported-runtime-type") :
                        new Observed(true, null, source, value.GetType().Name, structured: snapshot);
            }
            return text?.Length > Limits.MaxRuntimeChars ? Unknown("runtime-value-limit") :
                new Observed(true, text, source, value.GetType().Name);
        }

        static Observed Read(object? engineState, string name, bool forceGlobal = false)
        {
            try
            {
                if (!SafeName(name)) return Unknown("unsupported-variable-name");
                if (EnvName(name))
                {
                    var v = Environment.GetEnvironmentVariable(BaseName(name));
                    return v == null ? Unknown("environment-not-found") : Scalar(v, "process-environment");
                }
                if (engineState == null) return Unknown("runspace-unavailable");
                var variable = forceGlobal || GlobalName(name)
                    ? Method(engineState, "GetVariableAtScope", new[] { typeof(string), typeof(string) }, BaseName(name), "global")
                    : Method(engineState, "GetVariable", new[] { typeof(string) }, name);
                // Never evaluate custom variable getters or stringify arbitrary script objects.
                if (variable == null) return Unknown("variable-not-found");
                if (Kind(variable) != "PSVariable") return Unknown("custom-variable");
                return Scalar(Prop(variable, "Value"), "runtime");
            }
            catch { return Unknown("runtime-unavailable"); }
        }

        sealed class State
        {
            internal readonly object Gate = new object();
            internal sealed class Entry
            {
                internal readonly Observed Snapshot;
                internal readonly long Revision;
                internal Entry(Observed snapshot, long revision) { Snapshot = snapshot; Revision = revision; }
            }
            internal readonly Dictionary<string, Entry> Values = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
            internal readonly List<object> Reports = new List<object>();
            internal readonly List<object> PolicyReports = new List<object>();
            internal long Revision;
            internal void Invalidate() => Revision++;
            internal void MarkDirty(string key)
            {
                if (Values.TryGetValue(key, out var entry))
                    Values[key] = new Entry(entry.Snapshot, Revision - 1);
            }
            internal void Put(string key, Observed value, long revision)
            {
                if (!value.Known) { Values.Remove(key); return; }
                if (!Values.ContainsKey(key) && Values.Count >= MaxVars) Values.Remove(Values.Keys.First());
                Values[key] = new Entry(value, revision);
            }
        }

        sealed class Assignment
        {
            internal readonly string Name, Origin;
            internal readonly string[] DependsOn;
            internal readonly bool Persistent;
            internal readonly Observed Before, Prediction;
            internal Assignment(string name, string origin, string[] deps, bool persistent, Observed before, Observed prediction)
            { Name = name; Origin = origin; DependsOn = deps; Persistent = persistent; Before = before; Prediction = prediction; }
        }

        sealed class Pending
        {
            readonly State state;
            readonly object engine;
            readonly List<Assignment> writes = new List<Assignment>();
            readonly Dictionary<string, Payload> labels = new Dictionary<string, Payload>(StringComparer.OrdinalIgnoreCase);
            readonly List<PolicyWork> work = new List<PolicyWork>();
            readonly EventInfo changed;
            readonly Delegate handler;
            bool unknownEffects, subscribed, finished;
            internal Pending(State state, object engine, object pipeline)
            {
                this.state = state; this.engine = engine;
                changed = pipeline.GetType().GetEvent("StateChanged", Instance) ?? throw new InvalidOperationException();
                handler = Delegate.CreateDelegate(changed.EventHandlerType!, this,
                    typeof(Pending).GetMethod(nameof(Completed), Instance)!);
            }

            static bool Terminal(string outcome) => outcome is "Completed" or "Failed" or "Stopped";
            static string Outcome(object? stateInfo) => Str(Prop(stateInfo, "State"));

            internal bool Add(object pipeline, IEnumerable<Assignment> assignments, bool unknown, RulePlan plan)
            {
                var outcome = Outcome(Prop(pipeline, "PipelineStateInfo"));
                lock (state.Gate)
                {
                    if (finished) return false;
                    if (!Terminal(outcome))
                    {
                        // GetValue can construct more than one candidate. Subscribe only
                        // on the published Pending, while holding the same gate as completion.
                        if (!subscribed)
                        {
                            changed.AddEventHandler(pipeline, handler);
                            subscribed = true;
                        }
                        if (finished) return false;
                        AddWork(assignments, unknown, plan);
                    }
                }
                if (Terminal(outcome))
                {
                    Finish(pipeline, outcome);
                    return false;
                }
                Finish(pipeline, Outcome(Prop(pipeline, "PipelineStateInfo")));
                return true;
            }

            void AddWork(IEnumerable<Assignment> assignments, bool unknown, RulePlan plan)
            {
                unknownEffects |= unknown;
                if (unknown) state.Invalidate();
                foreach (var write in assignments.Where(a => a.Persistent).Take(MaxVars))
                {
                    var key = Canonical(write.Name);
                    var old = writes.FindIndex(x => string.Equals(Canonical(x.Name), key, StringComparison.OrdinalIgnoreCase));
                    if (old < 0 && writes.Count >= MaxVars) { unknownEffects = true; state.Invalidate(); continue; }
                    if (old >= 0)
                    {
                        writes[old] = new Assignment(write.Name, "multiple-writes", write.DependsOn, true,
                            writes[old].Before, write.Prediction);
                    }
                    else writes.Add(write);
                    if (plan.Assignments.TryGetValue(key, out var label) ||
                        plan.Assignments.TryGetValue(write.Name, out label)) labels[key] = label;
                    else labels.Remove(key);
                    state.MarkDirty(key); // Preserve provenance, but confirm the value before reuse.
                }
                foreach (var update in plan.Work.Take(Math.Max(0, MaxEffects - work.Count)))
                { update.Register(); work.Add(update); }
            }

            void Completed(object? sender, EventArgs e)
            {
                try { Finish(sender, Outcome(Prop(e, "PipelineStateInfo"))); }
                catch { lock (state.Gate) state.Invalidate(); }
            }

            void Finish(object? pipeline, string outcome)
            {
                if (!Terminal(outcome)) return;
                (Assignment Write, State.Entry? Entry)[] candidates;
                PolicyWork[] updates;
                bool detach;
                long revision;
                lock (state.Gate)
                {
                    if (finished) return;
                    finished = true;
                    detach = subscribed;
                    revision = state.Revision;
                    candidates = writes.Select(write =>
                    {
                        state.Values.TryGetValue(Canonical(write.Name), out var entry);
                        return (write, (State.Entry?)entry);
                    }).ToArray();
                    updates = work.ToArray();
                    work.Clear();
                    writes.Clear();
                }
                if (detach && pipeline != null)
                    try { changed.RemoveEventHandler(pipeline, handler); } catch { }
                // Keep the terminal entry for as long as the pipeline key is alive.
                try
                {
                    var observed = candidates.Select(candidate =>
                        (candidate.Write, candidate.Entry, Value: Read(engine, candidate.Write.Name, true))).ToArray();
                    lock (state.Gate)
                    {
                        bool revisionMatches = state.Revision == revision;
                        if (unknownEffects || outcome != "Completed") state.Invalidate();
                        foreach (var pair in observed)
                        {
                            var a = pair.Write;
                            var key = Canonical(a.Name);
                            state.Values.TryGetValue(key, out var entry);
                            bool canPublish = revisionMatches && ReferenceEquals(pair.Entry, entry) && outcome == "Completed";
                            var mark = canPublish && labels.TryGetValue(key, out var label) &&
                                label.IsString && pair.Value.Type == "String" && label.Text != null &&
                                pair.Value.Known && label.Text == pair.Value.Text ? label.Tags : null;
                            var value = pair.Value.From(a, mark);
                            if (canPublish && value.Structured == null && SafeStableVariable(a.Name))
                                state.Put(key, value.At("observed-after-pipeline"), state.Revision);
                            if (state.Reports.Count >= MaxVars) state.Reports.RemoveAt(0);
                            state.Reports.Add(Data("name", a.Name, "outcome", outcome,
                                "updated", value.Known && !value.Same(a.Before),
                                "observed", value.Report(a.Name), "candidateOrigin", a.Origin,
                                "dependsOn", a.DependsOn,
                                "predictionMatches", a.Prediction.Known && value.Known ? (bool?)value.Same(a.Prediction) : null));
                        }
                    }
                    foreach (var update in updates) update.Commit(outcome == "Completed", state);
                }
                catch
                {
                    lock (state.Gate) state.Invalidate();
                    foreach (var update in updates) update.Commit(false, state);
                }
                finally { labels.Clear(); }
            }
        }

        sealed class Flow
        {
            readonly object? runspace, engine, pipeline;
            readonly State? state;
            readonly bool globalScope;
            readonly Dictionary<string, Observed> before = new Dictionary<string, Observed>(StringComparer.OrdinalIgnoreCase);
            readonly Dictionary<string, Observed> predicted = new Dictionary<string, Observed>(StringComparer.OrdinalIgnoreCase);
            readonly List<Assignment> assignments = new List<Assignment>();
            readonly Dictionary<string, object> definitions = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            readonly HashSet<string> lookedUp = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            readonly object[] previous = Array.Empty<object>();
            readonly object[] previousPolicy = Array.Empty<object>();
            readonly bool effectsUnknown;
            string post = "pipeline-unavailable";
            int cacheHits, cacheRevalidations, runtimeReads;

            internal static Flow Create(Assembly assembly, IEnumerable<object> nodes, object[] root) => new Flow(assembly, nodes.ToArray(), root);

            Flow(Assembly assembly, object[] nodes, object[] root)
            {
                try
                {
                    runspace = assembly.GetType("System.Management.Automation.Runspaces.Runspace")
                        ?.GetProperty("DefaultRunspace", BindingFlags.Public | BindingFlags.Static)?.GetValue(null);
                    if (runspace != null && Kind(runspace) == "LocalRunspace")
                    {
                        engine = InternalProp(InternalProp(runspace, "ExecutionContext"), "EngineSessionState");
                        globalScope = engine != null && ReferenceEquals(InternalProp(engine, "CurrentScope"), InternalProp(engine, "GlobalScope"));
                        pipeline = Method(runspace, "GetCurrentlyRunningPipeline", Type.EmptyTypes);
                        state = Sessions.GetValue(runspace, _ => new State());
                        lock (state.Gate)
                        {
                            previous = state.Reports.ToArray();
                            state.Reports.Clear();
                            previousPolicy = state.PolicyReports.ToArray();
                            state.PolicyReports.Clear();
                        }
                    }
                }
                catch { }

                foreach (var node in nodes.Where(n => Kind(n) == "VariableExpressionAst"))
                    Get(VarName(node));

                var direct = new HashSet<object>(root.Where(IsDirectWrite));
                foreach (var node in nodes.Where(n => Kind(n) == "AssignmentStatementAst").Take(MaxVars))
                {
                    var name = VarName(Prop(node, "Left"));
                    if (!SafeName(name)) continue;
                    var right = ValueExpression(Prop(node, "Right"));
                    var deps = Dependencies(Prop(node, "Right"));
                    var kind = Kind(right);
                    var origin = kind == "VariableExpressionAst" ? (EnvName(VarName(right)) ? "environment" : "variable")
                        : Literal(right) != null || kind == "ConstantExpressionAst" ? "literal"
                        : ContainsFileRead(Prop(node, "Right")) ? "file-read-candidate" : "expression";
                    var safe = direct.Contains(node);
                    var value = safe && IsSimpleAssignment(node) && right != null
                        ? Resolve(right) ?? Unknown("expression") : Unknown(safe ? "expression" : "control-flow");
                    var persistent = (GlobalName(name) || globalScope || EnvName(name)) && safe &&
                        !name.StartsWith("local:", StringComparison.OrdinalIgnoreCase);
                    assignments.Add(new Assignment(name, origin, deps, persistent, Get(name), value));
                    if (!safe) continue;
                    if (value.Known)
                        predicted[Key(name)] = value.At("linear-assignment");
                    else predicted[Key(name)] = Unknown("assignment-unresolved");
                }

                effectsUnknown = root.Length == 0 || root.Any(n => !IsSimpleAssignment(n)) ||
                    nodes.Any(n => Kind(n) == "CommandAst" || Kind(n) == "InvokeMemberExpressionAst");
            }

            static object? ValueExpression(object? statement)
            {
                if (Kind(statement) == "CommandExpressionAst") return Prop(statement, "Expression");
                if (Kind(statement) == "PipelineAst")
                {
                    var elements = Items(Prop(statement, "PipelineElements")).Take(2).ToArray();
                    if (elements.Length == 1 && Kind(elements[0]) == "CommandExpressionAst") return Prop(elements[0], "Expression");
                }
                return null;
            }

            static bool IsDirectWrite(object node) =>
                Kind(node) == "AssignmentStatementAst" && Str(Prop(node, "Operator")) == "Equals" &&
                SafeName(VarName(Prop(node, "Left")));

            static bool IsSimpleAssignment(object node)
            {
                var name = VarName(Prop(node, "Left"));
                if (!IsDirectWrite(node) || !SafeStableVariable(name)) return false;
                var expr = ValueExpression(Prop(node, "Right"));
                return Literal(expr) != null || Kind(expr) == "ConstantExpressionAst" ||
                    (Kind(expr) == "VariableExpressionAst" && SafeName(VarName(expr)));
            }

            static IEnumerable<object> Walk(object? node)
            {
                if (node == null) return Enumerable.Empty<object>();
                var find = node.GetType().GetMethod("FindAll")!;
                var filter = Delegate.CreateDelegate(find.GetParameters()[0].ParameterType,
                    typeof(AstBridge).GetMethod(nameof(Interesting), BindingFlags.Static | BindingFlags.NonPublic)!);
                return Items(find.Invoke(node, new object[] { filter, true })).Take(Limits.MaxVars);
            }

            static string[] Dependencies(object? right) => Walk(right)
                .Where(n => Kind(n) == "VariableExpressionAst").Select(VarName)
                .Where(SafeName).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

            static bool ContainsFileRead(object? right) => Walk(right).Any(n => Kind(n) == "CommandAst" &&
                Regex.IsMatch(Command(n), @"^(?:Get-Content|gc|cat|type)$", RegexOptions.IgnoreCase));

            bool CanCache(string name) => state != null && SafeStableVariable(name) &&
                (GlobalName(name) || (globalScope && !name.Contains(":")));
            string Key(string name) => GlobalName(name) || (globalScope && !name.Contains(":")) ? Canonical(name) : name;

            Observed Get(string name, bool force = false)
            {
                if (!SafeName(name)) return Unknown("unsupported-variable-name");
                var key = Key(name);
                if (!force && before.TryGetValue(key, out var found)) return found;
                if (!force && before.Count >= MaxVars) return Unknown("tracked-variable-limit");
                var cached = CanCache(name);
                State.Entry? prior = null;
                long revision = 0;
                if (cached)
                {
                    lock (state!.Gate)
                    {
                        revision = state.Revision;
                        if (state.Values.TryGetValue(key, out prior) && !force && prior.Revision == revision)
                        {
                            cacheHits++;
                            return before[key] = prior.Snapshot.At("runspace-cache");
                        }
                    }
                }
                runtimeReads++;
                var actual = Read(engine, name);
                if (prior != null)
                {
                    cacheRevalidations++;
                    if (actual.Same(prior.Snapshot))
                    {
                        if (!force) cacheHits++;
                        actual = prior.Snapshot.At("runspace-cache-revalidated");
                    }
                }
                before[key] = actual;
                if (cached && actual.Structured == null)
                {
                    lock (state!.Gate)
                    {
                        // Do not publish over state already updated while the query ran.
                        state.Values.TryGetValue(key, out var current);
                        if (state.Revision == revision && ReferenceEquals(prior, current))
                            state.Put(key, actual, revision);
                    }
                }
                return actual;
            }

            internal Observed? Resolve(object node, bool force = false)
            {
                var literal = Literal(node);
                if (literal != null) return Scalar(literal, "literal");
                if (Kind(node) == "ConstantExpressionAst") return Scalar(Prop(node, "Value"), "literal");
                var name = VarName(node);
                if (!SafeName(name)) return null;
                var key = Key(name);
                return predicted.TryGetValue(key, out var value) ? value : Get(name, force);
            }

            internal bool IsShadowed(string name)
            {
                if (definitions.ContainsKey(name)) return true;
                if (engine == null || !SafeName(name) || lookedUp.Count >= MaxVars || !lookedUp.Add(name)) return false;
                try
                {
                    var definition = Method(engine, "GetAlias", new[] { typeof(string) }, name)
                        ?? Method(engine, "GetFunction", new[] { typeof(string) }, name);
                    if (definition == null) return false;
                    definitions[name] = Data("name", name, "kind", Kind(definition),
                        "target", Kind(definition) == "AliasInfo" ? Prop(definition, "Definition") : null,
                        "module", Prop(definition, "ModuleName"),
                        "file", Prop(Prop(definition, "ScriptBlock"), "File"));
                    return true;
                }
                catch { return false; }
            }

            internal bool HasAlias(string name)
            {
                try { return Method(engine, "GetAlias", new[] { typeof(string) }, name) != null; }
                catch { return true; }
            }
            // true: loaded stock function; null: installed auto-load candidate only;
            // false: shadowed, disabled, unavailable or not a recognised command.
            internal bool? StockArchiveDefinition(string name, bool qualified)
            {
                if (name.ToLowerInvariant() is not ("compress-archive" or "expand-archive") || engine == null) return false;
                try
                {
                    if (Method(engine, "GetAlias", new[] { typeof(string) }, name) != null) return false;
                    var cmd = Method(engine, "GetFunction", new[] { typeof(string) }, name);
                    var install = System.IO.Path.GetDirectoryName(engine.GetType().Assembly.Location);
                    if (string.IsNullOrEmpty(install)) return false;
                    var modules = System.IO.Path.Combine(install, "Modules");
                    var stock = System.IO.Path.Combine(modules, "Microsoft.PowerShell.Archive", "Microsoft.PowerShell.Archive.psm1");
                    if (cmd == null)
                    {
                        if (Method(engine, "GetCmdlet", new[] { typeof(string) }, name) != null ||
                            !Disk.ClearAncestors(stock) || !System.IO.File.Exists(stock)) return false;
                        var pref = Method(engine, "GetVariable", new[] { typeof(string) }, "PSModuleAutoLoadingPreference");
                        if (pref != null)
                        {
                            if (Kind(pref) != "PSVariable") return false;
                            var value = Prop(pref, "Value");
                            string? mode = value is string text ? text : value is Enum e &&
                                e.GetType().FullName == "System.Management.Automation.PSModuleAutoLoadingPreference" ? e.ToString() : null;
                            if (!string.Equals(mode, "All", StringComparison.OrdinalIgnoreCase) &&
                                !(qualified && string.Equals(mode, "ModuleQualified", StringComparison.OrdinalIgnoreCase))) return false;
                        }
                        var paths = Environment.GetEnvironmentVariable("PSModulePath");
                        if (paths == null || !paths.Split(System.IO.Path.PathSeparator).Any(p =>
                            PathEq(p.TrimEnd('\\','/'), modules))) return false;
                        // Discovery order may still select another module. Never import or
                        // certify this candidate from inside the scanner.
                        return null;
                    }
                    var source = Prop(Prop(cmd, "ScriptBlock"), "File") as string;
                    return source != null &&
                        Str(Prop(cmd, "ModuleName")).Equals("Microsoft.PowerShell.Archive", StringComparison.OrdinalIgnoreCase) &&
                        PathEq(source, stock);
                }
                catch { return false; }
            }

            internal bool StockAlias(string name, string target, string module = "Microsoft.PowerShell.Management")
            {
                try
                {
                    var alias = Method(engine, "GetAlias", new[] { typeof(string) }, name);
                    return alias != null &&
                        (string.Equals(Prop(alias, "Definition") as string, target, StringComparison.OrdinalIgnoreCase)
                         || string.Equals(Prop(alias, "Definition") as string, module + "\\" + target, StringComparison.OrdinalIgnoreCase)) &&
                        !IsShadowed(target);
                }
                catch { return false; }
            }
            internal string RuleVariableKey(string name) =>
                Key(name.StartsWith("local:", StringComparison.OrdinalIgnoreCase) ? BaseName(name) : name);
            internal Observed RuleRead(string name)
            {
                var value = Get(name);
                // Revalidate individually at consumption. A stale cache entry cannot
                // cancel a decision based on a separate, independently proven input.
                return value.Source == "runspace-cache" ? Get(name, true) : value;
            }
            internal (string? Display, string? Provider) FileSystemLocation
            {
                get
                {
                    try
                    {
                        var paths = Prop(InternalProp(engine, "PublicSessionState"), "Path");
                        var location = Prop(paths, "CurrentLocation");
                        return Str(Prop(Prop(location, "Provider"), "Name")) == "FileSystem"
                            ? (Prop(location, "Path") as string, Prop(location, "ProviderPath") as string) : default;
                    }
                    catch { return default; }
                }
            }
            internal string? FileSystemDirectory => FileSystemLocation.Provider;

            internal void Schedule(RulePlan plan)
            {
                if (pipeline == null || state == null || engine == null)
                {
                    if (state != null) lock (state.Gate) state.Invalidate();
                    return;
                }
                try
                {
                    var pending = Pipelines.GetValue(pipeline, p => new Pending(state, engine, p));
                    post = pending.Add(pipeline, assignments, effectsUnknown, plan)
                        ? "pipeline-completion" : "pipeline-already-finished";
                }
                catch { lock (state.Gate) state.Invalidate(); }
            }

            internal object Report() => Data(
                "runspaceId", Prop(runspace, "InstanceId"),
                "runspaceState", Prop(Prop(runspace, "RunspaceStateInfo"), "State")?.ToString(),
                "availability", Prop(runspace, "RunspaceAvailability")?.ToString(),
                "cacheHits", cacheHits, "cacheRevalidations", cacheRevalidations, "runtimeReads", runtimeReads,
                "postUpdate", post, "variableReads", before.Where(kv => !EnvName(kv.Key)).Select(kv => kv.Value.Report(kv.Key)).ToArray(),
                "environmentReads", before.Where(kv => EnvName(kv.Key)).Select(kv => kv.Value.Report(kv.Key)).ToArray(),
                "commandDefinitions", definitions.Values, "previousUpdates", previous, "previousPolicyUpdates", previousPolicy,
                "assignments", assignments.Select(a => Data("name", a.Name, "candidateOrigin", a.Origin,
                    "dependsOn", a.DependsOn, "persistent", a.Persistent, "prediction", a.Prediction.Report(a.Name))).ToArray());
        }
    }
}

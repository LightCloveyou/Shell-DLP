using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            [DllImport("kernel32.dll", ExactSpelling = true)] static extern IntPtr GetEnvironmentStringsW();
            [DllImport("kernel32.dll", ExactSpelling = true)] static extern bool FreeEnvironmentStringsW(IntPtr block);

            Payload ProcessEnvironmentValue(string name)
            {
                if (!EnvKeyName(name)) return Missing("environment-name");
                if (SafeName("env:" + name)) return Variable("env:" + name);
                if (barrier || variablesUnknown || !Budget()) return LocalValue("env:" + name);
                try { return SourceTagged(Text(Environment.GetEnvironmentVariable(name), "env:" + name), "env:" + name); }
                catch (System.Security.SecurityException) { return LocalValue("env:" + name); }
            }
            Payload EnvironmentEntry(string name, Payload value)
            {
                var key = Text(name, "environment name");
                var record = ReadObject("environment entry", ("Name", key), ("Key", key), ("Value", value));
                record.Tags = Merge(key.Tags.Concat(value.Tags));
                return record;
            }
            // The scanner only enumerates names on an explicit process-environment
            // enumeration. It doesn't copy the complete environment into managed strings,
            // read values for -Name, or enumerate other processes/user/machine registries.
            bool ProcessNames(HashSet<string> names, Func<string, bool> select)
            {
                if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || !Budget()) return false;
                IntPtr block = GetEnvironmentStringsW();
                if (block == IntPtr.Zero) return false;
                try
                {
                    int pos = 0;
                    int cap = Math.Min(MaxContent / 2, int.MaxValue / 2);
                    while (pos < cap && Budget())
                    {
                        int start = pos, equals = -1;
                        while (pos < cap)
                        {
                            int c = (ushort)Marshal.ReadInt16(block, 2 * pos++);
                            if (c == 0) break;
                            if (equals < 0 && c == '=') equals = pos - 1;
                            if ((pos & 1023) == 0 && !Budget()) return false;
                        }
                        if (pos >= cap) return false;
                        if (start == pos - 1) return true;
                        if (equals == start) continue; // Windows drive-current-directory pseudo entries
                        if (equals <= start || equals - start > Limits.MaxVariableName) return false;
                        string? name = Marshal.PtrToStringUni(IntPtr.Add(block, start * 2), equals - start);
                        if (name != null && select(name)) names.Add(name);
                        if (names.Count > Limits.MaxCollection) return false;
                    }
                    return false;
                }
                finally { FreeEnvironmentStringsW(block); }
            }
            Payload EnvironmentSelection(string pattern, bool literal, Func<string, bool> filter, bool namesOnly, bool map)
            {
                if (barrier || variablesUnknown || pattern.Contains('\\') || pattern.Contains('/')) return Missing("environment-selection");
                bool wild = !literal && pattern.IndexOfAny("*?[".ToCharArray()) >= 0;
                if (pattern.Length != 0 && !wild)
                {
                    if (!filter(pattern)) return CollectElements(Array.Empty<Payload>());
                    if (namesOnly)
                    {
                        if (values.TryGetValue(Key("env:" + pattern), out var known))
                            return known.Issue == "process-environment-removed" ? CollectElements(Array.Empty<Payload>()) :
                                known.Complete ? Text(pattern, "environment name") : Missing("environment-entry-not-observed");
                        var selectedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        bool all = ProcessNames(selectedNames, n => n.Equals(pattern, StringComparison.OrdinalIgnoreCase));
                        return selectedNames.Count != 0 ? Text(pattern, "environment name") : all ? CollectElements(Array.Empty<Payload>()) :
                            Missing("environment-entry-not-observed");
                    }
                    var value = ProcessEnvironmentValue(pattern);
                    return EnvironmentEntry(pattern, value);
                }
                var pred = wild ? CompileWildcard(pattern) : (Func<string, bool>)(_ => true);
                if (pred == null) return Missing("environment-pattern");
                bool Matches(string name) => pred(name) && filter(name);
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                bool complete = ProcessNames(names, Matches);
                foreach (string key in values.Keys.Where(EnvName))
                {
                    var n = BaseName(key);
                    if (!Matches(n)) continue;
                    if (values[key].Issue == "process-environment-removed") { names.Remove(n); continue; }
                    if (!values[key].Complete || values[key].InspectionPartial) complete = false;
                    names.Add(n);
                }
                var entries = new List<Payload>();
                var fields = new Dictionary<string, Payload>(StringComparer.Ordinal);
                foreach (string n in names.OrderBy(s => s, StringComparer.CurrentCultureIgnoreCase))
                {
                    if (!Budget() || entries.Count + fields.Count >= Limits.MaxCollection) { complete = false; break; }
                    if (namesOnly) entries.Add(Text(n, "environment name"));
                    else
                    {
                        var value = ProcessEnvironmentValue(n);
                        if (map) fields[n] = value; else entries.Add(EnvironmentEntry(n, value));
                    }
                }
                if (map) return new Payload { Map = fields, Complete = complete, InspectionPartial = !complete,
                    Issue = "environment-map", Tags = Merge(KnownMarks(fields.Values)), SourceRef = "process environment" };
                if (complete && entries.Count == 1) return entries[0];
                var result = CollectElements(entries);
                result.Tags = Merge(KnownMarks(entries));
                if (!complete || result.InspectionPartial)
                {
                    result = Partial(result, "environment-enumeration-partial");
                    result.RecordRemainder = Missing("environment-entry-not-observed");
                    result.FirstUncertainIndex = 0;
                }
                // Provider object output is sorted; GetChildNames/dictionary enumeration order isn't a contract.
                if (namesOnly && entries.Count > 1) result.FirstUncertainIndex = 0;
                return result;
            }
            Payload EnvironmentMapMembers(Payload map, string member)
            {
                if (map.Map == null || member is not ("keys" or "values" or "count" or "entries")) return Missing("environment-map-member");
                if (member == "count") return map.Complete && !map.InspectionPartial ? Number(map.Map.Count) : Missing("environment-count");
                var members = CollectElements(map.Map.Select(p => member == "keys" ? Text(p.Key, "environment name") :
                    member == "values" ? p.Value : EnvironmentEntry(p.Key, p.Value)));
                members.Tags = Merge(KnownMarks(members.Elements ?? Array.Empty<Payload>()));
                if (map.InspectionPartial) { members = Partial(members, "environment-map-partial"); members.RecordRemainder = Missing("environment-map-remainder"); }
                if (map.InspectionPartial || map.Map.Count > 1) members.FirstUncertainIndex = 0;
                return members;
            }
            string? EnvironmentScope(object arg, int depth)
            {
                if (Kind(arg) == "MemberExpressionAst" && Equals(Prop(arg, "Static"), true) &&
                    TypeName(Prop(arg, "Expression")) is ("environmentvariabletarget" or "system.environmentvariabletarget"))
                    return Literal(Prop(arg, "Member"))?.ToLowerInvariant();
                return Value(arg, depth + 1).Text?.ToLowerInvariant() switch {
                    "process" or "0" => "process", "user" or "1" => "user", "machine" or "2" => "machine", _ => null };
            }
            Payload ReadEnvironmentMethod(string op, object[] args, int depth)
            {
                bool many = op == "getenvironmentvariables";
                int n = many ? 0 : 1;
                if (args.Length < n || args.Length > n + 1) return Missing("environment-overload");
                var scope = args.Length == n ? "process" : EnvironmentScope(args[n], depth);
                if (scope is not ("process" or "user" or "machine")) return Missing("environment-scope");
                if (many)
                {
                    if (scope == "process") return EnvironmentSelection("", false, _ => true, false, true);
                    // Never enumerate the registry to simulate a script. Capture only configured exact names.
                    var fields = new Dictionary<string, Payload>(StringComparer.OrdinalIgnoreCase);
                    string prefix = "env:" + scope + ":";
                    foreach (var sel in (policy?.Rules.SelectMany(r => r.Sources) ?? Enumerable.Empty<string>()).Where(s => s.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
                        if (Budget() && fields.Count < Limits.MaxCollection) fields[sel.Substring(prefix.Length)] = LocalValue(sel);
                    return new Payload { Map = fields, InspectionPartial = true, Issue = "environment-map",
                        Tags = Merge(KnownMarks(fields.Values)), SourceRef = prefix };
                }
                var name = ExactString(Value(args[0], depth + 1));
                if (!EnvKeyName(name)) return Missing("environment-name");
                if (scope == "process") return ProcessEnvironmentValue(name!);
                var origin = "env:" + scope + ":" + name;
                if (barrier || DurableEnv.Owner(scope!) is not string owner || !DurableEnv.Read(scope!, name!, out var actual, out var stamp))
                    return LocalValue(origin);
                var key = EnvKey(scope!, name!);
                if (PendingFiles.ContainsKey(key)) return SourceTagged(Missing("persistent-variable-pending"), origin);
                bool current = Store.RefreshDerived(file: false);
                var records = Store.Persistent(scope!, owner, name!).ToArray();
                var result = Text(actual, origin, Merge(Witness(key, stamp).Concat(records.Where(s => s.Get("stamp") == stamp)
                    .Select(s => new Mark(s.Get("rule_id"), s.Get("origin"), s.Get("route"))))));
                if (!current) { result.Complete = false; result.Issue = "persistent-generation"; }
                else if (records.Any(s => s.Get("stamp") != stamp)) { result.Complete = false; result.Issue = "persistent-variable-stale"; }
                return SourceTagged(result, origin);
            }
        }
    }
}

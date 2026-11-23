using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            Payload ReadSystemCommand(object command, string name, Payload? pipe)
            {
                var parameters = name switch {
                    "get-process" => new[] { "Name", "Id" }, "get-service" => new[] { "Name", "DisplayName" },
                    "get-history" => new[] { "Id", "Count" }, "get-computerinfo" => new[] { "Property" },
                    "get-netipconfiguration" => new[] { "InterfaceAlias", "InterfaceIndex" },
                    "read-host" => new[] { "Prompt" }, _ => Empty };
                var flags = name == "read-host" ? new[] { "MaskInput", "AsSecureString" } :
                    name == "get-netipconfiguration" ? new[] { "All", "Detailed" } : Empty;
                using var args = new Args(this, command, parameters, flags);
                if (!args.Valid || pipe != null || args.Plain.Count > (parameters.Length == 0 ? 0 : 1) ||
                    args.Plain.Count == 1 && args.Has(parameters[0]) || args.Has("AsSecureString") && args.Has("MaskInput"))
                    return Missing("system-read-binding");
                if (name == "get-location")
                {
                    if (barrier || cwd == null) return Missing("provider-location-not-observed");
                    var path = Text(cwd, "filesystem location");
                    var location = flow.FileSystemLocation;
                    var display = !locationWasSet && location.Provider != null && PathEq(cwd, location.Provider) && location.Display != null
                        ? Text(location.Display, "PowerShell drive location") : Missing("location-display-path-not-observed");
                    return ReadObject("PathInfo", ("Path", display), ("ProviderPath", path));
                }
                if (name == "read-host")
                    return args.Has("AsSecureString") ? Missing("interactive-securestring-object") : LocalValue("session:input");
                if ((args.Has("Id") || args.Has("DisplayName") || args.Has("InterfaceIndex")) &&
                    (args.Has("Name") || args.Has("InterfaceAlias") || args.Plain.Count != 0)) return Missing("system-read-parameter-set");
                var source = name switch {
                    "get-process" => "system:process", "get-service" => "system:service",
                    "get-history" => "session:history", "get-netipconfiguration" => "system:ipconfiguration",
                    _ => "system:computer" };
                if (name == "get-computerinfo" && (args.Has("Property") || args.Plain.Count != 0))
                {
                    var fields = LocalNames(Value(args.Get("Property") ?? args.Plain[0]));
                    if (fields == null) return Missing("computer-info-projection");
                    return ReadObject("computer properties", fields.Distinct(StringComparer.OrdinalIgnoreCase)
                        .Select(f => (f, LocalValue(source, f))).ToArray());
                }
                var record = LocalValue(source, record: true);
                return name == "get-computerinfo" ? record : LocalRecordSet(new[] { record }, name);
            }
            static bool EnvKeyName(string? name) => !string.IsNullOrEmpty(name) && name!.Length <= Limits.MaxVariableName &&
                !name.Any(c => char.IsControl(c) || c == '=' || c == '\0');
            Payload SourceTagged(Payload v, string origin)
            {
                if (policy == null) return v;
                var marks = policy.Rules.Where(r => r.Sources.Contains(origin, StringComparer.OrdinalIgnoreCase))
                    .Select(r => new Mark(r.Id, origin, origin)).ToArray();
                if (marks.Length == 0) return v;
                var copy = v.Copy(); copy.Tags = Merge(v.Tags.Concat(marks)); RecordSource(copy, "local-source"); return copy;
            }
            static Payload RegistryHandle(string origin) => HttpObjectValue(new HttpObject(HttpObjectKind.RegistryKey,
                address: new Payload { IsString = true, Text = origin, Complete = true, SourceRef = "registry key" }));
            Payload RegistryRoot(string name)
            {
                var hive = name.ToLowerInvariant() switch { "currentuser" => "HKEY_CURRENT_USER", "localmachine" => "HKEY_LOCAL_MACHINE",
                    "classesroot" => "HKEY_CLASSES_ROOT", "users" => "HKEY_USERS", "currentconfig" => "HKEY_CURRENT_CONFIG", _ => null };
                return hive == null ? Missing("registry-hive") : RegistryHandle("registry:" + hive);
            }
            Payload ReadRegistryCall(HttpObject? key, string method, object[] args, int depth)
            {
                string? origin;
                int i = 0;
                if (key == null)
                {
                    if (method != "getvalue" || args.Length != 3) return Missing("registry-static-overload");
                    string? raw = ExactString(Value(args[i++], depth + 1));
                    origin = raw?.StartsWith("HKEY_", StringComparison.OrdinalIgnoreCase) == true ? RegistryOrigin(raw) : null;
                }
                else
                {
                    if (Slot(key, "closed") != null) return Missing("registry-key-closed");
                    if (method is ("dispose" or "close") && args.Length == 0)
                    { SaveHttp(ReaderSet(key, ("closed", Number(1)))); return Missing("no-expression-output"); }
                    origin = key.Address?.Text;
                }
                if (origin == null) return Missing("registry-key-selection");
                if (method == "opensubkey" && (args.Length == 1 || args.Length == 2 && Value(args[1], depth + 1).ScalarTruth == false))
                {
                    var path = ExactString(Value(args[0], depth + 1));
                    if (path == "") return RegistryHandle(origin);
                    var child = path != null && !path.StartsWith("\\", StringComparison.Ordinal) ? RegistryOrigin(origin.Substring(9) + "\\" + path) : null;
                    return child == null ? Missing("registry-subkey") : RegistryHandle(child);
                }
                if (method is ("getvaluenames" or "getsubkeynames") && args.Length == 0) return Missing("registry-names-not-observed");
                if (method != "getvalue" || args.Length - i is < 1 or > 2) return Missing("registry-read-overload");
                var node = args[i++];
                var field = VarName(node).Equals("null", StringComparison.OrdinalIgnoreCase) ? "" : ExactString(Value(node, depth + 1));
                if (field == "") field = "(Default)";
                if (!ExactSelector(field)) return Missing("registry-value-name");
                var read = LocalValue(origin, field);
                if (i < args.Length && !VarName(args[i]).Equals("null", StringComparison.OrdinalIgnoreCase))
                    read = UnknownValue("registry-value-or-default", read, Value(args[i], depth + 1));
                return read;
            }
            Payload NativeSystemReport(string tool, string[] tokens)
            {
                // Only stdout of local read-only modes. Never start a process or query a remote host.
                var args = tokens.Select(s => s.ToLowerInvariant()).ToArray();
                for (int i = 0; i < args.Length; i++)
                {
                    var a = args[i];
                    if (tool is ("tasklist" or "whoami" or "systeminfo") && a == "/fo" && ++i < args.Length &&
                        args[i] is ("list" or "csv" or "table")) continue;
                    if (tool == "tasklist" && a == "/fi" && ++i < args.Length) continue;
                    if ((tool is "tasklist" or "whoami" or "systeminfo") && a == "/nh" ||
                        tool == "tasklist" && a is ("/v" or "/svc" or "/apps") ||
                        tool == "whoami" && a is ("/upn" or "/fqdn" or "/logonid" or "/user" or "/groups" or "/priv" or "/all") ||
                        tool == "ipconfig" && a is ("/all" or "/allcompartments" or "/displaydns")) continue;
                    return Missing("native-system-report-mode");
                }
                return LocalValue("system:" + tool);
            }

            Payload NativeEnvironment(string[] args, bool cmd)
            {
                if (args.Any(a => !EnvKeyName(a) || a.StartsWith("-") || cmd &&
                    a.IndexOfAny("&|<>^%!()\"/\\".ToCharArray()) >= 0) || (cmd && args.Length > 1))
                    return Missing("native-environment-mode");
                if (!cmd && args.Length != 0) return ReadOutput(args.Select(ProcessEnvironmentValue), "printenv");
                var filter = args.Length == 0 ? "" : args[0];
                var map = EnvironmentSelection("", false, n => n.StartsWith(filter, StringComparison.OrdinalIgnoreCase), false, true);
                if (map.Map == null) return UnknownValue("native-environment-list", map);
                var lines = map.Map.Select(p => p.Value.Complete && p.Value.Text != null ?
                    Text(p.Key + "=" + p.Value.Text, "env:" + p.Key, FileRecordMarks(p.Value)) :
                    UnknownValue("environment-entry-value", p.Value)).ToArray();
                var result = CollectElements(lines);
                result.Tags = Merge(KnownMarks(lines));
                // Native ordering and any additional interpreter-created entries are not known.
                result.FirstUncertainIndex = 0;
                if (map.InspectionPartial || !map.Complete || cmd)
                {
                    result.InspectionPartial = true; result.Complete = false; result.Issue = "native-environment-remainder";
                    result.RecordRemainder = Missing(result.Issue);
                }
                return result;
            }

            Payload NativeLocalSource(string tool, string[] args, Payload? pipe)
            {
                if (tool == "certutil")
                {
                    if (args.Length is < 2 or > 3 || !args[0].Equals("-hashfile", StringComparison.OrdinalIgnoreCase) ||
                        args[1].StartsWith("-") || Disk.Bind(args[1], cwd) == null) return Missing("certutil-operation");
                    var algorithm = args.Length == 2 ? "SHA1" : args[2].ToUpperInvariant();
                    if (algorithm is not ("MD2" or "MD4" or "MD5" or "SHA1" or "SHA256" or "SHA384" or "SHA512")) return Missing("certutil-algorithm");
                    // The native result is localized text, not a Get-FileHash record. Do not hash the input.
                    return UnknownValue("certutil-digest-and-diagnostics-not-observed", Text(args[1], "digest filename"), Text(algorithm, "digest algorithm"));
                }
                if (tool == "wevtutil")
                {
                    if (args.Length < 2 || args[0].ToLowerInvariant() is not ("qe" or "query-events") || !ExactSelector(args[1]) ||
                        args[1].StartsWith("/") || args[1].Contains('\\')) return Missing("wevtutil-query");
                    foreach (var flag in args.Skip(2))
                    {
                        var arg = flag.ToLowerInvariant();
                        if (arg.StartsWith("/q:") || arg.StartsWith("/c:") && int.TryParse(arg.Substring(3), out int n) && n > 0 ||
                            arg is ("/rd:true" or "/rd:false" or "/f:xml" or "/f:text" or "/f:renderedxml")) continue;
                        return Missing("wevtutil-query-option"); // no remote hosts, event files, bookmarks or structured-XML queries
                    }
                    return UnknownValue("wevtutil-output-not-observed", LocalValue("eventlog:" + args[1], record: true));
                }
                if (args.Length < 2 || !args[0].Equals("query", StringComparison.OrdinalIgnoreCase) ||
                    args[1].StartsWith("\\", StringComparison.Ordinal)) return Missing("reg-operation");
                var parts = args[1].Split(new[] { '\\' }, 2);
                string hive = parts[0].ToUpperInvariant() switch { "HKLM" => "HKEY_LOCAL_MACHINE", "HKCU" => "HKEY_CURRENT_USER",
                    "HKCR" => "HKEY_CLASSES_ROOT", "HKU" => "HKEY_USERS", "HKCC" => "HKEY_CURRENT_CONFIG", _ => parts[0] };
                var origin = RegistryOrigin(hive + (parts.Length == 1 ? "" : "\\" + parts[1]));
                if (origin == null) return Missing("reg-key");
                string? field = null; bool recurse = false;
                for (int i = 2; i < args.Length; i++)
                {
                    switch (args[i].ToLowerInvariant())
                    {
                        case "/v" when field == null && i + 1 < args.Length: field = args[++i]; if (!ExactSelector(field)) return Missing("reg-value-name"); break;
                        case "/ve" when field == null: field = "(Default)"; break;
                        case "/s": recurse = true; break;
                        case "/reg:32": case "/reg:64": break;
                        default: return Missing("reg-query-option");
                    }
                }
                var source = LocalValue(origin, field, record: field == null);
                if (recurse && policy != null)
                {
                    var below = origin + "\\";
                    source.Tags = Merge(source.Tags.Concat(policy.Rules.SelectMany(r => r.Sources.Where(s =>
                        s.StartsWith(below, StringComparison.OrdinalIgnoreCase) && (field == null || !s.Contains('#') ||
                            s.EndsWith("#" + field, StringComparison.OrdinalIgnoreCase))).Select(s => new Mark(r.Id, s, s)))));
                }
                return UnknownValue("reg-query-output-not-observed", source);
            }
            Payload ReadAcl(object command, Payload? pipe)
            {
                using var args = new Args(this, command, Paths, new[] { "Audit", "AllCentralAccessPolicies" });
                var node = PathArg(args, 0, out int count);
                if (!args.Valid || args.Has("Path") && args.Has("LiteralPath") || args.Plain.Count != (node == null ? 0 : count) ||
                    node != null && pipe != null) return Missing("acl-binding");
                var input = node != null ? Value(node) : pipe ?? Text(cwd, "current directory");
                IEnumerable<Payload> Entries()
                {
                    foreach (var loc in input.Files?.Records ?? input.Elements ?? new[] { input })
                    {
                        var path = loc.FileObject?.Path ?? ExactString(loc);
                        var reg = path == null ? null : RegistryOrigin(path);
                        var full = reg == null ? Disk.Bind(path, cwd) : null;
                        if (reg == null && full == null) { yield return Missing("acl-provider-path"); continue; }
                        var obj = LocalValue("acl:" + (reg ?? full), record: true);
                        obj.Map = new Dictionary<string, Payload>(StringComparer.OrdinalIgnoreCase) {
                            ["Path"] = Text(reg != null ? "Microsoft.PowerShell.Core\\Registry::" + reg.Substring(9) :
                                "Microsoft.PowerShell.Core\\FileSystem::" + full, "security descriptor path") };
                        yield return obj; // never call GetAccessControl or query a live security descriptor
                    }
                    if (input.InspectionPartial) yield return Missing("acl-selection");
                }
                return ReadOutput(Entries(), "Get-Acl");
            }
        }
    }
}

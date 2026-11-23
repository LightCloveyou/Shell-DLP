using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            // A selector proves origin, not contents, existence, result count or successful execution.
            // In particular the AMSI callback must not start another PowerShell pipeline,
            // access the interactive clipboard, enumerate the registry or query a CIM server.
            Payload LocalValue(string origin, string? field = null, bool record = false)
            {
                string selected = field == null ? origin : origin + "#" + field;
                var value = Missing("local-source-value-not-observed");
                value.SourceRef = selected;
                value.InspectionPartial = true;
                if (record) value.LocalRecord = origin;
                if (policy != null) value.Tags = Merge(policy.Rules.Where(r => r.Sources.Any(s =>
                    string.Equals(s, origin, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(s, selected, StringComparison.OrdinalIgnoreCase) ||
                    record && s.StartsWith(origin + "#", StringComparison.OrdinalIgnoreCase))).Select(r => new Mark(r.Id, selected, selected)));
                RecordSource(value, "local-source");
                return value;
            }

            static bool ExactSelector(string? s) => !string.IsNullOrWhiteSpace(s) && s!.Length <= Limits.MaxRuntimeChars &&
                !s.Any(char.IsControl) && s.IndexOfAny("*?[]#".ToCharArray()) < 0;

            Payload LocalField(Payload receiver, string field)
            {
                if (receiver.RecordRemainder is Payload remainder && receiver.Issue == "local-source-records-not-observed")
                    return LocalField(remainder, field);
                if (receiver.Elements != null && receiver.Issue == "local-source-alternatives")
                    return UnknownValue("local-source-member", receiver.Elements.Select(v => LocalField(v, field)).ToArray());
                if (receiver.Map?.TryGetValue(field, out var exact) == true) return exact;
                if (receiver.LocalRecord == null || !ExactSelector(field)) return Missing("local-source-member");
                if (receiver.LocalRecord.StartsWith("registry:", StringComparison.OrdinalIgnoreCase) &&
                    new[] { "PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider" }.Contains(field, StringComparer.OrdinalIgnoreCase))
                    return Missing("registry-provider-metadata");
                return LocalValue(receiver.LocalRecord, field);
            }

            static string? RegistryOrigin(string raw)
            {
                if (!ExactSelector(raw)) return null;
                var path = raw.Replace('/', '\\');
                const string module = "Microsoft.PowerShell.Core\\";
                if (path.StartsWith(module, StringComparison.OrdinalIgnoreCase)) path = path.Substring(module.Length);
                if (path.StartsWith("Registry::", StringComparison.OrdinalIgnoreCase)) path = path.Substring(10);
                int slash = path.IndexOf('\\');
                var drive = slash < 0 ? path : path.Substring(0, slash);
                var hive = drive.ToUpperInvariant() switch {
                    "HKLM:" or "HKEY_LOCAL_MACHINE" => "HKEY_LOCAL_MACHINE",
                    "HKCU:" or "HKEY_CURRENT_USER" => "HKEY_CURRENT_USER",
                    "HKEY_CLASSES_ROOT" => "HKEY_CLASSES_ROOT", "HKEY_USERS" => "HKEY_USERS",
                    "HKEY_CURRENT_CONFIG" => "HKEY_CURRENT_CONFIG", _ => null };
                if (hive == null) return null;
                var parts = path.Substring(slash < 0 ? path.Length : slash).Split('\\', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Any(p => p is "." or ".." || p.Contains(':'))) return null;
                return "registry:" + hive + (parts.Length == 0 ? "" : "\\" + string.Join("\\", parts));
            }

            string[]? LocalNames(Payload input)
            {
                var names = (input.Elements ?? new[] { input }).Select(ExactString).ToArray();
                if (!input.Complete || input.InspectionPartial || names.Length == 0 || names.Any(s => !ExactSelector(s))) return null;
                return names.Select(s => s!).ToArray();
            }

            Payload ReadLocalSource(object command, string name, Payload? pipe)
            {
                if (name == "get-clipboard")
                {
                    using var args = new Args(this, command, new[] { "Delimiter" }, new[] { "Raw" });
                    return args.Valid && pipe == null && args.Plain.Count == 0 && !(args.Has("Raw") && args.Has("Delimiter"))
                        ? LocalValue("clipboard") : Missing("clipboard-binding");
                }
                if (name == "get-winevent")
                {
                    using var args = new Args(this, command, new[] { "LogName", "FilterHashtable", "MaxEvents", "FilterXPath",
                        "ComputerName", "Credential" }, new[] { "Oldest", "Force" });
                    var node = args.Get("LogName") ?? args.Plain.FirstOrDefault();
                    if (!args.Valid || pipe != null || args.Has("ComputerName") || args.Has("Credential") ||
                        args.Plain.Count != (args.Has("LogName") || node == null ? 0 : 1) ||
                        args.Has("FilterHashtable") && (node != null || args.Has("FilterXPath"))) return Missing("event-source-binding");
                    if (args.Has("MaxEvents") && (!CountValue(Value(args.Get("MaxEvents")), out int max) || max == 0)) return Missing("event-count");
                    var logs = args.Has("FilterHashtable") ? Value(args.Get("FilterHashtable")).Map : null;
                    var source = node != null ? Value(node) : logs?.TryGetValue("LogName", out var value) == true ? value : null;
                    if (source == null || LocalNames(source) is not string[] names) return Missing("event-log-selection");
                    return LocalRecordSet(names.Select(n => LocalValue("eventlog:" + n, record: true)).ToArray(), name);
                }
                if (name == "get-ciminstance")
                {
                    using var args = new Args(this, command, new[] { "ClassName", "Namespace", "Property", "Filter", "Query",
                        "ComputerName", "CimSession", "OperationTimeoutSec" }, new[] { "KeyOnly" });
                    var node = args.Get("ClassName") ?? args.Plain.FirstOrDefault();
                    if (!args.Valid || pipe != null || args.Has("ComputerName") || args.Has("CimSession") ||
                        args.Plain.Count != (node == null || args.Has("ClassName") ? 0 : 1) ||
                        args.Has("Query") && (node != null || args.Has("Property") || args.Has("Filter"))) return Missing("cim-source-binding");
                    var ns = args.Has("Namespace") ? ExactString(Value(args.Get("Namespace")))?.Replace('/', '\\') : @"root\cimv2";
                    var cls = node == null ? null : ExactString(Value(node));
                    string[]? properties = args.Has("Property") ? LocalNames(Value(args.Get("Property"))) : null;
                    if (args.Has("Property") && properties == null) return Missing("cim-property-selection");
                    if (args.Has("Query"))
                    {
                        var q = ExactString(Value(args.Get("Query")));
                        if (q == null || q.Length > Limits.MaxRuntimeChars) return Missing("cim-query");
                        Match m;
                        try { m = Regex.Match(q, @"^\s*SELECT\s+(?<p>\*|[\w, ]+)\s+FROM\s+(?<c>[\w]+)(?:\s+WHERE\s+[^;]+)?\s*$",
                            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(30)); }
                        catch (RegexMatchTimeoutException) { return Missing("cim-query-budget"); }
                        if (!m.Success) return Missing("cim-query");
                        cls = m.Groups["c"].Value;
                        if (m.Groups["p"].Value.Trim() != "*") properties = m.Groups["p"].Value.Split(',').Select(s => s.Trim()).ToArray();
                    }
                    if (!ExactSelector(cls) || cls!.Any(c => !char.IsLetterOrDigit(c) && c != '_') || ns == null ||
                        !ns.StartsWith("root\\", StringComparison.OrdinalIgnoreCase) || ns.Split('\\').Any(p => !SafeName(p) || p.Contains(':') || p.Contains('.')))
                        return Missing("cim-local-class");
                    var origin = "cim:" + ns + "/" + cls;
                    var record = LocalValue(origin, record: !args.Has("KeyOnly") && properties == null);
                    if (properties != null)
                    {
                        record.Map = new Dictionary<string, Payload>(StringComparer.OrdinalIgnoreCase);
                        foreach (var p in properties) { if (!ExactSelector(p)) return Missing("cim-property-selection"); record.Map[p] = LocalValue(origin, p); }
                        record.Tags = Merge(record.Tags.Concat(KnownMarks(record.Map.Values)));
                    }
                    return LocalRecordSet(new[] { record }, name);
                }
                return ReadItemProperties(command, name, pipe);
            }

            // A selector can yield zero, one or many objects. Expose a representative
            // only as a remainder so indexing and control flow cannot assert a nonempty list.
            Payload LocalRecordSet(Payload[] choices, string name)
            {
                var rest = choices.Length == 1 ? choices[0] : new Payload { Elements = choices, InspectionPartial = true,
                    Issue = "local-source-alternatives", Tags = Merge(KnownMarks(choices)) };
                return new Payload { Elements = Array.Empty<Payload>(), RecordRemainder = rest,
                    Tags = Merge(KnownMarks(choices)), SourceRef = name, InspectionPartial = true, Issue = "local-source-records-not-observed" };
            }

            Payload ReadItemProperties(object command, string name, Payload? pipe)
            {
                using var args = new Args(this, command, Paths.Concat(new[] { "Name" }).ToArray(), new[] { "Force" });
                int pos = 0;
                var path = args.Get("LiteralPath") ?? args.Get("Path");
                if (path == null && pos < args.Plain.Count) path = args.Plain[pos++];
                var prop = args.Get("Name");
                if (prop == null && pos < args.Plain.Count) prop = args.Plain[pos++];
                bool scalar = name == "get-itempropertyvalue";
                if (!args.Valid || args.Has("Path") && args.Has("LiteralPath") || pos != args.Plain.Count ||
                    (path == null) == (pipe == null) || scalar && prop == null) return Missing("item-property-binding");
                var keys = prop == null ? null : LocalNames(Value(prop));
                if (prop != null && keys == null) return Missing("item-property-name");
                var locations = pipe ?? Value(path);
                IEnumerable<Payload> Items()
                {
                    foreach (var loc in locations.Files?.Records ?? locations.Elements ?? new[] { locations })
                    {
                        var raw = loc.FileObject?.Path ?? ExactString(loc);
                        if (raw == null || !Budget()) { yield return Missing("item-property-path"); continue; }
                        var origin = RegistryOrigin(raw);
                        if (origin != null)
                        {
                            var record = LocalValue(origin, record: keys == null);
                            if (keys == null) { yield return record; continue; }
                            record.Map = new Dictionary<string, Payload>(StringComparer.OrdinalIgnoreCase);
                            foreach (var key in keys)
                            {
                                var v = LocalField(new Payload { LocalRecord = origin }, key);
                                if (scalar) yield return v; else record.Map[key] = v;
                            }
                            if (!scalar) { record.Tags = Merge(record.Tags.Concat(KnownMarks(record.Map.Values))); yield return record; }
                            continue;
                        }
                        var full = Disk.Bind(raw, cwd);
                        if (full == null || barrier || plannedFiles.Contains(full) || PendingFiles.ContainsKey(full) ||
                            Disk.ResolveLocalPath(full, () => FileTimeAvailable) is not string local || DiskAttributes(local) is not FileAttributes attrs)
                        { yield return Missing("item-property-provider"); continue; }
                        var item = new Payload { FileObject = new FileReference(full, attrs.HasFlag(FileAttributes.Directory) ? PathKind.DirectoryInfo : PathKind.FileInfo),
                            Complete = true, SourceRef = full };
                        if (keys == null) { yield return item; continue; }
                        var fields = new Dictionary<string, Payload>(StringComparer.OrdinalIgnoreCase);
                        foreach (var key in keys)
                        {
                            var v = FsProperty(key.ToLowerInvariant()) ? FileSystemMember(item,key.ToLowerInvariant()) : null;
                            if (scalar) yield return v ?? Missing("file-property-value"); else fields[key] = v ?? Missing("file-property-value");
                        }
                        if (!scalar) yield return new Payload { Map = fields, Complete = true, SourceRef = full };
                    }
                    if (locations.InspectionPartial) yield return Missing("item-property-selection");
                }
                return ReadOutput(Items(), name);
            }
        }
    }
}

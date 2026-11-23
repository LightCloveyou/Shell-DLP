using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            const string UtilityModule = "Microsoft.PowerShell.Utility", ManagementModule = "Microsoft.PowerShell.Management";
            static readonly Dictionary<string, (string Name, string Module)> ReaderAliases =
                new Dictionary<string, (string, string)>(StringComparer.OrdinalIgnoreCase)
                {
                    ["sort"] = ("Sort-Object", UtilityModule),
                    ["where"] = ("Where-Object", "Microsoft.PowerShell.Core"),
                    ["group"] = ("Group-Object", UtilityModule), ["gm"] = ("Get-Member", UtilityModule),
                    ["ipcsv"] = ("Import-Csv", UtilityModule), ["gv"] = ("Get-Variable", UtilityModule),
                    ["rvpa"] = ("Resolve-Path", ManagementModule), ["cvpa"] = ("Convert-Path", ManagementModule),
                    ["gi"] = ("Get-Item", ManagementModule), ["sls"] = ("Select-String", UtilityModule),
                    ["fhx"] = ("Format-Hex", UtilityModule), ["sxml"] = ("Select-Xml", UtilityModule),
                    ["gp"] = ("Get-ItemProperty", ManagementModule), ["gpv"] = ("Get-ItemPropertyValue", ManagementModule),
                    ["gcb"] = ("Get-Clipboard", ManagementModule), ["select"] = ("Select-Object", UtilityModule),
                    ["gcim"] = ("Get-CimInstance", "CimCmdlets"),
                    ["gps"] = ("Get-Process", ManagementModule), ["ps"] = ("Get-Process", ManagementModule),
                    ["gsv"] = ("Get-Service", ManagementModule), ["gl"] = ("Get-Location", ManagementModule),
                    ["pwd"] = ("Get-Location", ManagementModule), ["ghy"] = ("Get-History", "Microsoft.PowerShell.Core"),
                    ["h"] = ("Get-History", "Microsoft.PowerShell.Core"), ["history"] = ("Get-History", "Microsoft.PowerShell.Core")
                };

            static Payload ReadObject(string origin, params (string Key, Payload Value)[] fields) =>
                new Payload { Complete = true, SourceRef = origin, Map = fields.ToDictionary(p => p.Key, p => p.Value, StringComparer.OrdinalIgnoreCase) };

            Payload ReadOutput(IEnumerable<Payload> records, string origin)
            {
                var output = CollectElements(records);
                if (output.Complete && output.Elements?.Length == 1) return output.Elements[0];
                output.SourceRef = origin;
                output.Tags = Merge(output.Tags.Concat(KnownMarks(output.Elements ?? Array.Empty<Payload>())));
                return output;
            }

            Payload CollectRawReads(IEnumerable<Payload> stream)
            {
                var items = new List<Payload>();
                var marks = new Dictionary<(string, string), Mark>();
                var remaining = new Dictionary<(string, string), Mark>();
                long chars = 0, count = 0;
                bool omitted = false, countKnown = true;
                int? gap = null;
                foreach (var p in stream)
                {
                    count++;
                    bool exact = p.Complete && !p.InspectionPartial && p.IsString && p.Text != null;
                    if (!exact) { countKnown = false; gap ??= items.Count; }
                    chars += (p.Text?.Length ?? 0) + (long)Environment.NewLine.Length;
                    bool keep = items.Count < Limits.MaxCollection && chars <= MaxContent / sizeof(char);
                    foreach (var mark in p.Tags)
                    {
                        marks[(mark.Id, mark.Origin)] = mark;
                        if (!keep || !exact) remaining[(mark.Id, mark.Origin)] = mark;
                    }
                    if (keep) items.Add(p);
                    else { omitted = true; gap ??= items.Count; }
                    if (!Budget()) { countKnown = false; omitted = true; gap ??= items.Count; break; }
                }
                var all = items.ToArray();
                var issue = omitted ? "file-raw-materialization-limit" : countKnown ? "" : "file-raw-records-incomplete";
                var wire = issue.Length == 0 && all.Length != 0 ? string.Join(Environment.NewLine, all.Select(p => p.Text)) + Environment.NewLine : null;
                return new Payload { Elements = all, PipeText = wire, FirstUncertainIndex = gap, RecordCount = countKnown ? count : null,
                    Complete = issue.Length == 0, InspectionPartial = issue.Length != 0, SourceRef = "Get-Content -Raw paths", Issue = issue,
                    Tags = Merge(marks.Values.Concat(wire == null ? Array.Empty<Mark>() : Text(wire, "file records").Tags)),
                    RecordRemainder = issue.Length == 0 ? null : new Payload { Issue = issue, InspectionPartial = true, Tags = Merge(remaining.Values) } };
            }

            // Keep the pipeline record boundary separate from the contents of an emitted array.
            Payload FileByteRecords(Payload file, byte[] bytes, bool raw, long readCount, long? head, int? tail,
                ref int budget, ref int rawRoom)
            {
                var marks = FileRecordMarks(file);
                Payload ArrayOf(Payload[] items, long count, bool truncated = false)
                {
                    var remainder = truncated ? new Payload { InspectionPartial = true, Issue = "file-byte-record-limit",
                        SourceRef = file.SourceRef, Tags = marks } : null;
                    return new Payload { Elements = items, RecordCount = count, RecordRemainder = remainder, Complete = !truncated,
                        InspectionPartial = truncated, Issue = remainder?.Issue ?? "", SourceRef = file.SourceRef,
                        Tags = count == 0 ? Array.Empty<Mark>() : marks };
                }
                if (bytes.Length == 0)
                {
                    var empty = ArrayOf(Array.Empty<Payload>(), 0);
                    empty.ByteRecordData = Array.Empty<byte>();
                    return empty;
                }
                if (raw)
                {
                    if (bytes.Length > rawRoom || budget <= 0)
                        return ArrayOf(new[] { UnknownValue("file-byte-materialization-limit", file) }, 1);
                    rawRoom -= bytes.Length;
                    budget--;
                    var item = Bytes(bytes, file.SourceRef, file.Tags);
                    var rawRecords = ArrayOf(new[] { readCount == 1 ? item : ArrayOf(new[] { item }, 1) }, 1);
                    if (readCount == 1) rawRecords.ByteRecordData = bytes;
                    return rawRecords;
                }
                if (readCount < 0 && head.HasValue) return Missing("file-byte-negative-count-with-head");
                int length = (int)Math.Min(bytes.Length, head ?? (long?)tail ?? bytes.Length);
                int start = tail.HasValue ? bytes.Length - length : 0;
                int width = readCount <= 0 ? Math.Max(1, length) : (int)Math.Min(int.MaxValue, readCount);
                long total = (length + (long)width - 1) / width;
                var outer = new List<Payload>();
                for (int pos = 0; pos < length && budget > 0 && Budget();)
                {
                    int size = Math.Min(width, length - pos), materialized = Math.Min(budget, size);
                    var inner = new List<Payload>(materialized);
                    for (int i = 0; i < materialized && Budget(); i++)
                    {
                        var p = Number(bytes[start + pos + i]); p.NumericType = "Byte"; p.Tags = marks; p.SourceRef = file.SourceRef;
                        inner.Add(p);
                    }
                    if (inner.Count == 0) break;
                    outer.Add(readCount == 1 ? inner[0] : ArrayOf(inner.ToArray(), size, inner.Count < size));
                    budget -= inner.Count;
                    pos += size;
                }
                var records = ArrayOf(outer.ToArray(), total, outer.Count < total);
                if (readCount == 1 && rawRoom >= length)
                {
                    rawRoom -= length;
                    records.ByteRecordData = start == 0 && length == bytes.Length ? bytes : bytes.AsSpan(start, length).ToArray();
                }
                return records;
            }

            Payload JoinReadBatches(List<Payload> batches, string origin)
            {
                if (batches.Count == 1 && batches[0].Elements != null) return batches[0];
                var items = new List<Payload>();
                var evidence = new List<Payload>();
                int? gap = null;
                long? count = 0;
                foreach (var batch in batches)
                {
                    count += batch.RecordCount;
                    foreach (var item in batch.Elements ?? Array.Empty<Payload>())
                    {
                        if (items.Count >= Limits.MaxCollection) { gap ??= items.Count; evidence.Add(batch); break; }
                        items.Add(item);
                    }
                    if (!batch.Complete || batch.InspectionPartial || batch.Elements == null)
                    { gap ??= items.Count; evidence.Add(batch.RecordRemainder ?? batch); }
                }
                var rest = evidence.Count == 0 ? null : UnknownValue("file-byte-records-incomplete", evidence.ToArray());
                var result = new Payload { Elements = items.ToArray(), RecordCount = count, FirstUncertainIndex = gap, RecordRemainder = rest,
                    Complete = rest == null, InspectionPartial = rest != null, Issue = rest?.Issue ?? "", SourceRef = origin,
                    Tags = Merge(KnownMarks(batches)) };
                if (batches.All(b => b.ByteRecordData != null) && batches.Sum(b => (long)b.ByteRecordData!.Length) <= MaxContent)
                    result.ByteRecordData = batches.SelectMany(b => b.ByteRecordData!).ToArray();
                return result;
            }

            Payload? NativeInput(Payload? input)
            {
                if (input == null || input.Bytes != null) return input;
                if (input.ByteRecordData != null) return Bytes(input.ByteRecordData, input.SourceRef, Merge(KnownMarks(new[] { input })));
                byte? Scalar(Payload p) => p.Complete && !p.InspectionPartial && p.NumericType == "Byte" &&
                    byte.TryParse(p.Text, NumberStyles.None, CultureInfo.InvariantCulture, out var n) ? n : null;
                return Scalar(input) is byte one ? Bytes(new[] { one }, input.SourceRef, input.Tags) : input;
            }

            static string? ExactString(Payload value) => value.Complete && !value.InspectionPartial && value.IsString ? value.Text : null;

            Payload ReadProjection(Payload item, string key)
            {
                if (item.Map?.TryGetValue(key, out var field) == true) return field;
                if (CurrentHttp(item.HttpObject) is { Kind: HttpObjectKind.XmlDocument } xml)
                    return xml.Body?.Map?.TryGetValue(key, out var part) == true ? part : Missing("xml-document-member");
                if (item.Issue == "environment-map") return EnvironmentMapMembers(item, key.ToLowerInvariant());
                if (item.LocalRecord != null || item.Issue is "local-source-alternatives" or "local-source-records-not-observed") return LocalField(item, key);
                var lower = key.ToLowerInvariant();
                if (CurrentHttp(item.HttpObject) is HttpObject handle && IsReadHandle(handle)) return ReaderProperty(handle, lower);
                if (lower == "length" && item.Bytes != null) return Number(item.Bytes.Length);
                if (lower == "length" && item.IsString && item.Text != null) return Number(item.Text.Length);
                if (item.TimeValue is DateTime time) return TimestampProperty(time,lower);
                return FsProperty(lower) ? FileSystemMember(item, lower) ?? Missing("file-property") : Missing("selected-property-value");
            }

            Payload SelectReadProperties(object command, Payload? pipe)
            {
                using var args = new Args(this, command, new[] { "InputObject", "Property", "ExpandProperty", "First", "Skip", "Last" }, Empty);
                var node = args.Get("Property") ?? args.Plain.FirstOrDefault();
                var expand = args.Has("ExpandProperty");
                int first = int.MaxValue, last = int.MaxValue, skip = 0;
                if (!args.Valid || (pipe != null) == args.Has("InputObject") || args.Plain.Count != (args.Has("Property") || node == null ? 0 : 1) ||
                    expand && node != null || args.Has("First") && args.Has("Last") ||
                    args.Has("First") && !CountValue(Value(args.Get("First")), out first) ||
                    args.Has("Last") && !CountValue(Value(args.Get("Last")), out last) ||
                    args.Has("Skip") && !CountValue(Value(args.Get("Skip")), out skip))
                    return Missing("select-object-binding");
                var keys = Array.Empty<string?>();
                if (expand || node != null)
                {
                    var p = Value(expand ? args.Get("ExpandProperty") : node);
                    keys = (p.Elements ?? new[] { p }).Select(ExactString).ToArray();
                    if (!p.Complete || p.InspectionPartial || keys.Length == 0 || expand && keys.Length != 1 ||
                        keys.Any(k => string.IsNullOrEmpty(k) || k!.IndexOfAny(new[] { '*', '?', '[' }) >= 0) ||
                        keys.Distinct(StringComparer.OrdinalIgnoreCase).Count() != keys.Length) return Missing("selected-property");
                }
                var src = pipe ?? Value(args.Get("InputObject"));
                var items = pipe == null ? new[] { src } : IterationItems(src) ?? new[] { src };
                if (pipe != null && (src.InspectionPartial || src.RecordRemainder != null || src.FirstUncertainIndex != null ||
                    src.Files?.Records.Any(e => e.FileObject == null) == true) && (skip != 0 || args.Has("First") || args.Has("Last")))
                    return Missing("select-object-position");
                var chosen = args.Has("Last") ? items.Take(Math.Max(0, items.Length - skip)).TakeLast(last) : items.Skip(skip).Take(first);
                IEnumerable<Payload> Output()
                {
                    foreach (var item in chosen)
                    {
                        if (keys.Length == 0) { yield return item; continue; }
                        var fields = new Dictionary<string, Payload>(StringComparer.OrdinalIgnoreCase);
                        foreach (var key in keys)
                        {
                            fields[key!] = ReadProjection(item, key!);
                        }
                        if (expand)
                        {
                            var v = fields[keys[0]!];
                            foreach (var e in v.Elements ?? new[] { v }) yield return e;
                            if (v.Elements != null && v.InspectionPartial) yield return Missing("selected-property-remainder");
                        }
                        else yield return new Payload { Map = fields, Complete = true, SourceRef = "selected properties",
                            ReadType = "Selected.Object", MemberDisplayType=(item.MemberDisplayType??ReadObjectType(item)) is string t?"Selected."+t:null };
                    }
                }
                return ReadOutput(Output(), "Select-Object");
            }

            Payload? EnvironmentItem(Payload input, string operation)
            {
                var text = ExactString(input);
                if (text == null || !text.StartsWith("env:", StringComparison.OrdinalIgnoreCase)) return null;
                var name = text.Substring(4).TrimStart('\\', '/');
                if (name.Length == 0 && operation == "get-item") return EnvironmentSelection("", false, _ => true, false, false);
                if (!EnvKeyName(name) || name.IndexOfAny("*?[]\\/".ToCharArray()) >= 0) return Missing("environment-selection");
                var value = ProcessEnvironmentValue(name);
                return operation == "get-content" ? value : EnvironmentEntry(name, value);
            }

            static Encoding? ReaderEncoding(object node)
            {
                if (Kind(node) != "MemberExpressionAst" || !Equals(Prop(node, "Static"), true) ||
                    TypeName(Prop(node, "Expression")) is not ("text.encoding" or "system.text.encoding")) return null;
                return Literal(Prop(node, "Member"))?.ToLowerInvariant() switch
                {
                    "utf8" => StrictUtf8, "ascii" => Encoding.ASCII, "unicode" => Encoding.Unicode,
                    "bigendianunicode" => Encoding.BigEndianUnicode, "utf32" => Encoding.UTF32, _ => null
                };
            }

            Payload DotNetFileRead(string member, object[] arguments, int depth)
            {
                bool async = member.EndsWith("async", StringComparison.Ordinal);
                if (async && arguments.Length > 1 && NoCancellation(arguments[arguments.Length-1]))
                    arguments = arguments.Take(arguments.Length-1).ToArray();
                var method = async ? member.Substring(0, member.Length - 5) : member;
                Payload Read()
                {
                    if (arguments.Length is < 1 or > 2) return Missing("file-read-overload");
                    var path = Value(arguments[0], depth + 1);
                    var raw = ExactString(path);
                    var encoding = arguments.Length == 2 ? ReaderEncoding(arguments[1]) : null;
                    if (arguments.Length == 2 && (encoding == null || method == "readallbytes")) return Missing("file-read-overload");
                    if (method == "readallbytes")
                    {
                        if (raw == null) return SymbolicBytes("file-bytes", ReadFileArgument(path, false));
                        var file = File(raw, false, out var sample, forceBytes: true);
                        var bytes = sample?.Bytes ?? file.Bytes;
                        return bytes == null ? SymbolicBytes("file-bytes", file) : Bytes(bytes, file.SourceRef, file.Tags);
                    }
                    var contents = raw == null || encoding == null ? ReadFileArgument(path, true) : File(raw, true, out _, encoding: encoding);
                    if (method == "readalltext") return contents;
                    if (contents.Text == null || !contents.Complete) return UnknownValue("file-lines-partial", contents);
                    using var reader = new StringReader(contents.Text);
                    var marks = FileRecordMarks(contents);
                    IEnumerable<Payload> Lines()
                    {
                        string? s;
                        while ((s = reader.ReadLine()) != null) yield return Text(s, contents.SourceRef, marks);
                    }
                    var output = CollectElements(Lines());
                    output.Tags = Merge(KnownMarks(output.Elements ?? Array.Empty<Payload>()).Concat(output.Tags));
                    output.SourceRef = contents.SourceRef;
                    output.InspectionPartial |= contents.InspectionPartial;
                    return output;
                }
                var result = Read();
                return async ? new Payload { FileTaskResult = result, Issue = "file-read-task", SourceRef = member } : result;
            }

            Payload ReadNamedVariable(object command, Payload? pipe)
            {
                using var args = new Args(this, command, new[] { "Name", "Scope" }, new[] { "ValueOnly" });
                var node = args.Get("Name") ?? args.Plain.FirstOrDefault();
                if (!args.Valid || pipe != null || node == null || args.Plain.Count != (args.Has("Name") ? 0 : 1))
                    return Missing("variable-reader-selection");
                var scope = args.Has("Scope") ? ExactString(Value(args.Get("Scope")))?.ToLowerInvariant() : "";
                if (scope is not ("" or "local" or "global")) return Missing("variable-reader-scope");
                var names = Value(node);
                IEnumerable<Payload> Entries()
                {
                    foreach (var item in names.Elements ?? new[] { names })
                    {
                        var n = ExactString(item);
                        if (n == null || !SafeName(n) || n.Contains(':')) { yield return Missing("variable-reader-name"); continue; }
                        var value = Variable(scope == "" ? n : scope + ":" + n);
                        yield return args.Has("ValueOnly") ? value : ReadObject("PSVariable", ("Name", Text(n, "variable name")), ("Value", value));
                    }
                    if (names.InspectionPartial) yield return Missing("variable-reader-selection");
                }
                return ReadOutput(Entries(), "Get-Variable");
            }

            Payload JoinFilePath(object command, Payload? pipe)
            {
                using var args = new Args(this, command, new[] { "Path", "ChildPath" }, Empty);
                int pos = 0;
                var parent = args.Get("Path") ?? args.Plain.ElementAtOrDefault(pos++);
                var child = args.Get("ChildPath") ?? args.Plain.ElementAtOrDefault(pos++);
                if (!args.Valid || pipe != null || parent == null || child == null || args.Plain.Count != pos)
                    return Missing("join-path-binding");
                var a = Value(parent);
                var b = Value(child);
                var root = ExactString(a);
                var tail = ExactString(b);
                // Produce a string, not a FileInfo or a read of the target. Only use the
                // exact, local filesystem form; other providers and -Resolve need provider semantics.
                if (root == null || root.Length < 3 || root[1] != ':' || root[2] != '\\' ||
                    Disk.Bind(root, null) is not string bound ||
                    !string.Equals(bound.TrimEnd('\\'), root.TrimEnd('\\'), StringComparison.Ordinal) ||
                    string.IsNullOrEmpty(tail) || tail.IndexOfAny(new[] { '/', '\\', ':', '*', '?', '[', ']' }) >= 0 ||
                    tail.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || tail.EndsWith('.') || tail.EndsWith(' '))
                    return Missing("join-path-components");
                return Text(root.TrimEnd('\\') + "\\" + tail, "Join-Path", Merge(a.Tags.Concat(b.Tags)));
            }

            Payload ReadMetadata(object command, string name, Payload? pipe)
            {
                bool hash = name == "get-filehash";
                using var args = new Args(this, command, hash ? Paths.Concat(new[] { "Algorithm", "InputStream" }).ToArray() : Paths,
                    name == "resolve-path" ? new[] { "Relative" } : Empty);
                var path = PathArg(args, 0, out var count);
                if (!args.Valid || args.Plain.Count != (path == null ? 0 : count) || args.Has("Path") && args.Has("LiteralPath") ||
                    path != null && pipe != null) return Missing("metadata-reader-binding");
                var algorithm = args.Has("Algorithm") ? ExactString(Value(args.Get("Algorithm")))?.ToUpperInvariant() : "SHA256";
                if (hash && algorithm is not ("SHA1" or "SHA256" or "SHA384" or "SHA512" or "MD5")) return Missing("filehash-algorithm");
                // Digests are derived metadata. Do not read the file or fabricate digest bytes.
                Payload Digest(Payload filename) => ReadObject("file digest", ("Path", filename),
                    ("Algorithm", Text(algorithm, "digest algorithm")), ("Hash", Missing("digest-not-materialized")));
                if (args.Has("InputStream"))
                    return path == null && pipe == null ? Digest(Text("", "stream has no filename")) : Missing("filehash-binding");
                if (path == null && pipe == null) return Missing("metadata-reader-path");
                var input = path == null ? pipe! : Value(path);
                IEnumerable<Payload> Entries()
                {
                    foreach (var p in SelectFilePaths(input, args, includeDirectories: !hash))
                    {
                        var full = Disk.Bind(p.Text, cwd);
                        if (barrier || full == null || !Budget() || p.InspectionPartial || UncertainFileTree(Path.GetDirectoryName(full)) ||
                            plannedFiles.Contains(full) || PendingFiles.ContainsKey(full) ||
                            Disk.ResolveLocalPath(full, () => FileTimeAvailable) is not string local ||
                            DiskAttributes(local) is not FileAttributes attrs || hash && attrs.HasFlag(FileAttributes.Directory))
                        { yield return Missing("metadata-reader-path"); continue; }
                        var text = Text(full, "filesystem path");
                        if (hash) yield return Digest(text);
                        else if (name == "convert-path") yield return text;
                        else if (args.Has("Relative"))
                        {
                            if (cwd == null || !PathEq(Path.GetPathRoot(full)!, Path.GetPathRoot(cwd)!))
                            { yield return Missing("relative-path-base"); continue; }
                            var relative = Path.GetRelativePath(cwd, full);
                            yield return Text(relative == "." || relative == ".." || relative.StartsWith("..\\", StringComparison.Ordinal) ?
                                relative : ".\\" + relative, "relative path");
                        }
                        else yield return ReadObject("PathInfo", ("Path", text), ("ProviderPath", text));
                    }
                }
                return ReadOutput(Entries(), name);
            }

            // A field inherits a configured file origin, not every text match elsewhere in the file.
            Payload ReadCsv(object command, string name, Payload? pipe)
            {
                bool import = name == "import-csv";
                using var args = new Args(this, command, (import ? Paths : new[] { "InputObject" })
                    .Concat(new[] { "Delimiter", "Header" }).ToArray(), new[] { "UseCulture" });
                if (!args.Valid || args.Has("UseCulture") && args.Has("Delimiter")) return Missing("csv-binding");
                string? delimiter = args.Has("Delimiter") ? ExactString(Value(args.Get("Delimiter"))) :
                    args.Has("UseCulture") ? CultureInfo.CurrentCulture.TextInfo.ListSeparator : ",";
                if (delimiter?.Length != 1) return Missing("csv-delimiter");
                string[]? header = null;
                if (args.Has("Header"))
                {
                    var value = Value(args.Get("Header"));
                    var names = (value.Elements ?? new[] { value }).Select(ExactString).ToArray();
                    if (!value.Complete || value.InspectionPartial || names.Any(string.IsNullOrEmpty)) return Missing("csv-header");
                    header = names.Select(n => n!).ToArray();
                }
                var node = import ? PathArg(args, 0, out _) : args.Get("InputObject") ?? args.Plain.FirstOrDefault();
                if (import && args.Has("Path") && args.Has("LiteralPath") || args.Plain.Count != (args.Has("Path") || args.Has("LiteralPath") ||
                    args.Has("InputObject") || node == null ? 0 : 1) || node != null && pipe != null || node == null && pipe == null)
                    return Missing("csv-input-binding");
                var input = node == null ? pipe! : Value(node);
                IEnumerable<Payload> Rows()
                {
                    var columns = header;
                    var sources = import ? SelectFilePaths(input, args) : input.Elements ?? new[] { input };
                    foreach (var entry in sources)
                    {
                        if (!Budget()) { yield return Missing("csv-budget"); yield break; }
                        var source = import ? File(entry.Text, true, out _) : entry;
                        var text = import ? source.Text : source.PipeText ?? source.Text;
                        if (text == null || entry.InspectionPartial || !source.Complete || source.InspectionPartial)
                        { yield return Missing("csv-input-partial"); if (!import) yield break; continue; }
                        if (import) columns = header;
                        var marks = FileRecordMarks(source);
                        foreach (var cells in CsvRecords(text, delimiter![0]))
                        {
                            if (cells == null) { yield return Missing("csv-record-shape-or-limit"); yield break; }
                            if (columns == null)
                            {
                                if (cells[0].StartsWith("#Fields: ", StringComparison.Ordinal)) cells[0] = cells[0].Substring("#Fields: ".Length);
                                else if (cells[0].StartsWith("#", StringComparison.Ordinal)) continue;
                                columns = cells;
                                continue;
                            }
                            if (columns.Any(string.IsNullOrEmpty) || columns.Distinct(StringComparer.OrdinalIgnoreCase).Count() != columns.Length)
                            { yield return Missing("csv-header-shape"); yield break; }
                            var fields = new Dictionary<string, Payload>(StringComparer.OrdinalIgnoreCase);
                            for (int j = 0; j < columns.Length; j++)
                                fields.Add(columns[j], j < cells.Length ? Text(cells[j], source.SourceRef, marks) : Missing("csv-absent-field"));
                            yield return new Payload { Complete = true, Map = fields, SourceRef = source.SourceRef, ReadType = "System.Management.Automation.PSCustomObject" };
                        }
                    }
                    if (input.InspectionPartial) yield return Missing("csv-input-partial");
                }
                return ReadOutput(Rows(), name);
            }

            IEnumerable<string[]?> CsvRecords(string text, char delimiter)
            {
                var fields = new List<string>();
                var value = new StringBuilder();
                bool quoted = false, closed = false, started = false;
                for (int i = 0; i <= text.Length; i++)
                {
                    if ((i % 512 == 0 && !Budget()) || fields.Count >= Limits.MaxCollection) { yield return null; yield break; }
                    bool end = i == text.Length;
                    char c = end ? '\0' : text[i];
                    if (quoted)
                    {
                        if (end) { yield return null; yield break; }
                        if (c != '"') value.Append(c);
                        else if (i + 1 < text.Length && text[i + 1] == '"') { value.Append(c); i++; }
                        else { quoted = false; closed = true; }
                    }
                    else if (end || c == delimiter || c is '\r' or '\n')
                    {
                        if (c == delimiter && !end || fields.Count != 0 || started)
                        {
                            fields.Add(value.ToString());
                            if (end || c != delimiter) { yield return fields.ToArray(); fields.Clear(); }
                        }
                        if (!end && c == '\r' && i + 1 < text.Length && text[i + 1] == '\n') i++;
                        value.Clear(); started = closed = false;
                    }
                    else if (closed)
                    {
                        if (c is not (' ' or '\t')) { yield return null; yield break; }
                    }
                    else if (c == '"' && !started) started = quoted = true;
                    else { started = true; value.Append(c); }
                }
            }
        }
    }
}

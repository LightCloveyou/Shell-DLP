using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Enumeration;
using System.Linq;
using System.Text;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            Payload GetFileItem(object command, Payload? pipe)
            {
                using var args = new Args(this, command, Paths.Concat(new[] { "Filter", "Include", "Exclude", "Credential", "Stream" }).ToArray(), new[] { "Force" });
                var arg = PathArg(args, 0, out int count);
                if (!args.Valid || arg == null || args.Plain.Count != count || pipe != null)
                    return Missing("file-item-arguments");
                if (args.Has("Credential")) return Missing("file-item-provider");
                if (args.Has("Stream")) return StreamEntries(Value(arg), args);
                Payload Item(Payload value)
                {
                    if (EnvironmentItem(value, "get-item") is Payload env) return env;
                    var path = Disk.Bind(value.Text, cwd);
                    if (path == null || !Budget() || barrier && !Path.IsPathRooted(value.Text!)) return Missing("file-item-path");
                    FileAttributes? attrs;
                    if (predictedWrites.TryGetValue(path, out var predicted))
                    {
                        if (predicted.Issue == "file-moved") return Missing("file-item-unavailable");
                        attrs = predicted.PredictedAttributes;
                    }
                    else
                    {
                        if (plannedFiles.Contains(path) || Disk.ResolveLocalPath(path, () => FileTimeAvailable) is not string local ||
                            (attrs = DiskAttributes(local)) == null) return Missing("file-item-unavailable");
                    }
                    var kind = attrs?.HasFlag(FileAttributes.Directory) == true ? PathKind.DirectoryInfo : PathKind.FileInfo;
                    return new Payload { FileObject = new FileReference(path, kind), Complete = true, InspectionPartial = value.InspectionPartial, SourceRef = path };
                }
                var items = CollectElements(SelectFilePaths(Value(arg), args, includeDirectories: true).Select(Item));
                return items.Complete && items.Elements?.Length == 1 ? items.Elements[0] : items;
            }

            Func<string, bool>? FileNameFilter(Args args, object? filterNode)
            {
                Func<string, bool>[]? Patterns(string parameter)
                {
                    if (!args.Has(parameter)) return Array.Empty<Func<string, bool>>();
                    var value = Value(args.Get(parameter));
                    if (!value.Complete) return null;
                    var known = new List<Func<string, bool>>();
                    foreach (var item in value.Elements ?? new[] { value })
                    {
                        if (!item.Complete || !item.IsString || item.Text == null || CompileWildcard(item.Text) is not { } predicate)
                            return null;
                        known.Add(predicate);
                    }
                    return known.ToArray();
                }
                var include = Patterns("Include");
                var exclude = Patterns("Exclude");
                if (include == null || exclude == null) return null;
                string? filter = null;
                if (filterNode != null)
                {
                    var value = Value(filterNode);
                    if (!value.Complete || !value.IsString || value.Text == null || value.Text.Length > Limits.MaxFilter ||
                        value.Text.IndexOfAny(new[] { (char)92, '/', ':', (char)0 }) >= 0)
                        return null;
                    filter = FileSystemName.TranslateWin32Expression(value.Text);
                }

                return name =>
                    (filter == null || FileSystemName.MatchesWin32Expression(filter.AsSpan(), name.AsSpan(), ignoreCase: true)) &&
                    (include.Length == 0 || include.Any(p => p(name))) && !exclude.Any(p => p(name));
            }

            // FileSystem provider filters apply during enumeration. A literal path
            // bypasses globbing, including the engine's include/exclude expansion.
            IEnumerable<Payload> SelectFilePaths(Payload input, Args args, bool includeDirectories = false)
            {
                input = MaterializeDirectory(input);
                var matches = FileNameFilter(args, args.Get("Filter"));
                if (matches == null) { yield return Missing("file-selection-filter"); yield break; }
                foreach (var item in input.Files?.Records ?? input.Elements ?? new[] { input })
                {
                    var paths = item.PathAlternatives?.Select(p => p.Path).Distinct(StringComparer.OrdinalIgnoreCase) ?? new[] { item.FileObject?.Path ?? item.Text };
                    Payload SelectedPath(string raw)
                    {
                        var selected = Text(raw, "file path");
                        if (item.PathAlternatives != null || item.InspectionPartial) selected = Partial(selected, "conditional-file-selection");
                        return selected;
                    }
                    foreach (var raw in paths)
                    {
                        if (raw == null || !Budget()) { yield return Missing("file-selection-path-or-budget"); continue; }
                        bool literal = args.Has("LiteralPath");
                        bool glob = !literal && raw.IndexOfAny(new[] { '*', '?', '[' }) >= 0;
                        if (!glob)
                        {
                            if (literal || !args.Has("Include") && !args.Has("Exclude") || matches(Path.GetFileName(raw)))
                                yield return SelectedPath(raw);
                            continue;
                        }
                        int firstWildcard = raw.IndexOfAny(new[] { '*', '?', '[' });
                        int sep = raw.Substring(0, firstWildcard).LastIndexOfAny(new[] { (char)92, '/' });
                        var folder = sep < 0 ? cwd : Disk.Bind(raw.Substring(0, sep + 1), cwd);
                        var segments = raw.Substring(sep + 1).Split(new[] { (char)92, '/' }, StringSplitOptions.RemoveEmptyEntries);
                        if (barrier || folder == null || segments.Length == 0 || segments.Length > MaxExpressionDepth)
                        { yield return Missing("file-wildcard-path"); continue; }

                        IEnumerable<Payload> Expand(string parent, int level)
                        {
                            if (!Budget() || !StackAvailable) { yield return Missing("file-selection-budget"); yield break; }
                            var pattern = CompileWildcard(segments[level]);
                            if (pattern == null) { yield return Missing("file-wildcard-pattern"); yield break; }
                            bool last = level == segments.Length - 1;
                            bool Selected(string leaf) => pattern(leaf) && (!last || matches(leaf));
                            foreach (var (entry, issue) in EnumerateFiles(parent, false, args.Has("Force"), !last || includeDirectories,
                                matchesName: Selected, matchesAttributes: attr => last || (attr & FileAttributes.Directory) != 0))
                            {
                                if (entry == null) yield return Missing(issue ?? "file-wildcard-enumeration");
                                else if (last) yield return SelectedPath(entry.Path);
                                else foreach (var result in Expand(entry.Path, level + 1)) yield return result;
                            }
                        }
                        foreach (var result in Expand(folder, 0)) yield return result;
                    }
                }
                if (input.Elements != null && input.InspectionPartial)
                {
                    if (input.RecordRemainder?.PathAlternatives != null)
                        foreach (var path in SelectFilePaths(input.RecordRemainder, args, includeDirectories)) yield return path;
                    yield return Missing("file-selection-partial");
                }
            }

            Payload DirectoryRead(string member, object[] args, int depth)
            {
                if (args.Length is < 1 or > 3) return Missing("directory-read-overload");
                var root = ExactString(Value(args[0], depth + 1));
                var pattern = args.Length > 1 ? ExactString(Value(args[1], depth + 1)) : "*";
                // Relative System.IO paths use the process working directory, not the PS provider location.
                if (root == null || !Path.IsPathFullyQualified(root) || Disk.Bind(root, null) is not string full ||
                    !string.Equals(root.TrimEnd('\\'), full.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase) ||
                    pattern == null || pattern.Length == 0 || pattern.Length > Limits.MaxRuntimeChars ||
                    pattern.IndexOfAny("\\/:<>|\"".ToCharArray()) >= 0 || pattern.Any(char.IsControl))
                    return Missing("directory-root-or-pattern");
                bool recurse = false;
                if (args.Length == 3)
                {
                    var a = args[2];
                    var mode = Kind(a) == "MemberExpressionAst" && Equals(Prop(a, "Static"), true) &&
                        HttpType(TypeName(Prop(a, "Expression"))) == "io.searchoption" ? Literal(Prop(a, "Member")) :
                        ExactString(Value(a, depth + 1));
                    if (string.Equals(mode, "AllDirectories", StringComparison.OrdinalIgnoreCase)) recurse = true;
                    else if (!string.Equals(mode, "TopDirectoryOnly", StringComparison.OrdinalIgnoreCase))
                        return Missing("directory-search-option");
                }
                PathKind? kind = member.EndsWith("directories", StringComparison.Ordinal) ? PathKind.DirectoryInfo :
                    member.EndsWith("files", StringComparison.Ordinal) ? PathKind.FileInfo : null;
                var pending = new Payload { DeferredDirectory = (full, FileSystemName.TranslateWin32Expression(pattern), kind, recurse),
                    SourceRef = "Directory." + member, Issue = "directory-enumeration-deferred" };
                return member.StartsWith("enumerate", StringComparison.Ordinal) ? pending : MaterializeDirectory(pending);
            }

            Payload MaterializeDirectory(Payload value)
            {
                if (value.DeferredDirectory is not { } s) return value;
                if (barrier || !Budget() || UncertainFileTree(s.Root) || PendingFiles.ContainsKey(s.Root)) return Missing("directory-state-unknown");
                var rootAttributes = predictedWrites.TryGetValue(s.Root, out var state) ? state.PredictedAttributes :
                    Disk.ResolveLocalPath(s.Root, () => FileTimeAvailable) is string local ? DiskAttributes(local) : null;
                if (rootAttributes?.HasFlag(FileAttributes.Directory) != true) return Missing("directory-root-unavailable");
                var entries = new List<Payload>();
                int? gap = null;
                string issue = "";
                // A recursive walker or planned directory change can establish a set of paths, but not OS index order.
                bool orderUnknown = s.Recursive || predictedWrites.Keys.Any(p => InFolder(p, s.Root));
                foreach (var (entry, error) in EnumerateFiles(s.Root, s.Recursive, true, true,
                    n => FileSystemName.MatchesWin32Expression(s.Filter, n, true), providerOrder: false))
                {
                    if (entries.Count >= Limits.MaxCollection || !Budget()) { gap ??= entries.Count; issue = "directory-materialization-limit"; break; }
                    if (entry == null) { gap ??= entries.Count; issue = error ?? "directory-entry"; entries.Add(Missing(issue)); continue; }
                    if (s.Kind != null && s.Kind != entry.Kind) continue;
                    entries.Add(Text(entry.Path, "filesystem path"));
                }
                return new Payload { Elements = entries.ToArray(), SourceRef = value.SourceRef, FirstUncertainIndex = orderUnknown && entries.Count > 1 ? 0 : gap,
                    Complete = gap == null, InspectionPartial = gap != null, RecordCount = gap == null ? entries.Count : null,
                    Issue = issue, RecordRemainder = gap == null ? null : Missing(issue) };
            }

            Payload FileSet(object command, Payload? pipe)
            {
                using var args = new Args(this, command, Paths.Concat(new[] { "Filter", "Include", "Exclude", "Depth", "Attributes" }).ToArray(),
                    new[] { "File", "Directory", "Recurse", "Force", "Hidden", "System", "ReadOnly", "Name", "FollowSymlink" });
                var pathNode = PathArg(args, 0, out int expected);
                if (pathNode == null && !args.Has("Path") && !args.Has("LiteralPath") && args.Plain.Count == 0) expected = 0;
                if (pathNode == null && (args.Has("Path") || args.Has("LiteralPath"))) return Missing("file-set-path");
                object? filterNode = args.Get("Filter");
                if (filterNode == null && args.Plain.Count == expected + 1) filterNode = args.Plain[expected++];
                if (!args.Valid || args.Plain.Count != expected || pipe != null || barrier)
                    return Missing("file-set-arguments");
                var pathValue = pathNode == null ? null : Value(pathNode);
                bool literal = args.Has("LiteralPath"), recurse = args.Has("Recurse"), files = args.Has("File");
                uint depth = uint.MaxValue;
                if (args.Has("Depth"))
                {
                    if (!uint.TryParse(Value(args.Get("Depth")).Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out depth))
                        return Missing("file-set-depth");
                    recurse = true;
                }
                bool hidden = args.Has("Hidden");
                // -System alone selects visible system entries; it does not opt in to Hidden.
                bool includeHidden = hidden || args.Has("Force");
                Func<FileAttributes, bool>? evaluate = null;
                if (args.Has("Attributes"))
                {
                    var expression = Value(args.Get("Attributes"));
                    var terms = expression.Elements ?? new[] { expression };
                    if (terms.Any(p => !p.Complete || p.Text == null)) return Missing("file-set-attributes");
                    try
                    {
                        var type = command.GetType().Assembly.GetType("System.Management.Automation.FlagsExpression`1", true)!
                            .MakeGenericType(typeof(FileAttributes));
                        object argument = expression.Elements == null ? (object)terms[0].Text! : terms.Select(v => (object)v.Text!).ToArray();
                        var parser = Activator.CreateInstance(type, new[] { argument });
                        evaluate = (Func<FileAttributes, bool>)type.GetMethod("Evaluate")!.CreateDelegate(typeof(Func<FileAttributes, bool>), parser);
                        var mentions = type.GetMethod("ExistsInExpression", System.Reflection.BindingFlags.Public |
                            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                        if (mentions == null) return Missing("file-set-attributes");
                        includeHidden |= Equals(mentions.Invoke(parser, new object[] { FileAttributes.Hidden }), true);
                    }
                    catch (Exception) { return Missing("file-set-attributes"); }
                }
                bool Attributes(FileAttributes value) => (!hidden || value.HasFlag(FileAttributes.Hidden)) &&
                    (!args.Has("System") || value.HasFlag(FileAttributes.System)) &&
                    (!args.Has("ReadOnly") || value.HasFlag(FileAttributes.ReadOnly)) &&
                    (!args.Has("Directory") || value.HasFlag(FileAttributes.Directory)) &&
                    (!files || !value.HasFlag(FileAttributes.Directory)) && (evaluate?.Invoke(value) ?? true);
                var selection = FileNameFilter(args, filterNode);
                if (selection == null) return Missing("file-set-filter");
                bool namesOnly = args.Has("Name");
                if (ExactString(pathValue ?? Missing("environment-path")) is string env && env.StartsWith("env:", StringComparison.OrdinalIgnoreCase))
                {
                    if (files || args.Has("Directory") || args.Has("Attributes") || args.Has("System") ||
                        args.Has("Hidden") || args.Has("ReadOnly") || args.Has("FollowSymlink") || filterNode != null) return Missing("environment-selection");
                    return EnvironmentSelection(env.Substring(4).TrimStart('\\', '/'), literal, selection, namesOnly, false);
                }
                IEnumerable<Payload> Entries(Payload location)
                {
                    var requested = location.FileObject?.Path ?? location.Text;
                    if (requested == null || !location.Complete) { yield return Missing("file-set-path"); yield break; }
                    if (requested.StartsWith("env:", StringComparison.OrdinalIgnoreCase))
                    {
                        var entry = EnvironmentItem(location, "get-childitem");
                        if (entry?.Map == null || !selection(entry.Map["Name"].Text!) || leafOnlyOptions()) { yield return Missing("environment-selection"); yield break; }
                        yield return namesOnly ? entry.Map["Name"] : entry;
                        yield break;
                    }
                    bool leafOnlyOptions() => files || args.Has("Directory") || args.Has("Attributes") || args.Has("System") ||
                        args.Has("Hidden") || args.Has("ReadOnly") || recurse || filterNode != null;
                    bool glob = !literal && requested.IndexOfAny(new[] { '*', '?', '[' }) >= 0;
                    Func<string, bool>? leaf = null;
                    if (glob)
                    {
                        int slash = requested.LastIndexOfAny(new[] { (char)92, '/' });
                        leaf = CompileWildcard(requested.Substring(slash + 1));
                        if (leaf == null) { yield return Missing("file-set-path-pattern"); yield break; }
                        requested = slash < 0 ? cwd : requested.Substring(0, slash + 1);
                    }
                    var root = Disk.Bind(requested, cwd);
                    if (root == null) { yield return Missing("file-set-path"); yield break; }
                    if (!literal && !glob && !recurse && files && args.Has("Include") && Directory.Exists(root)) yield break;
                    bool Matches(string name) => (leaf?.Invoke(name) ?? true) && selection(name);
                    foreach (var (entry, issue) in EnumerateFiles(root, recurse, includeHidden, !files, Matches, Attributes,
                        depth, args.Has("FollowSymlink")))
                    {
                        if (entry == null) yield return Missing(issue ?? "file-set-unavailable");
                        else if (namesOnly) yield return Text(PathEq(entry.Path, root) ? Path.GetFileName(root) :
                            Path.GetRelativePath(root, entry.Path), "Get-ChildItem -Name");
                        else yield return new Payload { Complete = true, SourceRef = entry.Path, FileObject = entry };
                    }
                }
                var input = pathValue ?? Text(cwd, "current directory");
                IEnumerable<Payload> Records()
                {
                    var locations = input.Elements ?? new[] { input };
                    foreach (var location in input.RecordRemainder == null ? locations.AsEnumerable() : locations.Append(input.RecordRemainder))
                    {
                        if (!Budget()) { yield return Missing("file-time-budget"); yield break; }
                        if (location.PathAlternatives is { } alternatives)
                        {
                            yield return Missing("conditional-file-selection");
                            foreach (var path in alternatives.Select(a => a.Path).Distinct(StringComparer.OrdinalIgnoreCase))
                            {
                                if (!Budget()) { yield return Missing("file-time-budget"); yield break; }
                                foreach (var entry in Entries(Text(path, "possible file path"))) yield return entry;
                            }
                            continue;
                        }
                        foreach (var entry in Entries(location)) yield return entry;
                    }
                    if (input.InspectionPartial) yield return Missing("file-set-path");
                }
                if (namesOnly)
                {
                    var names = CollectElements(Records());
                    names.Tags = Merge(KnownMarks(names.Elements ?? Array.Empty<Payload>()).Concat(names.Tags));
                    if (names.Complete && names.Elements?.Length == 1) return names.Elements[0];
                    return names.Elements?.Any(v => !v.Complete) == true ? Partial(names, "file-set-name") : names;
                }
                var records = Records().ToArray();
                if (records.Length == 1 && (records[0].FileObject != null || records[0].Map != null)) return records[0];
                if (records.Any(r => r.Map != null)) return ReadOutput(records, "provider entries");
                int unknown=Array.FindIndex(records,p=>p.FileObject==null || p.InspectionPartial || !p.Complete);
                return new Payload { Files = new FileSetReference(records), Complete = unknown<0, InspectionPartial = unknown>=0,
                    FirstUncertainIndex=unknown<0?(int?)null:unknown, Issue=unknown<0?"":"file-set-unobserved-entries", SourceRef = "Get-ChildItem" };
            }

            IEnumerable<Payload> MultipartFiles(IEnumerable<Payload> records)
            {
                foreach (var item in records)
                {
                    if (item.PathAlternatives is { } alternatives)
                    {
                        yield return item; // The alternatives are not an exhaustive list.
                        foreach (var reference in alternatives)
                            foreach (var part in MultipartEntry(reference)) yield return part;
                    }
                    else if (item.FileObject is FileReference reference)
                        foreach (var part in MultipartEntry(reference)) yield return part;
                    else yield return item;
                }
            }

            IEnumerable<Payload> MultipartEntry(FileReference entry)
            {
                if (entry.Kind == PathKind.PathString) { yield return Text(entry.Path, "multipart field"); yield break; }
                if (entry.Kind == PathKind.DirectoryInfo) { yield return Missing("multipart-directory-metadata"); yield break; }
                yield return Text(Path.GetFileName(entry.Path), "multipart filename");
                yield return File(entry.Path, false, out _).Via("multipart file");
            }

            IEnumerable<Payload> FormValues(Payload form)
            {
                if (form.Map == null) { yield return UnknownValue("http-form-shape", form); yield break; }
                foreach (var field in form.Map.Take(Limits.MaxCollection))
                {
                    yield return Text(field.Key, "http-form-field");
                    if (field.Value.RecordRemainder == null && field.Value.Elements != null && field.Value.InspectionPartial)
                        yield return new Payload { Tags = field.Value.Tags, InspectionPartial = true, Issue = "http-form-item-limit" };
                    var items = field.Value.Elements ?? new[] { field.Value };
                    if (items.Length > Limits.MaxCollection && items.All(v => v.FileObject != null))
                        yield return AggregateFileEvidence(MultipartFiles(items), "multipart files");
                    else
                    {
                        foreach (var item in items.Take(Limits.MaxCollection))
                        {
                            if (item.Files is FileSetReference set)
                                yield return AggregateFileEvidence(MultipartFiles(set.Records), "multipart files");
                            else if (item.PathAlternatives != null || item.FileObject != null)
                                foreach (var part in MultipartFiles(new[] { item })) yield return part;
                            else if (item.Map != null || item.Elements != null || item.Bytes != null)
                                yield return Missing("http-form-nested-value");
                            else yield return item;
                        }
                        if (items.Length > Limits.MaxCollection)
                            yield return UnknownValue("http-form-item-limit", items.Skip(Limits.MaxCollection).ToArray());
                    }
                    if (field.Value.RecordRemainder is Payload rest)
                    {
                        foreach (var part in MultipartFiles(new[] { rest })) yield return part;
                    }
                }
            }

            Payload ConvertJson(object command, Payload? pipe)
            {
                using var args = new Args(this, command, new[] { "InputObject", "Depth", "EscapeHandling", "OutVariable" },
                    new[] { "Compress", "AsArray", "EnumsAsStrings" });
                var node = args.Get("InputObject") ?? args.Plain.FirstOrDefault();
                if (!args.Valid || args.Plain.Count > (args.Has("InputObject") ? 0 : 1) ||
                    (node != null && pipe != null)) return Missing("json-arguments");
                int requestedDepth = 2;
                if (args.Has("Depth") && (!int.TryParse(Value(args.Get("Depth")).Text, NumberStyles.Integer,
                    CultureInfo.InvariantCulture, out requestedDepth) || requestedDepth < 0 || requestedDepth > 100))
                    return Missing("json-depth-argument");
                var escape = args.Has("EscapeHandling") ? Value(args.Get("EscapeHandling")).Text : "Default";
                if (!new[] { "Default", "EscapeNonAscii", "EscapeHtml" }.Contains(escape, StringComparer.OrdinalIgnoreCase))
                    return Missing("json-escape-handling");

                var input = node == null ? pipe : Value(node);
                if (input == null) return Missing("json-input");
                var emptyLineInput = new Payload { Complete = true };
                var partialLineInputs = new HashSet<Payload>();
                Payload ConvertLineRecords(Payload value)
                {
                    if (value.Issue == "file-read-count-grouping" && value.Elements != null)
                        return new Payload { Elements = value.Elements, Complete = true, SourceRef = value.SourceRef };
                    if (value.Elements != null || !value.Complete || value.PipeText is not string lines) return value;
                    using var reader = new StringReader(lines);
                    var records = new List<Payload>();
                    var inherited = FileRecordMarks(value);
                    string? line;
                    while ((line = reader.ReadLine()) != null && records.Count < MaxJsonElements)
                        records.Add(Text(line, value.SourceRef, inherited));
                    if (records.Count == 0) return emptyLineInput;
                    if (records.Count == 1 && line == null)
                        return records[0];
                    var array = new Payload { Elements = records.ToArray(), Complete = true, SourceRef = value.SourceRef };
                    if (line != null) { array.Tags = value.Tags; partialLineInputs.Add(array); }
                    return array;
                }
                input = ConvertLineRecords(input);
                if (node == null && ReferenceEquals(input, emptyLineInput))
                    return Missing("json-empty-pipeline");
                bool pipelineArray = node == null && (input.Elements?.Length > 1 || partialLineInputs.Contains(input));
                // Pipeline input is enumerated. An explicit InputObject is passed as-is.
                if (node == null && input.Elements is { } records && records.Length <= 1 && !input.InspectionPartial && !partialLineInputs.Contains(input))
                {
                    if (records.Length == 0) return Missing("json-empty-pipeline");
                    input = records[0];
                }
                if (args.Has("AsArray") && !pipelineArray)
                    input = new Payload { Elements = new[] { input }, Complete = true };

                var builder = new StringBuilder();

                var marks = new List<Mark>();
                int visited = 0;
                bool exact = args.Has("Compress"); // Otherwise whitespace is not reproduced.
                bool complete = true;
                void Quote(string value)
                {
                    if (!exact) return;
                    builder.Append('"');
                    foreach (char c in value)
                    {
                        if (builder.Length > MaxContent || !Budget()) { exact = false; break; }
                        switch (c)
                        {
                            case '"': builder.Append("\\\""); break;
                            case '\\': builder.Append("\\\\"); break;
                            case '\b': builder.Append("\\b"); break;
                            case '\f': builder.Append("\\f"); break;
                            case '\r': builder.Append("\\r"); break;
                            case '\n': builder.Append("\\n"); break;
                            case '\t': builder.Append("\\t"); break;
                            default:
                                if (char.IsControl(c) || char.IsSurrogate(c) || c is '\u0085' or '\u2028' or '\u2029')
                                    builder.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                                else builder.Append(c);
                                break;
                        }
                    }
                    builder.Append('"');
                }
                void RemainingMarks(Payload value, int depth, HashSet<Payload> ancestors)
                {
                    bool container = value.Map != null || value.Elements != null || value.UnmaterializedFileRecords ||
                        value.PipeText != null;
                    if (container && depth > requestedDepth || !ancestors.Add(value)) return;
                    try
                    {
                        marks.AddRange(value.Tags);
                        if (value.Map != null)
                            foreach (var pair in value.Map)
                            {
                                marks.AddRange(Text(pair.Key, "json-field").Tags);
                                RemainingMarks(pair.Value, depth + 1, ancestors);
                            }
                        if (value.Elements != null)
                            foreach (var element in value.Elements) RemainingMarks(element, depth + 1, ancestors);
                    }
                    finally { ancestors.Remove(value); }
                }

                void Write(Payload value, int depth)
                {
                    if (++visited > MaxJsonElements || depth > MaxExpressionDepth)
                    { RemainingMarks(value, depth, new HashSet<Payload>()); complete = false; return; }
                    value = ConvertLineRecords(value);
                    if (ReferenceEquals(value, emptyLineInput)) { builder.Append("null"); return; }
                    if (!value.Complete || value.InspectionPartial || value.FileObject != null || value.Files != null || value.Bytes != null ||
                        value.Model != null || value.PipeText != null)
                    {
                        // The source can be known without knowing the exact string or
                        // line array. For a possible array, honor the serializer depth.
                        bool scalar = value.IsString && value.Map == null && value.Elements == null && value.FileObject == null &&
                            value.Files == null && value.Bytes == null && value.Model == null && value.PipeText == null;
                        int recordDepth = value.Issue is ("file-unmaterialized-groups" or "file-multi-groups") ? depth + 1 : depth;
                        if (scalar || (value.UnmaterializedFileRecords ? recordDepth <= requestedDepth : value.InspectionPartial))
                            marks.AddRange(value.Issue is ("file-multi-records" or "file-multi-groups") ? FileRecordMarks(value) : value.Tags);
                        complete = false;
                        builder.Append("null");
                        return;
                    }
                    if (value.Map != null || value.Elements != null)
                    {
                        // A container beyond PowerShell's depth becomes a representation of
                        // the container, not a serialization of all its child fields.
                        if (depth > requestedDepth) { complete = false; builder.Append("null"); return; }
                        if (value.Map is { } map)
                        {
                            // Hashtables do not promise source-order enumeration.
                            if (map.Count > 1) exact = false;
                            builder.Append('{');
                            bool first = true;
                            foreach (var pair in map)
                            {
                                if (visited >= MaxJsonElements) { RemainingMarks(value, depth, new HashSet<Payload>()); complete = false; break; }
                                if (!first) builder.Append(',');
                                first = false;
                                marks.AddRange(Text(pair.Key, "json-field").Tags);
                                Quote(pair.Key);
                                builder.Append(':');
                                Write(pair.Value, depth + 1);
                            }
                            builder.Append('}');
                        }
                        else
                        {
                            builder.Append('[');
                            bool first = true;
                            foreach (var item in value.Elements!)
                            {
                                if (visited >= MaxJsonElements) { RemainingMarks(value, depth, new HashSet<Payload>()); complete = false; break; }
                                if (!first) builder.Append(',');
                                first = false;
                                Write(item, depth + 1);
                            }
                            builder.Append(']');
                            // Array payloads produced by a complete file line stream carry
                            // source labels independently of the individual line strings.
                            if (value.Tags.Length > 0) marks.AddRange(value.Tags);
                            if (partialLineInputs.Contains(value)) complete = false;
                        }
                        return;
                    }
                    if (value.Text != null && value.IsString)
                    { marks.AddRange(value.Tags); Quote(value.Text); }
                    else if (value.Text != null && value.NumericType is ("Int32" or "Int64") &&
                        long.TryParse(value.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number))
                    { marks.AddRange(value.Tags); builder.Append(number.ToString(CultureInfo.InvariantCulture)); }
                    else if (value.NumericType == null && value.ScalarTruth is bool truth)
                    { marks.AddRange(value.Tags); builder.Append(truth ? "true" : "false"); }
                    else { complete = false; builder.Append("null"); }
                }
                Write(input, 0);
                exact &= complete && builder.Length <= MaxContent &&
                    escape!.Equals("Default", StringComparison.OrdinalIgnoreCase);
                var tags = Merge(marks.Select(m => m.Via("ConvertTo-Json")));
                return exact ? Text(builder.ToString(), "ConvertTo-Json", tags) :
                    new Payload { IsString = true, Tags = tags, SourceRef = "ConvertTo-Json",
                        InspectionPartial = !complete, Issue = complete ? "json-output-format" : "json-output-partial" };
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            int MaxStatements => (policy ?? Limits).MaxStatements;
            static int MaxExpressionDepth => Limits.MaxExpressionDepth;
            int MaxLoopIterations => (policy ?? Limits).MaxLoopIterations;
            int MaxForEachIterations => (policy ?? Limits).MaxForEachIterations;
            int MaxOutVariableRecords => (policy ?? Limits).MaxOutVariableRecords;
            int MaxJsonElements => (policy ?? Limits).MaxJsonElements;
            readonly Flow flow;
            Policy? policy;
            string policyProblem;
            readonly RulePlan plan = new RulePlan();
            readonly Dictionary<string, Payload> values = new Dictionary<string, Payload>(StringComparer.OrdinalIgnoreCase);
            readonly HashSet<string> plannedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            readonly Dictionary<string, Payload> predictedWrites = new Dictionary<string, Payload>(StringComparer.OrdinalIgnoreCase);
            readonly HashSet<object> visitedHttpMethods = new HashSet<object>();
            readonly HashSet<object> visitedNetwork = new HashSet<object>();
            readonly HashSet<string> scriptDefinitions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            readonly HashSet<(int Start, int End)> skippedBlocks = new HashSet<(int, int)>();
            readonly HashSet<(int Start, int End)> reachedBlocks = new HashSet<(int, int)>();
            int statements;
            readonly Stopwatch clock;
            string? cwd;
            bool locationWasSet;
            int filesRead, filesEnumerated;
            long fileBytesReserved;
            bool barrier;
            bool filesUnknown, variablesUnknown;
            Dictionary<string, Payload>? usingValues;
            int currentStage;
            int currentChain;
            Action? observeStatement;
            Action<StatementState, StatementExit>? observeAlternateExit;
            static readonly HashSet<string> OpaqueOutputOnly = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { "sort-object", "measure-object" };
            bool uncertainProcessContext;
            bool TrustLoopback => !uncertainProcessContext && policy?.TrustLoopback == true && policyProblem.Length == 0;
            // Invalidate session observations, not the traversal or independent command classification.
            void InvalidateSessionFacts()
            {
                barrier = true;
                httpStates.Clear();
                values.Clear();
                plan.Assignments.Clear();
                InvalidateFileFacts();
            }
            internal AdapterContext(Flow flow, Stopwatch elapsed)
            {
                this.flow = flow;
                cwd = flow.FileSystemDirectory;
                policy = Store.Current(out policyProblem);
                plan.Configuration = policyProblem;
                clock = elapsed;
            }
            string Key(string name) => functionScopes.Count != 0 && !GlobalName(name) && !EnvName(name) ?
                functionScopes.Peek() + BaseName(name) : flow.RuleVariableKey(name);
            Rule? Find(string id) => policy?.Rules.FirstOrDefault(r => r.Id == id);
            Mark[] Merge(IEnumerable<Mark> items) => items.Where(t => Find(t.Id) != null)
                .GroupBy(x => (x.Id, x.Origin)).Select(x => x.First()).OrderByDescending(t => Find(t.Id)?.Action == "block").ToArray();
            bool Budget() => clock.ElapsedMilliseconds <= (policy ?? Limits).FileScanBudgetMs;

            static IEnumerable<Mark> KnownMarks(IEnumerable<Payload?> roots, HashSet<Payload>? visited = null)
            {
                var seen = visited ?? new HashSet<Payload>();
                var pending = new Stack<Payload>(roots.OfType<Payload>());
                while (pending.Count != 0)
                {
                    var item = pending.Pop();
                    if (!seen.Add(item)) continue;
                    foreach (var tag in item.Tags) yield return tag;
                    if (item.Model != null)
                        foreach (var tag in item.Model.Marks) yield return tag;
                    if (item.Elements != null) foreach (var child in item.Elements) pending.Push(child);
                    if (item.Map != null) foreach (var child in item.Map.Values) pending.Push(child);
                    if (item.Files != null) foreach (var record in item.Files.Records) pending.Push(record);
                    if (item.RecordRemainder != null) pending.Push(item.RecordRemainder);
                }
            }

            static IEnumerable<FileReference> FilePathCandidates(Payload value)
            {
                if (value.FileObject is FileReference file) yield return file;
                if (value.PathAlternatives is { } alternatives)
                    foreach (var path in alternatives) yield return path;
                if (value.RecordRemainder?.PathAlternatives is { } remaining)
                    foreach (var path in remaining) yield return path;
                foreach (var item in value.Files?.Records ?? value.Elements ?? Array.Empty<Payload>())
                {
                    if (item.FileObject != null) yield return item.FileObject;
                    if (item.PathAlternatives != null)
                        foreach (var path in item.PathAlternatives) yield return path;
                }
            }

            static Payload UnknownValue(string reason, params Payload?[] inputs)
            {
                var paths = inputs.OfType<Payload>().SelectMany(FilePathCandidates).Distinct().ToArray();
                var known = inputs.OfType<Payload>().ToArray();
                HttpObject? http = null;
                if (known.Length != 0 && known[0].HttpObject is HttpObject first && known.All(v => v.HttpObject?.Kind == first.Kind))
                {
                    http = known.Select(v => v.HttpObject!).Aggregate(JoinHttp);
                }
                return new Payload { Issue = reason, InspectionPartial = true, HttpObject = http,
                    PathAlternatives = paths.Length == 0 ? null : paths,
                    Tags = KnownMarks(inputs).GroupBy(t => (t.Id, t.Origin)).Select(g => g.First()).ToArray() };
            }

            Payload Text(string? content, string origin, Mark[]? inherited = null)
            {
                var tags = (inherited ?? Array.Empty<Mark>()).ToList();
                var positions = tags.Select(t => (Start: 0, Tag: t)).ToList();
                bool materialized = content != null && (long)content.Length * sizeof(char) <= MaxContent;
                if (content != null && policy != null)
                {
                    foreach (var r in policy.Rules)
                    {
                        int first = int.MaxValue;
                        foreach (var needle in r.Texts)
                        {
                            int found = content.IndexOf(needle, StringComparison.Ordinal);
                            if (found >= 0 && found < first) first = found;
                        }
                        if (first == int.MaxValue) continue;
                        var mark = new Mark(r.Id, origin, origin);
                        tags.Add(mark);
                        positions.Add((first, mark));
                    }
                }
                return new Payload { Text = materialized ? content : null, Complete = materialized, IsString = content != null,
                    Tags = Merge(tags), TagPositions = positions.Take(Limits.MaxPositions).ToArray(), SourceRef = origin, Issue = content == null ? "payload-value" : "content-budget" };
            }

            static bool InFolder(string path, string root) => path.StartsWith(
                root.EndsWith("\\", StringComparison.Ordinal) ? root : root + "\\", StringComparison.OrdinalIgnoreCase);
            Payload File(string? raw, bool needText, out Disk.Sample? sample, bool forceBytes = false, System.Text.Encoding? encoding = null, bool decodeUnavailable = false, Func<string, string>? sliceText = null, int? tailLines = null, long? headLines = null, string? delimiter = null, bool inspectArchive = true, bool symbolicCompressionCopy = false)
            {
                sample = null;
                if (policy == null) return Missing(policyProblem);
                var path = Disk.Bind(raw, cwd);
                if (path == null)
                {
                    var external = Disk.ExternalRulePath(raw);
                    if (external == null) return Missing("file-path");
                    // Apply configured path rules, but don't open shares or removable
                    // devices in the AMSI callback (availability and identity are unknown).
                    return FilePathEvidence(external, "file-external-content");
                }
                if (PendingFiles.ContainsKey(path)) return FilePathEvidence(path, "file-pending");
                if (barrier && !plannedFiles.Contains(path))
                {
                    // An opaque statement may change the provider, working directory or
                    // file bytes. An absolute configured path is still a separate fact.
                    if (barrier && (raw == null || raw.Length < 3 || raw[1] != ':' ||
                        (raw[2] != '\\' && raw[2] != '/'))) return Missing("file-location-changed");
                    return FilePathEvidence(path, "file-after-unknown-effects");
                }
                if (plannedFiles.Contains(path))
                {
                    if (!predictedWrites.TryGetValue(path, out var write)) return FilePathEvidence(path, "file-pending");
                    if (write.Issue == "file-moved") return write;
                    if (write.PredictedAttributes?.HasFlag(FileAttributes.Directory) == true) return Missing("file-is-directory");
                    var plannedMarks = ConfiguredPathMarks(policy, path, path, out _);
                    if (plannedMarks.Length != 0)
                    {
                        // The destination is also a source in its own right. Do not
                        // mutate a prediction shared with another branch or file.
                        write = write.Copy();
                        write.Tags = Merge(write.Tags.Concat(plannedMarks));
                    }
                    if (write.MayReadOriginal)
                    {
                        plannedFiles.Remove(path);
                        try
                        {
                            var original = File(path, needText, out _, forceBytes, encoding, decodeUnavailable, sliceText, tailLines, headLines, delimiter, inspectArchive);
                            var alternative = UnknownValue("conditional-file-content", write, original);
                            alternative.IsString = needText && !forceBytes && !decodeUnavailable;
                            return alternative;
                        }
                        finally { plannedFiles.Add(path); }
                    }
                    if (!needText && !forceBytes) return write.Via(path);
                    if (forceBytes && write.Bytes is { } bytes) return Bytes(bytes, path, write.Tags);
                    if (needText && !decodeUnavailable)
                    {
                        if (encoding == null && write.IsString && write.Text is string predicted)
                        {
                            if (sliceText == null) return write.Via(path);
                            var selected = Text(sliceText(predicted), path, FileRecordMarks(write));
                            selected.Complete &= write.Complete;
                            return selected;
                        }
                        if (write.Bytes is { } data)
                        {
                            string? decoded = null;
                            try
                            {
                                if (encoding == null) decoded = Disk.Decode(data);
                                else
                                {
                                    using var stream = new MemoryStream(data, false);
                                    using var reader = new StreamReader(stream, encoding, detectEncodingFromByteOrderMarks: true);
                                    decoded = reader.ReadToEnd();
                                }
                            }
                            catch (ArgumentException) { }
                            if (decoded != null)
                                return Text(sliceText == null ? decoded : sliceText(decoded), path, FileRecordMarks(write));
                        }
                    }
                    return new Payload { SourceRef = path, Tags = sliceText == null ? write.Tags : FileRecordMarks(write),
                        Issue = decodeUnavailable ? "file-encoding" : "file-pending-format" };
                }
                if (!BeginFile()) return FilePathEvidence(path, "file-budget");
                bool metadataCurrent = Store.RefreshDerived(file: true);
                policy = Store.Current(out policyProblem);
                if (policy == null || policyProblem.Length != 0) return Missing("policy-unavailable-or-invalid");
                var snapshot = policy;
                bool requireValue = needText || forceBytes || sliceText != null || headLines.HasValue || tailLines.HasValue || delimiter != null;
                bool checkText = false, pathOnly = false;
                string? confirmedPath = null;
                Mark[] pathMarks = Array.Empty<Mark>();
                bool NeedsContent(Disk.Sample identity)
                {
                    confirmedPath = identity.Path;
                    pathMarks = ConfiguredPathMarks(snapshot, path, identity.Path, out bool blocks);
                    // A path warning must not mask an independent blocking text rule.
                    // Compression output is already symbolic: a definitive blocking path and
                    // the confirmed remaining length suffice. Ordinary byte consumers still read.
                    pathOnly = symbolicCompressionCopy && blocks ||
                        pathMarks.Length != 0 && !requireValue &&
                        (blocks || !snapshot.Rules.Any(r => r.Action == "block" && r.Texts.Length != 0));
                    identity.ContentSkippedForPath = pathOnly;
                    // An unknown decoder cannot establish any textual match. Keep
                    // file-encoding uncertainty instead of reading bytes as default UTF.
                    checkText = !pathOnly && (forceBytes || !decodeUnavailable && (requireValue || snapshot.FileTextRules.Length != 0));
                    return checkText;
                }
                long limit = snapshot.MaxFileBytes == 0 ? long.MaxValue : snapshot.MaxFileBytes;
                Action<Stream, long, Disk.Sample>? streamScan = null;
                if (!decodeUnavailable)
                {
                    if (delimiter != null)
                        streamScan = (stream, size, result) => ScanFileStream(stream, size, result, snapshot, limit, encoding,
                            selection: new DelimitedSelection(delimiter, headLines, tailLines));
                    else if (tailLines is int lines)
                        streamScan = (stream, size, result) => ScanFileTail(stream, size, result, snapshot, limit, encoding, lines);
                    else if (headLines is long first)
                        streamScan = (stream, size, result) => ScanFileHead(stream, size, result, snapshot, limit, encoding, first);
                    else if (sliceText == null)
                        streamScan = (stream, size, result) => ScanFileStream(stream, size, result, snapshot, limit, encoding);
                }
                if (snapshot.MaxTotalFileBytes != 0)
                    limit = Math.Min(limit, Math.Max(0, snapshot.MaxTotalFileBytes - fileBytesReserved));
                string readPath = Disk.ClearAncestors(path) ? path : Disk.ResolveLocalPath(path, () => FileTimeAvailable) ?? path;
                sample = Disk.TrySample(readPath, true, limit, streamScan,
                    reader: snapshot.MaxTotalFileBytes == 0 ? null : stream => new CountedFileStream(stream, this, snapshot.MaxTotalFileBytes),
                    needsContent: NeedsContent);
                if (sample == null)
                {
                    if (confirmedPath != null && pathMarks.Length != 0)
                    {
                        var unavailable = new Payload { SourceRef = confirmedPath, Tags = pathMarks, Issue = "file-content-unavailable" };
                        RecordSource(unavailable, "file");
                        return unavailable;
                    }
                    return Disk.TargetStamp(path) == "" ? Missing("file-unavailable") : FilePathEvidence(path, "file-unavailable");
                }
                var witnessed = Witness(sample.Path, sample.Stamp);
                var tags = pathMarks.Concat(witnessed).Concat(sample.StreamMarks).ToList();
                bool stale = false;
                foreach (var rule in snapshot.Rules)
                {
                    foreach (var entry in rule.Copies)
                    {
                        string copyPath = ConfigPath(entry.Get("path"), Path.GetDirectoryName(Store.Config)!);
                        if (!PathEq(copyPath, sample.Path)) continue;
                        if (entry.Get("stamp") != sample.Stamp) { stale |= witnessed.Length == 0; continue; }
                        string origin = entry.Get("origin").Length > 0 ? entry.Get("origin") : entry.Get("copied_from");
                        tags.Add(new Mark(rule.Id, origin, entry.Get("route").Length == 0
                            ? entry.Get("copied_from") + " → " + sample.Path : entry.Get("route")));
                    }
                }
                if (encoding != null && sample.Bytes != null)
                {
                    try
                    {
                        using var input = new MemoryStream(sample.Bytes, false);
                        using var reader = new StreamReader(input, encoding, detectEncodingFromByteOrderMarks: true);
                        sample.Text = reader.ReadToEnd();
                    }
                    catch (ArgumentException) { sample.Text = null; }
                }
                if (decodeUnavailable)
                {
                    var evidence = new Payload { SourceRef = sample.Path, Tags = Merge(tags), Issue = "file-encoding" };
                    RecordSource(evidence, "file");
                    return evidence;
                }
                if (sliceText != null && sample.Text != null && !sample.LineSelectionApplied) sample.Text = sliceText(sample.Text);
                var result = pathOnly ? new Payload { SourceRef = sample.Path, Tags = Merge(tags) }
                    : Text(sample.Text, sample.Path, Merge(tags));
                bool checkedText = sample.Text != null || (!needText && !forceBytes && sample.StreamChecked);
                result.Complete = (!checkText || checkedText) && !stale && metadataCurrent;
                result.Issue = !metadataCurrent ? "copy-generation" : stale ? "copy-stale" :
                    result.Complete ? "" : sample.StreamIssue.Length != 0 ? sample.StreamIssue : "file-content";
                if (!pathOnly && inspectArchive && !needText && ArchiveKind(sample.Path, sample.Bytes ?? sample.Probe) is string kind)
                {
                    var packed = sample.Bytes == null ? Missing("archive-not-materialized") : InspectPacked(sample.Bytes, sample.Path, kind);
                    result = Combine(result, packed, preserveCompleteness: false);
                    if (!metadataCurrent || stale) { result.Complete = false; result.Issue = !metadataCurrent ? "copy-generation" : "copy-stale"; }
                }
                if (UncertainFileTree(Path.GetDirectoryName(path)))
                {
                    result.InspectionPartial = true;
                    if (result.Issue.Length == 0) result.Issue = "file-after-unknown-write";
                }
                RecordSource(result, "file");
                return result;
            }

            static Mark[] ConfiguredPathMarks(Policy snapshot, string boundPath, string actualPath, out bool blocks)
            {
                var marks = new List<Mark>();
                blocks = false;
                bool distinct = !PathEq(boundPath, actualPath);
                foreach (var rule in snapshot.Rules)
                {
                    bool Match(string p) => rule.Files.Any(f => PathEq(f, p)) || rule.Folders.Any(f => InFolder(p, f));
                    string? origin = Match(actualPath) ? actualPath : distinct && Match(boundPath) ? boundPath : null;
                    if (origin == null) continue;
                    marks.Add(new Mark(rule.Id, origin, origin));
                    blocks |= rule.Action == "block";
                }
                return marks.ToArray();
            }

            Payload FilePathEvidence(string path, string issue)
            {
                var evidence = new Payload { Tags = ConfiguredPathMarks(policy!, path, path, out _), SourceRef = path, Issue = issue };
                RecordSource(evidence, "file");
                return evidence;
            }

            void RecordSource(Payload payload, string kind)
            {
                if (payload.Tags.Length != 0)
                    plan.Source(kind, payload.SourceRef, currentStage, payload.Tags);
            }

            Mark[] FileRecordMarks(Payload source) => source.Tags.Where(mark => Find(mark.Id) is { } rule &&
                (rule.Sources.Any(s => mark.Origin.Equals(s, StringComparison.OrdinalIgnoreCase) ||
                     mark.Origin.StartsWith(s + "#", StringComparison.OrdinalIgnoreCase)) ||
                 rule.Files.Any(path => PathEq(path, mark.Origin) || PathEq(path, source.SourceRef)) ||
                 rule.Folders.Any(path => InFolder(mark.Origin, path) || InFolder(source.SourceRef, path)) ||
                 rule.Copies.Any(copy => copy.Get("origin") == mark.Origin && mark.Origin != source.SourceRef))).ToArray();

            Payload Variable(string name)
            {
                var value = VariableCore(name);
                return EnvName(name) ? SourceTagged(value, "env:" + BaseName(name)) : value;
            }
            Payload VariableCore(string name)
            {
                if (values.TryGetValue(Key(name), out var found)) return found;
                if (functionScopes.Count != 0 && !name.Contains(':'))
                {
                    foreach (var scope in functionScopes.Skip(1))
                        if (values.TryGetValue(scope + name, out found)) return found;
                    if (values.TryGetValue(flow.RuleVariableKey(name), out found)) return found;
                }
                return barrier || variablesUnknown ? Missing("session-state-changed") : SessionVariable(name);
            }

            Payload SessionVariable(string name)
            {
                var raw = flow.RuleRead(name);
                if (raw.Structured != null) return SnapshotPayload(raw.Structured, "$" + name);
                if (!raw.Known || raw.Text == null) return Missing(raw.Source == "variable-not-found" ? "variable-value" : raw.Source);
                var value = Text(raw.Text, "$" + name, raw.Marks);
                value.IsString = raw.Type == "String";
                value.ScalarTruth = ScalarTruth(raw.Type, raw.Text);
                if (NumericScalar(raw.Type)) value.NumericType = raw.Type;
                if (EnvName(name) && policy != null)
                {
                    if (!Store.RefreshDerived(file: false)) { value.Complete = false; value.Issue = "persistent-generation"; }
                    foreach (var scope in new[] { "user", "machine" })
                    {
                        var owner = DurableEnv.Owner(scope);
                        if (owner == null) continue;
                        var old = Store.Persistent(scope, owner, BaseName(name)).ToArray();
                        var envKey = EnvKey(scope, BaseName(name));
                        if (PendingFiles.ContainsKey(envKey)) { value.Complete = false; value.Issue = "persistent-variable-pending"; continue; }
                        if (old.Length == 0 && !HasWitness(envKey)) continue;
                        if (!DurableEnv.Read(scope, BaseName(name), out var actual, out var stamp) ||
                            old.Any(s => s.Get("stamp") != stamp) || actual != raw.Text)
                        {
                            value.Complete = false;
                            value.Issue = "persistent-variable-stale";
                        }
                        if (stamp != null && actual == raw.Text)
                            value.Tags = Merge(value.Tags.Concat(Witness(envKey, stamp).Select(m => m.Via("$" + name)))
                                .Concat(old.Where(s => s.Get("stamp") == stamp).Select(s =>
                                    new Mark(s.Get("rule_id"), s.Get("origin"), s.Get("route")).Via("$" + name))));
                    }
                }
                return value;
            }
            Payload Value(object? node, int depth = 0)
            {
                if (node is Payload bound) return bound;
                if (!StackAvailable || depth > MaxExpressionDepth) return Missing("expression-limit");
                if (Kind(node) == "ConvertExpressionAst" && TypeName(Prop(node, "Type")) is ("xml" or "xml.xmldocument" or "system.xml.xmldocument"))
                    return HttpObjectValue(new HttpObject(HttpObjectKind.XmlDocument,
                        body: LoadXmlSource(Value(Prop(node, "Child"), depth + 1), "dom-xml", false, false)));
                var literal = Literal(node);
                if (literal != null) return Text(literal, "literal");
                if (Kind(node) == "UsingExpressionAst")
                {
                    var captured = VarName(Prop(node, "SubExpression"));
                    return usingValues != null && usingValues.TryGetValue(Key(captured), out var value) ?
                        value : Missing("using-variable");
                }
                if (Kind(node) == "ConvertExpressionAst" &&
                    Str(Prop(Prop(Prop(node, "Type"), "TypeName"), "FullName")).ToLowerInvariant() is "uri" or "system.uri")
                {
                    var inner = Value(Prop(node, "Child"), depth + 1);
                    return inner.Complete && inner.IsString && Http(inner.Text) != null ? inner : Missing("uri-cast-value");
                }
                if (Kind(node) == "ConvertExpressionAst" &&
                    Str(Prop(Prop(Prop(node, "Type"), "TypeName"), "FullName")).ToLowerInvariant() is
                        ("pscustomobject" or "system.management.automation.pscustomobject") &&
                    Kind(Prop(node, "Child")) == "HashtableAst")
                {
                    var obj=StructuredValue(Prop(node, "Child"), depth + 1) ?? Missing("pscustomobject-fields");
                    if(obj.Map==null || !obj.Complete)return obj;
                    if(obj.Map.TryGetValue("PSTypeName",out var declared))
                    {
                        if(ExactString(declared) is not string type || type.Length==0 || type.Length>Limits.MaxRuntimeChars)
                            return Missing("custom-object-type-name");
                        obj.Map.Remove("PSTypeName");obj.MemberDisplayType=type;
                    }
                    obj.ReadType="System.Management.Automation.PSCustomObject";return obj;
                }
                if (Kind(node) == "ConvertExpressionAst" && TypeName(Prop(node, "Type")) is
                    ("system.net.httpwebrequest" or "net.httpwebrequest" or "system.net.webrequest" or "net.webrequest"))
                {
                    var request = Value(Prop(node, "Child"), depth + 1);
                    return request.HttpObject?.Kind == HttpObjectKind.Request ? request : Missing("request-cast");
                }
                if (Kind(node) == "ConvertExpressionAst" && HttpType(TypeName(Prop(node, "Type"))) is
                    ("collections.generic.dictionary[string,string]" or "collections.generic.dictionary[system.string,system.string]"))
                {
                    var source = Value(Prop(node, "Child"), depth + 1);
                    if (source.Map == null) return Missing("form-dictionary-shape");
                    return HttpObjectValue(new HttpObject(HttpObjectKind.Fields, fields: new Dictionary<string, Payload>(source.Map, StringComparer.Ordinal)));
                }
                if (Kind(node) == "ConvertExpressionAst" && HttpType(TypeName(Prop(node,"Type"))) is string referenceType &&
                    (referenceType == "object" || StreamReferenceType(referenceType)))
                {
                    var value = Value(Prop(node,"Child"),depth+1);
                    return referenceType == "object" || IsStreamValue(value) ? value : UnknownValue("reference-cast", value);
                }
                if (Kind(node) == "ConvertExpressionAst" && TypeName(Prop(node, "Type")) is ("byte[]" or "system.byte[]"))
                {
                    var source = Value(Prop(node, "Child"), depth + 1);
                    if (source.Bytes != null || source.Model?.Kind==ModelKind.PackedBytes) return source;
                    if (source.ByteRecordData != null) return Bytes(source.ByteRecordData, "byte array", Merge(KnownMarks(new[] { source })));
                    if (!source.Complete || source.InspectionPartial || source.RecordRemainder != null || source.FirstUncertainIndex != null)
                        return SymbolicBytes("byte-array-conversion-incomplete", source);
                    var data = new List<byte>();
                    foreach (var item in source.Elements ?? new[] { source })
                    {
                        if (!item.Complete || !byte.TryParse(item.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var b) ||
                            data.Count >= MaxContent) return UnknownValue("byte-array-conversion", source);
                        data.Add(b);
                    }
                    return Bytes(data.ToArray(), "byte array", Merge(KnownMarks(new[] { source })));
                }
                if (Kind(node) == "ConvertExpressionAst" && TypeName(Prop(node, "Type")) is ("void" or "system.void"))
                { Value(Prop(node, "Child"), depth + 1); return Missing("no-expression-output"); }
                var variable = VarName(node);
                if (variable.Equals("true", StringComparison.OrdinalIgnoreCase) || variable.Equals("false", StringComparison.OrdinalIgnoreCase))
                {
                    var boolean = Text(variable.Equals("true", StringComparison.OrdinalIgnoreCase) ? "True" : "False", "boolean");
                    boolean.IsString = false;
                    boolean.ScalarTruth = boolean.Text == "True";
                    return boolean;
                }
                if (SafeName(variable)) return Variable(variable);
                if (Kind(node) == "ParenExpressionAst")
                {
                    var nestedPipeline = Prop(node, "Pipeline");
                    if (Kind(nestedPipeline) == "PipelineChainAst")
                        return Pipeline(nestedPipeline, depth + 1) ?? Missing("parenthesized-output");
                    var elements = Items(Prop(nestedPipeline, "PipelineElements")).Take(2).ToArray();
                    if (elements.Length == 1 && Kind(elements[0]) == "CommandExpressionAst" &&
                        !Items(Prop(elements[0], "Redirections")).Any())
                        return Value(Prop(elements[0], "Expression"), depth + 1);
                    if (elements.Length != 0)
                        return Pipeline(Prop(node, "Pipeline"), depth + 1) ?? Missing("parenthesized-output");
                }
                if (Kind(node) == "BinaryExpressionAst" && Str(Prop(node, "Operator")) == "Plus")
                {
                    var left = Value(Prop(node, "Left"), depth + 1);
                    var right = Value(Prop(node, "Right"), depth + 1);
                    if (left.IsString && right.IsString && left.Text != null && right.Text != null &&
                        left.Complete && right.Complete && (long)left.Text.Length + right.Text.Length <= MaxContent)
                    {
                        var joined = Text(left.Text + right.Text, "concatenation",
                            Merge(left.Tags.Concat(right.Tags)).Select(t => t.Via("concatenation")).ToArray());
                        joined.TagPositions = Positions(left, 0, "concatenation")
                            .Concat(Positions(right, left.Text.Length, "concatenation")).Take(Limits.MaxPositions).ToArray();
                        return joined;
                    }
                    return UnknownValue("concatenation-input", left, right);
                }
                return DotNetExpression(node, depth) ?? StructuredValue(node, depth) ?? Transform(node, depth) ?? ModelExpression(node, depth) ?? Missing("dynamic-value");
            }
            static string Name(object command) => Command(command).ToLowerInvariant();
            static bool LiteralPathCommand(string name) => name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                (name.Contains("/") || name.Contains("\\"));
            static string Tool(string name)
            {
                if (LiteralPathCommand(name)) name = name.Substring(Math.Max(name.LastIndexOf('/'), name.LastIndexOf('\\')) + 1);
                return name.EndsWith(".exe", StringComparison.Ordinal) ? name.Substring(0, name.Length - 4) : name;
            }
            string LocalName(string raw)
            {
                if (raw.EndsWith(".com",StringComparison.Ordinal) && Path.GetFileName(raw.Replace('/','\\'))=="tree.com")
                    return "native-read:tree";
                if (raw.EndsWith(".com", StringComparison.Ordinal) &&
                    Path.GetFileName(raw.Replace('/', '\\')) == "more.com") return "native-read:more";
                if (raw.EndsWith(".exe", StringComparison.Ordinal))
                {
                    var program = Tool(raw);
                    if (NativeReaders.Contains(program)) return "native-read:" + program;
                    return NativeTransfers.ContainsKey(program) || program == "git" ? program : raw;
                }
                if (raw == "microsoft.powershell.core\\foreach-object" ||
                    (raw is "%" or "foreach") && flow.StockAlias(raw, "ForEach-Object", "Microsoft.PowerShell.Core"))
                    return "foreach-object";
                if (raw == "microsoft.powershell.diagnostics\\get-winevent") return "get-winevent";
                if (raw == "cimcmdlets\\get-ciminstance") return "get-ciminstance";
                if (raw == "microsoft.powershell.security\\get-acl") return "get-acl";
                if (raw == "microsoft.powershell.core\\get-history") return "get-history";
                if (raw == "nettcpip\\get-netipconfiguration") return "get-netipconfiguration";
                if (raw == "bitstransfer\\start-bitstransfer") return "start-bitstransfer";
                if (raw == "microsoft.powershell.archive\\expand-archive") return "expand-archive";
                if (raw == "microsoft.powershell.archive\\compress-archive") return "compress-archive";
                if (raw == "microsoft.powershell.management\\join-path") return "join-path";
                if ((raw is "gci" or "ls" or "dir") && flow.StockAlias(raw, "Get-ChildItem")) return "get-childitem";
                if (ReaderAliases.TryGetValue(raw, out var readerAlias) && flow.StockAlias(raw, readerAlias.Name, readerAlias.Module))
                    return readerAlias.Name.ToLowerInvariant();
                if (raw is ("cd" or "sl" or "chdir") && flow.StockAlias(raw, "Set-Location") ||
                    raw == "microsoft.powershell.management\\set-location") return "set-location";
                if (raw == "get-content" || raw == "microsoft.powershell.management\\get-content") return "get-content";
                if ((raw is "cat" or "gc" or "type") && flow.StockAlias(raw, "Get-Content"))
                    return "get-content";
                if (raw == "iwr" && flow.StockAlias(raw, "Invoke-WebRequest", "Microsoft.PowerShell.Utility"))
                    return "invoke-webrequest";
                if (raw == "irm" && flow.StockAlias(raw, "Invoke-RestMethod", "Microsoft.PowerShell.Utility"))
                    return "invoke-restmethod";
                const string management = "microsoft.powershell.management\\";
                if (raw.StartsWith(management, StringComparison.Ordinal) && raw.Substring(management.Length) is
                    ("start-process" or "get-item" or "get-childitem" or "set-content" or "add-content" or "copy-item" or "clear-content" or "move-item" or "remove-item" or "rename-item" or "resolve-path" or "convert-path" or "get-itemproperty" or "get-itempropertyvalue" or "get-clipboard" or "get-process" or "get-service" or "get-computerinfo" or "get-location"))
                    return raw.Substring(management.Length);
                const string utility = "microsoft.powershell.utility\\";
                if (raw.StartsWith(utility, StringComparison.Ordinal))
                {
                    var cmdlet = raw.Substring(utility.Length);
                    if (!NativeTransfers.ContainsKey(cmdlet) && cmdlet != "git") return cmdlet;
                }
                return NativeReaders.Contains(raw) ? "native-read:" + raw : raw;
            }
            static bool Network(string cmd) => cmd == "invoke-webrequest" || cmd == "invoke-restmethod" ||
                NativeTransfers.ContainsKey(cmd) || cmd == "git" || cmd == "start-bitstransfer";

            bool ShadowedInScript(string raw, string resolved) => !raw.Contains("\\") && !raw.Contains("/") &&
                (scriptDefinitions.Contains(raw) ||
                 (ReaderAliases.ContainsKey(raw) && scriptDefinitions.Contains(resolved)) ||
                 ((raw is "iwr" or "irm" or "gc" or "cat" or "type" or "%" or "foreach" or "gci" or "ls" or "dir") && scriptDefinitions.Contains(resolved)));

            static readonly string[] CommonArguments = ("ErrorAction WarningAction InformationAction ProgressAction " +
                "ErrorVariable WarningVariable InformationVariable OutVariable OutBuffer PipelineVariable").Split(' ');
            static readonly string[] CommonFlags = { "Verbose", "Debug" };
            static readonly string[] CommonNames = CommonArguments.Concat(CommonFlags).ToArray();
            static readonly string[] CommonOutputVariables = { "ErrorVariable", "WarningVariable", "InformationVariable", "PipelineVariable" };
            static readonly string[] ContentArgs = ("Path LiteralPath Encoding ReadCount TotalCount Tail OutVariable Stream Filter Include Exclude Credential Delimiter").Split(' ');
            static readonly string[] ContentFlags = { "Raw", "AsByteStream", "Force", "Wait" };
            static readonly Dictionary<string, string> ParameterAliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ah"] = "Hidden", ["as"] = "System", ["ad"] = "Directory", ["af"] = "File", ["ar"] = "ReadOnly",
                ["args"] = "ArgumentList", ["ea"] = "ErrorAction", ["wa"] = "WarningAction", ["infa"] = "InformationAction",
                ["proga"] = "ProgressAction", ["ob"] = "OutBuffer", ["vb"] = "Verbose", ["db"] = "Debug",
                ["ev"] = "ErrorVariable", ["wv"] = "WarningVariable", ["iv"] = "InformationVariable",
                ["ov"] = "OutVariable", ["pv"] = "PipelineVariable", ["wi"] = "WhatIf", ["cf"] = "Confirm",
                ["pspath"] = "LiteralPath", ["lp"] = "LiteralPath", ["last"] = "Tail",
                ["first"] = "TotalCount", ["head"] = "TotalCount", ["nooverwrite"] = "NoClobber"
            };
            static string? ResolveParameter(string? text, IEnumerable<string> names) =>
                ResolveParameter(text, names, out _);

            static string? ResolveParameter(string? text, IEnumerable<string> names, out bool ambiguous,
                Dictionary<string, string>? aliases = null)
            {
                ambiguous = false;
                if (string.IsNullOrEmpty(text)) return null;
                var distinct = names.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                var exact = distinct.FirstOrDefault(k => k.Equals(text, StringComparison.OrdinalIgnoreCase));
                if (exact != null) return exact;
                var applicable = (aliases ?? ParameterAliases)
                    .Where(a => a.Key.StartsWith(text, StringComparison.OrdinalIgnoreCase) &&
                        distinct.Contains(a.Value, StringComparer.OrdinalIgnoreCase)).ToArray();
                var exactAlias = applicable.FirstOrDefault(a => a.Key.Equals(text, StringComparison.OrdinalIgnoreCase)).Value;
                if (exactAlias != null) return exactAlias;
                var matches = distinct.Where(k => k.StartsWith(text, StringComparison.OrdinalIgnoreCase))
                    .Concat(applicable.Select(a => a.Value))
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                if (matches.Length <= 1) return matches.FirstOrDefault();
                var declared = matches.Where(k => !CommonNames.Contains(k) && k is not ("WhatIf" or "Confirm")).Take(2).ToArray();
                ambiguous = declared.Length != 1;
                return ambiguous ? null : declared[0];
            }

            sealed class Args : IDisposable
            {
                internal readonly Dictionary<string, object?> Named = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                internal readonly List<object> Plain = new List<object>();
                internal readonly List<Payload> Extras = new List<Payload>();
                internal readonly List<string> Disabled = new List<string>();
                internal bool Valid = true;
                internal bool Uncertain;
                readonly AdapterContext context;
                readonly List<(string Name, Payload Destination)> captures = new List<(string, Payload)>();
                public void Dispose()
                {
                    foreach (var capture in captures)
                        context.InvalidateOutputVariable(capture.Destination, allowAppend: capture.Name != "PipelineVariable");
                }
                internal Args(AdapterContext context, object command, string[] args, string[] flags, bool commonParameters = true, Dictionary<string, string>? aliases = null, bool allowExtraNamed = false)
                {
                    this.context = context;
                    if (commonParameters)
                    {
                        args = args.Concat(CommonArguments).ToArray();
                        flags = flags.Concat(CommonFlags).ToArray();
                    }
                    var names = args.Concat(flags);
                    var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    var tables = new List<Dictionary<string, Payload>>();
                    var elements = Items(Prop(command, "CommandElements")).Skip(1).Take(ProbeCount(Limits.MaxArguments)).ToArray();
                    if (elements.Length > Limits.MaxArguments) { Valid = false; Uncertain = true; }
                    for (int i = 0; i < Math.Min(elements.Length, Limits.MaxArguments); i++)
                    {
                        var e = elements[i];
                        if (Equals(Prop(e, "Splatted"), true))
                        {
                            var expanded = context.Value(e);
                            if (expanded.Map != null) tables.Add(expanded.Map);
                            else if (expanded.Elements != null && expanded.Complete && !expanded.InspectionPartial)
                                Plain.AddRange(expanded.Elements);
                            else { Valid = false; Uncertain = true; }
                            continue;
                        }
                        if (Kind(e) != "CommandParameterAst") { Plain.Add(e); continue; }
                        var raw = Str(Prop(e, "ParameterName"));
                        var name = ResolveParameter(raw, names, out bool ambiguous, aliases);
                        if (name == null && allowExtraNamed && !ambiguous)
                        {
                            Uncertain = true;
                            Extras.Add(context.Text("-" + raw, "function argument"));
                            if (Prop(e, "Argument") is object extra) Extras.Add(context.Value(extra));
                            continue;
                        }
                        if (name == null || !seen.Add(name)) { Valid = false; return; }
                        var argument = Prop(e, "Argument");
                        if (args.Contains(name, StringComparer.OrdinalIgnoreCase))
                        {
                            if (argument == null && i + 1 < elements.Length && IsParameterValue(elements[i + 1]))
                                argument = elements[++i];
                            if (argument == null)
                            { Valid = false; return; }
                        }
                        else
                        {
                            if (!flags.Contains(name, StringComparer.OrdinalIgnoreCase)) { Valid = false; return; }
                            if (argument != null)
                            {
                                var flag = context.Value(argument);
                                if (!flag.Complete || !flag.ScalarTruth.HasValue) { Valid = false; Uncertain = true; continue; }
                                if (flag.IsString) { Valid = false; return; }
                                if (!flag.ScalarTruth.Value) { Disabled.Add(name); continue; }
                            }
                        }
                        Named.Add(name, argument);
                    }
                    // Explicit parameters override splatted parameters regardless of token order.
                    var splattedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var table in tables)
                        foreach (var pair in table)
                        {
                            var name = ResolveParameter(pair.Key, names, out _, aliases);
                            if (name == null) { Valid = false; return; }
                            if (seen.Contains(name)) continue;
                            if (!splattedNames.Add(name)) { Valid = false; return; }
                            if (flags.Contains(name, StringComparer.OrdinalIgnoreCase))
                            {
                                var flag = pair.Value;
                                if (!flag.Complete || !flag.ScalarTruth.HasValue) { Valid = false; Uncertain = true; continue; }
                                if (flag.IsString) { Valid = false; return; }
                                if (!flag.ScalarTruth.Value) { Disabled.Add(name); continue; }
                            }
                            else if (!args.Contains(name, StringComparer.OrdinalIgnoreCase)) { Valid = false; return; }
                            Named.Add(name, pair.Value);
                        }
                    if ((Valid || Uncertain) && commonParameters && Get("OutVariable") is object destination &&
                        context.capture?.Command == command)
                    {
                        context.capture.Destination = context.Value(destination);
                        context.capture.NoEnumerate = Has("NoEnumerate");
                    }
                    if (Valid && commonParameters)
                        foreach (var parameter in CommonOutputVariables)
                            if (Get(parameter) is object node) captures.Add((parameter, context.Value(node)));
                }
                internal object? Get(string name) => Named.TryGetValue(name, out var o) ? o : null;
                internal bool Has(string name) => Named.ContainsKey(name);
            }
            static bool IsParameterValue(object node) =>
                Kind(node) != "CommandParameterAst" && !Equals(Prop(node, "Splatted"), true);
            static readonly string[] Paths = { "Path", "LiteralPath" };
            static readonly string[] Empty = Array.Empty<string>();
            static object? PathArg(Args args, int positional, out int expected, string pathParameter = "Path")
            {
                expected = args.Has(pathParameter) || args.Has("LiteralPath") ? 0 : 1;
                if (args.Has(pathParameter) && args.Has("LiteralPath")) return null;
                return args.Get("LiteralPath") ?? args.Get(pathParameter) ?? args.Plain.ElementAtOrDefault(positional);
            }

            bool DefaultDataStream(Args args) => Value(args.Get("Stream")).Text?.ToUpperInvariant() is ":$DATA" or "::$DATA";

            void InvalidateFileFacts()
            {
                filesUnknown = true;
                foreach (var path in plannedFiles.ToArray()) MarkPossibleWrite(path, null);
                plan.Work.RemoveAll(w => w.File);
            }

            bool UncertainFileTree(string? directory)
            {
                if (filesUnknown) return true;
                for (var parent = directory; parent != null; parent = Path.GetDirectoryName(parent))
                    if (predictedWrites.TryGetValue(parent, out var state) && state.Issue == "possible-file-write")
                        return true;
                return false;
            }

            void MarkPossibleWrite(string path, Payload? possible)
            {
                predictedWrites.TryGetValue(path, out var prior);
                var prediction = UnknownValue("possible-file-write", prior, possible);
                if (policy != null)
                    prediction.Tags = Merge(prediction.Tags.Concat(FilePathEvidence(path, "possible-file-write").Tags));
                prediction.MayReadOriginal = prior == null || prior.MayReadOriginal;
                ForgetFilePrediction(path);
                predictedWrites[path] = prediction;
            }

            Payload UncertainWrite(string issue, string? target = null, Payload? possible = null)
            {
                var path = Disk.Bind(target, cwd);
                int first = target?.IndexOfAny(new[] { '*', '?', '[' }) ?? -1;
                if (path == null && target != null && first >= 0)
                {
                    int slash = target.Substring(0, first).LastIndexOfAny(new[] { (char)92, '/' });
                    path = slash < 0 ? cwd : Disk.Bind(target.Substring(0, slash + 1), cwd);
                }
                if (path == null) InvalidateFileFacts();
                else
                {
                    if (Directory.Exists(path))
                    {
                        path = Path.GetFullPath(Path.Combine(path, "."));
                        foreach (var child in plannedFiles.Where(f => InFolder(f, path)).ToArray()) MarkPossibleWrite(child, null);
                    }
                    MarkPossibleWrite(path, possible);
                }
                ReportMissing(issue);
                return Missing(issue);
            }

            FileContentProof? SourceProof(string path, string stamp)
            {
                if (policy == null || !Budget()) return null;
                long limit = policy.MaxFileBytes == 0 ? long.MaxValue : policy.MaxFileBytes;
                if (policy.MaxTotalFileBytes != 0) limit = Math.Min(limit, Math.Max(0, policy.MaxTotalFileBytes - fileBytesReserved));
                return FileContentProof.Capture(path, stamp, limit, Budget, count => fileBytesReserved += Math.Min(limit, count));
            }

            void PlanWrite(string? target, Payload content, byte[]? bytes, bool append, bool noNewline = false,
                bool appendRecordNewline = false, FileContentProof? proof = null, bool ascii = false)
            {
                var path = Disk.Bind(target, cwd);
                if (policy == null || path == null || !Budget())
                { UncertainWrite("write-target-or-budget", target, content); return; }
                bool wasPlanned = plannedFiles.Contains(path);
                predictedWrites.TryGetValue(path, out var previous);
                var previousWork = plan.Work.LastOrDefault(w => w.File && PathEq(w.Target, path));
                var previousStamp = previousWork?.Before;
                if (previousStamp == null && plan.Work.Count >= MaxEffects)
                { UncertainWrite("write-target-or-budget", target, content); return; }
                ForgetFilePrediction(path);
                var before = previousStamp ?? Disk.TargetStamp(path);
                string? text = content.PipeText ?? content.Text;
                var label = content.Via(path);
                label.Tags = Merge(KnownMarks(new[] { content }).Select(m => m.Via(path)));
                bool exactText = content.Complete && (content.PipeText != null || (noNewline && content.IsString));
                if (appendRecordNewline && !noNewline && content.PipeText == null && content.IsString && text != null)
                {
                    text += Environment.NewLine;
                    exactText = content.Complete;
                }
                var asciiBytes = ascii && exactText && text != null ? System.Text.Encoding.ASCII.GetBytes(text) : null;
                if (asciiBytes != null) bytes = asciiBytes;
                if (append)
                {
                    byte[]? prefixBytes = previous?.Bytes;
                    Payload? old = previous;
                    if (previous?.Bytes is byte[] previousBytes && Disk.Decode(previousBytes) is string previousText)
                    {
                        old = Text(previousText, path, previous.Tags);
                        old.Complete &= previous.Complete;
                        old.InspectionPartial = previous.InspectionPartial;
                    }
                    var prefixProof = previousWork?.Proof;
                    if (!wasPlanned && before != "" && !barrier)
                    {
                        plannedFiles.Remove(path);
                        try
                        {
                            old = File(path, true, out var original);
                            prefixBytes = original?.Bytes;
                            if (original != null && original.Text == null) prefixProof = SourceProof(path, original.Stamp);
                        }
                        finally { plannedFiles.Add(path); }
                    }
                    bool empty = previous?.Issue == "file-moved" || !wasPlanned && before == "" && !barrier && !filesUnknown;
                    label.Tags = Merge(KnownMarks(new[] { old, label }));
                    if (!empty)
                    {
                        if (old?.InspectionPartial == true) label.InspectionPartial = true;
                        if (old?.Text is string prefix && old.IsString && old.Complete && text != null &&
                            (long)prefix.Length + text.Length <= MaxContent)
                            text = prefix + text;
                        else
                        {
                            if (exactText && text != null) proof = prefixProof?.Append(text);
                            text = null;
                            exactText = false;
                        }
                        bytes = asciiBytes != null && prefixBytes != null && (long)prefixBytes.Length + asciiBytes.Length <= MaxContent
                            ? prefixBytes.Concat(asciiBytes).ToArray() : null;
                    }
                }
                var marks = Merge(label.Tags.Concat(FilePathEvidence(path, "write-path").Tags));
                var outgoing = bytes != null ? Bytes(bytes, path, marks) : Text(text, path, marks);
                outgoing.IsString = exactText && bytes == null && text != null;
                outgoing.Complete &= label.Complete && !label.InspectionPartial && (bytes != null || outgoing.IsString);
                if (!outgoing.Complete) outgoing.Issue = "file-write-format";
                outgoing.PredictedAttributes = previous?.PredictedAttributes ?? DiskAttributes(path) ??
                    (before == "" ? FileAttributes.Archive : (FileAttributes?)null);
                predictedWrites[path] = outgoing;
                if (before != null && !barrier && !label.InspectionPartial && (proof != null || bytes != null || text != null && content.Complete))
                    plan.Work.Add(new PolicyWork { Target = path, From = content.SourceRef, Before = before,
                        Bytes = bytes, Value = text, Tags = label.Tags, ExactText = exactText, Proof = proof });
            }

            void ForgetFilePrediction(string path)
            {
                plannedFiles.Add(path);
                predictedWrites.Remove(path);
                plan.Work.RemoveAll(w => w.File && PathEq(w.Target, path));
            }
            Payload? FileCommandOutput(List<Payload>? records)
            {
                if (records == null || records.Count == 0) return null;
                return records.Count == 1 ? records[0] : new Payload { Files = new FileSetReference(records.ToArray()),
                    Complete = true, SourceRef = "file command output" };
            }

            void CopyFilePrediction(string source, string destination, bool move, List<Payload>? output)
            {
                predictedWrites.TryGetValue(source, out var prediction);
                if (prediction?.Issue == "file-moved") return;
                bool text = prediction?.IsString == true && prediction.Bytes == null;
                var content = File(source, text, out var sample, forceBytes: !text);
                if (sample == null && prediction == null && Disk.TargetStamp(source) == "") return;
                var bytes = sample?.Bytes ?? content.Bytes;
                var proof = bytes == null && !text ? plan.Work.LastOrDefault(w => w.File && PathEq(w.Target, source))?.Proof ??
                    (sample == null ? null : SourceProof(source, sample.Stamp)) : null;
                PlanWrite(destination, content, bytes, false, noNewline: text, proof: proof);
                if (predictedWrites.TryGetValue(destination, out var copy))
                    copy.PredictedAttributes = prediction?.PredictedAttributes ?? DiskAttributes(source);
                output?.Add(new Payload { FileObject = new FileReference(destination), Complete = true, SourceRef = destination });
                if (move)
                {
                    ForgetFilePrediction(source);
                    predictedWrites[source] = Missing("file-moved");
                }
            }

            Payload? MutateFile(object command, string name, Payload? pipe)
            {
                var names = Paths.Concat(new[] { "Filter", "Include", "Exclude", "Credential" });
                names = name == "rename-item" ? names.Append("NewName") : names.Append("Stream");
                var flags = new[] { "Force", "WhatIf", "Confirm" }.AsEnumerable();
                if (name == "remove-item") flags = flags.Append("Recurse");
                else if (name == "rename-item") flags = flags.Append("PassThru");
                using var args = new Args(this, command, names.ToArray(), flags.ToArray());
                if (!args.Valid && !args.Uncertain || args.Has("WhatIf")) return null;
                var target = PathArg(args, 0, out var count);
                var input = target == null ? pipe : Value(target);
                var newName = args.Get("NewName");
                if (name == "rename-item" && newName == null) newName = args.Plain.ElementAtOrDefault(count++);
                if (input == null || !args.Valid || target != null && args.Plain.Count != count)
                    return UncertainWrite("file-mutation-shape", input?.Text);
                if (args.Has("Credential")) return Missing("file-mutation-credential");
                var output = args.Has("PassThru") ? new List<Payload>() : null;
                var rename = newName == null ? null : Value(newName).Text;
                var stream = args.Has("Stream") && !DefaultDataStream(args);
                foreach (var selected in SelectFilePaths(input, args, includeDirectories: true))
                {
                    var path = Disk.Bind(selected.Text, cwd);
                    if (path == null) { var unknown = UncertainWrite("file-mutation-path", input.Text); output?.Add(unknown); continue; }
                    if (stream)
                    {
                        if (Value(args.Get("Stream")).Text == null) UncertainWrite("file-mutation-stream", path);
                        continue;
                    }
                    string? destination = name == "rename-item" && rename != null && rename.Length > 0 &&
                        Path.GetFileName(rename) == rename ? Disk.Bind(rename, Path.GetDirectoryName(path)) : null;
                    if (selected.InspectionPartial || args.Has("Confirm") || Directory.Exists(path) || name == "rename-item" && destination == null)
                    {
                        var unknown = UncertainWrite("file-mutation-target", path);
                        output?.Add(unknown);
                        if (name == "rename-item") UncertainWrite("rename-destination", destination ?? Path.GetDirectoryName(path));
                        continue;
                    }
                    if (destination != null)
                    {
                        if (!PathEq(path, destination) && Disk.TargetStamp(destination) == "") CopyFilePrediction(path, destination, true, output);
                    }
                    else if (name == "remove-item")
                    {
                        if (!args.Has("Force") && System.IO.File.Exists(path))
                        {
                            try
                            {
                                if ((System.IO.File.GetAttributes(path) & (FileAttributes.ReadOnly | FileAttributes.Hidden)) != 0)
                                    continue;
                            }
                            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                            { UncertainWrite("remove-file-access", path); continue; }
                        }
                        ForgetFilePrediction(path);
                        predictedWrites[path] = Missing("file-moved");
                    }
                    else if (predictedWrites.TryGetValue(path, out var previous) ? previous.Issue != "file-moved" : Disk.TargetStamp(path) is { Length: > 0 })
                        PlanWrite(path, Text("", path), Array.Empty<byte>(), false, noNewline: true);
                }
                return FileCommandOutput(output);
            }

            Payload? LocalCommand(object command, string name, Payload? pipe)
            {
                if (name == "join-path") return JoinFilePath(command, pipe);
                if (name == "expand-archive") return ExpandZipCommand(command, pipe);
                if (name.StartsWith("native-read:", StringComparison.Ordinal)) return NativeRead(command, name.Substring(12), NativeInput(pipe));
                if (name is "import-csv" or "convertfrom-csv") return ReadCsv(command, name, pipe);
                if (name is "resolve-path" or "convert-path" or "get-filehash") return ReadMetadata(command, name, pipe);
                if (name == "get-variable") return ReadNamedVariable(command, pipe);
                if (name == "get-acl") return ReadAcl(command, pipe);
                if (name == "group-object") return GroupRead(command,pipe);
                if (name == "get-member") return MemberRead(command,pipe);
                if (name is "get-process" or "get-service" or "get-history" or "read-host" or "get-computerinfo" or "get-netipconfiguration" or "get-location")
                    return ReadSystemCommand(command, name, pipe);
                if (name == "convertfrom-stringdata") return ReadStringData(command, pipe);
                if (name == "import-localizeddata") return ReadLocalizedData(command, pipe);
                if (name is "get-clipboard" or "get-itemproperty" or "get-itempropertyvalue" or "get-winevent" or "get-ciminstance")
                    return ReadLocalSource(command, name, pipe);
                if (name == "select-string") return SearchText(command, pipe);
                if (name == "format-hex") return FormatHex(command, pipe);
                if (name == "select-object") return SelectReadProperties(command, pipe);
                if (name is "import-powershelldatafile" or "import-clixml" or "convertfrom-json" or "select-xml")
                    return ReadStructured(command, name, pipe);
                if (name == "get-item") return GetFileItem(command, pipe);
                if (name == "get-childitem") return FileSet(command, pipe);
                if (name == "convertto-json") return ConvertJson(command, pipe);
                if (name == "compress-archive")
                {
                    if (pipe != null || !PlanArchive(command)) { UncertainWrite("archive-creation-shape"); }
                    return null;
                }
                if (name == "get-content")
                {
                    using var args = new Args(this, command, ContentArgs, ContentFlags);
                    Payload Done(Payload result)
                    {
                        if (args.Valid && args.Has("Wait"))
                        {
                            result = UnknownValue("file-wait-future-records", result);
                            result.UnmaterializedFileRecords = true;
                        }
                        return result;
                    }
                    var from = PathArg(args, 0, out int total);
                    if (!args.Valid || from == null || args.Plain.Count != total) return Done(Missing("file-read-shape"));
                    if (args.Has("Credential")) return Done(Missing("file-read-credential"));
                    var delimiter = args.Has("Delimiter") ? Value(args.Get("Delimiter")).Text : null;
                    if (args.Has("Delimiter") && (args.Has("Raw") || args.Has("AsByteStream")))
                        return Done(Missing("file-delimiter"));
                    if (delimiter == "") return Done(CollectElements(Array.Empty<Payload>()));
                    bool unknownDelimiter = args.Has("Delimiter") && delimiter == null;
                    if (delimiter == "\n") delimiter = null;
                    if (args.Has("Wait") && args.Has("Raw")) return Done(Missing("file-wait-raw-binding"));
                    long readCount = 1;
                    bool countKnown = !args.Has("ReadCount") || long.TryParse(Value(args.Get("ReadCount")).Text,
                        NumberStyles.Integer, CultureInfo.InvariantCulture, out readCount);
                    bool tail = args.Has("Tail"), head = args.Has("TotalCount");
                    Func<string, string>? slice = null;
                    int? tailLines = null;
                    long? headLines = null;
                    if (tail || head)
                    {
                        if (tail && head || args.Has("Raw") ||
                            !long.TryParse(Value(args.Get(tail ? "Tail" : "TotalCount")).Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var take) || take < 0 ||
                            (tail && take > int.MaxValue))
                            return Done(Missing("file-line-count"));
                        if (take == 0 && !(tail && args.Has("Wait"))) return Done(new Payload { Elements = Array.Empty<Payload>(), Complete = true, SourceRef = "empty-file-selection" });
                        int count = (int)Math.Min(int.MaxValue, take);
                        slice = delimiter == null ? s => SliceLines(s, count, tail) :
                            s => string.Concat(tail ? DelimitedRecords(s, delimiter).TakeLast(count) : DelimitedRecords(s, delimiter).Take(count));
                        if (tail) tailLines = (int)take;
                        else headLines = take;
                    }
                    if (unknownDelimiter && (head || tail)) slice = _ => "";
                    var paths = Value(from);
                    if (paths.Text?.StartsWith("env:", StringComparison.OrdinalIgnoreCase) == true)
                    {
                        if (args.Named.Keys.Except(Paths.Concat(CommonNames), StringComparer.OrdinalIgnoreCase).Any())
                            return Done(Missing("environment-content-arguments"));
                        return Done(EnvironmentItem(paths, "get-content") ?? Missing("environment-selection"));
                    }
                    System.Text.Encoding? encoding = null;
                    if (args.Has("Encoding"))
                        encoding = Value(args.Get("Encoding")).Text?.ToLowerInvariant() switch
                        {
                            "utf8" or "utf8nobom" or "utf8bom" or "65001" => StrictUtf8,
                            "unicode" or "1200" => new System.Text.UnicodeEncoding(false, true, true),
                            "bigendianunicode" or "1201" => new System.Text.UnicodeEncoding(true, true, true),
                            "utf32" or "12000" => new System.Text.UTF32Encoding(false, true, true),
                            "bigendianutf32" or "12001" => new System.Text.UTF32Encoding(true, true, true),
                            "ascii" or "20127" => System.Text.Encoding.ASCII,
                            _ => null
                        };
                    bool unknownEncoding = args.Has("Encoding") && encoding == null;
                    using var selected = SelectFilePaths(paths, args).GetEnumerator();
                    if (!selected.MoveNext()) return Done(CollectElements(Array.Empty<Payload>()));
                    var first = selected.Current;
                    bool multiple = selected.MoveNext();
                    int byteBudget = Limits.MaxCollection, rawRoom = MaxContent;
                    if (args.Has("AsByteStream"))
                    {
                        IEnumerable<Payload> Selections()
                        {
                            yield return first;
                            if (multiple) do { yield return selected.Current; } while (selected.MoveNext());
                        }
                        var batches = new List<Payload>();
                        foreach (var path in Selections())
                        {
                            if (!Budget() || batches.Count >= Limits.MaxCollection)
                            { batches.Add(Missing("file-byte-path-limit")); break; }
                            batches.Add(ReadPath(path));
                        }
                        var records = JoinReadBatches(batches, "Get-Content bytes");
                        if (!args.Has("Wait") && capture?.Destination != null) capture.Records = records;
                        return Done(records.Complete && records.Elements?.Length == 1 ? records.Elements[0] : records);
                    }
                    if (!multiple)
                    {
                        var single = ReadPath(first);
                        return Done(first.InspectionPartial ? Partial(single, "conditional-file-selection") : single);
                    }
                    if (args.Has("Raw") && countKnown && readCount == 1)
                    {
                        IEnumerable<Payload> RawRecords()
                        {
                            Payload? Record(Payload path)
                            {
                                var p = ReadPath(path);
                                if (path.InspectionPartial) return UnknownValue("conditional-file-selection", p);
                                if (p.Complete && p.Elements?.Length == 0) return null;
                                return p;
                            }
                            if (Record(first) is Payload start) yield return start;
                            do { if (Record(selected.Current) is Payload next) yield return next; } while (selected.MoveNext());
                        }
                        var records = CollectRawReads(RawRecords());
                        if (!args.Has("Wait") && capture?.Destination != null) capture.Records = records;
                        return Done(records.Complete && records.Elements?.Length == 1 ? records.Elements[0] : records);
                    }
                    IEnumerable<Payload> ReadAll()
                    {
                        yield return ReadPath(first);
                        do { yield return ReadPath(selected.Current); } while (selected.MoveNext());
                    }
                    var combined = Partial(AggregateFileEvidence(ReadAll(), "Get-Content paths"), "file-multi-records");
                    if (!args.Has("AsByteStream") && countKnown)
                    {
                        combined.UnmaterializedFileRecords = true;
                        if (args.Has("Raw")) combined.Issue = "file-multi-raw";
                        else if (readCount != 1) combined.Issue = "file-multi-groups";
                    }
                    return Done(combined);

                    Payload ReadPath(Payload path)
                    {
                        if (path.Text == null) return path;
                        var rawPath = path.Text;
                        var alternate = args.Has("Stream") && !DefaultDataStream(args);
                        string? streamName = alternate ? ExactString(Value(args.Get("Stream"))) : null;
                        if (alternate && !Disk.SafeStreamName(streamName))
                        {
                            var bound = Disk.Bind(rawPath, cwd) ?? Disk.ExternalRulePath(rawPath);
                            var stream = bound != null && policy != null ? FilePathEvidence(bound, "file-alternate-stream") : Missing("file-alternate-stream");
                            stream.InspectionPartial = true;
                            stream.IsString = args.Has("Raw") && !args.Has("AsByteStream");
                            stream.UnmaterializedFileRecords = !stream.IsString;
                            return stream;
                        }
                        if (args.Has("AsByteStream"))
                        {
                            Disk.Sample? binary;
                            var file = alternate ? ReadDataStream(rawPath, streamName!, out binary, true, null, false, null) :
                                File(rawPath, false, out binary, forceBytes: true, inspectArchive: false);
                            var data = binary?.Bytes ?? file.Bytes;
                            if (data == null || path.InspectionPartial || file.MayReadOriginal || file.InspectionPartial || !countKnown)
                                return new Payload { Tags = FileRecordMarks(file), SourceRef = file.SourceRef, InspectionPartial = true,
                                    Issue = !countKnown ? "file-byte-read-count" : "file-bytes-unavailable" };
                            return FileByteRecords(file, data, args.Has("Raw"), readCount, headLines, tailLines, ref byteBudget, ref rawRoom);
                        }
                        Disk.Sample? sample;
                        var result = alternate ? ReadDataStream(rawPath, streamName!, out sample, false, encoding, unknownEncoding, slice) :
                            File(rawPath, true, out sample, encoding: encoding,
                            decodeUnavailable: unknownEncoding, sliceText: slice, tailLines: unknownDelimiter ? null : tailLines, headLines: unknownDelimiter ? null : headLines, delimiter: delimiter);
                        var fileText = sample?.Text ?? (result.IsString ? result.Text : null);
                        if (args.Has("Raw") && fileText == "" && result.Complete && !result.InspectionPartial)
                            return CollectElements(Array.Empty<Payload>());
                        if (!unknownEncoding && (sample != null || result.Tags.Length != 0 || result.MayReadOriginal))
                        {
                            if (args.Has("Raw")) result.IsString = true;
                            else if (!result.Complete && fileText == null && countKnown)
                            {
                                result.UnmaterializedFileRecords = true;
                                if (readCount > 1) result.Issue = "file-unmaterialized-groups";
                            }
                        }
                        if (result.Issue == "file-encoding") return result;
                        if (delimiter != null || unknownDelimiter)
                        {
                            if (delimiter == null || fileText == null || !countKnown)
                            {
                                var partial = UnknownValue(sample?.StreamIssue is { Length: > 0 } reason ? reason : "file-delimited-records", result);
                                partial.UnmaterializedFileRecords = true;
                                return partial;
                            }
                            var records = DelimitedRecords(fileText, delimiter).Take(ProbeCount(Limits.MaxLines)).ToArray();
                            if (records.Length > Limits.MaxLines)
                            {
                                var partial = UnknownValue("file-delimited-record-limit", result);
                                partial.UnmaterializedFileRecords = true;
                                return partial;
                            }
                            var marks = FileRecordMarks(result);
                            var items = records.Select(r => Text(r, result.SourceRef, marks)).ToArray();
                            if (readCount == 1)
                            {
                                var output = CollectElements(items);
                                if (items.Length == 1) output = items[0].Copy();
                                output.Tags = Merge(KnownMarks(items).Concat(output.Tags));
                                output.InspectionPartial |= result.InspectionPartial || !result.Complete;
                                if (records.Sum(r => (long)r.Length + Environment.NewLine.Length) <= MaxContent)
                                {
                                    output.PipeText = records.Length == 0 ? "" : string.Join(Environment.NewLine, records) + Environment.NewLine;
                                    output.Tags = Merge(output.Tags.Concat(Text(output.PipeText, result.SourceRef).Tags));
                                }
                                if (items.Length == 1) output.Elements = items;
                                return output;
                            }
                            int size = readCount <= 0 ? Math.Max(1, items.Length) : (int)Math.Min(int.MaxValue, readCount);
                            var groups = items.Select((record, i) => (record, i)).GroupBy(e => e.i / size)
                                .Select(g => CollectElements(g.Select(e => e.record))).ToArray();
                            var grouped = Partial(result, "file-read-count-grouping");
                            grouped.Elements = groups;
                            return grouped;
                        }
                        if (!multiple && !args.Has("Wait") && capture?.Destination != null && !args.Has("Raw") && countKnown && readCount == 1 && fileText is string contents)
                        {
                            // A capture is a collection of output records, not the flattened stdin representation.
                            using var records = new StringReader(contents);
                            var collected = new List<Payload>();
                            var marks = FileRecordMarks(result);
                            string? line;
                            while ((line = records.ReadLine()) != null && collected.Count < MaxOutVariableRecords)
                                collected.Add(Text(line, result.SourceRef, marks));
                            capture.Records = new Payload { Elements = collected.ToArray(), Complete = result.Complete && line == null,
                                SourceRef = result.SourceRef, RecordRemainder = line == null ? null : UnknownValue("out-variable-record-limit", result) };
                        }
                        if (!args.Has("Raw") && fileText != null)
                        {
                            using var lines = new StringReader(fileText);
                            var data = new List<string>();
                            string? line;
                            while ((line = lines.ReadLine()) != null && data.Count < Limits.MaxLines) data.Add(line);
                            if (line != null)
                            {
                                result.Complete = false;
                                result.UnmaterializedFileRecords = countKnown;
                                result.Issue = countKnown && readCount > 1 ? "file-unmaterialized-groups" : "file-line-limit";
                            }
                            else if (countKnown && readCount != 1 && result.Complete)
                            {
                                var marks = FileRecordMarks(result);
                                int groupSize = readCount <= 0 ? Math.Max(1, data.Count) : (int)Math.Min(readCount, Limits.MaxLines);
                                var groups = new List<Payload>();
                                for (int start = 0; start < data.Count; start += groupSize)
                                {
                                    var records = data.Skip(start).Take(groupSize)
                                        .Select(value => Text(value, result.SourceRef, marks)).ToArray();
                                    groups.Add(new Payload { Elements = records, Complete = true, SourceRef = result.SourceRef });
                                }
                                if (!multiple && !args.Has("Wait") && capture?.Destination != null)
                                {
                                    capture.Records = new Payload { Elements = groups.ToArray(), Complete = true };
                                }
                                // Native/stdin stringification remains partial. A consumer that can
                                // serialize the collection can use the individual output records.
                                result = Partial(result, "file-read-count-grouping");
                                result.Elements = groups.ToArray();
                            }
                            else if (!countKnown || readCount != 1) result = Partial(result, "file-read-count-grouping");
                            else result.PipeText = data.Count == 0 ? "" : string.Join(Environment.NewLine, data) + Environment.NewLine;
                            result.Text = data.Count == 1 ? data[0] : null;
                        }
                        return result;
                    }
                }
                if (name is "copy-item" or "move-item")
                {
                    using var args = new Args(this, command, new[] { "Path", "LiteralPath", "Destination", "OutVariable", "Filter", "Include", "Exclude", "Credential", "FromSession", "ToSession" },
                        new[] { "Force", "WhatIf", "Confirm", "Container", "Recurse", "PassThru" });
                    var from = PathArg(args, 0, out int total);
                    var dest = args.Get("Destination") ?? args.Plain.ElementAtOrDefault(total);
                    if (!args.Has("Destination")) total++;
                    var to = dest == null ? null : Value(dest).Text;
                    if (!args.Valid && !args.Uncertain || args.Has("WhatIf")) return null;
                    if (name == "move-item" && (args.Has("FromSession") || args.Has("ToSession"))) return Missing("move-session-binding");
                    if (from == null && dest != null && pipe != null && args.Has("Destination") && args.Plain.Count == 0 &&
                        (args.Has("ToSession") || ShareHost(to) != null) && !args.Has("FromSession") && args.Valid)
                        return RemoteCopy(name, args, pipe, Value(dest));
                    if (!args.Valid || from == null || dest == null || args.Plain.Count != total)
                        return UncertainWrite("copy-shape", to);
                    if (args.Has("ToSession") && args.Has("FromSession"))
                        return Missing("copy-session-conflict");
                    if (args.Has("FromSession"))
                    {
                        if (ShareHost(to) is string shared)
                        {
                            ShareSend(name, shared, new[] { Value(dest), Missing("copy-remote-source") }, "copy-remote-source");
                            return args.Has("PassThru") ? Missing("copy-remote-output") : null;
                        }
                        return UncertainWrite("copy-remote-source", to);
                    }
                    if (args.Has("ToSession") || ShareHost(to) != null)
                        return RemoteCopy(name, args, Value(from), Value(dest));
                    if (args.Has("Credential")) return Missing("copy-provider-credential");
                    var destination = Disk.Bind(to, cwd);
                    if (destination == null) return UncertainWrite("copy-target");
                    var output = args.Has("PassThru") ? new List<Payload>() : null;
                    bool directory = Directory.Exists(destination);
                    var sources = SelectFilePaths(Value(from), args, includeDirectories: true);
                    foreach (var selected in sources)
                    {
                        var source = Disk.Bind(selected.Text, cwd);
                        if (source == null) { var unknown = UncertainWrite("copy-source", destination); output?.Add(unknown); continue; }
                        var target = directory ? Path.Combine(destination, Path.GetFileName(source)) : destination;
                        if (PathEq(source, target)) continue;
                        if (selected.InspectionPartial || Directory.Exists(source) || args.Has("Confirm"))
                        {
                            var unknown = UncertainWrite("copy-directory-or-confirmation", target);
                            output?.Add(unknown);
                            if (name == "move-item") UncertainWrite("move-source", source);
                        }
                        else CopyFilePrediction(source, target, name == "move-item", output);
                    }
                    return FileCommandOutput(output);
                }
                if (name is "clear-content" or "remove-item" or "rename-item")
                    return MutateFile(command, name, pipe);
                if (name == "set-content" || name == "out-file" || name == "add-content")
                {
                    bool outFile = name == "out-file";
                    using var args = outFile
                        ? new Args(this, command, new[] { "FilePath", "LiteralPath", "InputObject", "Encoding", "OutVariable", "Width" },
                            new[] { "NoNewline", "Append", "Force", "WhatIf", "Confirm", "NoClobber" })
                        : new Args(this, command, new[] { "Path", "LiteralPath", "Value", "Encoding", "OutVariable", "Filter", "Include", "Exclude", "Credential", "Stream" },
                            new[] { "NoNewline", "AsByteStream", "Force", "WhatIf", "Confirm", "PassThru" });
                    var dest = PathArg(args, 0, out int total, outFile ? "FilePath" : "Path");
                    var value = args.Get(outFile ? "InputObject" : "Value");
                    var encoding = args.Get("Encoding");
                    if (args.Plain.Count > total)
                    {
                        if (outFile && encoding == null) encoding = args.Plain[total++];
                        if (!outFile && value == null && pipe == null) value = args.Plain[total++];
                    }
                    if (!args.Valid && !args.Uncertain || args.Has("WhatIf")) return null;
                    var target = dest == null ? pipe?.FileObject?.Path : Value(dest).Text;
                    if (!args.Valid || dest == null || args.Plain.Count != total || (value != null && pipe != null))
                        return UncertainWrite("write-shape", target);
                    if (args.Has("Credential")) return Missing("write-provider-credential");
                    if (args.Has("Stream") && !DefaultDataStream(args))
                        return Value(args.Get("Stream")).Text == null ? UncertainWrite("write-stream", target) : Missing("write-alternate-stream");
                    var payload = value == null ? pipe ?? Missing("write-input") : Value(value);
                    var codec = encoding == null ? "utf8" : Value(encoding).Text?.ToLowerInvariant();
                    bool ascii = codec is "ascii" or "20127";
                    if (ascii && !args.Has("AsByteStream"))
                    {
                        string RoundTrip(string text) => System.Text.Encoding.ASCII.GetString(System.Text.Encoding.ASCII.GetBytes(text));
                        var source = payload;
                        payload = Text(source.Text == null ? null : RoundTrip(source.Text), source.SourceRef, FileRecordMarks(source));
                        if (source.PipeText != null)
                        {
                            payload.PipeText = RoundTrip(source.PipeText);
                            payload.Tags = Merge(payload.Tags.Concat(Text(payload.PipeText, source.SourceRef).Tags));
                        }
                        if (source.Text == null && source.PipeText == null)
                            payload.Tags = Merge(payload.Tags.Concat(source.Tags.Where(m => Find(m.Id)?.Texts.All(t => t.All(c => c < 128)) == true)));
                    }
                    foreach (var selected in SelectFilePaths(Value(dest), args))
                    {
                        if (ShareHost(selected.Text) is string share)
                        {
                            var body = ShareBody(payload);
                            ShareSend(name, share, new[] { selected, body }, args.Has("Confirm") ? "confirmation" : null);
                            continue;
                        }
                        var path = Disk.Bind(selected.Text, cwd);
                        if (path == null) { UncertainWrite("write-target", target, payload); continue; }
                        if (args.Has("NoClobber") && (predictedWrites.TryGetValue(path, out var existing) ?
                            existing.Issue != "file-moved" : Disk.TargetStamp(path) != "")) continue;
                        if (selected.InspectionPartial || args.Has("Confirm") || args.Has("Width") || encoding != null && !ascii &&
                            codec is not ("utf8" or "utf8nobom" or "utf8bom" or "unicode" or "bigendianunicode" or "utf32" or
                                "bigendianutf32" or "65001" or "1200" or "1201" or "12000" or "12001"))
                        { UncertainWrite("write-format-or-confirmation", path, payload); continue; }
                        if (args.Has("AsByteStream"))
                        {
                            if (name != "set-content" || args.Has("NoNewline") || payload.Bytes == null)
                                UncertainWrite("write-byte-stream-shape", path, payload);
                            else PlanWrite(path, payload, payload.Bytes, false);
                        }
                        else if (args.Has("NoNewline") && payload.PipeText != null) UncertainWrite("pipeline-format", path, payload);
                        else PlanWrite(path, payload, null, args.Has("Append") || name == "add-content", args.Has("NoNewline"),
                            appendRecordNewline: !outFile, ascii: ascii);
                    }
                    return args.Has("PassThru") ? payload : null;
                }
                if (name == "write-output")
                {
                    using var args = new Args(this, command, new[] { "InputObject", "OutVariable" }, new[] { "NoEnumerate" });
                    var input = args.Get("InputObject") ?? args.Plain.FirstOrDefault();
                    var output = !args.Valid || args.Plain.Count > (args.Has("InputObject") ? 0 : 1) ||
                        (input != null && pipe != null) ? Missing("write-output-shape") :
                        input == null ? pipe ?? Missing("write-output-input") : Value(input);
                    return output;
                }
                return Missing("unsupported-propagation");
            }

            void InvalidateOutputFile(Payload output, bool dashMeansStdout = false)
            {
                if (dashMeansStdout && output.Complete && output.Text == "-") return;
                var path = Disk.Bind(output.Complete ? output.Text : null, cwd);
                if (path == null || barrier) { InvalidateFileFacts(); return; }
                ForgetFilePrediction(path);
            }
            void UnknownVariableWrite()
            {
                variablesUnknown = true;
                foreach (var key in values.Keys.ToArray())
                    values[key] = UnknownValue("possible-variable-write", values[key]);
                plan.Assignments.Clear();
            }
            void InvalidateOutputVariable(Payload output, bool allowAppend = false)
            {
                var name = output.Text;
                bool rawAppend = allowAppend && name?.StartsWith("+", StringComparison.Ordinal) == true;
                if (rawAppend) name = name!.Substring(1);
                if (!output.Complete || name == null || !SafeName(name)) { UnknownVariableWrite(); return; }
                var key = Key(name);
                values[key] = rawAppend ? UnknownValue("stream-output-variable", Variable(name)) : Missing("stream-output-variable");
                plan.Assignments.Remove(key);
            }

            sealed class CommandCapture
            {
                internal readonly object Command;
                internal Payload? Destination, Records;
                internal bool NoEnumerate;
                internal CommandCapture(object command) { Command = command; }
            }
            CommandCapture? capture;

            void WriteOutVariable(Payload destination, Payload? output, bool noEnumerate)
            {
                var raw = destination.Text;
                bool append = raw?.StartsWith("+", StringComparison.Ordinal) == true;
                var name = append ? raw!.Substring(1) : raw;
                if (!destination.Complete || name == null || !SafeName(name) || EnvName(name))
                { UnknownVariableWrite(); return; }

                var prefix = new List<Payload>();
                var remainingPaths = new HashSet<FileReference>();
                var remainingMarks = new Dictionary<(string, string), Mark>();
                bool partial = false;
                long? count = 0;
                void Remainder(Payload item)
                {
                    partial = true;
                    foreach (var mark in KnownMarks(new[] { item })) remainingMarks[(mark.Id, mark.Origin)] = mark;
                    remainingPaths.UnionWith(FilePathCandidates(item));
                }
                void AddOutput(Payload? value, bool single)
                {
                    if (value == null) return;
                    var items = single ? new[] { value } : value.Files?.Records ?? value.Elements ?? new[] { value };
                    foreach (var item in items)
                    {
                        // Enumeration and unknown command output can represent any number of records.
                        if ((item.UnmaterializedFileRecords || !item.Complete && !item.IsString) && item.Elements == null && item.FileObject == null &&
                            item.Bytes == null && !single)
                        { count = null; Remainder(item); continue; }
                        count++;
                        if (!partial && prefix.Count < MaxOutVariableRecords) prefix.Add(item);
                        else Remainder(item);
                    }
                    if (!single && (value.RecordRemainder != null || value.Elements != null && (!value.Complete || value.InspectionPartial)))
                    {
                        count = count + (value.RecordCount - items.Length);
                        Remainder(value.RecordRemainder ?? value);
                    }
                }
                var prior = append ? Variable(name) : null;
                if (prior != null && prior.Issue != "variable-value") AddOutput(prior, false);
                AddOutput(output, noEnumerate);
                var remainder = partial ? new Payload { InspectionPartial = true, Issue = "out-variable-record-limit",
                    Tags = Merge(remainingMarks.Values), PathAlternatives = remainingPaths.Count == 0 ? null : remainingPaths.ToArray() } : null;
                var captured = new Payload { Elements = prefix.ToArray(), Complete = !partial, InspectionPartial = partial,
                    SourceRef = "$" + name, Issue = remainder?.Issue ?? "", RecordCount = count, RecordRemainder = remainder };
                captured.Tags = Merge(KnownMarks(prefix).Concat(remainder?.Tags ?? Array.Empty<Mark>())
                    .Concat(prior?.Tags ?? Array.Empty<Mark>()).Concat(output?.Tags ?? Array.Empty<Mark>()));
                values[Key(name)] = captured;
                plan.Assignments.Remove(Key(name));
            }
            bool? Truth(Payload value, int depth = 0)
            {
                if (!StackAvailable || depth > MaxExpressionDepth || !value.Complete) return null;
                if (value.Elements is { } list)
                    return list.Length == 1 ? Truth(list[0], depth + 1) : list.Length != 0;
                if (value.IsString) return value.Text?.Length > 0;
                return value.ScalarTruth;
            }
            static bool NumericScalar(string type) => type is "Byte" or "SByte" or "Int16" or "UInt16" or
                "Int32" or "UInt32" or "Int64" or "UInt64" or "Decimal" or "Single" or "Double";
            static bool IsIncrement(string op) =>
                op is "PlusPlus" or "PostfixPlusPlus" or "MinusMinus" or "PostfixMinusMinus";

            Payload ApplyIncrement(object? expression, string op)
            {
                var name = VarName(Prop(expression, "Child"));
                if (!SafeName(name) || EnvName(name))
                { InvalidateSessionFacts(); return Missing("increment-target"); }
                var previous = Variable(name);
                var key = Key(name);
                int delta = op.Contains("Plus", StringComparison.Ordinal) ? 1 : -1;
                var next = Missing("increment-value");
                if (previous.Complete && previous.NumericType is ("Int32" or "Int64") &&
                    long.TryParse(previous.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) &&
                    !(value == long.MaxValue && delta == 1) && !(value == long.MinValue && delta == -1))
                {
                    long sum = value + delta;
                    next = Text(sum.ToString(CultureInfo.InvariantCulture), "$" + name,
                        previous.Tags.Select(m => m.Via("increment")).ToArray());
                    next.IsString = false;
                    next.ScalarTruth = sum != 0;
                    next.NumericType = previous.NumericType == "Int32" && sum >= int.MinValue && sum <= int.MaxValue
                        ? "Int32" : "Int64";
                }
                values[key] = next;
                plan.Assignments.Remove(key);
                return op.StartsWith("Postfix", StringComparison.Ordinal) && next.Complete ? previous : next;
            }

            void Send(string name, string? target, IEnumerable<Payload> payloads, string? uncertain = null,
                Dictionary<Payload, Payload>? inspected = null, int? targetOrdinal = null)
            {
                var parts = new List<Payload>();
                var overflowVisited = new HashSet<Payload>();
                var overflowMarks = new Dictionary<(string, string), Mark>();
                foreach (var payload in payloads)
                {
                    if (parts.Count >= Limits.MaxParts)
                    {
                        uncertain ??= "payload-part-limit";
                        foreach (var mark in KnownMarks(new[] { payload }, overflowVisited))
                            overflowMarks[(mark.Id, mark.Origin)] = mark;
                        continue;
                    }
                    // Shared request fields may require archive or encoding inspection.
                    // Reuse only content evidence; routes and decisions are per destination.
                    if (inspected != null && inspected.TryGetValue(payload, out var prior)) parts.Add(prior);
                    else
                    {
                        var part = DiscoverSendContent(payload);
                        parts.Add(part);
                        if (inspected != null && inspected.Count < Limits.MaxParts) inspected.Add(payload, part);
                    }
                }
                foreach (var part in parts) RecordSource(part, "outbound");
                // Omitted parts are already classified as transmitted by the adapter.
                // Reuse known evidence, without decoding more bytes or opening additional files.
                var labels = Merge(parts.SelectMany(p => p.Tags).Concat(overflowMarks.Values)).Select(t => t.Via(name + " → " + (target ?? "?"))).ToArray();
                bool badPolicy = policy == null || policyProblem.Length != 0;
                var incomplete = parts.FirstOrDefault(p => !p.Complete || p.InspectionPartial);
                var issue = badPolicy ? policyProblem : uncertain ?? (target == null ? "destination" :
                    barrier ? "preceding-effects" : incomplete == null ? null :
                    string.IsNullOrEmpty(incomplete.Issue) ? "send-input-incomplete" : incomplete.Issue);
                int decision = 2;
                string reason = "no-match";
                if (badPolicy)
                { decision = 3; reason = "missing:" + (issue ?? "send-input"); }
                else if (labels.Any(m => Find(m.Id)?.Action == "block"))
                { decision = 1; reason = "block:" + labels.First(m => Find(m.Id)?.Action == "block").Id; }
                else if (target == null)
                { decision = 3; reason = "missing:" + (issue ?? "destination"); }
                else if (labels.Length != 0)
                { decision = 5; reason = "warn:sensitive-rule"; }
                else if (issue != null)
                { decision = 3; reason = "missing:" + issue; }
                var evidence = Data("command", name, "endpoint", target, "decision", reason,
                    "flow", labels.Take(Limits.MaxReportMarks).Select(t => t.Report()).ToArray(), "matchedRules", labels.Select(t => t.Id).Distinct().Count(),
                    "inspection", issue == null ? "configured-matchers" : "partial", "missingInput", issue,
                    "stage", currentStage, "chain", currentChain);
                if (targetOrdinal.HasValue) evidence["targetOrdinal"] = targetOrdinal.Value;
                plan.Result(decision, reason, evidence);
            }
            void SkipLoopback(string name, string? target, int? targetOrdinal = null)
            {
                var evidence = Data("command", name, "endpoint", target, "decision", "skip:loopback");
                if (targetOrdinal.HasValue) evidence["targetOrdinal"] = targetOrdinal.Value;
                plan.Result(2, "skip:loopback", evidence);
            }
            static string? Http(string? value) => value != null && Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
                (uri.Scheme == "http" || uri.Scheme == "https") && uri.Host.Length != 0 ? uri.GetComponents(UriComponents.SchemeAndServer, UriFormat.UriEscaped) : null;
            string?[] FlattenNative(object command, out Payload?[] boundValues)
            {
                if (command is Payload[] prepared)
                {
                    boundValues = prepared;
                    return prepared.Select(v => v.Complete ? v.Text : null).ToArray();
                }
                var nodes = Items(Prop(command, "CommandElements")).Skip(1).ToArray();
                var values = new List<Payload?>();
                var flat = new List<string?>();
                void Add(string? text, Payload? value = null) { flat.Add(text); values.Add(value); }
                foreach (var n in nodes)
                {
                    if (Kind(n) == "CommandParameterAst")
                        Add(Prop(n, "Argument") == null ? Prop(Prop(n, "Extent"), "Text") as string : null);
                    else
                    {
                        var value = Kind(n) == "ConstantExpressionAst" && Prop(n, "Value") is IFormattable number
                            ? Text(number.ToString(null, CultureInfo.InvariantCulture), "native-number") : Value(n);
                        if (Equals(Prop(n, "Splatted"), true))
                        {
                            if (!value.Complete || value.InspectionPartial || value.Elements == null)
                                Add(null);
                            else foreach (var item in value.Elements.Take(ProbeCount(Limits.MaxArguments)))
                                Add(item.Complete ? item.Text : null, item);
                        }
                        else Add(value.Complete ? value.Text : null, value);
                    }
                    if (flat.Count > Limits.MaxArguments) break;
                }
                boundValues = values.ToArray();
                return flat.ToArray();
            }
            void Git(object command)
            {
                var arguments = FlattenNative(command, out _);
                string? directory = cwd;
                int index = 0;
                while (index < arguments.Length && arguments[index] != "push")
                {
                    var option = arguments[index++];
                    if (option == "-C" && index < arguments.Length)
                    {
                        var path = arguments[index++];
                        if (path != "") directory = Disk.Bind(path, directory);
                    }
                    else if (option is not ("--no-pager" or "-P" or "--no-optional-locks"))
                    {
                        if (arguments.Skip(index).Contains("push")) Send("git push", null, Array.Empty<Payload>(), "git-global-options");
                        return;
                    }
                }
                if (index == arguments.Length) return;
                arguments = arguments.Skip(index).ToArray();
                if (arguments.Length > Limits.MaxArguments)
                { Send("git push", null, Array.Empty<Payload>(), "git-argument-limit"); return; }
                if (TrustLoopback && !barrier && arguments.Length > 1 && LoopbackSsh(arguments[1]))
                { SkipLoopback("git push", arguments[1]); return; }
                var proof = GitProof.TryRead(directory, arguments.Skip(1).ToArray(), policy);
                if (proof == null) Send("git push", arguments.ElementAtOrDefault(1), Array.Empty<Payload>(), "git-baseline-or-preflight");
                else if (TrustLoopback && !barrier && proof.Loopback) SkipLoopback("git push", proof.Endpoint);
                else if (proof.Network) Send("git push", proof.Endpoint, proof.Parts);
            }

            Payload? Pipeline(object? node, int depth = 0, bool backgroundScope = false)
            {
                if (node == null) return null;
                if (!StackAvailable || depth > MaxExpressionDepth) return Missing("expression-limit");
                var kind = Kind(node);
                if (kind == "CommandExpressionAst") return Expression(Prop(node, "Expression"), depth);
                if (kind is not ("PipelineAst" or "PipelineChainAst")) return Missing("control-flow");
                if (!backgroundScope && Equals(Prop(node, "Background"), true))
                {
                    var entry = new StatementState(this, preserveMutableValues: true);
                    InvalidateSessionFacts();
                    try { Pipeline(node, depth, backgroundScope: true); }
                    finally { RestoreStatementState(entry); }
                    InvalidateFileFacts();
                    ReportMissing("background-effects");
                    return Missing("background-output");
                }
                if (kind == "PipelineChainAst") return PipelineChain(node, depth);
                Payload? result = null;
                var elements = Items(Prop(node, "PipelineElements")).Take(ProbeCount(MaxEffects)).ToArray();
                int parentStage = currentStage, parentChain = currentChain;
                currentChain = 1;
                for (int index = 0; index < Math.Min(MaxEffects, elements.Length); index++)
                {
                    var element = elements[index];
                    currentStage = index + 1;
                    var incoming = result;
                    result = AnalyzeStage(element, incoming, depth);
                    if (result?.Issue == "no-expression-output") result = null;
                    if (incoming is { Complete: false } && result is { Complete: true })
                        currentChain++;

                    foreach (var redir in Items(Prop(element, "Redirections")).Take(MaxEffects))
                    {
                        if (Kind(redir) == "FileRedirectionAst" && Str(Prop(redir, "FromStream")) == "Output")
                        {
                            var path = Value(Prop(redir, "Location")).Text;
                            PlanWrite(path, result ?? Missing("redirect-input"), null, Equals(Prop(redir, "Append"), true));
                            result = null;
                        }
                        else if (Kind(redir) == "FileRedirectionAst")
                        {
                            UncertainWrite("file-redirection-stream", Value(Prop(redir, "Location")).Text);
                            if (Str(Prop(redir, "FromStream")) == "All") result = null;
                        }
                        else result = UnknownValue("stream-redirection", result);
                    }
                }
                currentStage = parentStage;
                currentChain = parentChain;
                if (elements.Length > MaxEffects)
                {
                    ReportMissing("pipeline-limit");
                    InvalidateSessionFacts();
                    return Missing("pipeline-limit");
                }
                return result;
            }

            Payload? PipelineChain(object node, int depth)
            {
                var left = Prop(node, "LhsPipelineChain");
                var right = Prop(node, "RhsPipeline");
                var first = Pipeline(left, depth + 1);
                var literal = Prop(SingleElement(left), "Expression");
                bool definitelySucceeded = Kind(literal) is "StringConstantExpressionAst" or "ConstantExpressionAst" ||
                    VarName(literal).ToLowerInvariant() is "true" or "false" or "null";
                if (definitelySucceeded && Str(Prop(node, "Operator")) == "OrOr")
                {
                    SkipBranch(right);
                    return first;
                }
                var skipped = definitelySucceeded ? null : new StatementState(this);
                ReachBranch(right);
                var second = Pipeline(right, depth + 1);
                if (skipped != null)
                {
                    skipped.Join(new StatementState(this));
                    RestoreStatementState(skipped);
                    ReportMissing("pipeline-chain-condition");
                }
                else if (first == null || second == null) return first ?? second;
                var parts = new[] { first, second }.OfType<Payload>().ToArray();
                return parts.Length == 0 ? null : new Payload { Elements = parts,
                    Tags = Merge(parts.SelectMany(p => p.Tags)), InspectionPartial = true, Issue = "pipeline-chain-output" };
            }

            Payload? AnalyzeStage(object element, Payload? input, int depth)
            {
                var parent = capture;
                capture = new CommandCapture(element);
                try
                {
                    var result = AnalyzeStageCore(element, input?.DeferredDirectory == null ? input : MaterializeDirectory(input), depth);
                    if (capture.Destination is Payload destination)
                        WriteOutVariable(destination, capture.Records ?? result, capture.NoEnumerate);
                    return result;
                }
                finally { capture = parent; }
            }

            Payload? AnalyzeStageCore(object element, Payload? input, int depth)
            {
                if (Kind(element) == "CommandExpressionAst") return Expression(Prop(element, "Expression"), depth);
                if (Kind(element) != "CommandAst")
                { InvalidateSessionFacts(); return Missing("pipeline-element"); }

                var raw = Name(element);
                var op = Str(Prop(element, "InvocationOperator"));
                if (raw.Length == 0 && op == "Ampersand")
                {
                    var head = Items(Prop(element, "CommandElements")).FirstOrDefault();
                    if (Kind(head) == "VariableExpressionAst")
                    {
                        var command = Value(head);
                        if (command.Complete && command.IsString && command.Text != null)
                        {
                            var candidate = command.Text.ToLowerInvariant();
                            if (NativeTransfers.ContainsKey(Tool(candidate)) || NativeReaders.Contains(Tool(candidate)) || functions.ContainsKey(candidate) ||
                                (!candidate.EndsWith(".exe", StringComparison.Ordinal) &&
                                 LocalName(candidate) is ("invoke-webrequest" or "invoke-restmethod"))) raw = candidate;
                        }
                    }
                }
                var name = LocalName(raw);
                if (Network(name)) visitedNetwork.Add(element);
                if (op is ("Unknown" or "Ampersand") && functions.TryGetValue(raw, out var definitions) && !flow.HasAlias(raw))
                    return CallFunctions(definitions, element, input, depth + 1);
                bool archiveCommand = name is "compress-archive" or "expand-archive";
                bool? archiveDefinition = archiveCommand ? flow.StockArchiveDefinition(name, raw.Contains("\\")) : false;
                bool shadowedInScript = ShadowedInScript(raw, name);
                if ((op != "Unknown" && (op != "Ampersand" || raw.Length == 0)) || shadowedInScript ||
                    (archiveCommand ? archiveDefinition != true :
                     !LiteralPathCommand(raw) && flow.IsShadowed(raw) &&
                     !(name == "set-location" && flow.StockAlias(raw, "Set-Location")) &&
                     !(name == "get-childitem" && flow.StockAlias(raw, "Get-ChildItem")) &&
                     !(name == "foreach-object" && (raw is "%" or "foreach") && flow.StockAlias(raw, "ForEach-Object", "Microsoft.PowerShell.Core")) &&
                     !(name == "get-content" && flow.StockAlias(raw, "Get-Content")) &&
                     !(ReaderAliases.TryGetValue(raw, out var readerAlias) && readerAlias.Name.Equals(name, StringComparison.OrdinalIgnoreCase)
                         && flow.StockAlias(raw, readerAlias.Name, readerAlias.Module)) &&
                     !(raw == "iwr" && name == "invoke-webrequest") && !(raw == "irm" && name == "invoke-restmethod")))
                {
                    if (Network(name)) Send(name, null, Array.Empty<Payload>(), "command-definition");
                    else if (archiveCommand)
                    {
                        ReportMissing("archive-command-definition");
                        if (archiveDefinition == null && name == "compress-archive" && !shadowedInScript &&
                            op is ("Unknown" or "Ampersand") && input == null && !barrier && !variablesUnknown)
                            PlanArchive(element, possibleDefinition: true);
                    }
                    // Dot-sourcing executes in the current scope. An unmodelled command
                    // otherwise produces an opaque stream, without poisoning independent reads.
                    if (op == "Dot") InvalidateSessionFacts();
                    return Missing("command-definition");
                }
                if (name is "set-location" or "push-location" or "pop-location")
                {
                    locationWasSet = true;
                    using var args = new Args(this, element, Paths.Append("StackName").ToArray(), new[] { "PassThru" });
                    var path = PathArg(args, 0, out int expected);
                    var target = path == null ? null : Value(path, depth + 1);
                    cwd = args.Valid && !args.Has("StackName") && args.Plain.Count == expected && target?.Complete == true ?
                        Disk.Bind(target.Text, cwd) : null;
                    if (cwd != null && (!Disk.ClearAncestors(cwd) || !Directory.Exists(cwd))) cwd = null;
                    return args.Has("PassThru") ? Missing("location-object") : null;
                }
                if (name == "start-process") { visitedNetwork.Add(element); return StartProcess(element); }
                if (name == "foreach-object") return ForEachObject(element, input, depth, currentStage > 1);
                if (name == "start-bitstransfer") return BitsTransfer(element, input);
                if (name is "invoke-webrequest" or "invoke-restmethod")
                {
                    HttpCmd(element, name, input);
                    return Missing("http-response-not-observed");
                }
                if (NativeTransfers.TryGetValue(name, out var transfer))
                {
                    transfer(this, element, NativeInput(input));
                    return Missing("native-output-not-observed");
                }
                if (name == "git")
                {
                    Git(element);
                    return Missing("git-output-not-observed");
                }
                if (name is "write-host" or "out-null")
                {
                    using var args = name == "out-null" ? new Args(this, element, new[] { "InputObject" }, Empty) :
                        new Args(this, element, new[] { "Object", "Separator", "ForegroundColor", "BackgroundColor" }, new[] { "NoNewline" });
                    return null;
                }
                if (name == "start-sleep" && IsPlainDelay(element)) return null;
                if (name == "test-path") return TestFilePath(element, input);
                if ((name is "get-date" or "write-warning" or "write-verbose" or "write-debug") &&
                    AnalyzeReadOnlyOutput(element, name, input))
                    return name == "get-date" ? Missing("pipeline-output-not-modelled") : null;
                if (OpaqueOutputOnly.Contains(name))
                {
                    using var args = name == "sort-object" ? new Args(this, element,
                        new[] { "InputObject", "Property", "Culture", "Top", "Bottom" }, new[] { "Stable", "Descending", "Unique", "CaseSensitive" }) :
                        new Args(this, element, new[] { "InputObject", "Property" }, new[] { "Sum", "Average", "Maximum", "Minimum",
                            "StandardDeviation", "AllStats", "Line", "Word", "Character", "IgnoreWhiteSpace" });
                    return Missing("pipeline-output-not-modelled");
                }
                return name == "new-object" && input == null && !barrier && !Items(Prop(element, "Redirections")).Any()
                    ? NewCompressionObject(element, depth) ?? Missing("unsupported-propagation")
                    : LocalCommand(element, name, input);
            }

            bool AnalyzeReadOnlyOutput(object command, string name, Payload? input)
            {
                var captured = new[] { "ErrorVariable", "WarningVariable", "InformationVariable", "OutVariable", "PipelineVariable" };
                var parameters = name == "get-date"
                    ? new[] { "Date", "LastWriteTime", "DisplayHint", "Format", "UFormat", "Year", "Month", "Day",
                        "Hour", "Minute", "Second", "Millisecond", "UnixTimeSeconds" }
                    : new[] { "Message" };
                using var args = new Args(this, command, parameters.Concat(captured).ToArray(),
                    name == "get-date" ? new[] { "AsUTC" } : Empty);
                if (!args.Valid || args.Plain.Count > 1 || input != null) return false;
                foreach (var node in args.Named.Values.Concat(args.Plain))
                {
                    if (node == null || Kind(node) is "StringConstantExpressionAst" or "ConstantExpressionAst") continue;
                    if (node is not Payload && Kind(node) != "VariableExpressionAst") return false;
                    var operand = Value(node);
                    if (operand is { Complete: true, Text: not null }) continue;
                    if (name == "get-date" || operand.Issue != "caught-error") return false;
                }
                return true;
            }

            Payload TestFilePath(object command, Payload? input)
            {
                using var args = new Args(this, command, Paths.Concat(new[] { "PathType" }).ToArray(), Empty);
                var node = PathArg(args, 0, out int expected);
                var mode = args.Has("PathType") ? Value(args.Get("PathType")).Text?.ToLowerInvariant() : "any";
                if (barrier || !args.Valid || node == null || args.Plain.Count != expected || input != null ||
                    mode is not ("any" or "leaf" or "container")) return Missing("test-path-shape");
                var path = Disk.Bind(Value(node).Text, cwd);
                if (path == null || filesUnknown || plannedFiles.Contains(path) || PendingFiles.ContainsKey(path) || !Budget())
                    return Missing("test-path-unavailable");
                bool present;
                try
                {
                    var attrs = System.IO.File.GetAttributes(path);
                    if (!Disk.ClearAncestors(path)) return Missing("test-path-unavailable");
                    bool directory = (attrs & FileAttributes.Directory) != 0;
                    present = mode == "any" || (mode == "container" ? directory : !directory);
                }
                catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
                {
                    if (!Disk.ClearAncestors(Path.GetDirectoryName(path)!)) return Missing("test-path-unavailable");
                    present = false;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                { return Missing("test-path-unavailable"); }
                return new Payload { Text = present ? "True" : "False", ScalarTruth = present, Complete = true, SourceRef = "Test-Path" };
            }

            bool IsPlainDelay(object command)
            {
                using var args = new Args(this, command, new[] { "Seconds", "Milliseconds", "Duration" }, Empty);
                var duration = args.Named.Where(p => !CommonNames.Contains(p.Key, StringComparer.OrdinalIgnoreCase)).ToArray();
                if (!args.Valid || duration.Length + args.Plain.Count != 1) return false;
                var value = duration.FirstOrDefault().Value ?? args.Plain.FirstOrDefault();
                return value is Payload p ? p.Complete : value != null && Kind(value) is ("ConstantExpressionAst" or "StringConstantExpressionAst");
            }

            static bool EnvironmentMethod(object? expression, string method)
            {
                if (Kind(expression) != "InvokeMemberExpressionAst" || !Equals(Prop(expression, "Static"), true) ||
                    !string.Equals(Literal(Prop(expression, "Member")), method, StringComparison.OrdinalIgnoreCase)) return false;
                var target = Prop(expression, "Expression");
                var type = Str(Prop(Prop(target, "TypeName"), "FullName"));
                return Kind(target) == "TypeExpressionAst" && (type.Equals("Environment", StringComparison.OrdinalIgnoreCase) ||
                    type.Equals("System.Environment", StringComparison.OrdinalIgnoreCase));
            }
            Payload Expression(object? expression, int depth)
            {
                if (EnvironmentMethod(expression, "SetEnvironmentVariable"))
                {
                    var args = Items(Prop(expression, "Arguments")).ToArray();
                    if (args.Length == 2 || args.Length == 3 && EnvironmentScope(args[2], depth) == "process")
                    {
                        var n = ExactString(Value(args[0], depth + 1));
                        if (n == null || !SafeName("env:" + n)) return Missing("process-environment-write");
                        var v = VarName(args[1]).Equals("null", StringComparison.OrdinalIgnoreCase) ?
                            Missing("process-environment-removed") : Value(args[1], depth + 1);
                        values[Key("env:" + n)] = v.IsString || v.Issue == "process-environment-removed" ? v : UnknownValue("process-environment-value", v);
                        return Missing("no-expression-output");
                    }
                    if (args.Length == 3 && plan.Work.Count < MaxEffects && !barrier)
                    {
                        var name = Value(args[0]).Text;
                        var value = Value(args[1]);
                        var scope = Value(args[2]).Text?.ToLowerInvariant();
                        bool isNull = VarName(args[1]).Equals("null", StringComparison.OrdinalIgnoreCase);
                        if (name != null && SafeName(name) && !name.Contains(":") &&
                            (scope == "user" || scope == "machine") && (isNull || value.Text != null) &&
                            (value.Complete || value.Tags.Length != 0 || isNull) &&
                            DurableEnv.Read(scope!, name, out _, out var stamp))
                            plan.Work.Add(new PolicyWork { Scope = scope!, Name = name, Before = stamp,
                                Value = isNull ? null : value.Text, Tags = isNull ? Array.Empty<Mark>() : value.Via(scope + ":" + name).Tags });
                    }
                    return Missing("no-expression-output");
                }
                if (ApplyMutation(expression)) return Missing("no-expression-output");
                if (Kind(expression) == "ParenExpressionAst")
                    return Pipeline(Prop(expression, "Pipeline"), depth + 1) ?? Missing("parenthesized-value");
                var evaluated = Value(expression, depth);
                if (evaluated.Issue == "dynamic-value" && Kind(expression) == "InvokeMemberExpressionAst" &&
                    values.Values.Any(v => v.HttpObject?.Kind == HttpObjectKind.FileStream || v.Model?.Kind == ModelKind.Characters))
                    InvalidateSessionFacts(); // an opaque call may mutate a tracked object through any alias
                return evaluated;
            }

            void ReportMissing(string issue)
            {
                var reason = "missing:" + issue;
                plan.Result(3, reason, Data("decision", reason));
            }

            static (int Start, int End)? BlockExtent(object? node)
            {
                var extent = Prop(node, "Extent");
                if (Prop(extent, "StartOffset") is int start && Prop(extent, "EndOffset") is int end)
                    return (start, end);
                return null;
            }
            void SkipBranch(object? node)
            {
                if (BlockExtent(node) is { } extent && !reachedBlocks.Contains(extent)) skippedBlocks.Add(extent);
            }
            void ReachBranch(object? node)
            {
                if (BlockExtent(node) is not { } extent) return;
                reachedBlocks.Add(extent);
                skippedBlocks.Remove(extent);
            }
            bool Skipped(object node)
            {
                if (Prop(Prop(node, "Extent"), "StartOffset") is not int start) return false;
                return skippedBlocks.Any(p => p.Start <= start && start < p.End);
            }
            static bool? ScalarTruth(string type, string value)
            {
                if (type == "Boolean") return bool.TryParse(value, out var flag) ? flag : (bool?)null;
                if (type is "String" or "Char") return value.Length != 0;
                if (type is "Byte" or "SByte" or "Int16" or "UInt16" or "Int32" or "UInt32" or "Int64" or "UInt64" or "Decimal")
                    return decimal.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var exact) ? exact != 0 : (bool?)null;
                if (type is "Single" or "Double")
                    return double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var floating) ? floating != 0 : (bool?)null;
                return null;
            }

            static IEnumerable<(int Start, Mark Tag)> Positions(Payload input, int offset, string route)
            {
                if (input.Text is not { Length: > 0 }) yield break;
                if (input.TagPositions != null)
                    foreach (var item in input.TagPositions) yield return (item.Start + offset, item.Tag.Via(route));
                else
                    foreach (var tag in input.Tags) yield return (offset, tag.Via(route));
            }

            bool? LiteralCondition(object? test, int depth = 0)
            {
                if (!StackAvailable || depth > MaxExpressionDepth) return null;
                var element = SingleElement(test);
                if (Kind(element) == "CommandAst" && Str(Prop(element, "InvocationOperator")) == "Unknown" &&
                    Name(element!) == "test-path" && !ShadowedInScript("test-path", "test-path") && !flow.IsShadowed("test-path") &&
                    !Items(Prop(element, "Redirections")).Any())
                    return Truth(AnalyzeStage(element!, null, depth + 1) ?? Missing("test-path-output"));
                var n = Prop(element, "Expression") ?? test;
                switch (Kind(n))
                {
                    case "ParenExpressionAst": return LiteralCondition(Prop(n, "Pipeline"), depth + 1);
                    case "VariableExpressionAst":
                        var variable = VarName(n);
                        if (variable.Equals("null", StringComparison.OrdinalIgnoreCase)) return false;
                        var known = Value(n, depth + 1);
                        return Truth(known);
                    case "ConstantExpressionAst":
                        var scalar = Scalar(Prop(n, "Value"), "condition");
                        return scalar.Text != null ? ScalarTruth(scalar.Type, scalar.Text) : (bool?)null;
                    case "StringConstantExpressionAst": return Literal(n)?.Length > 0;
                    case "UnaryExpressionAst":
                        if (Str(Prop(n, "TokenKind")) is "Not" or "Exclaim")
                            return !LiteralCondition(Prop(n, "Child"), depth + 1);
                        break;
                }
                return null;
            }
            bool AnalyzeIf(object node, int depth, out StatementExit exit, List<Payload>? output)
            {
                exit = StatementExit.None;
                var clauses = Items(Prop(node, "Clauses")).Take(ProbeCount(MaxStatements)).ToArray();
                if (clauses.Length == 0 || clauses.Length > MaxStatements) return false;
                var paths = new List<(StatementState State, StatementExit Exit)>();
                bool selected = false;
                var otherwise = Prop(node, "ElseClause");
                foreach (var clause in clauses)
                {
                    var condition = Prop(clause, "Item1");
                    var body = Prop(clause, "Item2");
                    if (selected) { SkipBranch(condition); SkipBranch(body); continue; }
                    ReachBranch(condition);
                    bool mutatesOrCompares = NeedsConditionEvaluation(condition);
                    var truth = mutatesOrCompares ? ApplyConditionMutation(condition) : LiteralCondition(condition);
                    if (truth == null && !mutatesOrCompares && Kind(condition) is ("PipelineAst" or "PipelineChainAst") &&
                        !ExpressionOnlyCondition(condition))
                        truth = Truth(Pipeline(condition) ?? Missing("condition-output"));
                    if (truth == false) { SkipBranch(body); continue; }

                    var whenFalse = truth == null ? new StatementState(this) : null;
                    ReachBranch(body);
                    exit = AnalyzeStatements(Items(Prop(body, "Statements")), depth + 1, output);
                    if (whenFalse != null)
                    {
                        paths.Add((new StatementState(this), exit));
                        RestoreStatementState(whenFalse);
                    }
                    else selected = true;
                }
                if (selected) SkipBranch(otherwise);
                else
                {
                    ReachBranch(otherwise);
                    exit = AnalyzeStatements(Items(Prop(otherwise, "Statements")), depth + 1, output);
                }
                if (paths.Count != 0)
                {
                    paths.Add((new StatementState(this), exit));
                    exit = MergeStatementPaths(paths);
                    ReportMissing("conditional-effects");
                }
                return true;
            }

            bool? ApplyConditionMutation(object? test, int depth = 0)
            {
                if (!StackAvailable || depth > MaxExpressionDepth) return null;
                var expression = Prop(SingleElement(test), "Expression") ?? test;
                if (Kind(expression) == "ParenExpressionAst")
                    return ApplyConditionMutation(Prop(expression, "Pipeline"), depth + 1);
                if (Kind(expression) == "UnaryExpressionAst" && Str(Prop(expression, "TokenKind")) is "Not" or "Exclaim")
                    return !ApplyConditionMutation(Prop(expression, "Child"), depth + 1);
                return Truth(Value(expression, depth + 1));
            }

            static bool NeedsConditionEvaluation(object? test, int depth = 0)
            {
                if (!StackAvailable || depth > MaxExpressionDepth) return false;
                var expr = Prop(SingleElement(test), "Expression") ?? test;
                if (Kind(expr) == "ParenExpressionAst") return NeedsConditionEvaluation(Prop(expr, "Pipeline"), depth + 1);
                if (Kind(expr) == "UnaryExpressionAst" && Str(Prop(expr, "TokenKind")) is "Not" or "Exclaim")
                    return NeedsConditionEvaluation(Prop(expr, "Child"), depth + 1);
                return (Kind(expr) == "BinaryExpressionAst" && ComparisonOperator(Str(Prop(expr, "Operator")))) ||
                       ConditionMutates(expr, depth);
            }

            static bool ConditionMutates(object? test, int depth = 0)
            {
                if (!StackAvailable || depth > MaxExpressionDepth) return false;
                var expression = Prop(SingleElement(test), "Expression") ?? test;
                if (Kind(expression) == "ParenExpressionAst")
                    return ConditionMutates(Prop(expression, "Pipeline"), depth + 1);
                if (Kind(expression) == "BinaryExpressionAst")
                    return ConditionMutates(Prop(expression, "Left"), depth + 1) ||
                           ConditionMutates(Prop(expression, "Right"), depth + 1);
                if (Kind(expression) != "UnaryExpressionAst") return false;
                return IsIncrement(Str(Prop(expression, "TokenKind"))) || ConditionMutates(Prop(expression, "Child"), depth + 1);
            }
            static bool ExpressionOnlyCondition(object? condition)
            {
                var expr = Prop(SingleElement(condition), "Expression");
                return Kind(expr) is "VariableExpressionAst" or "ConstantExpressionAst" or "StringConstantExpressionAst";
            }

            enum StatementExit { None, Break, Continue, Return, Throw, Exit }

            sealed class StatementState
            {
                internal readonly Dictionary<string, Payload> Values;
                internal readonly Dictionary<HttpObject, HttpObject> HttpStates;
                internal readonly HashSet<string> Files;
                internal readonly Dictionary<string, Payload> Predictions;
                internal readonly HashSet<string> Definitions;
                internal readonly Dictionary<string, object?[]> Functions;
                internal readonly List<PolicyWork> Work;
                internal readonly Dictionary<string, Payload> Assignments;
                internal bool Barrier, FilesUnknown, VariablesUnknown;
                internal string? Directory;
                readonly AdapterContext context;

                internal StatementState(AdapterContext context, bool preserveMutableValues = false)
                {
                    this.context = context;
                    Values = context.values.ToDictionary(item => item.Key, item =>
                        preserveMutableValues || Shareable(item.Value)
                            ? context.SnapshotHttpValue(item.Value) : UnknownValue("conditional-value", item.Value), StringComparer.OrdinalIgnoreCase);
                    HttpStates = new Dictionary<HttpObject, HttpObject>(context.httpStates);
                    Files = new HashSet<string>(context.plannedFiles, StringComparer.OrdinalIgnoreCase);
                    Predictions = new Dictionary<string, Payload>(context.predictedWrites, StringComparer.OrdinalIgnoreCase);
                    Functions = new Dictionary<string, object?[]>(context.functions, context.functions.Comparer);
                    Definitions = new HashSet<string>(context.scriptDefinitions, StringComparer.OrdinalIgnoreCase);
                    Work = context.plan.Work.ToList();
                    Assignments = new Dictionary<string, Payload>(context.plan.Assignments, StringComparer.OrdinalIgnoreCase);
                    Directory = context.cwd;
                    Barrier = context.barrier;
                    FilesUnknown = context.filesUnknown;
                    VariablesUnknown = context.variablesUnknown;
                }

                static bool Shareable(Payload value)
                {
                    if (value.Map == null && value.Elements == null) return value.Model == null;
                    var pending = new Stack<Payload>();
                    var seen = new HashSet<Payload>();
                    pending.Push(value);
                    while (pending.Count != 0)
                    {
                        var item = pending.Pop();
                        if (!seen.Add(item)) continue;
                        if (item.Model != null || seen.Count > Limits.MaxCollection) return false;
                        if (item.Map != null) foreach (var child in item.Map.Values) pending.Push(child);
                        if (item.Elements != null) foreach (var child in item.Elements) pending.Push(child);
                    }
                    return true;
                }

                static bool PlainScalar(Payload p) => p.Map == null && p.Elements == null && p.Bytes == null &&
                    p.ByteRecordData == null && p.Model == null && p.HttpObject == null && p.Files == null &&
                    p.FileObject == null && p.PathAlternatives == null && p.FileTaskResult == null &&
                    p.DeferredDirectory == null && p.DeferredRead == null && p.RecordRemainder == null;

                static bool SameScalarValue(Payload a, Payload b) =>
                    (PlainScalar(a) && PlainScalar(b) && a.Complete && b.Complete && a.Text != null && a.Text == b.Text && a.IsString == b.IsString &&
                     a.MayReadOriginal == b.MayReadOriginal && a.ReadType == b.ReadType &&
                     a.MemberDisplayType == b.MemberDisplayType && a.TimeValue == b.TimeValue &&
                     a.RecordCount == b.RecordCount && a.FirstUncertainIndex == b.FirstUncertainIndex &&
                     a.UnmaterializedFileRecords == b.UnmaterializedFileRecords && a.LocalRecord == b.LocalRecord &&
                     a.PredictedAttributes == b.PredictedAttributes && a.NumericType == b.NumericType && a.ScalarTruth == b.ScalarTruth && a.PipeText == b.PipeText &&
                     !a.InspectionPartial && !b.InspectionPartial);

                static bool SameScalar(Payload a, Payload b) => ReferenceEquals(a, b) ||
                    ((SameScalarValue(a, b) || a.HttpObject is HttpObject ha && IsReadHandle(ha) &&
                      ReferenceEquals(ha.Identity, b.HttpObject?.Identity) && a.Complete == b.Complete &&
                      a.InspectionPartial == b.InspectionPartial && a.Issue == b.Issue) &&
                     (ReferenceEquals(a.TagPositions, b.TagPositions) || a.TagPositions != null && b.TagPositions != null &&
                      a.TagPositions.Select(t => (t.Start,t.Tag.Id,t.Tag.Origin)).SequenceEqual(b.TagPositions.Select(t => (t.Start,t.Tag.Id,t.Tag.Origin)))) &&
                     a.Tags.Select(t => (t.Id, t.Origin)).SequenceEqual(b.Tags.Select(t => (t.Id, t.Origin))));

                static Payload MergeValue(Payload? left, Payload? right, Dictionary<(Payload, Payload), Payload> mergedMaps, int depth = 0)
                {
                    if (left != null && right != null && SameScalar(left, right)) return left;
                    if (left != null && right != null && mergedMaps.TryGetValue((left, right), out var prior)) return prior;
                    if (left != null && right != null && SameScalarValue(left, right))
                    {
                        // Equal values can have different origins. Keep the exact value (e.g.
                        // a file argument) as well as both branches' evidence.
                        var result = left.Copy();
                        result.Tags = left.Tags.Concat(right.Tags).GroupBy(t => (t.Id, t.Origin)).Select(g => g.First()).ToArray();
                        result.TagPositions = Positions(left, 0, "conditional value").Concat(Positions(right, 0, "conditional value"))
                            .GroupBy(t => (t.Start, t.Tag.Id, t.Tag.Origin)).Select(g => g.First()).Take(Limits.MaxPositions).ToArray();
                        return result;
                    }
                    if (StackAvailable && depth < MaxExpressionDepth && left?.Map is { } a && right?.Map is { } b &&
                        a.Count == b.Count && a.Keys.All(b.ContainsKey))
                    {
                        var result = new Payload { Complete = left.Complete && right.Complete,
                            InspectionPartial = left.InspectionPartial || right.InspectionPartial,
                            Issue = left.Issue.Length != 0 ? left.Issue : right.Issue,
                            SourceRef = left.SourceRef == right.SourceRef ? left.SourceRef : "conditional map",
                            ReadType = left.ReadType == right.ReadType ? left.ReadType : null,
                            LocalRecord = left.LocalRecord == right.LocalRecord ? left.LocalRecord : null,
                            Tags = left.Tags.Concat(right.Tags).GroupBy(t => (t.Id, t.Origin)).Select(g => g.First()).ToArray() };
                        mergedMaps.Add((left, right), result);
                        result.Map = a.ToDictionary(pair => pair.Key, pair => MergeValue(pair.Value, b[pair.Key], mergedMaps, depth + 1), a.Comparer);
                        return result;
                    }
                    return UnknownValue("conditional-value", left, right);
                }

                internal void Join(StatementState other)
                {

                    void JoinValues(Dictionary<string, Payload> target, Dictionary<string, Payload> branch)
                    {
                        var mergedMaps = new Dictionary<(Payload, Payload), Payload>();
                        foreach (var key in target.Keys.Concat(branch.Keys).Distinct(StringComparer.OrdinalIgnoreCase).ToArray())
                        {
                            target.TryGetValue(key, out var left);
                            branch.TryGetValue(key, out var right);
                            if (ReferenceEquals(target, Values))
                            {
                                if (left == null && !Barrier && !VariablesUnknown && !key.StartsWith("@function", StringComparison.Ordinal)) left = context.SessionVariable(key);
                                if (right == null && !other.Barrier && !other.VariablesUnknown && !key.StartsWith("@function", StringComparison.Ordinal)) right = context.SessionVariable(key);
                            }
                            if (left == null || right == null || !SameScalar(left, right))
                            {
                                var merged = MergeValue(left, right, mergedMaps);
                                if (ReferenceEquals(target, Predictions))
                                {
                                    merged = merged.Copy();
                                    merged.MayReadOriginal = left?.MayReadOriginal == true || right?.MayReadOriginal == true ||
                                        left == null && !Files.Contains(key) || right == null && !other.Files.Contains(key);
                                }
                                target[key] = merged;
                            }
                        }
                    }
                    foreach (var id in HttpStates.Keys.Union(other.HttpStates.Keys).ToArray())
                    {
                        // The original object is the baseline if only one branch mutated it.
                        var initial = id;
                        HttpStates.TryGetValue(id, out var a);
                        other.HttpStates.TryGetValue(id, out var b);
                        HttpStates[id] = JoinHttp(a ?? initial, b ?? initial);
                    }
                    JoinValues(Values, other.Values);
                    JoinValues(Predictions, other.Predictions);
                    if (!string.Equals(Directory, other.Directory, StringComparison.OrdinalIgnoreCase)) Directory = null;
                    Barrier |= other.Barrier;
                    FilesUnknown |= other.FilesUnknown;
                    VariablesUnknown |= other.VariablesUnknown;
                    Files.UnionWith(other.Files);
                    foreach (var name in Functions.Keys.Union(other.Functions.Keys, Functions.Comparer).ToArray())
                    {
                        Functions.TryGetValue(name, out var a);
                        other.Functions.TryGetValue(name, out var b);
                        if (!ReferenceEquals(a, b)) Functions[name] = (a ?? new object?[] { null }).Concat(b ?? new object?[] { null }).Distinct().ToArray();
                    }
                    Definitions.UnionWith(other.Definitions);
                    Work.RemoveAll(item => !other.Work.Contains(item));
                    foreach (var key in Assignments.Keys.ToArray())
                        if (!other.Assignments.TryGetValue(key, out var right) || !ReferenceEquals(Assignments[key], right))
                            Assignments.Remove(key);
                }
            }

            void RestoreStatementState(StatementState state)
            {
                values.Clear();
                httpStates.Clear();
                foreach (var item in state.HttpStates) httpStates.Add(item.Key, item.Value);
                foreach (var item in state.Values) values.Add(item.Key, item.Value);
                plannedFiles.Clear();
                plannedFiles.UnionWith(state.Files);
                predictedWrites.Clear();
                foreach (var item in state.Predictions) predictedWrites.Add(item.Key, item.Value);
                scriptDefinitions.Clear();
                scriptDefinitions.UnionWith(state.Definitions);
                functions.Clear();
                foreach (var pair in state.Functions) functions.Add(pair.Key, pair.Value);
                plan.Work.Clear();
                plan.Work.AddRange(state.Work);
                plan.Assignments.Clear();
                foreach (var item in state.Assignments) plan.Assignments.Add(item.Key, item.Value);
                cwd = state.Directory;
                barrier = state.Barrier;
                filesUnknown = state.FilesUnknown;
                variablesUnknown = state.VariablesUnknown;
            }

            StatementExit AnalyzeTry(object node, int depth, List<Payload>? output)
            {
                var catches = Items(Prop(node, "CatchClauses")).Take(ProbeCount(MaxEffects)).ToArray();
                var finalizer = Prop(node, "Finally");
                var body = Items(Prop(Prop(node, "Body"), "Statements")).ToArray();
                if (body.Length == 0)
                {
                    foreach (var clause in catches) SkipBranch(clause);
                    return AnalyzeStatements(Items(Prop(finalizer, "Statements")), depth + 1, output);
                }
                var exceptional = new StatementState(this);
                var paths = new List<(StatementState State, StatementExit Exit)>();
                var observeOuter = observeStatement;
                // A terminating error can leave any prefix of the try block executed.
                observeStatement = () =>
                {
                    exceptional.Join(new StatementState(this));
                    observeOuter?.Invoke();
                };
                try
                {
                    var exit = AnalyzeBlock(body, depth + 1, paths, output);
                    paths.Add((new StatementState(this), exit));
                }
                finally { observeStatement = observeOuter; }

                paths.RemoveAll(path => path.Exit == StatementExit.Throw);
                foreach (var clause in catches.Take(MaxEffects))
                {
                    RestoreStatementState(exceptional);
                    ReachBranch(clause);
                    values[Key("_")] = values[Key("PSItem")] = Missing("caught-error");
                    var exit = AnalyzeBlock(Items(Prop(Prop(clause, "Body"), "Statements")), depth + 1, paths, output);
                    paths.Add((new StatementState(this), exit));
                }
                if (catches.Length > MaxEffects)
                {
                    ReportMissing("catch-limit");
                    InvalidateSessionFacts();
                    paths.Add((new StatementState(this), StatementExit.None));
                }
                if (!catches.Any(clause => !Items(Prop(clause, "CatchTypes")).Any()))
                    paths.Add((exceptional, StatementExit.Throw));

                if (finalizer == null) return MergeStatementPaths(paths);
                var completed = new List<(StatementState State, StatementExit Exit)>();
                var finalStatements = Items(Prop(finalizer, "Statements")).ToArray();
                foreach (var (state, exit) in paths)
                {
                    RestoreStatementState(state);
                    var next = AnalyzeBlock(finalStatements, depth + 1, completed, output);
                    completed.Add((new StatementState(this), next == StatementExit.None ? exit : next));
                }
                return MergeStatementPaths(completed);
            }

            StatementExit AnalyzeBlock(IEnumerable<object> statements, int depth,
                List<(StatementState State, StatementExit Exit)> alternatives, List<Payload>? output = null)
            {
                var outer = observeAlternateExit;
                observeAlternateExit = (state, exit) => alternatives.Add((state, exit));
                try { return AnalyzeStatements(statements, depth, output); }
                finally { observeAlternateExit = outer; }
            }

            StatementExit MergeStatementPaths(List<(StatementState State, StatementExit Exit)> paths)
            {
                if (paths.Count == 0) return StatementExit.None;
                var selected = paths.Any(path => path.Exit == StatementExit.None) ? StatementExit.None :
                    paths.Any(path => path.Exit == StatementExit.Continue) ? StatementExit.Continue : paths[0].Exit;
                StatementState? common = null;
                foreach (var (state, exit) in paths)
                {
                    if (exit != selected) observeAlternateExit?.Invoke(state, exit);
                    else if (common == null) common = state;
                    else common.Join(state);
                }
                if (common != null) RestoreStatementState(common);
                return selected;
            }

            Payload[]? IterationItems(Payload? sequence)
            {
                if (sequence?.DeferredDirectory != null) sequence = MaterializeDirectory(sequence);
                if (sequence?.Files is FileSetReference set) return set.Records;
                if (sequence?.Elements != null)
                    return sequence.InspectionPartial ? sequence.Elements.Concat(new[] { sequence.RecordRemainder ?? UnknownValue("foreach-item", sequence) }).ToArray() :
                        sequence.Elements;
                if (sequence?.PipeText is string lines)
                {
                    using var reader = new StringReader(lines);
                    var records = new List<Payload>();
                    var marks = FileRecordMarks(sequence);
                    while (records.Count <= MaxForEachIterations && reader.ReadLine() is string line)
                        records.Add(Text(line, sequence.SourceRef, marks));
                    if (records.Count > MaxForEachIterations) records.Add(UnknownValue("foreach-record-limit", sequence));
                    return records.ToArray();
                }
                return sequence != null && (sequence.Text != null || sequence.FileObject != null) ? new[] { sequence } : null;
            }

            Payload ReadFileArgument(Payload argument, bool text)
            {
                if (argument.PathAlternatives is { } paths)
                    return Partial(AggregateFileEvidence(paths.Select(path => path.Kind == PathKind.DirectoryInfo ?
                        Missing("file-is-directory") : File(path.Path, text, out _))
                        .Prepend(new Payload { Complete = true, Tags = argument.Tags }), "alternative file paths"), "alternative-file-paths");
                if (argument.FileObject?.Kind == PathKind.DirectoryInfo) return Missing("file-is-directory");
                return File(argument.FileObject?.Path ?? (argument.Complete ? argument.Text : null), text, out _);
            }

            StatementExit AnalyzeForEach(object node, int depth, List<Payload>? output)
            {
                var name = VarName(Prop(node, "Variable"));
                var condition = Prop(node, "Condition");
                var body = Prop(node, "Body");
                if (VarName(Prop(SingleElement(condition), "Expression")).Equals("null", StringComparison.OrdinalIgnoreCase))
                { SkipBranch(body); return StatementExit.None; }
                var sequence = Pipeline(condition);
                var bodyStatements = Items(Prop(body, "Statements")).ToArray();
                var items = IterationItems(sequence);
                bool bindable = SafeName(name) && !EnvName(name);
                if (!bindable || Str(Prop(node, "Flags")) is not ("" or "None"))
                { ReportMissing("foreach-binding"); InvalidateSessionFacts(); items = null; }
                var key = bindable ? Key(name) : null;
                var afterLoop = new List<(StatementState State, StatementExit Exit)>();
                bool Iteration(Payload value)
                {
                    ReachBranch(body);
                    if (key != null)
                    {
                        values[key] = value.Via("$" + name);
                        plan.Assignments.Remove(key);
                    }
                    var alternatives = new List<(StatementState State, StatementExit Exit)>();
                    var exit = AnalyzeBlock(bodyStatements, depth + 1, alternatives, output);
                    if (alternatives.Count == 0 && exit is (StatementExit.None or StatementExit.Continue)) return true;
                    alternatives.Add((new StatementState(this), exit));
                    StatementState? nextIteration = null;
                    foreach (var (state, outcome) in alternatives)
                    {
                        if (outcome is StatementExit.None or StatementExit.Continue)
                        {
                            if (nextIteration == null) nextIteration = state;
                            else nextIteration.Join(state);
                        }
                        else afterLoop.Add((state, outcome == StatementExit.Break ? StatementExit.None : outcome));
                    }
                    if (nextIteration == null) return false;
                    RestoreStatementState(nextIteration);
                    return true;
                }

                if (items?.Length == 0) SkipBranch(body);
                bool canIterate = true;
                foreach (var item in (items ?? Array.Empty<Payload>()).Take(MaxForEachIterations))
                {
                    canIterate = Iteration(item);
                    if (!canIterate) break;
                }
                if (canIterate && (items == null || items.Length > MaxForEachIterations))
                {
                    afterLoop.Add((new StatementState(this), StatementExit.None));
                    var unknownItem = UnknownValue("foreach-item", items == null ? new[] { sequence } :
                        items.Skip(MaxForEachIterations).ToArray());
                    canIterate = Iteration(unknownItem);
                    // The second possible iteration can consume state written in the first.
                    if (canIterate && items == null)
                    {
                        afterLoop.Add((new StatementState(this), StatementExit.None));
                        canIterate = Iteration(unknownItem);
                    }
                    ReportMissing("foreach-iteration");
                }
                if (afterLoop.Count == 0) return StatementExit.None;
                if (canIterate) afterLoop.Add((new StatementState(this), StatementExit.None));
                return MergeStatementPaths(afterLoop);
            }

            StatementExit AnalyzeStatements(IEnumerable<object> nodes, int depth, List<Payload>? output = null)
            {
                if (!StackAvailable || depth > MaxExpressionDepth) { ReportMissing("control-flow-depth"); InvalidateSessionFacts(); return StatementExit.None; }
                var exit = StatementExit.None;
                foreach (var node in nodes)
                {
                    if (exit != StatementExit.None) { SkipBranch(node); continue; }
                    if (++statements > MaxStatements || !Budget()) { ReportMissing("analysis-limit"); InvalidateSessionFacts(); return exit; }
                    ReachBranch(node);
                    var kind = Kind(node);
                    if (kind == "AssignmentStatementAst" && Str(Prop(node, "Operator")) == "Equals" &&
                        SafeName(VarName(Prop(node, "Left"))))
                    {
                        var name = VarName(Prop(node, "Left"));
                        var value = Pipeline(Prop(node, "Right"), depth + 1) ?? Missing("assignment-value");
                        var propagated = value.Via("$" + name);
                        values[Key(name)] = propagated;
                        plan.Assignments[Key(name)] = propagated;
                    }
                    else if (kind == "AssignmentStatementAst" && SafeName(VarName(Prop(node, "Left"))) &&
                        Str(Prop(node, "Operator")) is ("PlusEquals" or "MinusEquals"))
                    {
                        var name = VarName(Prop(node, "Left"));
                        var old = Variable(name);
                        var added = Pipeline(Prop(node, "Right"), depth + 1) ?? Missing("assignment-value");
                        var updated = UnknownValue("compound-assignment", old, added);
                        bool plus = Str(Prop(node, "Operator")) == "PlusEquals";
                        if (old.Complete && added.Complete && old.IsString && plus && added.Text != null && old.Text != null &&
                            (long)old.Text.Length + added.Text.Length <= MaxContent / sizeof(char))
                            updated = Text(old.Text + added.Text, "$" + name, updated.Tags);
                        else if (old.NumericType == "Int32" && added.NumericType == "Int32" &&
                            int.TryParse(old.Text, out int left) && int.TryParse(added.Text, out int right))
                        {
                            long number = plus ? (long)left + right : (long)left - right;
                            if (number >= int.MinValue && number <= int.MaxValue)
                                updated = new Payload { Text = number.ToString(CultureInfo.InvariantCulture), NumericType = "Int32",
                                    ScalarTruth = number != 0, Complete = true, Tags = updated.Tags };
                        }
                        values[Key(name)] = updated;
                        plan.Assignments[Key(name)] = updated;
                    }
                    else if (kind is "PipelineAst" or "PipelineChainAst" or "CommandExpressionAst")
                    {
                        var record = Pipeline(node, depth);
                        if (record != null && record.Issue != "no-expression-output") output?.Add(record);
                    }
                    else if (kind is "ForStatementAst" or "WhileStatementAst" or "DoWhileStatementAst" or "DoUntilStatementAst")
                        exit = AnalyzeLoop(node, depth, output);
                    else if (kind == "SwitchStatementAst") exit = AnalyzeSwitch(node, depth, output);
                    else if (kind == "IfStatementAst" && AnalyzeIf(node, depth, out exit, output)) { }
                    else if (kind == "TryStatementAst") exit = AnalyzeTry(node, depth, output);
                    else if (kind == "ForEachStatementAst") exit = AnalyzeForEach(node, depth, output);
                    else if (kind == "FunctionDefinitionAst")
                    {
                        var name = Str(Prop(node, "Name"));
                        if (name.Length > 0)
                        {
                            scriptDefinitions.Add(BaseName(name));
                            if (!name.Contains(':') && !Equals(Prop(node, "IsWorkflow"), true))
                                functions[name] = new object?[] { node };
                            SkipBranch(Prop(node, "Body"));
                        }
                    }
                    else if (kind is "BreakStatementAst" or "ContinueStatementAst")
                    {
                        if (Prop(node, "Label") != null)
                        { ReportMissing("labelled-loop-control"); InvalidateSessionFacts(); }
                        else exit = kind == "BreakStatementAst" ? StatementExit.Break : StatementExit.Continue;
                    }
                    else if (kind is "ReturnStatementAst" or "ThrowStatementAst" or "ExitStatementAst")
                    {
                        var returned = Pipeline(Prop(node, "Pipeline"), depth + 1);
                        if (kind == "ReturnStatementAst" && returned != null) output?.Add(returned);
                        exit = kind == "ThrowStatementAst" ? StatementExit.Throw :
                            kind == "ExitStatementAst" ? StatementExit.Exit : StatementExit.Return;
                    }
                    else if (kind == "AssignmentStatementAst" && UpdateHttpProperty(node, depth)) { }
                    else if (!UpdateTrackedMap(node)) InvalidateSessionFacts();
                    observeStatement?.Invoke();
                }
                return exit;
            }
            void AnalyzeScript(object ast, object[] end)
            {
                var dynamicParameters = Prop(ast, "DynamicParamBlock");
                var begin = Prop(ast, "BeginBlock");
                var process = Prop(ast, "ProcessBlock");
                var clean = Prop(ast, "CleanBlock");
                if (dynamicParameters == null && begin == null && process == null && clean == null)
                { AnalyzeStatements(end, 0); return; }

                var interrupted = clean == null ? null : new StatementState(this);
                var observeOuter = observeStatement;
                if (interrupted != null) observeStatement = () => interrupted.Join(new StatementState(this));
                bool RunBlock(IEnumerable<object> statements)
                {
                    var paths = new List<(StatementState State, StatementExit Exit)>();
                    var exit = AnalyzeBlock(statements, 0, paths);
                    if (paths.Count == 0) return exit is StatementExit.None or StatementExit.Return;
                    paths.Add((new StatementState(this), exit));
                    paths.RemoveAll(path => path.Exit is not (StatementExit.None or StatementExit.Return));
                    if (paths.Count == 0) return false;
                    var continuing = paths[0].State;
                    foreach (var path in paths.Skip(1)) continuing.Join(path.State);
                    RestoreStatementState(continuing);
                    return true;
                }

                bool reachesEnd;
                try
                {
                    reachesEnd = RunBlock(Items(Prop(dynamicParameters, "Statements")));
                    if (reachesEnd) reachesEnd = RunBlock(Items(Prop(begin, "Statements")));
                    else SkipBranch(begin);
                    if (reachesEnd && process != null)
                    {
                        var entry = new StatementState(this);
                        var statements = Items(Prop(process, "Statements")).ToArray();
                        values[Key("_")] = values[Key("PSItem")] = values[Key("input")] = Missing("process-input");
                        if (RunBlock(statements))
                        {
                            entry.Join(new StatementState(this));
                            if (RunBlock(statements)) entry.Join(new StatementState(this));
                        }
                        RestoreStatementState(entry);
                        if (statements.Length != 0) ReportMissing("process-iterations");
                    }
                    else if (!reachesEnd) SkipBranch(process);
                    if (reachesEnd) reachesEnd = RunBlock(end);
                    else SkipBranch(Prop(ast, "EndBlock"));
                }
                finally { observeStatement = observeOuter; }

                if (clean == null || interrupted == null) return;
                var cleanup = Items(Prop(clean, "Statements")).ToArray();
                StatementState? normal = null;
                if (reachesEnd)
                {
                    AnalyzeStatements(cleanup, 0);
                    normal = new StatementState(this);
                }
                RestoreStatementState(interrupted);
                AnalyzeStatements(cleanup, 0);
                if (normal != null) RestoreStatementState(normal);
                else { plan.Work.Clear(); plan.Assignments.Clear(); }
            }

            internal RulePlan Build(object ast, object[] root, IEnumerable<object> nodes, bool truncated, bool externalUsing = false)
            {
                try { AnalyzePlan(ast, root, nodes, truncated, externalUsing); }
                catch (Exception error) when (error is not (OutOfMemoryException or StackOverflowException or AccessViolationException))
                {
                    // Diagnostics/adapter failures must not erase a decision already reached.
                    // Predictions from an aborted analysis are not evidence of completed writes.
                    plan.Work.Clear();
                    plan.Assignments.Clear();
                    ReportMissing("analysis-interrupted");
                }
                return plan;
            }

            void AnalyzePlan(object ast, object[] root, IEnumerable<object> nodes, bool truncated, bool externalUsing)
            {
                if (externalUsing)
                {
                    InvalidateSessionFacts();
                    ReportMissing("external-using-effects");
                }
                foreach (var directive in Items(Prop(ast, "UsingStatements")))
                    if (Str(Prop(directive, "UsingStatementKind")) == "Namespace" && Literal(Prop(directive, "Name")) is string ns)
                        httpNamespaces.Add(ns);
                AnalyzeScript(ast, root);
                var nestedNetwork = nodes.Where(x => Kind(x) == "CommandAst" && !visitedNetwork.Contains(x) && !Skipped(x)).Any(x =>
                {
                    var raw = Name(x);
                    var name = Tool(raw);
                    return raw is "irm" or "iwr" || name == "start-process" || Network(name) && (name != "git" ||
                        Items(Prop(x, "CommandElements")).Skip(1).Any(n => Literal(n) == "push"));
                });
                if (!Budget() || root.Length > MaxStatements || truncated) ReportMissing("analysis-limit");
                else if (nestedNetwork || nodes.Any(x => Kind(x) == "InvokeMemberExpressionAst" && !Skipped(x) &&
                    !visitedHttpMethods.Contains(x) && Literal(Prop(x, "Member"))?.ToLowerInvariant() is
                        ("uploadstring" or "uploadfile" or "uploaddata" or "postasync" or "putasync" or "patchasync" or "sendasync" or "getrequeststream" or "getresponse" or "getresponseasync")))
                    ReportMissing("unsupported-control-flow");
            }
        }
    }
}

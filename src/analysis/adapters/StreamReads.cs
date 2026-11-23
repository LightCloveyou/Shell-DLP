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
        sealed class DeferredStreamRead
        {
            internal readonly List<(HttpObject Waiting, HttpObject Done)> States = new List<(HttpObject, HttpObject)>();
            internal readonly List<(string Path, Payload Waiting, Payload Done)> Files = new List<(string, Payload, Payload)>();
            internal Payload? Buffer;
        }
        sealed partial class AdapterContext
        {
            long retainedStreamBytes;
            static bool IsReadHandle(HttpObject state) => state.Kind is HttpObjectKind.FileStream or HttpObjectKind.TextReader or HttpObjectKind.BinaryReader;
            static Payload? Slot(HttpObject s, string k) => s.Fields.TryGetValue(k, out var v) ? v : null;
            static HttpObject ReaderSet(HttpObject s, params (string Key, Payload Value)[] updates)
            {
                var fields = new Dictionary<string, Payload>(s.Fields, s.Fields.Comparer);
                foreach (var (key, value) in updates) fields[key] = value;
                return s.WithFields(fields);
            }
            void MoveReader(HttpObject s, Payload position) => SaveHttp(ReaderSet(CurrentHttp(s)!, ("pos", position), ("epoch", new Payload())));
            // A merged close marker is not proof that every reachable handle is closed.
            static bool ReaderOpen(HttpObject s) => Slot(s, "closed")?.Text != "1";
            static bool Position(HttpObject s, out int n) => CountValue(Slot(s, "pos") ?? Missing("stream-position"), out n);

            string? EnumArgument(object arg, string enumType, int depth)
            {
                if (Kind(arg) == "MemberExpressionAst" && Equals(Prop(arg, "Static"), true) &&
                    HttpType(TypeName(Prop(arg, "Expression"))) == "io." + enumType)
                    return Literal(Prop(arg, "Member"))?.ToLowerInvariant();
                return Value(arg, depth + 1).Text?.ToLowerInvariant();
            }
            Payload OpenReader(Payload path, string member, object[] options, int depth)
            {
                string mode = member == "create" ? "create" : member == "openwrite" ? "openorcreate" : "open";
                string access = member is "create" or "open" ? "readwrite" : member == "openwrite" ? "write" : "read";
                if (member == "open")
                {
                    if (options.Length is < 1 or > 3) return Missing("file-open-overload");
                    mode = EnumArgument(options[0], "filemode", depth) switch {
                        "2" or "create" => "create", "3" or "open" => "open", "4" or "openorcreate" => "openorcreate", _ => "" };
                    if (options.Length >= 2) access = EnumArgument(options[1], "fileaccess", depth) switch {
                        "read" or "1" => "read", "write" or "2" => "write", "readwrite" or "3" => "readwrite", _ => "" };
                    if (mode == "" || access == "" || mode == "create" && access == "read" ||
                        options.Length == 3 && EnumArgument(options[2], "fileshare", depth) is not
                            ("none" or "read" or "readwrite" or "write" or "delete" or "0" or "1" or "2" or "3" or "4"))
                        return Missing("file-open-mode-or-access");
                }
                else if (options.Length != 0 && !(member == "create" && options.Length == 1 &&
                    CountValue(Value(options[0], depth + 1), out int buffer) && buffer > 0)) return Missing("file-open-overload");
                var raw = ExactString(path);
                var full = Disk.Bind(raw, cwd);
                if (full == null && Disk.ExternalRulePath(raw) == null) return Missing("file-open-path");
                var s = ReaderSet(new HttpObject(HttpObjectKind.FileStream, address: Text(full ?? raw, "stream path")),
                    ("pos", Number(0)), ("epoch", new Payload()), ("access", Text(access,"stream access")));
                if (mode is "create" or "openorcreate" && full != null && !barrier && Budget() &&
                    !PendingFiles.ContainsKey(full) && Disk.ClearAncestors(Path.GetDirectoryName(full)!) &&
                    (mode == "create" || (plannedFiles.Contains(full) ? predictedWrites.TryGetValue(full, out var prior) && prior.Issue == "file-moved" :
                     !UncertainFileTree(Path.GetDirectoryName(full)) && Disk.TargetStamp(full) == "")))
                {
                    var empty = Bytes(Array.Empty<byte>(), "empty file stream");
                    PlanWrite(full, empty, empty.Bytes, false);
                }
                // Capture only identity at Open. The existing guarded file reader does all subsequent content inspection.
                if (full != null && !barrier && FileTimeAvailable && !PendingFiles.ContainsKey(full) && Budget())
                {
                    if (plannedFiles.Contains(full) && predictedWrites.TryGetValue(full, out var write))
                        s = ReaderSet(s, ("prediction", write));
                    else if (!plannedFiles.Contains(full) && !UncertainFileTree(Path.GetDirectoryName(full)) &&
                        Disk.ResolveLocalPath(full, () => FileTimeAvailable) is string local && Disk.TrySample(local, false) is Disk.Sample meta)
                        s = ReaderSet(s, ("stamp", new Payload { Text = meta.Stamp, Complete = true }));
                }
                return member == "opentext" ? WrapReader(s, true, Encoding.UTF8, true, false) : HttpObjectValue(s);
            }
            Payload WrapReader(HttpObject s, bool text, Encoding encoding, bool bom, bool leaveOpen)
            {
                s = CurrentHttp(s)!;
                if (s.Kind != HttpObjectKind.FileStream || !ReaderOpen(s)) return Missing("reader-base-stream");
                return HttpObjectValue(ReaderSet(new HttpObject(text ? HttpObjectKind.TextReader : HttpObjectKind.BinaryReader,
                    owner: s, method: encoding.WebName), ("pos", Number(0)), ("epoch", Slot(s, "epoch")!),
                    ("bom", Number(bom ? 1 : 0)), ("leaveOpen", Number(leaveOpen ? 1 : 0))));
            }
            Payload ConstructReader(string type, object[] args, int depth)
            {
                if (args.Length == 0) return Missing("reader-constructor");
                var first = Value(args[0], depth + 1);
                if (type is "byte[]" or "char[]")
                {
                    if (args.Length != 1 || !CountValue(first, out var length) || length > MaxContent / (type == "char[]" ? 2 : 1) || !Budget())
                        return Missing("read-buffer-size");
                    return type == "byte[]" ? Bytes(new byte[length], "byte buffer") :
                        Symbol(new ModelValue(ModelKind.Characters, Array.Empty<Mark>()) { Exact = new string('\0', length) }, "character buffer");
                }
                if (type == "io.fileinfo")
                {
                    var full = Disk.Bind(ExactString(first), cwd);
                    return args.Length == 1 && full != null ? new Payload { FileObject = new FileReference(full), SourceRef = full, Complete = true } :
                        Missing("fileinfo-path");
                }
                if (type == "io.filestream")
                {
                    if(args.Length>=5)
                    {
                        if(args.Length>6 || !CountValue(Value(args[4],depth+1),out int block) || block==0) return Missing("file-stream-buffer-size");
                        if(args.Length==6 && !(Kind(args[5])=="MemberExpressionAst" && Equals(Prop(args[5],"Static"),true) &&
                            HttpType(TypeName(Prop(args[5],"Expression")))=="io.fileoptions" &&
                            Literal(Prop(args[5],"Member"))?.ToLowerInvariant() is ("none" or "asynchronous" or "sequentialscan" or "randomaccess")))
                        {
                            var flag=Value(args[5],depth+1);
                            if (!flag.Complete || flag.IsString || flag.NumericType!=null || !flag.ScalarTruth.HasValue) return Missing("file-stream-options");
                        }
                    }
                    return OpenReader(first,"open",args.Skip(1).Take(3).ToArray(),depth);
                }
                bool text = type == "io.streamreader", detect = true, leaveOpen = false;
                var stream = CurrentHttp(first.HttpObject);
                int max = text ? (stream == null ? 4 : 5) : 3;
                if (args.Length > max) return Missing("reader-constructor-overload");
                Encoding? encoding = Encoding.UTF8;
                if (args.Length >= 2)
                {
                    encoding = ReaderEncoding(args[1]);
                    if (encoding == null)
                    {
                        var flag = Value(args[1], depth + 1).ScalarTruth;
                        if (!text || args.Length != 2 || flag == null) return Missing("reader-encoding");
                        encoding = Encoding.UTF8; detect = flag.Value;
                    }
                }
                if (args.Length >= 3)
                {
                    var flag = Value(args[2], depth + 1).ScalarTruth;
                    if (flag == null) return Missing("reader-constructor-flag");
                    if (text) detect = flag.Value; else leaveOpen = flag.Value;
                }
                if (args.Length >= 4 && (!CountValue(Value(args[3], depth + 1), out var size) || size == 0)) return Missing("reader-buffer-size");
                if (args.Length == 5)
                {
                    var flag = Value(args[4], depth + 1).ScalarTruth;
                    if (flag == null) return Missing("reader-leave-open");
                    leaveOpen = flag.Value;
                }
                if (stream == null && text) stream = OpenReader(first, "openread", Array.Empty<object>(), depth).HttpObject;
                return stream == null ? Missing("reader-stream") : WrapReader(stream, text, encoding, detect, leaveOpen);
            }

            Payload StreamSource(HttpObject s) => StreamSource(s, false, out _);
            Payload StreamSource(HttpObject s, bool symbolicCompressionCopy, out long? length)
            {
                length = null;
                if (!ReaderOpen(s)) return Missing("stream-closed");
                if (IsCodec(s)) return CodecSource(s);
                if (s.Address == null && s.Body != null)
                    return s.Owner?.Owner is HttpObject archive && !ReaderOpen(CurrentHttp(archive)!) ? Missing("archive-closed") : s.Body;
                var path = s.Address?.Text;
                Payload PartialSource(string reason) => path != null && policy != null ? FilePathEvidence(path, reason) : Missing(reason);
                if (path == null || barrier || !FileTimeAvailable || !Budget() || PendingFiles.ContainsKey(path))
                    return PartialSource("stream-file-unavailable");
                var predicted = Slot(s, "prediction");
                var stamp = Slot(s, "stamp")?.Text;
                if (predicted != null ? !plannedFiles.Contains(path) || !predictedWrites.TryGetValue(path, out var current) || !ReferenceEquals(current, predicted) :
                    stamp == null || plannedFiles.Contains(path)) return PartialSource("stream-file-identity");
                if (s.Body?.Bytes != null && !UncertainFileTree(Path.GetDirectoryName(path)))
                {
                    if (predicted != null || Disk.ResolveLocalPath(path, () => FileTimeAvailable) is string local && Disk.TargetStamp(local) == stamp)
                        return s.Body;
                    return PartialSource("stream-file-changed");
                }
                if (predicted != null && s.Body != null) return s.Body;
                var content = File(path, false, out var sample, forceBytes: true, inspectArchive: false,
                    symbolicCompressionCopy: symbolicCompressionCopy && predicted == null);
                if (predicted == null && stamp != null && sample?.Stamp != stamp)
                    return PartialSource("stream-file-changed");
                if (content.InspectionPartial) return UnknownValue("stream-file-partial", content, PartialSource("stream-file-partial"));
                if (symbolicCompressionCopy && sample?.ContentSkippedForPath == true)
                {
                    length = sample.Size;
                    return SymbolicBytes("stream-bytes-from-protected-path", content);
                }
                var bytes = sample?.Bytes ?? content.Bytes;
                if (bytes == null) return UnknownValue("stream-content-not-materialized", content);
                var result = Bytes(bytes, content.SourceRef, content.Tags);
                result.InspectionPartial = content.InspectionPartial;
                if (retainedStreamBytes + bytes.Length <= MaxContent)
                {
                    retainedStreamBytes += bytes.Length;
                    SaveHttp(CurrentHttp(s)!.WithBody(result));
                }
                return result;
            }
            Payload StreamPiece(Payload src, int start, int count)
            {
                if (count == 0) return Bytes(Array.Empty<byte>(), "empty stream segment");
                if (src.Bytes == null) return UnknownValue("stream-segment", src);
                if (start == 0 && count == src.Bytes.Length) return src;
                var bytes = new byte[count];
                Buffer.BlockCopy(src.Bytes, start, bytes, 0, count);
                return Bytes(bytes, src.SourceRef, FileRecordMarks(src));
            }
            Payload RemainingStream(HttpObject state, bool consume, bool symbolicCompressionCopy = false)
            {
                if (!CanReadStream(state)) return Missing("stream-not-readable");
                if (Slot(state,"atEnd") is Payload end && ReferenceEquals(end,Slot(state,"epoch")))
                    return Bytes(Array.Empty<byte>(), "stream EOF");
                long cursor = 0;
                bool copyWithPosition = symbolicCompressionCopy && Slot(state,"pos") is { Complete: true } p &&
                    long.TryParse(p.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out cursor) && cursor >= 0;
                var src = StreamSource(state, copyWithPosition, out var length);
                if (length is long size)
                {
                    if (consume) MoveReader(state, Number(Math.Max(cursor, size)));
                    return cursor >= size ? Bytes(Array.Empty<byte>(), "stream EOF") : src;
                }
                if (src.Bytes == null || !Position(state, out var pos))
                {
                    if (consume && (src.Bytes != null || src.Model?.Kind == ModelKind.PackedBytes) && Slot(state,"readPending")==null)
                    {
                        var epoch = new Payload();
                        SaveHttp(ReaderSet(CurrentHttp(state)!, ("pos", Missing("stream-position")), ("epoch", epoch), ("atEnd", epoch)));
                    }
                    else if (consume) MoveReader(state,Missing("stream-position"));
                    return UnknownValue("stream-remaining", src);
                }
                var start = Math.Min(pos, src.Bytes.Length);
                if (consume) MoveReader(state, Number(Math.Max(pos, src.Bytes.Length)));
                return StreamPiece(src, start, src.Bytes.Length - start);
            }
            Payload ReaderProperty(HttpObject s, string property)
            {
                if (IsCodec(s) && property == "basestream" && ReaderOpen(s)) return HttpObjectValue(CurrentHttp(s.Owner)!);
                if (IsCodec(s) && property is ("length" or "position")) return Missing("compression-stream-not-seekable");
                if (!ReaderOpen(s)) return Missing("stream-closed");
                if (property=="safefilehandle" && s.Kind==HttpObjectKind.FileStream && s.Address!=null)
                    return SafeHandleValue(s);
                if (property == "basestream" && s.Kind != HttpObjectKind.FileStream && s.Owner != null) return HttpObjectValue(CurrentHttp(s.Owner)!);
                if (s.Kind == HttpObjectKind.FileStream && property == "position") return Slot(s, "pos") ?? Missing("stream-position");
                if (s.Kind == HttpObjectKind.FileStream && property == "name") return s.Address ?? Missing("stream-name");
                if (s.Kind == HttpObjectKind.FileStream && property == "length")
                {
                    if (s.Address == null) return s.Body?.Bytes is byte[] bytes ? Number(bytes.Length) : Missing("stream-length");
                    var path = s.Address.Text;
                    if (path != null && !barrier && !PendingFiles.ContainsKey(path) && FileTimeAvailable && Budget())
                    {
                        if (plannedFiles.Contains(path) && predictedWrites.TryGetValue(path, out var write) && ReferenceEquals(write, Slot(s, "prediction")) && write.Bytes != null)
                            return Number(write.Bytes.Length);
                        if (!plannedFiles.Contains(path) && Slot(s, "stamp")?.Text is string stamp &&
                            Disk.ResolveLocalPath(path, () => FileTimeAvailable) is string local && Disk.TrySample(local, false) is Disk.Sample meta && stamp == meta.Stamp)
                            return Number(meta.Size);
                    }
                    return Missing("stream-length");
                }
                return Missing("reader-property");
            }
            Payload WriteMemory(HttpObject memory, Payload src, bool async)
            {
                if (!ReaderOpen(memory)) return Missing("stream-closed");
                var previous = memory.Body;
                if (src.Bytes?.Length == 0) return async ? Missing("stream-write-task") : Missing("no-expression-output");
                Payload next, position;
                if (src.Bytes is byte[] data && previous?.Bytes is byte[] old && Position(memory, out int pos) &&
                    (long)pos + data.Length <= MaxContent && ReserveStreamBytes(Math.Max(pos + data.Length, old.Length)))
                {
                    var dst = new byte[Math.Max(pos + data.Length, old.Length)];
                    Buffer.BlockCopy(old, 0, dst, 0, old.Length);
                    Buffer.BlockCopy(data, 0, dst, pos, data.Length);
                    var origins = pos == 0 && data.Length >= old.Length ? Array.Empty<Mark>() : FileRecordMarks(previous);
                    next = Bytes(dst, "memory stream", Merge(origins.Concat(src.Tags)));
                    position = Number(pos + data.Length);
                }
                else { next = SymbolicBytes("stream-write-bytes-not-materialized", previous, src); position = Missing("stream-position"); }
                var epoch = new Payload();
                var changed = ReaderSet(memory.WithBody(next), ("pos", position), ("epoch", epoch), ("modified", Number(1)));
                if (Slot(memory,"atEnd") is Payload eof && ReferenceEquals(eof,Slot(memory,"epoch")) ||
                    previous?.Bytes is byte[] original && Position(memory,out int priorPos) && priorPos >= original.Length)
                    changed = ReaderSet(changed,("atEnd",epoch));
                SaveHttp(changed);
                return async ? Missing("stream-write-task") : Missing("no-expression-output");
            }

            void ReplaceReaderBuffer(string? variable, Payload old, Payload next, bool updateViews=true)
            {
                bool Alias(Payload v) => ReferenceEquals(v, old) || old.Bytes != null && ReferenceEquals(v.Bytes, old.Bytes) ||
                    old.Model != null && ReferenceEquals(v.Model, old.Model);
                foreach (var table in new[] { values, plan.Assignments })
                    foreach (var k in table.Keys.Where(k => Alias(table[k])).ToArray()) table[k] = next;
                // MemoryStream(byte[], ...) is a view, not an independent copy. Other
                // views of the same array see just their own logical range.
                if (updateViews) foreach (var view in httpStates.Values.Where(v => v.Method=="memory" && Slot(v,"backing") is Payload backing && Alias(backing)).ToArray())
                {
                    Payload body;
                    if (view.Body?.Bytes is byte[] previous && next.Bytes is byte[] all && Slot(view,"start") is Payload index &&
                        CountValue(index,out int start) && start <= all.Length-previous.Length &&
                        (start==0 && all.Length==previous.Length || ReserveStreamBytes(previous.Length)))
                        body=StreamPiece(next,start,previous.Length);
                    else body=SymbolicBytes("memory-backing-alias",next);
                    SaveHttp(ReaderSet(view.WithBody(body),("backing",next),("epoch",new Payload())));
                }
                if (variable != null)
                {
                    values[Key(variable)] = next;
                    plan.Assignments[Key(variable)] = next;
                }
            }
            Payload FinishRead(Payload task)
            {
                if (task.DeferredRead is DeferredStreamRead effect)
                {
                    // Commit the transition as a unit. A conflict on the source must not
                    // publish the destination as exact (and vice versa).
                    bool raced = effect.States.Any(p => !ReferenceEquals(CurrentHttp(p.Waiting),p.Waiting) &&
                        !ReferenceEquals(CurrentHttp(p.Waiting),p.Done));
                    raced |= effect.Files.Any(p => !predictedWrites.TryGetValue(p.Path,out var current) ||
                        !ReferenceEquals(current,p.Waiting) && !ReferenceEquals(current,p.Done));
                    if (raced) return UnknownValue("async-read-order", task.FileTaskResult);
                    foreach (var (waiting, done) in effect.States)
                    {
                        var current = CurrentHttp(waiting);
                        if (ReferenceEquals(current, waiting)) SaveHttp(done);
                    }
                    foreach (var file in effect.Files) predictedWrites[file.Path]=file.Done;
                    if (effect.Buffer != null)
                        foreach (var table in new[] { values, plan.Assignments })
                            foreach (var k in table.Keys.Where(k => table[k].FileTaskResult == null &&
                                ReferenceEquals(table[k].DeferredRead, effect)).ToArray()) table[k] = effect.Buffer;
                }
                return task.FileTaskResult ?? Missing("file-read-result");
            }
            Payload ReadMember(HttpObject state, string name, object[] args, int depth)
            {
                var owner = CurrentHttp(state.Kind == HttpObjectKind.FileStream ? state : state.Owner)!;
                if (owner == null || !ReaderOpen(state) || !ReaderOpen(owner) ||
                    owner.Owner?.Owner is HttpObject archive && !ReaderOpen(CurrentHttp(archive)!)) return Missing("stream-closed-or-conditional");
                if (name is ("close" or "dispose") && args.Length == 0)
                {
                    SaveHttp(ReaderSet(state, ("closed", Number(1))));
                    if (state.Kind != HttpObjectKind.FileStream && Slot(state, "leaveOpen")?.Text != "1")
                        SaveHttp(ReaderSet(owner, ("closed", Number(1))));
                    return Missing("no-expression-output");
                }
                bool async = name.EndsWith("async", StringComparison.Ordinal);
                string op = async ? name.Substring(0, name.Length - 5) : name;
                bool text = state.Kind == HttpObjectKind.TextReader, binary = state.Kind == HttpObjectKind.BinaryReader;
                var effect = async ? new DeferredStreamRead() : null;
                Payload Out(Payload result)
                {
                    if (effect == null) return result;
                    foreach (var handle in new[] { owner, state }.Select(h => h.Identity).Distinct())
                    {
                        var done = CurrentHttp(handle)!;
                        var waiting = ReaderSet(done, ("pos", Missing("async-position-pending")), ("epoch", new Payload()), ("readPending", Number(1)));
                        effect.States.Add((waiting, done)); SaveHttp(waiting);
                    }
                    return new Payload { Issue = op is "readexactly" or "readatleast" ? "file-read-valuetask" : "file-read-task",
                        FileTaskResult = result, DeferredRead = effect, SourceRef = name };
                }
                bool exactly=op=="readexactly", atLeast=op=="readatleast";
                if ((exactly || atLeast) && (text || binary)) return Missing("read-method-on-non-stream");
                bool bufferCall = op=="read" && args.Length==3 || exactly && args.Length is (1 or 3) || atLeast && args.Length is (2 or 3);
                string var = bufferCall ? VarName(args[0]) : "";
                Payload? buffer = bufferCall ? Value(args[0], depth + 1) : null;
                void SetBuffer(Payload next)
                {
                    if (effect == null) { ReplaceReaderBuffer(var, buffer!, next); return; }
                    effect.Buffer = next;
                    var pending = UnknownValue("async-buffer-pending", buffer, next);
                    pending.DeferredRead = effect;
                    ReplaceReaderBuffer(var, buffer!, pending);
                }
                void UncertainPosition()
                {
                    MoveReader(owner, Missing("stream-position"));
                    if (text) MoveReader(state, Missing("reader-position"));
                }
                Payload Uncertain(string reason, Payload? evidence = null)
                {
                    UncertainPosition();
                    if (buffer != null && SafeName(var))
                        SetBuffer(UnknownValue(reason, buffer, evidence));
                    // The numeric count is not the payload written to the buffer.
                    return Out(bufferCall ? Missing("stream-read-count") : UnknownValue(reason, evidence));
                }
                if (Slot(owner, "readPending") != null || Slot(state, "readPending") != null)
                    return Uncertain("overlapping-stream-reads", StreamSource(owner));
                if (op == "seek")
                {
                    if (state.Kind != HttpObjectKind.FileStream || args.Length != 2) return Uncertain("stream-seek");
                    var offsetValue = Value(args[0], depth + 1);
                    if (!offsetValue.Complete || !long.TryParse(offsetValue.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out long delta))
                        return Uncertain("stream-seek-offset");
                    int? basis = EnumArgument(args[1], "seekorigin", depth) switch {
                        "begin" or "0" => 0, "current" or "1" => Position(state, out int here) ? here : null,
                        "end" or "2" => CountValue(ReaderProperty(state, "length"), out int length) ? length : null, _ => null };
                    if (basis == null || delta < -basis.Value || delta > int.MaxValue - basis.Value) return Uncertain("stream-seek-position");
                    var posValue = Number(basis.Value + delta);
                    MoveReader(state, posValue);
                    return posValue;
                }
                if (!CanReadStream(owner)) return Missing("stream-not-readable");
                int count = 0, offset = 0, minimum=0; bool throwOnEnd=true;
                if (bufferCall)
                {
                    int? length = text ? buffer?.Model?.Exact?.Length : buffer?.Bytes?.Length;
                    if (!SafeName(var) || length == null) return Uncertain("stream-buffer-range", StreamSource(owner));
                    if(atLeast || exactly && args.Length==1) count=length.Value;
                    else if (!CountValue(Value(args[1], depth + 1), out offset) ||
                        !CountValue(Value(args[2], depth + 1), out count) || offset > length.Value - count)
                        return Uncertain("stream-buffer-range", StreamSource(owner));
                    minimum=exactly?count:0;
                    if(atLeast)
                    {
                        if(!CountValue(Value(args[1],depth+1),out minimum) || minimum>count) return Out(Missing("read-at-least-minimum"));
                        if(args.Length==3)
                        {
                            var flag=Value(args[2],depth+1);
                            if(!flag.Complete || flag.ScalarTruth is not bool t || flag.IsString || flag.NumericType!=null)
                                return Uncertain("read-at-least-eof-argument",StreamSource(owner));
                            throwOnEnd=t;
                        }
                    }
                    if (count == 0 || atLeast && minimum==0) return Out(exactly?Missing("no-expression-output"):Number(0));
                }
                else if (op == "readbytes" && binary && args.Length == 1)
                {
                    if (!CountValue(Value(args[0], depth + 1), out count)) return Uncertain("reader-count", StreamSource(owner));
                    if (count == 0) return Out(Bytes(Array.Empty<byte>(), "empty read"));
                }
                else if (args.Length != 0 || !(text && op is ("read" or "peek" or "readline" or "readtoend") || !text && op == "readbyte"))
                    return Uncertain("reader-method-overload", StreamSource(owner));
                if (async && !(text && op is ("read" or "readline" or "readtoend") || !text && !binary && bufferCall))
                    return Uncertain("reader-async-overload", StreamSource(owner));
                if (!text)
                {
                    var src = StreamSource(owner);
                    if (src.Bytes == null || src.InspectionPartial || !Position(owner, out var pos)) return Uncertain("stream-position-or-bytes", src);
                    int start = Math.Min(pos, src.Bytes.Length);
                    int n = Math.Min(op == "readbyte" ? 1 : count, src.Bytes.Length - start);
                    if(atLeast && n>minimum && owner.Method!="memory")
                    {
                        // A file stream can short-read. The prefix is guaranteed; the rest and next cursor aren't.
                        var guaranteed=StreamPiece(src,start,minimum);
                        SetBuffer(UnknownValue("read-at-least-variable-length",guaranteed));
                        MoveReader(owner,Missing("stream-position-after-short-read"));
                        return Out(Missing("read-at-least-count-range"));
                    }
                    if (n > 0) MoveReader(owner, Number(pos + n));
                    var piece = StreamPiece(src, start, n);
                    if (op == "readbyte")
                    {
                        if (n == 0) return binary ? Missing("binary-reader-end-of-stream") : Number(-1);
                        var scalar = Number(piece.Bytes![0]); scalar.Tags = piece.Tags; return scalar;
                    }
                    if (!bufferCall) return Out(piece);
                    if (n > 0)
                    {
                        var bytes = (byte[])buffer!.Bytes!.Clone();
                        Buffer.BlockCopy(piece.Bytes!, 0, bytes, offset, n);
                        var prior = offset == 0 && n == bytes.Length ? Array.Empty<Mark>() : FileRecordMarks(buffer);
                        SetBuffer(Bytes(bytes, src.SourceRef, Merge(prior.Concat(piece.Tags))));
                    }
                    if(n<minimum && throwOnEnd)return Out(Missing("stream-end-before-minimum"));
                    return Out(exactly?Missing("no-expression-output"):Number(n));
                }
                var epoch = Slot(owner, "epoch");
                if (epoch == null || !ReferenceEquals(epoch, Slot(state, "epoch")) || !Position(state, out var cursor))
                    return Uncertain("text-reader-base-position", StreamSource(owner));
                var decoded = state.Body;
                if (decoded == null)
                {
                    var src = RemainingStream(owner, false);
                    if (src.Bytes == null) return Uncertain("text-reader-input", src);
                    try
                    {
                        using var stream = new MemoryStream(src.Bytes, false);
                        var enc = Encoding.GetEncoding(state.Method!, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
                        using var reader = new StreamReader(stream, enc, detectEncodingFromByteOrderMarks: Slot(state, "bom")?.Text == "1");
                        decoded = Text(reader.ReadToEnd(), src.SourceRef, FileRecordMarks(src));
                    }
                    catch (ArgumentException) { return Uncertain("text-reader-encoding", src); }
                }
                if (decoded.Text is not string chars || cursor > chars.Length) return Uncertain("text-reader-input", decoded);
                int end = cursor, after;
                if (op == "readline")
                {
                    while (end < chars.Length && chars[end] != '\r' && chars[end] != '\n') end++;
                    after = end;
                    if (after < chars.Length && chars[after++] == '\r' && after < chars.Length && chars[after] == '\n') after++;
                }
                else
                {
                    end = op == "readtoend" ? chars.Length : cursor + Math.Min(bufferCall ? count : 1, chars.Length - cursor);
                    after = op == "peek" ? cursor : end;
                }
                // StreamReader buffers ahead. Its character cursor is exact; BaseStream.Position generally isn't.
                MoveReader(owner, Missing("buffered-byte-position"));
                SaveHttp(ReaderSet(state.WithBody(decoded), ("pos", Number(after)), ("epoch", Slot(CurrentHttp(owner)!, "epoch")!)));
                int take = end - cursor;
                if (take == 0 && !bufferCall && op == "readline") return Out(Missing("no-expression-output"));
                var selected = Text(chars.Substring(cursor, take), decoded.SourceRef, take == 0 ? Array.Empty<Mark>() : FileRecordMarks(decoded));
                if (bufferCall)
                {
                    if (take > 0)
                    {
                        var dst = buffer!.Model!.Exact!.ToCharArray();
                        chars.CopyTo(cursor, dst, offset, take);
                        var rebuilt = Text(new string(dst), decoded.SourceRef,
                            Merge((take == dst.Length ? Array.Empty<Mark>() : FileRecordMarks(buffer)).Concat(selected.Tags)));
                        SetBuffer(Symbol(new ModelValue(ModelKind.Characters, rebuilt.Tags) { Exact = rebuilt.Text }, "reader buffer"));
                    }
                    return Out(Number(take));
                }
                if (op is "peek" or "read")
                {
                    var numeric = Number(take == 0 ? -1 : chars[cursor]); numeric.Tags = selected.Tags; return numeric;
                }
                return Out(selected);
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            // Streams, wrappers and their aliases use the same immutable identity map as
            // requests. A handle is never itself a payload; only reads and writes carry data.
            bool ReserveStreamBytes(long count)
            {
                if (!Budget() || count < 0 || count > MaxContent - retainedStreamBytes) return false;
                retainedStreamBytes += count;
                return true;
            }
            static bool IsCodec(HttpObject s) => s.Method is "compress" or "decompress";
            static bool StreamReferenceType(string type) => type is "io.stream" or "idisposable" or "iasyncdisposable" or "marshalbyrefobject";
            static bool IsStreamValue(Payload value) => value.HttpObject?.Kind is HttpObjectKind.FileStream or HttpObjectKind.RequestStream;
            static bool CanReadStream(HttpObject s) => ReaderOpen(s) && s.Method != "compress" &&
                Slot(s, "access")?.Text != "write";
            static bool CanWriteStream(HttpObject s) => ReaderOpen(s) && (s.Kind == HttpObjectKind.RequestStream ||
                s.Kind == HttpObjectKind.FileStream && (s.Method == "compress" || s.Method == "memory" && Slot(s,"access")?.Text != "read" ||
                    Slot(s,"access")?.Text is "write" or "readwrite"));

            Payload NewMemoryStream(object[] args, int depth)
            {
                var empty = Bytes(Array.Empty<byte>(), "empty memory stream");
                var first = args.Length == 0 ? empty : Value(args[0], depth+1);
                bool seeded = args.Length != 0 && (first.Bytes != null || first.Model?.Kind == ModelKind.PackedBytes);
                bool writable = true, exposable = !seeded;
                int start=0; int? capacity=first.Bytes?.Length;
                if (!seeded && args.Length != 0 && (args.Length != 1 || !CountValue(first, out _))) return Missing("memory-stream-constructor");
                if (seeded && args.Length >= 3)
                {
                    if(args.Length>5 || !CountValue(Value(args[1],depth+1),out start) || !CountValue(Value(args[2],depth+1),out int n) ||
                        start>int.MaxValue-n || capacity.HasValue && start>capacity.Value-n) return Missing("memory-stream-segment-constructor");
                    capacity=n;
                    if(args.Length==5)
                    {
                        var flag=Value(args[4],depth+1);
                        if (flag is not {Complete:true,IsString:false,ScalarTruth:not null})return Missing("memory-stream-visibility");
                        exposable=flag.ScalarTruth.Value;
                    }
                }
                if (seeded && args.Length is 2 or 4 or 5)
                {
                    var flag = Value(args[args.Length==2?1:3], depth+1);
                    if (!flag.Complete || flag.IsString || !flag.ScalarTruth.HasValue) return Missing("memory-stream-access");
                    writable = flag.ScalarTruth.Value;
                }
                var body = !seeded ? empty : args.Length<3 ? first : StreamPiece(first,start,capacity!.Value);
                var stream = ReaderSet(new HttpObject(HttpObjectKind.FileStream, body: body, method: "memory"),
                    ("pos", Number(0)), ("epoch", new Payload()), ("exposable",Number(exposable?1:0)), ("access", Text(writable ? "readwrite" : "read", "memory access")));
                if (seeded)
                {
                    stream = ReaderSet(stream, ("backing", first),("start",Number(start)),
                        ("capacity",capacity.HasValue?Number(capacity.Value):Missing("memory-backing-length")));
                    SaveHttp(stream);
                }
                return HttpObjectValue(stream);
            }

            string? CodecMode(object arg, int depth)
            {
                string? type = null, name;
                if (Kind(arg) == "MemberExpressionAst" && Equals(Prop(arg,"Static"),true))
                { type = HttpType(TypeName(Prop(arg,"Expression"))); name = Literal(Prop(arg,"Member"))?.ToLowerInvariant(); }
                else
                { var v = Value(arg, depth+1); type = v.ReadType; name = v.Text?.ToLowerInvariant(); }
                if (type != null && type is not ("io.compression.compressionmode" or "io.compression.compressionlevel")) return null;
                if (type != "io.compression.compressionlevel" && name is ("compress" or "decompress")) return name;
                return type != "io.compression.compressionmode" && name is ("optimal" or "fastest" or "nocompression" or "smallestsize") ? "compress" : null;
            }

            Payload NewCodecStream(string codec, object[] args, int depth)
            {
                if (args.Length is not (2 or 3)) return Missing("compression-constructor");
                var owner = CurrentHttp(Value(args[0],depth+1).HttpObject);
                var mode = CodecMode(args[1],depth);
                var leave = args.Length == 2 ? Number(0) : Value(args[2],depth+1);
                if (owner == null || mode == null || !leave.Complete || leave.IsString || !leave.ScalarTruth.HasValue ||
                    (mode == "compress" ? !CanWriteStream(owner) : owner.Kind != HttpObjectKind.FileStream || !CanReadStream(owner)))
                    return Missing("compression-mode-or-stream");
                return HttpObjectValue(ReaderSet(new HttpObject(HttpObjectKind.FileStream, method: mode, owner: owner),
                    ("codec",Text(codec,"stream codec")), ("leaveOpen",Number(leave.ScalarTruth.Value ? 1 : 0)),
                    ("pos",Number(0)), ("epoch",new Payload())));
            }

            Payload SymbolicBytes(string issue, params Payload?[] inputs)
            {
                var p = Symbol(new ModelValue(ModelKind.PackedBytes, Merge(KnownMarks(inputs))), issue);
                p.Issue = issue; p.InspectionPartial = true;
                return p;
            }
            Payload StreamArray(HttpObject s)
            {
                // MemoryStream.ToArray returns its logical contents, independently of
                // Position, and remains valid after Close/Dispose.
                if (s.Body?.Bytes is byte[] bytes && !s.Body.InspectionPartial && ReserveStreamBytes(bytes.Length))
                    return Bytes((byte[])bytes.Clone(), "MemoryStream.ToArray", s.Body.Tags);
                return SymbolicBytes("memory-array-not-materialized", s.Body);
            }

            Payload CodecSource(HttpObject wrapper)
            {
                var owner = CurrentHttp(wrapper.Owner);
                if (wrapper.Method != "decompress" || owner == null || !CanReadStream(owner)) return Missing("compression-stream-not-readable");
                if (wrapper.Body != null)
                    return ReferenceEquals(Slot(owner,"epoch"),Slot(wrapper,"baseEpoch")) ? wrapper.Body :
                        UnknownValue("compression-base-position-changed",wrapper.Body);
                if (!StackAvailable || !Budget())
                {
                    var origin = owner.Address?.Text is string path && policy!=null ? FilePathEvidence(path,"decompression-budget") : null;
                    return SymbolicBytes("decompression-budget",owner.Body,origin);
                }
                var source = RemainingStream(owner, consume:false);
                Payload result;
                if (source.Bytes is not byte[] input || source.InspectionPartial)
                    result = SymbolicBytes("decompression-input-not-materialized",source);
                else try
                {
                    int limit = Math.Min(MaxContent, ExpansionRoom());
                    byte[] clear;
                    if (Slot(wrapper,"codec")?.Text == "gzipstream") clear = GunzipBytes(input,limit);
                    else
                    {
                        using var packed = new MemoryStream(input, false);
                        using Stream decoder = Slot(wrapper,"codec")?.Text == "deflatestream"
                            ? new DeflateStream(packed,CompressionMode.Decompress) : new BrotliStream(packed,CompressionMode.Decompress);
                        clear = ExpandStream(decoder,null,limit);
                    }
                    result = Bytes(clear,"decompressed stream", clear.Length == 0 ? Array.Empty<Mark>() : FileRecordMarks(source));
                }
                catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException or ArgumentException)
                { result = SymbolicBytes("decompression-invalid-or-budget",source); }
                // Codec read-ahead is implementation dependent; no fictitious raw offset.
                MoveReader(owner,Missing("compression-read-ahead"));
                SaveHttp(ReaderSet(CurrentHttp(wrapper)!.WithBody(result),("baseEpoch",Slot(CurrentHttp(owner)!,"epoch")!)));
                return result;
            }

            Payload WriteTransfer(HttpObject s, Payload piece, string operation, int depth=0)
            {
                s = CurrentHttp(s)!;
                if (!CanWriteStream(s)) return Missing("stream-not-writable");
                if (piece.Bytes?.Length == 0) return Missing("no-expression-output");
                if (depth >= MaxExpressionDepth || !StackAvailable)
                { ReportMissing("stream-wrapper-depth"); return Missing("stream-wrapper-depth"); }
                if (s.Kind == HttpObjectKind.RequestStream)
                {
                    if (s.Owner == null) return Missing("request-stream-owner");
                    var body = AppendRequest(s.Owner,piece,false);
                    var owner = CurrentHttp(s.Owner)!;
                    var parts = new List<Payload> {body};
                    parts.AddRange(owner.Fields.SelectMany(f => new[]{Text(f.Key,"HTTP header name"),f.Value}));
                    if (s.Address != null) AddRequestTarget(parts,s.Address);
                    Send(operation,Http(s.Address?.Text),parts); return Missing("no-expression-output");
                }
                if (s.Method == "compress")
                {
                    var owner = CurrentHttp(s.Owner);
                    if (owner == null || !CanWriteStream(owner)) return Missing("compression-base-closed");
                    // Keep a bounded plaintext tail for text matches spanning Write calls.
                    var evidence = piece;
                    var tail = Array.Empty<byte>();
                    if (piece.Bytes is byte[] b && Budget())
                    {
                        int keep = (int)Math.Min(MaxContent, 4L*(policy?.LongestFileNeedle ?? 0));
                        int first = Math.Min(keep,b.Length);
                        if (s.ByteTail.Length != 0 && first != 0)
                            evidence = Combine(piece,Bytes(s.ByteTail.Concat(b.Take(first)).ToArray(),"compression write boundary"),true);
                        tail = b.Length >= keep ? b.Skip(b.Length-keep).ToArray() :
                            s.ByteTail.Skip(Math.Max(0,s.ByteTail.Length+b.Length-keep)).Concat(b).ToArray();
                    }
                    var written = SymbolicBytes("compression-output-not-materialized",s.Body,evidence.Via(Slot(s,"codec")!.Text!));
                    SaveHttp(s.WithBody(written,byteTail:tail));
                    return WriteTransfer(owner,written,operation,depth+1);
                }
                if (s.Method == "memory")
                {
                    var backing = Slot(s,"backing");
                    if (backing!=null && Slot(s,"capacity") is Payload cap && CountValue(cap,out int size) &&
                        Position(s,out int pos) && piece.Bytes is byte[] incoming &&
                        (long)pos + incoming.Length > size) return Missing("memory-stream-fixed-capacity");
                    var result = WriteMemory(s,piece,false);
                    if (backing != null && CurrentHttp(s) is HttpObject changed && changed.Body is Payload revised)
                    {
                        PublishBacking(changed,backing,revised);
                    }
                    return result;
                }
                if (ShareHost(s.Address?.Text) is string share)
                {
                    ShareSend(operation.StartsWith("HttpWebRequest",StringComparison.Ordinal) ? "FileStream.Write" : operation,
                        share,new[]{s.Address!,piece},null);
                    return Missing("no-expression-output");
                }
                if (s.Address?.Text is not string path || Disk.Bind(path,null) == null || barrier) return Missing("stream-write-target");
                var old = StreamSource(s);
                var current = CurrentHttp(s)!;
                WriteMemory(current.WithBody(old),piece,false);
                var updated = CurrentHttp(s)!;
                var data = updated.Body ?? UnknownValue("file-stream-write",old,piece);
                PlanWrite(path,data,data.Bytes,false); // prediction only; durable state needs a separate confirmation
                if (predictedWrites.TryGetValue(path,out var pred)) SaveHttp(ReaderSet(updated,("prediction",pred)));
                return Missing("no-expression-output");
            }

            void PublishBacking(HttpObject stream, Payload old, Payload content)
            {
                Payload next;
                int start=0;
                if (Slot(stream,"start") is Payload st) CountValue(st,out start);
                if (old.Bytes is byte[] original && content.Bytes is byte[] b && start<=original.Length-b.Length)
                {
                    if(start==0 && b.Length==original.Length)next=content;
                    else if (ReserveStreamBytes(original.Length))
                    {
                        var copy=(byte[])original.Clone();Buffer.BlockCopy(b,0,copy,start,b.Length);
                        next=Bytes(copy,"memory backing array",Merge(FileRecordMarks(old).Concat(content.Tags)));
                    }
                    else next=SymbolicBytes("memory-backing-budget",old,content);
                }
                else next=SymbolicBytes("memory-backing-range",old,content);
                ReplaceReaderBuffer(null,old,next);
                SaveHttp(ReaderSet(stream,("backing",next)));
            }

            Payload CloseStream(HttpObject s, int depth=0)
            {
                if (ReaderOpen(s) && depth < MaxExpressionDepth)
                {
                    SaveHttp(ReaderSet(s,("closed",Number(1))));
                    if (IsCodec(s) && Slot(s,"leaveOpen")?.Text == "0" && CurrentHttp(s.Owner) is HttpObject owner)
                        CloseStream(owner,depth+1);
                }
                return Missing("no-expression-output");
            }

            Payload? StreamOperation(HttpObject s,string method,object[] args,int depth)
            {
                Payload Arg(int n) => Value(args[n],depth+1);
                bool async = method.EndsWith("async",StringComparison.Ordinal);
                string op = async ? method.Substring(0,method.Length-5) : method;
                Payload Void() => Missing("no-expression-output");
                if (op is "dispose" or "close" && args.Length == 0)
                {
                    var value = CloseStream(s);
                    return async ? new Payload { FileTaskResult=value,Issue="file-read-valuetask" } : value;
                }
                if (op == "flush" && args.Length == 0)
                    return async ? new Payload {FileTaskResult=Void(),Issue="file-read-task"} : Void();
                if (op == "seek" && IsCodec(s)) return Missing("compression-stream-not-seekable");
                if (op == "setlength") return ResizeStream(s,args.Length==1?Arg(0):null);
                if (op=="getbuffer" && s.Method=="memory" && args.Length==0)
                    return Slot(s,"exposable")?.Text!="1" ? Missing("memory-buffer-not-public") :
                        Slot(s,"backing") ?? SymbolicBytes("memory-buffer-capacity-not-materialized",s.Body);
                bool copy = op is "copyto" or "writeto";
                if (op=="writeto" && (s.Method!="memory" || args.Length!=1))return Missing("memory-writeto-overload");
                if (!copy && op is not ("write" or "writebyte")) return null;
                if (!ReaderOpen(s) || args.Length == 0) return Missing("stream-transfer-shape");
                HttpObject? dest = copy ? CurrentHttp(Arg(0).HttpObject) : s;
                if (dest == null || !CanWriteStream(dest) || copy && !CanReadStream(s)) return Missing("stream-transfer-access");
                // A wrapper and its own base cannot be treated as independent endpoints.
                var handles = new Dictionary<HttpObject,HttpObject>();
                bool AddChain(HttpObject root)
                {
                    for (HttpObject? h=root; h!=null; h=IsCodec(h) ? CurrentHttp(h.Owner) : null)
                    {
                        if (handles.Count >= MaxExpressionDepth || handles.ContainsKey(h.Identity)) return false;
                        handles[h.Identity]=h;
                    }
                    return true;
                }
                if (!AddChain(dest) || copy && !AddChain(s)) return Missing("stream-transfer-alias");
                if (copy && handles.Values.Where(h=>h.Kind==HttpObjectKind.FileStream && h.Address?.Text!=null)
                    .GroupBy(h=>h.Address!.Text!,StringComparer.OrdinalIgnoreCase).Any(g=>g.Count()>1))
                    return Missing("stream-copy-overlapping-file");
                if (async)
                {
                    var backings=handles.Values.Select(h=>Slot(h,"backing")).OfType<Payload>().ToArray();
                    if (backings.Length!=0)
                        foreach(var h in httpStates.Values.Where(h=>Slot(h,"backing") is Payload arr &&
                            backings.Any(b=>ReferenceEquals(b,arr) || b.Bytes!=null && ReferenceEquals(b.Bytes,arr.Bytes))))
                            handles[h.Identity]=h;
                }
                bool tokenUnknown = false;
                Payload chunk;
                if (op=="writeto")chunk=StreamArray(s);
                else if (op=="copyto")
                {
                    if (args.Length > (async?3:2)) return Missing("stream-copy-overload");
                    if (args.Length >= 2 && !(async && args.Length==2 && NoCancellation(args[1])))
                    {
                        var size=Arg(1);
                        if (CountValue(size,out int n)) { if(n==0)return Missing("stream-copy-buffer-size"); }
                        else if (!size.Complete) tokenUnknown=true;
                        else return Missing("stream-copy-buffer-size");
                    }
                    if(args.Length==3 && !NoCancellation(args[2]))tokenUnknown=true;
                    chunk=RemainingStream(s,true,symbolicCompressionCopy: dest.Method == "compress");
                }
                else if(op=="writebyte")
                {
                    var v=Arg(0);
                    if (args.Length!=1 || !CountValue(v,out int b) || b>255) return Missing("stream-write-byte");
                    chunk=Bytes(new[]{(byte)b},"stream byte",v.Tags);
                }
                else
                {
                    if (args.Length==1 || async && args.Length==2)
                    {
                        var v=Arg(0);
                        chunk=v.Bytes!=null || v.Model?.Kind==ModelKind.PackedBytes ? v : UnknownValue("stream-write-buffer",v);
                        tokenUnknown=args.Length==2 && !NoCancellation(args[1]);
                    }
                    else if (args.Length==3 || async && args.Length==4)
                    {
                        chunk=ByteSegment(Arg(0),Arg(1),Arg(2));
                        if(chunk.Issue=="invalid-stream-write-range")return chunk;
                        tokenUnknown=args.Length==4 && !NoCancellation(args[3]);
                    }
                    else return Missing("stream-write-overload");
                }
                bool conflict = handles.Values.Any(h=>Slot(h,"readPending")!=null || Slot(h,"closed")!=null);
                if (tokenUnknown || conflict) chunk = UnknownValue("stream-transfer-order-or-cancellation",chunk);
                var doneValue=WriteTransfer(dest,chunk,copy?"HttpWebRequest.GetRequestStream.CopyTo":"HttpWebRequest.GetRequestStream.Write");
                if (!async && !conflict && !tokenUnknown) return doneValue;
                var effect=new DeferredStreamRead();
                foreach(var prior in handles.Values)
                {
                    var done=CurrentHttp(prior)!;
                    if(ReferenceEquals(prior,done))continue;
                    var uncertain=JoinHttp(prior,done);
                    var pending=ReaderSet(uncertain,("readPending",Number(1)),("epoch",new Payload()),("pos",Missing("stream-transfer-pending")));
                    SaveHttp(pending);
                    if(!conflict && !tokenUnknown)effect.States.Add((pending,done));
                    if(Slot(prior,"backing") is Payload old && Slot(done,"backing") is Payload updated && !ReferenceEquals(old,updated))
                    {
                        var pendingArray=SymbolicBytes("async-memory-backing-pending",old,updated);
                        if(!conflict && !tokenUnknown){ pendingArray.DeferredRead=effect;effect.Buffer=updated; }
                        ReplaceReaderBuffer(null,updated,pendingArray,updateViews:false);
                    }
                    if(done.Address?.Text is string path && CanWriteStream(done) && !ReferenceEquals(prior.Body,done.Body) &&
                        done.Kind==HttpObjectKind.FileStream && plannedFiles.Contains(path) && predictedWrites.TryGetValue(path,out var finalFile))
                    {
                        MarkPossibleWrite(path,UnknownValue("async-file-write",prior.Body,done.Body));
                        if(!conflict && !tokenUnknown)effect.Files.Add((path,predictedWrites[path],finalFile));
                    }
                }
                return async ? new Payload{FileTaskResult=Void(),Issue="file-read-task",DeferredRead=effect} : Missing("stream-transfer-order");
            }

            Payload ResizeStream(HttpObject s,Payload? length)
            {
                if (!CanWriteStream(s) || IsCodec(s)) return Missing("stream-setlength-access");
                var previous=StreamSource(s);
                Payload body, pos;
                if (length!=null && CountValue(length,out int n) && (n==0 || previous.Bytes!=null) && ReserveStreamBytes(n))
                {
                    if(Slot(s,"capacity") is Payload cap && CountValue(cap,out int capacity) && n>capacity)return Missing("memory-stream-fixed-capacity");
                    var data=new byte[n]; int copy=Math.Min(n,previous.Bytes?.Length??0);
                    if(copy>0)Buffer.BlockCopy(previous.Bytes!,0,data,0,copy);
                    body=Bytes(data,"stream resize",copy==0?Array.Empty<Mark>():FileRecordMarks(previous));
                    pos=Position(s,out int p)?Number(Math.Min(p,n)):Missing("stream-position");
                }
                else { body=UnknownValue("stream-length",previous); pos=Missing("stream-position"); }
                var changed=ReaderSet(s.WithBody(body),("pos",pos),("epoch",new Payload()));
                if(s.Address?.Text is string path && Disk.Bind(path,null)!=null && !barrier)
                {
                    PlanWrite(path,body,body.Bytes,false);
                    if(predictedWrites.TryGetValue(path,out var pred))changed=ReaderSet(changed,("prediction",pred));
                }
                SaveHttp(changed);
                if(Slot(s,"backing") is Payload backing)PublishBacking(changed,backing,body);
                return Missing("no-expression-output");
            }
        }
    }
}

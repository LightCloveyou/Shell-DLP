using System;
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
            static bool AuxReader(HttpObject s)=>s.Kind is HttpObjectKind.SafeReadHandle or HttpObjectKind.AsyncLines or HttpObjectKind.AsyncLineCursor;
            Payload SafeHandleValue(HttpObject stream)
            {
                stream=CurrentHttp(stream)!;
                if(!ReaderOpen(stream) || stream.Address==null)return Missing("file-handle-not-observed");
                if(Slot(stream,"safeHandle") is Payload existing)return existing;
                var h=HttpObjectValue(new HttpObject(HttpObjectKind.SafeReadHandle,owner:stream));
                SaveHttp(ReaderSet(stream,("safeHandle",h)));return h;
            }
            Payload ReadAtOffset(object[] args,int depth)
            {
                if(args.Length!=3)return Missing("random-access-overload");
                var handle=CurrentHttp(Value(args[0],depth+1).HttpObject);
                var buffer=Value(args[1],depth+1);var name=VarName(args[1]);
                var file=CurrentHttp(handle?.Owner);
                if(handle?.Kind!=HttpObjectKind.SafeReadHandle || !ReaderOpen(handle) || file==null || !ReaderOpen(file) ||
                    !SafeName(name) || buffer.Bytes is not byte[] old) return Missing("random-access-handle-or-buffer");
                var arg=Value(args[2],depth+1);
                var source=StreamSource(file);
                if(!arg.Complete || !long.TryParse(arg.Text,NumberStyles.Integer,CultureInfo.InvariantCulture,out long off) || off<0 ||
                    source.Bytes==null || source.InspectionPartial)
                {
                    ReplaceReaderBuffer(name,buffer,UnknownValue("random-access-buffer",buffer,source));
                    return Missing("random-access-count");
                }
                int at=(int)Math.Min(off,source.Bytes.Length),n=Math.Min(old.Length,source.Bytes.Length-at);
                if(n>0)
                {
                    var piece=StreamPiece(source,at,n);var updated=(byte[])old.Clone();
                    Buffer.BlockCopy(source.Bytes,at,updated,0,n);
                    var prior=n==old.Length?Array.Empty<Mark>():FileRecordMarks(buffer);
                    ReplaceReaderBuffer(name,buffer,Bytes(updated,source.SourceRef,Merge(prior.Concat(piece.Tags))));
                }
                // RandomAccess uses an explicit file offset; it does not advance FileStream.Position.
                return Number(n);
            }
            static bool NoCancellation(object arg)=>Kind(arg)=="MemberExpressionAst" && Equals(Prop(arg,"Static"),true) &&
                TypeName(Prop(arg,"Expression")) is ("threading.cancellationtoken" or "system.threading.cancellationtoken") &&
                string.Equals(Literal(Prop(arg,"Member")),"None",StringComparison.OrdinalIgnoreCase);
            Payload OpenAsyncLines(object[] args,int depth)
            {
                if(args.Length is <1 or >3)return Missing("async-lines-overload");
                int count=args.Length;if(count>1 && NoCancellation(args[count-1]))count--;
                var encoding=count==1?Encoding.UTF8:count==2?ReaderEncoding(args[1]):null;
                var path=Value(args[0],depth+1);
                if(encoding==null || ExactString(path) is not string raw || !Path.IsPathFullyQualified(raw))return Missing("async-lines-arguments");
                var stream=OpenReader(path,"openread",Array.Empty<object>(),depth).HttpObject;
                if(stream==null)return Missing("async-lines-path");
                var reader=WrapReader(stream,true,encoding,true,false).HttpObject;
                return HttpObjectValue(new HttpObject(HttpObjectKind.AsyncLines,address:path,owner:reader,method:encoding.WebName));
            }
            Payload AuxReadMember(HttpObject s,string op,object[] args,int depth)
            {
                if(!ReaderOpen(s))return Missing("reader-closed");
                if(s.Kind==HttpObjectKind.SafeReadHandle)
                {
                    if(op is ("close" or "dispose") && args.Length==0)
                    {
                        SaveHttp(ReaderSet(s,("closed",Number(1))));
                        if(CurrentHttp(s.Owner) is HttpObject f)SaveHttp(ReaderSet(f,("closed",Number(1))));
                        return Missing("no-expression-output");
                    }
                    return Missing("safe-file-handle-method");
                }
                if(s.Kind==HttpObjectKind.AsyncLines)
                {
                    if(op!="getasyncenumerator" || !(args.Length==0 || args.Length==1 && NoCancellation(args[0])))return Missing("async-lines-enumerator");
                    var reader=CurrentHttp(s.Owner);
                    if(Slot(s,"used")!=null)
                    {
                        var stream=OpenReader(s.Address!,"openread",Array.Empty<object>(),depth).HttpObject;
                        if(stream==null)return Missing("async-lines-reopen");
                        reader=WrapReader(stream,true,Encoding.GetEncoding(s.Method!),true,false).HttpObject;
                    }
                    SaveHttp(ReaderSet(s,("used",Number(1))));
                    return HttpObjectValue(new HttpObject(HttpObjectKind.AsyncLineCursor,owner:reader));
                }
                var owner=CurrentHttp(s.Owner);
                if(owner==null || args.Length!=0)return Missing("async-cursor-method");
                if(op=="disposeasync")
                {
                    ReadMember(owner,"dispose",Array.Empty<object>(),depth);SaveHttp(ReaderSet(s,("closed",Number(1))));
                    return new Payload{Issue="file-read-valuetask",FileTaskResult=Missing("no-expression-output")};
                }
                if(op!="movenextasync")return Missing("async-cursor-method");
                if(Slot(s,"readPending")!=null)
                {
                    SaveHttp(ReaderSet(s,("closed",Number(1))));return Missing("overlapping-async-iteration");
                }
                var line=ReadMember(owner,"readline",args,depth);
                bool eof=line.Issue=="no-expression-output";
                var moved=eof || line.Complete && line.IsString?new Payload{Text=eof?"False":"True",ScalarTruth=!eof,Complete=true}:
                    Missing("async-next-result");
                var done=ReaderSet(s,("current",eof?Missing("async-enumerator-end"):line));
                var pending=ReaderSet(s,("readPending",Number(1)));SaveHttp(pending);
                var effect=new DeferredStreamRead();effect.States.Add((pending,done));
                return new Payload{Issue="file-read-valuetask",FileTaskResult=moved,DeferredRead=effect,SourceRef="MoveNextAsync"};
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            static bool IsPythonTool(string tool) => tool is "python" or "python3" or "py";
            static readonly Regex PyCoding = new Regex(@"^[ \t\f]*\#.*?coding[:=][ \t]*([-_.a-zA-Z0-9]+)");
            string PythonFile(string path,out string stamp)
            {
                var p=policy!;
                if (PendingFiles.ContainsKey(path) || plannedFiles.Contains(path) || UncertainFileTree(Path.GetDirectoryName(path)))
                    throw new PyGap("python-script-pending");
                if (!BeginFile()) throw new PyGap("python-analysis-limit");
                long limit=Math.Min(Math.Min(p.MaxScriptBytes, MaxContent), 262144);
                if(p.MaxFileBytes!=0) limit=Math.Min(limit,p.MaxFileBytes);
                if(p.MaxTotalFileBytes!=0) limit=Math.Min(limit,Math.Max(0,p.MaxTotalFileBytes-fileBytesReserved));
                var sample=Disk.TrySample(path,true,limit,needsContent:s=>PathEq(path,s.Path) && s.Size<=limit && Budget(),
                    reserve:n=>fileBytesReserved+=n);
                if(sample?.Bytes is not byte[] data)throw new PyGap("python-script-unavailable-or-limit");
                stamp=sample.Stamp;
                int start=data.Length>=3 && data[0]==0xef && data[1]==0xbb && data[2]==0xbf ? 3 : 0;
                string text;
                try {text=StrictUtf8.GetString(data,start,data.Length-start);} catch(DecoderFallbackException){throw new PyGap("python-source-encoding");}
                using var sr=new StringReader(text);
                for(int i=0;i<2;i++)
                {
                    var line=sr.ReadLine();if(line==null)break;
                    var m=PyCoding.Match(line);
                    if(m.Success && !(m.Groups[1].Value.Replace("_","-").ToLowerInvariant() is "utf-8" or "utf8"))throw new PyGap("python-source-encoding");
                }
                return text;
            }

            int openGrepSpentMs;
            void ScanOpenGrep(Policy snapshot,string code,string origin,string? stamp)
            {
                int remaining=snapshot.PythonOpenGrepTimeoutMs-openGrepSpentMs;
                OpenGrepScan.Result result;
                if(remaining<=0)result=new OpenGrepScan.Result{Issue="opengrep-time-budget"};
                else
                {
                    // The subprocess has a separate aggregate deadline. Charging its wait
                    // to the AST clock would skip independent later PowerShell statements.
                    bool running=clock.IsRunning; clock.Stop();
                    var elapsed=Stopwatch.StartNew();
                    try{result=OpenGrepScan.Run(snapshot,code,cwd,elapsed,remaining);}
                    finally{openGrepSpentMs+=(int)Math.Min(remaining,Math.Max(1,elapsed.ElapsedMilliseconds));if(running)clock.Start();}
                }
                if(stamp!=null && stamp!=Disk.TargetStamp(origin))throw new PyGap("python-script-changed");
                if(!Store.RefreshDerived(true) || !ReferenceEquals(snapshot,Store.Current(out var issue)) || issue!="")
                    throw new PyGap("python-policy-changed");
                foreach(var hit in result.Hits)
                {
                    var rule=hit.Key;
                    var reason=rule.Action=="block"?"block:"+rule.Id:"warn:sensitive-rule";
                    var tag=new Mark(rule.Id,origin+":"+hit.Value,"OpenGrep: configured source → Python network payload");
                    plan.Result(rule.Action=="block"?1:5,reason,Data("command","python","engine","opengrep","source",origin,
                        "line",hit.Value,"decision",reason,"matchedRules",1,"flow",new[]{tag.Report()},"inspection","taint-match",
                        "stage",currentStage,"chain",currentChain));
                }
                if(result.Issue.Length!=0 || result.Hits.Count==0)
                {
                    string reason=result.Issue.Length!=0?"missing:"+result.Issue:"no-match:opengrep-rules";
                    plan.Result(result.Issue.Length!=0?3:2,reason,Data("command","python","engine","opengrep","source",origin,
                        "decision",reason,"inspection",result.Issue.Length!=0?"partial":"generated-rules","missingInput",
                        result.Issue.Length!=0?result.Issue:null,"stage",currentStage,"chain",currentChain));
                }
            }

            Payload InspectPython(string tool,object command)
            {
                string origin="python invocation"; PyFlow? interpreter=null;
                try
                {
                    if(policy==null || policyProblem.Length!=0 || barrier || uncertainProcessContext)throw new PyGap("python-context");
                    var args=FlattenNative(command,out _); int i=0;
                    while (i<args.Length && (args[i] is "-B" or "-E" or "-I" or "-s" or "-S" or "-u" ||
                        tool=="py" && args[i]=="-3"))i++;
                    bool literal=i<args.Length && args[i]=="--"; if(literal)i++;
                    if(i>=args.Length || args[i] is not string arg)throw new PyGap("python-entrypoint");
                    string code; string? stamp=null;
                    if(!literal && arg=="-c")
                    {
                        if(i+1>=args.Length || args[i+1] is not string snippet)throw new PyGap("python-inline-source");
                        origin="python -c";code=snippet;
                    }
                    else
                    {
                        if(arg=="-" || !literal && arg.StartsWith("-",StringComparison.Ordinal) ||
                            !arg.EndsWith(".py",StringComparison.OrdinalIgnoreCase))throw new PyGap("python-entrypoint");
                        var path=Disk.Bind(arg,cwd);if(path==null)throw new PyGap("python-script-path");
                        origin=path;code=PythonFile(path,out stamp);
                        if(tool=="py" && code.StartsWith("#!",StringComparison.Ordinal))throw new PyGap("python-launcher-shebang");
                    }
                    if(!Budget() || code.Length>262144 || StrictUtf8.GetByteCount(code)>policy.MaxScriptBytes)throw new PyGap("python-analysis-limit");
                    if(policy.PythonOpenGrep)ScanOpenGrep(policy,code,origin,stamp);
                    var statements=new PySyntax(code,Budget).Parse();
                    interpreter=new PyFlow(this,origin);interpreter.Run(statements);
                    if(!interpreter.Sent)
                        plan.Result(2,"no-match:python-modeled-subset",Data("command",tool,"source",origin,
                            "decision","no-match:python-modeled-subset","inspection","python-subset","stage",currentStage,"chain",currentChain));
                    return interpreter.Output();
                }
                catch(PyGap gap)
                {
                    var reason="missing:"+gap.Message;
                    plan.Result(3,reason,Data("command",tool,"source",origin,"decision",reason,"inspection","partial",
                        "missingInput",gap.Message,"line",interpreter?.Line,"stage",currentStage,"chain",currentChain));
                    return UnknownValue(gap.Message,interpreter?.Output());
                }
            }

            sealed class PyFlow
            {
                // These are symbolic values, never objects imported from the inspected program.
                sealed class Val
                {
                    internal readonly string Type;
                    internal readonly Payload? Data;
                    internal readonly Val? Owner;
                    internal (Val Host,Val Port)? Pair;
                    internal string? Endpoint;
                    internal Dictionary<string,Val>? Entries;
                    internal bool Consumed, Closed;
                    internal Val(string type,Payload? data=null,Val? owner=null){Type=type;Data=data;Owner=owner;}
                }
                readonly AdapterContext ctx; readonly string source;
                readonly Dictionary<string,Val> vars=new Dictionary<string,Val>(StringComparer.Ordinal);
                readonly List<Payload> stdout=new List<Payload>();
                internal int Line;
                internal bool Sent;
                internal PyFlow(AdapterContext ctx,string source){this.ctx=ctx;this.source=source;}
                string At => source+":"+Line;
                static bool ModelImport(string s) => s is "pathlib" or "pathlib.Path" or "httpx" or "requests" or "socket" or "socket.create_connection" ||
                    s is "requests.post" or "requests.put" or "requests.patch" or "httpx.post" or "httpx.put" or "httpx.patch";
                static void Require(bool b) {if(!b)throw new PyGap("python-call-shape");}
                internal void Run(List<PyNode> statements)
                {
                    foreach(var s in statements)
                    {
                        if(!ctx.Budget())throw new PyGap("python-analysis-limit");
                        Line=s.Line;
                        switch(s.Kind)
                        {
                            case "pass":break;
                            case "main":
                                if(!vars.TryGetValue("__name__",out var name))Run(s.Body!);
                                else if(name.Type=="str" && name.Data?.Text!=null){if(name.Data.Text=="__main__")Run(s.Body!);}
                                else throw new PyGap("python-module-name");
                                break;
                            case "import":
                                if(!ModelImport(s.Child!.Name))throw new PyGap("python-import");
                                vars[s.Name]=new Val(s.Child.Name);break;
                            case "assign":vars[s.Name]=Eval(s.Child!);break;
                            case "with":
                                var handle=Eval(s.Child!);Require(handle.Type is "file-r" or "file-rb" or "tcp");
                                vars[s.Name]=handle;try{Run(s.Body!);}finally{handle.Closed=true;}break;
                            case "drain":DrainToSocket(s);break;
                            default:Eval(s);break;
                        }
                    }
                }
                internal Payload Output()
                {
                    if(stdout.Count==0)return new Payload{Complete=true,Elements=Array.Empty<Payload>(),SourceRef="python stdout"};
                    // Do not claim exact formatting or PowerShell's native-output record boundaries.
                    return UnknownValue("python-stdout-format",stdout.ToArray()).Via("python stdout");
                }
                Val Read(Val f,bool bytes)
                {
                    Require(!f.Closed);
                    if(f.Consumed)return new Val(bytes?"bytes":"str",ctx.Text("",At));
                    f.Consumed=true;
                    var value=ctx.File(f.Data?.Text,false,out _,inspectArchive:false).Via(At+" file read");
                    return new Val(bytes?"bytes":"str",value);
                }
                void SocketSend(Val socket,string method,Payload body)
                {
                    Require(socket.Type=="tcp" && !socket.Closed);
                    var name="python socket."+method;
                    if(ctx.TrustLoopback && LoopbackUri(socket.Endpoint))ctx.SkipLoopback(name,socket.Endpoint);
                    else ctx.Send(name,socket.Endpoint,new[]{body.Via(At+" "+method+" bytes")});
                    Sent=true;
                }
                void DrainToSocket(PyNode loop)
                {
                    // Summarize the entire byte stream only when every nonempty read goes
                    // directly to sendall on the same live socket, without intervening effects.
                    var read=loop.Child!;var recv=read.Child?.Child;
                    var send=loop.Body?.Count==1?loop.Body[0]:null;var sock=send?.Child?.Child;
                    if(read.Kind!="call" || read.Child?.Kind!="member" || read.Child.Name!="read" || recv?.Kind!="id" ||
                        read.Args.Count!=1 || read.Args[0].Key!="" || read.Args[0].Expr.Kind is not ("int" or "id") ||
                        send?.Kind!="call" || send.Child?.Kind!="member" || send.Child.Name!="sendall" || sock?.Kind!="id" ||
                        send.Args.Count!=1 || send.Args[0].Key!="" || send.Args[0].Expr.Kind!="id" || send.Args[0].Expr.Name!=loop.Name ||
                        loop.Name==recv.Name || loop.Name==sock.Name || (read.Args[0].Expr.Kind=="id" && read.Args[0].Expr.Name==loop.Name))
                        throw new PyGap("python-loop-flow");
                    var file=Eval(recv);var dest=Eval(sock);var size=Eval(read.Args[0].Expr);
                    Require(file.Type=="file-rb" && !file.Closed && dest.Type=="tcp" && !dest.Closed && size.Type=="int" &&
                        int.TryParse(size.Data?.Text,out int n) && n>0);
                    if(!file.Consumed)
                    {
                        var bytes=ctx.File(file.Data?.Text,false,out var sample,inspectArchive:false);
                        if(sample==null)throw new PyGap("python-loop-file-unconfirmed");
                        if(sample.Size>0){Line=send.Line;SocketSend(dest,"sendall",bytes.Via(source+":"+loop.Line+" binary read loop"));}
                        file.Consumed=true;
                    }
                    vars[loop.Name]=new Val("bytes",ctx.Text("",At));
                }
                IEnumerable<Payload> Fields(Val map,string mode,int depth)
                {
                    if(depth>Math.Min(32,Limits.MaxExpressionDepth))throw new PyGap("python-analysis-limit");
                    Require(map.Type=="dict");
                    foreach(var entry in map.Entries!)
                    {
                        if(!ctx.Budget() || ++parts>Limits.MaxParts)throw new PyGap("python-analysis-limit");
                        yield return ctx.Text(entry.Key,At);
                        var v=entry.Value;
                        if(mode=="files" && (v.Type is "file-r" or "file-rb"))v=Read(v,v.Type=="file-rb");
                        if(mode=="json" && v.Type=="dict")
                        {foreach(var p in Fields(v,mode,depth+1))yield return p;continue;}
                        Require(mode=="json" ? v.Type is "str" or "int" : v.Type is "str" or "bytes" or "int");
                        yield return v.Data!;
                    }
                }
                int parts;
                Val Eval(PyNode n)
                {
                    if(!StackAvailable || !ctx.Budget())throw new PyGap("python-analysis-limit");
                    if(n.Kind is "str" or "bytes" or "int")return new Val(n.Kind,ctx.Text(n.Name,At));
                    if(n.Kind=="id")return vars.TryGetValue(n.Name,out var v)?v:
                        n.Name is "open" or "print"?new Val(n.Name):throw new PyGap("python-name");
                    if(n.Kind=="dict")return new Val("dict"){Entries=n.Args.ToDictionary(a=>a.Key,a=>Eval(a.Expr),StringComparer.Ordinal)};
                    if(n.Kind=="pair")return new Val("pair"){Pair=(Eval(n.Args[0].Expr),Eval(n.Args[1].Expr))};
                    var obj=Eval(n.Child!);
                    if(n.Kind=="member")
                    {
                        if(ModelImport(obj.Type+"."+n.Name))return new Val(obj.Type+"."+n.Name);
                        if(obj.Type=="tcp" && n.Name is ("send" or "sendall"))return new Val("tcp."+n.Name,owner:obj);
                        if(obj.Type=="path" && n.Name is ("read_text" or "read_bytes") ||
                            (obj.Type is "file-r" or "file-rb") && n.Name=="read")
                            return new Val(n.Name,owner:obj);
                        throw new PyGap("python-member");
                    }
                    var args=n.Args.Select(a=>(a.Key,Value:Eval(a.Expr))).ToArray();
                    var pos=args.Where(a=>a.Key=="").Select(a=>a.Value).ToArray();
                    Val? Arg(string name,int index=-1)
                    {
                        var byName=args.FirstOrDefault(a=>a.Key==name).Value;
                        if(index<0 || index>=pos.Length)return byName;
                        Require(byName==null);return pos[index];
                    }
                    bool Keys(params string[] keys)=>args.All(a=>a.Key=="" || keys.Contains(a.Key,StringComparer.Ordinal));
                    if(obj.Type=="socket.create_connection")
                    {
                        Require(pos.Length<=2 && Keys("address","timeout"));
                        var address=Arg("address",0)?.Pair;var timeout=Arg("timeout",1);
                        Require(timeout==null || timeout.Type=="int" && timeout.Data?.Text!="0");
                        if(address is not { } ap || ap.Host.Type!="str" || ap.Port.Type!="int" || ap.Host.Data?.Text is not string host ||
                            Uri.CheckHostName(host)==UriHostNameType.Unknown || !ushort.TryParse(ap.Port.Data?.Text,out var port) || port==0)
                            throw new PyGap("python-socket-address");
                        var endpoint=new UriBuilder("tcp",host,port).Uri.GetLeftPart(UriPartial.Authority);
                        return new Val("tcp"){Endpoint=endpoint}; // metadata only; never connect
                    }
                    if(obj.Type is "tcp.send" or "tcp.sendall")
                    {
                        Require(args.Length==1 && pos.Length==1 && pos[0].Type=="bytes");
                        SocketSend(obj.Owner!,obj.Type.Substring(4),pos[0].Data!);
                        return obj.Type=="tcp.sendall"?new Val("none"):new Val("int");
                    }
                    if(obj.Type=="pathlib.Path")
                    {Require(pos.Length==1 && args.Length==1 && pos[0].Type=="str");return new Val("path",pos[0].Data);}
                    if(obj.Type=="open")
                    {
                        Require(pos.Length<=2 && Keys("file","mode","encoding"));
                        var file=Arg("file",0);var mode=Arg("mode",1);var encoding=Arg("encoding");
                        var m=mode==null?"r":mode.Type=="str"?mode.Data?.Text:null;
                        Require((file?.Type is "path" or "str") && file.Data?.Text!=null && (m is "r" or "rt" or "rb") &&
                            (encoding==null || m!="rb" && encoding.Type=="str" && (encoding.Data?.Text is "utf-8" or "utf8")));
                        return new Val(m=="rb"?"file-rb":"file-r",file!.Data);
                    }
                    if(obj.Type=="read"){Require(args.Length==0);return Read(obj.Owner!,obj.Owner!.Type=="file-rb");}
                    if(obj.Type is "read_bytes" or "read_text")
                    {
                        Require(args.Length==0 || obj.Type=="read_text" && args.Length==1 &&
                            (args[0].Key is "" or "encoding") && args[0].Value.Type=="str" && (args[0].Value.Data?.Text is "utf8" or "utf-8"));
                        return Read(new Val("file-r",obj.Owner!.Data),obj.Type=="read_bytes");
                    }
                    if(obj.Type=="print")
                    {
                        Require(Keys() && pos.All(v=>v.Type is "str" or "int" or "bytes"));
                        if(stdout.Count+pos.Length>Limits.MaxCollection)throw new PyGap("python-analysis-limit");
                        foreach(var v in pos)stdout.Add(v.Data!);
                        return new Val("none");
                    }
                    if(obj.Type.StartsWith("requests.",StringComparison.Ordinal) || obj.Type.StartsWith("httpx.",StringComparison.Ordinal))
                    {
                        bool requests=obj.Type.StartsWith("requests.",StringComparison.Ordinal);
                        Require(pos.Length<=(requests?2:1) && Keys("data","json","url","timeout","files",requests?"data":"content"));
                        var endpoint=Arg("url",0);var timeout=Arg("timeout");
                        var data=Arg("data",requests?1:-1);var json=Arg("json");var content=Arg("content");var files=Arg("files");
                        Require(timeout==null || timeout.Type=="int");
                        Require(json==null || data==null && content==null && files==null);
                        Require(content==null || data==null && files==null);
                        var body=new List<Payload>();parts=0;
                        if(files!=null)body.AddRange(Fields(files,"files",0));
                        if(data!=null && files!=null)Require(data.Type=="dict");
                        var value=data??json??content;
                        if(value?.Type=="dict" && content==null)body.AddRange(Fields(value,json==null?"form":"json",0));
                        else if(value!=null)
                        {
                            if(requests && data!=null && (value.Type is "file-r" or "file-rb"))value=Read(value,value.Type=="file-rb");
                            Require((requests || data==null) && (json==null ? value.Type is "str" or "bytes" : value.Type is "str" or "int"));
                            body.Add(value.Data!);
                        }
                        if(endpoint?.Type!="str")throw new PyGap("python-http-target");
                        var target=Http(endpoint.Data?.Text);
                        if(target==null && endpoint.Data?.Text!=null)throw new PyGap("python-http-target");
                        ctx.Send("python "+obj.Type,target,body.Select(p=>p.Via(At+" request body")),target==null?"python-http-target":null);
                        Sent=true;return new Val("http-response");
                    }
                    throw new PyGap("python-call");
                }
            }
        }
    }
}

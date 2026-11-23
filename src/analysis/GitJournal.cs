using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class GitProof
        {
            // This path is deliberately offline. It never runs Git, hooks, a credential
            // helper or a remote query. A journal entry is a hint, not a signed receipt.
            static string JournalKey(string repo) => ProofKey(repo, new[] { "observations-v1" });
            static readonly System.Reflection.ConstructorInfo? ZlibReader = typeof(DeflateStream).Assembly
                .GetType("System.IO.Compression.ZLibStream")?.GetConstructor(new[] { typeof(Stream), typeof(CompressionMode) });
            // Capture only routing fields, not raw config, URL userinfo/query, commit
            // messages, or matching plaintext.
            sealed class JournalConfig
            {
                internal readonly Dictionary<string,List<string>> Values=new Dictionary<string,List<string>>(StringComparer.Ordinal);
                readonly Dictionary<string,string> stamps=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
                internal bool Current() => stamps.All(k=>ConfigStamp(k.Key)==k.Value);
                static readonly Regex SectionLine=new Regex(@"^\[\s*(?<type>[A-Za-z0-9.-]+)(?:\s+""(?<sub>[^""\\]+)"")?\s*\]\s*(?:[;#].*)?$");
                static string? SystemConfig()
                {
                    // Git for Windows may be installed on any drive. Locate the ordinary
                    // layout from PATH without launching the executable or probing shares.
                    foreach(var item in (Environment.GetEnvironmentVariable("PATH")??"").Split(Path.PathSeparator).Take(256))
                    {
                        string dir=item.Trim().Trim('"').TrimEnd('\\','/');
                        if(!Disk.Local(dir) || !Disk.ClearAncestors(dir))continue;
                        if(!File.Exists(Path.Combine(dir,"git.exe")))continue;
                        var leaf=Path.GetFileName(dir); var root=Path.GetDirectoryName(dir);
                        if(root==null || !PathEq(leaf,"cmd") && !PathEq(leaf,"bin"))return null;
                        if(PathEq(Path.GetFileName(root),"mingw64") || PathEq(Path.GetFileName(root),"mingw32") ||
                            PathEq(Path.GetFileName(root),"usr"))root=Path.GetDirectoryName(root);
                        return root==null?null:Path.Combine(root,"etc","gitconfig");
                    }
                    return null;
                }
                internal static JournalConfig? Load(string repo, bool forAllowlist = false)
                {
                    var c=new JournalConfig();
                    var home=Environment.GetEnvironmentVariable("HOME");
                    if (string.IsNullOrEmpty(home)) home=Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                    var xdg=Environment.GetEnvironmentVariable("XDG_CONFIG_HOME");
                    var system=SystemConfig(); if(system==null)return null;
                    var paths=new[]{
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"Git","config"),
                        system,
                        Path.Combine(string.IsNullOrEmpty(xdg)?Path.Combine(home!,".config"):xdg!,"git","config"),
                        Path.Combine(home!,".gitconfig"),Path.Combine(repo,".git","config")};
                    foreach(var path in paths.Distinct(StringComparer.OrdinalIgnoreCase))
                    {
                        if(!Disk.Local(path))return null;
                        var stamp=ConfigStamp(path); if(stamp==null)return null;
                        c.stamps[path]=stamp;
                        if(stamp=="")continue;
                        var sample=Disk.TrySample(path,true,Limits.MaxGitMetadataBytes);
                        if(sample?.Text is not string text || sample.Stamp!=stamp || !PathEq(path,sample.Path))return null;
                        string group="";
                        foreach(var raw in text.Split('\n'))
                        {
                            var line=raw.Trim();
                            if(line.Length==0 || line[0] is '#' or ';')continue;
                            if(line.EndsWith("\\",StringComparison.Ordinal))return null;
                            if(line[0]=='[')
                            {
                                var m=SectionLine.Match(line); if(!m.Success)return null;
                                var section=m.Groups["type"].Value.ToLowerInvariant();
                                if(section.StartsWith("include",StringComparison.Ordinal) || section=="url" ||
                                    section.StartsWith("url.",StringComparison.Ordinal))return null;
                                group=section+(m.Groups["sub"].Success?"."+m.Groups["sub"].Value:"");
                                continue;
                            }
                            if(group.Length==0)return null;
                            int eq=line.IndexOf('=');
                            var key=group+"."+(eq<0?line:line.Substring(0,eq)).Trim().ToLowerInvariant();
                            if(key.EndsWith(".mirror",StringComparison.Ordinal) || key is "extensions.worktreeconfig" or "push.followtags" ||
                                key.EndsWith(".vcs",StringComparison.Ordinal))return null;
                            if(forAllowlist && (key is "push.recursesubmodules" or "submodule.recurse" or "core.gitproxy" or "core.sshcommand" ||
                                key.StartsWith("remotes.",StringComparison.Ordinal) ||
                                key=="core.worktree" || key=="extensions.partialclone"))return null;
                            if(!key.StartsWith("remote.",StringComparison.Ordinal) && !key.StartsWith("branch.",StringComparison.Ordinal) &&
                                !key.StartsWith("push.",StringComparison.Ordinal))continue;
                            var v=eq<0?"true":line.Substring(eq+1).Trim();
                            if(v.Length>=2 && v[0]=='"' && v[v.Length-1]=='"')v=v.Substring(1,v.Length-2);
                            if(v.Length==0 || v.IndexOfAny(new[]{'"','\\','#',';'})>=0 || v.Any(char.IsControl))return null;
                            if(!c.Values.TryGetValue(key,out var set))c.Values.Add(key,set=new List<string>());
                            set.Add(v);
                        }
                    }
                    return c;
                }
                internal string? Target(string remote)
                {
                    var url=RawTarget(remote);
                    return url==null?null:SafeTarget(url);
                }
                internal string? RawTarget(string remote)
                {
                    if(NetworkTarget(remote))return remote;
                    if(!RemoteName(remote) || !(Values.TryGetValue("remote."+remote+".pushurl",out var urls) ||
                        Values.TryGetValue("remote."+remote+".url",out urls)) || urls.Count!=1)return null;
                    return urls[0];
                }
                static string? SafeTarget(string value)
                {
                    static string Project(string path) => path.Length<=512 && Regex.IsMatch(path,@"^/?[A-Za-z0-9_.~-]+(?:/[A-Za-z0-9_.~-]+)*/?$")
                        && !path.Split('/').Any(s=>s is "." or ".." || s.Length>80) ? "/"+path.Trim('/') : "";
                    if(value.Contains("://"))
                    {
                        if(!Uri.TryCreate(value,UriKind.Absolute,out var u) || u.Scheme is not ("http" or "https" or "ssh") ||
                            u.Host.Length==0)return null;
                        return u.GetComponents(UriComponents.SchemeAndServer,UriFormat.UriEscaped)+Project(u.AbsolutePath);
                    }
                    var m=Regex.Match(value,@"^(?:[^@:/\s]+@)?(?<host>[A-Za-z0-9.-]{2,}):(?<path>[^:\s]+)$");
                    return m.Success?"ssh://"+m.Groups["host"].Value+Project(m.Groups["path"].Value):null;
                }
                internal IEnumerable<string> Remotes() => Values.Keys.Where(k=>k.StartsWith("remote.",StringComparison.Ordinal) &&
                    (k.EndsWith(".url",StringComparison.Ordinal)||k.EndsWith(".pushurl",StringComparison.Ordinal)))
                    .Select(k=>k.Substring(7,k.LastIndexOf('.')-7)).Where(RemoteName).Distinct(StringComparer.Ordinal)
                    .Select(r=>(r,t:Target(r))).Where(x=>x.t!=null).Select(x=>x.r+"="+x.t).Take(Limits.MaxGitRefs);
            }

            internal sealed class JournalUpdate
            {
                internal readonly string RepoPath;
                readonly string op, head;
                readonly string? before, config;
                readonly string[] beforeRoutes;
                internal JournalUpdate(string repo,string op,string head,string? before,string? config,string[] beforeRoutes)
                {RepoPath=repo;this.op=op;this.head=head;this.before=before;this.config=config;this.beforeRoutes=beforeRoutes;}
                internal string Finish()
                {
                    try
                    {
                        if(!NoOverrides() || Repo(RepoPath)!=RepoPath)return "git-context-changed";
                        var dot=Path.Combine(RepoPath,".git");
                        var cfgFile=Path.Combine(dot,"config");
                        var branch=HeadRef(dot);
                        if(branch!=head)return "git-head-changed";
                        string? Tip()=>ReadRef(dot,head,Disk.TrySample(Path.Combine(dot,"packed-refs"),true));
                        var id=Tip();
                        var cfgStamp=ConfigStamp(cfgFile);
                        if(op=="commit" ? id==null || id==before : cfgStamp==null || cfgStamp==config)return "git-no-observed-change";
                        var cfg=JournalConfig.Load(RepoPath);
                        var stamp=ConfigStamp(Store.Config);
                        if(!Store.RefreshDerived(true))return "git-policy-unavailable";
                        var policy=Store.Current(out var issue);
                        if(policy==null || issue!="" || string.IsNullOrEmpty(stamp))return "git-policy-unavailable";
                        var hits=new List<LocalObjects.Hit>(); string[] parents=Array.Empty<string>();
                        bool partial=false;
                        if(op=="commit")
                        {
                            var clock=Stopwatch.StartNew();
                            var objects=new LocalObjects(RepoPath,policy,()=>clock.ElapsedMilliseconds<Math.Min(policy.MaxGitTime,2000));
                            var obj=objects.Commit(id!);
                            if(obj.HasValue)
                            {
                                parents=obj.Value.Parents;
                                hits=objects.Inspect(id!,obj.Value,new HashSet<string>(),false);
                            }
                            partial=objects.Partial || !obj.HasValue;
                        }
                        if(branch!=HeadRef(dot) || id!=Tip() || cfgStamp!=ConfigStamp(cfgFile) || cfg?.Current()==false ||
                            stamp!=ConfigStamp(Store.Config))return "git-state-changed";
                        var b=new StringBuilder("[[observation]]\n").Append(Field("repo",RepoPath)).Append(Field("operation",op))
                            .Append(Field("time",DateTime.UtcNow.ToString("O",CultureInfo.InvariantCulture))).Append(Field("ref",head))
                            .Append(Field("commit",id??"")).Append(Field("before",before??"")).Append(Field("policy_stamp",stamp!))
                            .Append(Field("coverage",partial?"partial-positive-observations":"positive-observations")).Append("parents = ").AppendLine(StringList(parents))
                            .Append(Field("routing",cfg==null?"unresolved":"local-config")).Append("previous_remotes = ").AppendLine(StringList(beforeRoutes))
                            .Append("configured_remotes = ").AppendLine(StringList(cfg?.Remotes()??Array.Empty<string>()))
                            .Append("paths = ").AppendLine(StringList(hits.Select(h=>h.PathName)))
                            .Append("rules = ").AppendLine(StringList(hits.Select(h=>h.Rule)))
                            .Append("blobs = ").AppendLine(StringList(hits.Select(h=>h.Blob)))
                            .Append("matches = ").AppendLine(StringList(hits.Select(h=>h.Match)))
                            .Append("changes = ").AppendLine(StringList(hits.Select(h=>h.Change)));
                        return Store.AppendJournal(JournalKey(RepoPath),b.ToString())?"git-observation-recorded":"git-journal-write-failed";
                    }
                    catch(Exception e) when(e is not (OutOfMemoryException or StackOverflowException or AccessViolationException))
                    { return "git-observation-unavailable"; }
                }
            }

            internal static JournalUpdate? Observe(string? directory,string op)
            {
                try
                {
                    if(!NoOverrides() || Repo(directory) is not string repo)return null;
                    var dot=Path.Combine(repo,".git"); var head=HeadRef(dot);
                    return head==null?null:new JournalUpdate(repo,op,head,
                        ReadRef(dot,head,Disk.TrySample(Path.Combine(dot,"packed-refs"),true)),ConfigStamp(Path.Combine(dot,"config")),
                        op=="commit"?Array.Empty<string>():JournalConfig.Load(repo)?.Remotes().ToArray()??Array.Empty<string>());
                }
                catch {return null;}
            }

            internal static GitProof? LocalPush(string? directory,string?[] argv, Policy policy,Func<bool> time)
            {
                try
                {
                    var input=CanonicalPush(argv,out _,out var selectors);
                    if(!time() || !NoOverrides() || input==null || selectors.Length!=0 || Repo(directory) is not string repo ||
                        !Store.RefreshDerived(true) || !ReferenceEquals(policy,Store.Current(out var issue)) || issue!="")return null;
                    var cfg=JournalConfig.Load(repo); if(cfg==null)return null;
                    var dot=Path.Combine(repo,".git"); var head=HeadRef(dot);
                    var args=input.Length>=2?input:head==null?null:ResolveDefaultPush(head,cfg.Values,input.FirstOrDefault());
                    if(args==null || args.Length<2 || cfg.Target(args[0]) is not string endpoint ||
                        policy.TrustLoopback && LoopbackSsh(endpoint))return null;
                    var refs=args.Skip(1).Select(s=>s.Split(':')[0]).Select(s=>s=="HEAD"?head:s).ToArray();
                    if(refs.Any(r=>r==null || !GitRef(r)))return null;
                    string?[] Tips()
                    {
                        var packed=Disk.TrySample(Path.Combine(dot,"packed-refs"),true);
                        return refs.Select(r=>ReadRef(dot,r!,packed)).ToArray();
                    }
                    var tips=Tips(); var ids=tips.OfType<string>().ToArray(); if(ids.Length==0 || ids.Length!=tips.Length)return null;
                    var stamp=ConfigStamp(Store.Config); if(string.IsNullOrEmpty(stamp))return null;
                    var hints=new Dictionary<string,HashSet<string>>(StringComparer.Ordinal);
                    try
                    {
                        var data=Store.ReadJournal(JournalKey(repo));
                        if(data!=null)foreach(var s in new Toml(data).Sections.Where(s=>s.Name=="[[observation" && PathEq(s.Get("repo"),repo) &&
                            s.Get("operation")=="commit" && s.Get("policy_stamp")==stamp && ObjectId(s.Get("commit"))))
                            hints[s.Get("commit")]=new HashSet<string>(s.Array("paths").Take(512),StringComparer.Ordinal);
                    }
                    catch(FormatException) {hints.Clear();}
                    var objects=new LocalObjects(repo,policy,time);
                    var seen=new HashSet<string>(); var queue=new Queue<string>(ids);
                    var marks=new Dictionary<string,Mark>();
                    while(queue.Count!=0 && seen.Count<policy.GitMaxCommits && time())
                    {
                        var id=queue.Dequeue(); if(!seen.Add(id))continue;
                        var commit=objects.Commit(id); if(!commit.HasValue)continue;
                        foreach(var hit in objects.Inspect(id,commit.Value,hints.TryGetValue(id,out var paths)?paths:new HashSet<string>(),true))
                        {
                            string origin=hit.PathName==""?"commit:"+id:Path.Combine(repo,hit.PathName.Replace('/','\\'));
                            marks[hit.Rule]=new Mark(hit.Rule,origin,origin).Via("git commit "+id);
                        }
                        if(policy.Rules.Any(r=>r.Action=="block" && marks.ContainsKey(r.Id)))break;
                        foreach(var p in commit.Value.Parents)queue.Enqueue(p);
                    }
                    if(!tips.SequenceEqual(Tips()) || head!=HeadRef(dot) || !cfg.Current() || stamp!=ConfigStamp(Store.Config))return null;
                    string missing = marks.Count!=0?"git-local-history-partial":
                        !time()?"git-local-time-budget":objects.Partial?"git-local-object-or-coverage":"git-local-no-positive-proof";
                    return new GitProof {Network=true,Endpoint=endpoint,Parts=new[]{new Payload {Tags=marks.Values.ToArray(),
                        InspectionPartial=true,Issue=missing,SourceRef="git local object database"}}};
                }
                catch(Exception e) when(e is not (OutOfMemoryException or StackOverflowException or AccessViolationException))
                {return null;}
            }

            internal static string? RemoteOperand(string?[] argv)
            {
                var remote=CanonicalPush(argv,out _,out _)?.FirstOrDefault();
                if(remote==null)return null;
                return RemoteName(remote)?remote:new JournalConfig().Target(remote);
            }
            sealed class LocalObjects
            {
                readonly string repo, dot;
                readonly Policy policy;
                readonly Func<bool> time;
                readonly Dictionary<string, (string Type, byte[] Data)?> cache = new Dictionary<string, (string, byte[])?>();
                readonly Dictionary<string, List<(string Name, string Mode, string Id)>> trees = new Dictionary<string, List<(string,string,string)>>();
                readonly int cap;
                long bytesLeft;
                int bindings, objects;
                internal bool Partial;
                internal LocalObjects(string repo, Policy policy, Func<bool> time)
                {
                    this.repo=repo; dot=Path.Combine(repo,".git"); this.policy=policy; this.time=time;
                    cap=Math.Min(MaxContent, policy.MaxGitMetadataBytes);
                    bytesLeft=Math.Min(policy.MaxGitCache, policy.MaxTotalFileBytes == 0 ? long.MaxValue : policy.MaxTotalFileBytes);
                }
                (string Type, byte[] Data)? Object(string id)
                {
                    if (cache.TryGetValue(id, out var hit)) return hit;
                    if (!ObjectId(id) || ZlibReader == null || !time() || ++objects > policy.GitMaxObjects)
                    { Partial=true; return null; }
                    cache[id]=null;
                    try
                    {
                        var path=Path.Combine(dot,"objects",id.Substring(0,2),id.Substring(2));
                        var limit=Math.Min(cap,bytesLeft);
                        var sample=Disk.TrySample(path,true,limit);
                        if (sample?.Bytes is not byte[] compressed || !PathEq(sample.Path,path)) { Partial=true; return null; }
                        bytesLeft-=compressed.Length;
                        using var source=new MemoryStream(compressed,false);
                        using var z=(Stream)ZlibReader.Invoke(new object[]{source,CompressionMode.Decompress});
                        var header=new StringBuilder();
                        for (;;)
                        {
                            int c=z.ReadByte();
                            if (c==0) break;
                            if (c<32 || c>126 || header.Length>=40) throw new InvalidDataException();
                            header.Append((char)c);
                        }
                        var parts=header.ToString().Split(' ');
                        if (parts.Length!=2 || parts[0] is not ("tree" or "commit" or "blob" or "tag") ||
                            !int.TryParse(parts[1],NumberStyles.None,CultureInfo.InvariantCulture,out int n) ||
                            n>cap || n>bytesLeft || parts[0]=="blob" && policy.MaxFileBytes!=0 && n>policy.MaxFileBytes)
                        { Partial=true; return null; }
                        bytesLeft-=n;
                        var data=new byte[n];
                        for (int i=0;i<n;)
                        {
                            if (!time()) { Partial=true; return null; }
                            int read=z.Read(data,i,Math.Min(n-i,32768));
                            if (read==0) throw new InvalidDataException();
                            i+=read;
                        }
                        if (z.ReadByte()!=-1) throw new InvalidDataException();
                        return cache[id]=(parts[0],data);
                    }
                    catch (Exception e) when (e is IOException or InvalidDataException or ArgumentException or System.Reflection.TargetInvocationException)
                    { Partial=true; return null; }
                }
                internal (string Tree,string[] Parents,byte[] Data)? Commit(string id)
                {
                    var obj=Object(id);
                    if (obj?.Type!="commit") { Partial=true; return null; }
                    // Only the ASCII identity headers are structural; messages need not be UTF-8.
                    var data=obj.Value.Data;
                    int pos=0;
                    string? tree=null; var parents=new List<string>();
                    while (pos<data.Length)
                    {
                        int next=Array.IndexOf(data,(byte)10,pos);
                        if (next<0) break;
                        var line=Encoding.ASCII.GetString(data,pos,next-pos);
                        pos=next+1;
                        if (line.Length==0 && tree!=null) return (tree,parents.ToArray(),data);
                        if (tree==null && line.StartsWith("tree ",StringComparison.Ordinal) && ObjectId(line.Substring(5)) && line.Length==id.Length+5) tree=line.Substring(5);
                        else if (line.StartsWith("parent ",StringComparison.Ordinal))
                        {
                            if (!ObjectId(line.Substring(7)) || line.Length!=id.Length+7 || parents.Count>=policy.MaxGitRefs) break;
                            parents.Add(line.Substring(7));
                        }
                    }
                    Partial=true; return null;
                }
                List<(string Name,string Mode,string Id)>? Tree(string id)
                {
                    if (trees.TryGetValue(id,out var known)) return known;
                    var obj=Object(id);
                    if (obj?.Type!="tree") { Partial=true; return null; }
                    var data=obj.Value.Data; int width=id.Length/2;
                    var entries=new List<(string,string,string)>();
                    var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    for (int at=0;at<data.Length;)
                    {
                        int sp=Array.IndexOf(data,(byte)' ',at);
                        int end=sp<0 ? -1 : Array.IndexOf(data,(byte)0,sp+1);
                        if (!time() || sp-at is < 1 or > 6 || end<=sp+1 || end>data.Length-1-width ||
                            entries.Count>=policy.GitMaxPathBindings) { Partial=true; return null; }
                        string mode=Encoding.ASCII.GetString(data,at,sp-at);
                        string name;
                        try { name=StrictUtf8.GetString(data,sp+1,end-sp-1); }
                        catch (DecoderFallbackException) { Partial=true; at=end+1+width; continue; }
                        if (name is "." or ".." || PathEq(name,".git") || name.Any(char.IsControl) ||
                            name.IndexOfAny(Path.GetInvalidFileNameChars())>=0 || name.EndsWith('.') || name.EndsWith(' ') ||
                            !names.Add(name)) { Partial=true; at=end+1+width; continue; }
                        entries.Add((name,mode,BitConverter.ToString(data,end+1,width).Replace("-","").ToLowerInvariant()));
                        at=end+1+width;
                    }
                    return trees[id]=entries;
                }
                string? FindBlob(string tree,string relative)
                {
                    var segments=relative.Split('/');
                    for (int i=0;i<segments.Length;i++)
                    {
                        var rows=Tree(tree);
                        if (rows==null) return null;
                        var row=rows.FirstOrDefault(x=>x.Name==segments[i]);
                        if (row.Name==null) return "";
                        if (i==segments.Length-1) return row.Id;
                        if (row.Mode!="40000") return "";
                        tree=row.Id;
                    }
                    return null;
                }
                internal sealed class Hit
                {
                    internal readonly string Rule, PathName, Blob, Match;
                    internal string Change="present";
                    internal Hit(string rule,string path,string blob,string match)
                    {Rule=rule;PathName=path;Blob=blob;Match=match;}
                }
                internal List<Hit> Inspect(string id, (string Tree,string[] Parents,byte[] Data) commit,
                    HashSet<string> hints, bool quick)
                {
                    var hits=new List<Hit>();
                    var files=new List<(string Relative,string Full,string Id)>();
                    bool blocked=false;
                    void Add(Rule r,string name,string blob,string kind)
                    {
                        if (hits.Count>=Math.Min(512,policy.GitMaxPathBindings))
                        {
                            Partial=true;
                            if(r.Action!="block" || blocked)return;
                            hits.RemoveAt(hits.Count-1);
                        }
                        hits.Add(new Hit(r.Id,name,blob,kind));
                        blocked|=r.Action=="block";
                    }
                    bool Under(string path,string root) => PathEq(path,root) ||
                        path.StartsWith(root.TrimEnd('\\')+"\\",StringComparison.OrdinalIgnoreCase);
                    bool Preferred(string relative)
                    {
                        var path=Path.Combine(repo,relative.Replace('/','\\'));
                        return policy.Rules.Any(r=>r.Files.Concat(r.Folders).Any(f=>Under(f,path)||Under(path,f))) ||
                               hints.Any(h=>h.StartsWith(relative+"/",StringComparison.Ordinal)||h==relative);
                    }
                    void Visit(string tree,string prefix,int depth)
                    {
                        if (!time() || depth>Math.Min(64,Limits.MaxPathDepth) || bindings>=policy.GitMaxPathBindings) {Partial=true;return;}
                        var rows=Tree(tree); if(rows==null)return;
                        foreach(var row in rows.OrderByDescending(r=>Preferred(prefix+r.Name)))
                        {
                            if (!time() || ++bindings>policy.GitMaxPathBindings) {Partial=true;break;}
                            var relative=prefix+row.Name;
                            if (row.Mode=="40000") Visit(row.Id,relative+"/",depth+1);
                            else if (row.Mode is "100644" or "100755" or "120000")
                            {
                                var path=Path.Combine(repo,relative.Replace('/','\\'));
                                foreach(var rule in policy.Rules)
                                    if(rule.Files.Any(f=>PathEq(f,path)) || rule.Folders.Any(f=>path.StartsWith(f.TrimEnd('\\')+"\\",StringComparison.OrdinalIgnoreCase)))
                                        Add(rule,relative,row.Id,"path");
                                files.Add((relative,path,row.Id));
                            }
                            else Partial=true;
                            if(quick && blocked) return;
                        }
                    }
                    Visit(commit.Tree,"",0);
                    if (!(quick && blocked))
                    {
                        var textRules=policy.Rules.Where(r=>r.Texts.Length!=0).ToArray();
                        foreach(var file in files.OrderByDescending(f=>hints.Contains(f.Relative)))
                        {
                            if (!time()) { Partial=true;break; }
                            var needed=textRules.Where(r=>!hits.Any(h=>h.PathName==file.Relative && h.Rule==r.Id)).ToArray();
                            if (needed.Length==0) continue;
                            var obj=Object(file.Id);
                            string? text=obj?.Type=="blob"?Disk.Decode(obj.Value.Data):null;
                            if(text==null){Partial=true;continue;}
                            foreach(var rule in needed)
                                if(rule.Texts.Any(t=>text.IndexOf(t,StringComparison.Ordinal)>=0))Add(rule,file.Relative,file.Id,"text");
                            if(quick && blocked)break;
                        }
                        string? message=Disk.Decode(commit.Data);
                        if(message!=null) foreach(var rule in textRules)
                            if(rule.Texts.Any(t=>message.IndexOf(t,StringComparison.Ordinal)>=0))Add(rule,"",id,"commit-text");
                    }
                    if(!quick)
                    {
                        var parent=commit.Parents.Length==0?null:Commit(commit.Parents[0])?.Tree;
                        foreach(var hit in hits.Where(h=>h.PathName.Length!=0))
                        {
                            var old=commit.Parents.Length==0?"":parent==null || !time()?null:FindBlob(parent,hit.PathName);
                            hit.Change=old==null?"unknown":old==""?"added":old==hit.Blob?"present":"modified";
                        }
                    }
                    return hits;
                }
            }
        }
    }
}

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
            Payload DirectoryTool(string tool,string[] argv)
            {
                if(barrier || policy==null || argv.Any(a=>a.IndexOf('\0')>=0))return Missing("native-directory-context");
                if(tool=="where")return WhereOutput(argv);
                if(tool=="stat")return StatOutput(argv);
                bool dos=tool=="dir",tree=tool=="tree",bare=false,recurse=tree,hidden=false,dot=false,lower=false,
                    longForm=false,self=false,withFiles=false,end=false;
                FileAttributes must=0,not=0;
                var operands=new List<string>();
                if(dos && argv.Any(a=>a.IndexOfAny("&|<>^%!()\"\r\n".ToCharArray())>=0))return Missing("cmd-dir-shell-syntax");
                if(dos)
                {
                    if(variablesUnknown || uncertainProcessContext)return Missing("cmd-dir-inherited-environment");
                    if(values.TryGetValue(Key("env:DIRCMD"),out var defaults))
                    {
                        if(defaults.Issue!="process-environment-removed" &&
                            (ExactString(defaults) is not string s || !string.IsNullOrWhiteSpace(s)))
                            return Missing("cmd-dir-inherited-options");
                    }
                    else
                    {
                        try{if(!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("DIRCMD")))return Missing("cmd-dir-inherited-options");}
                        catch(System.Security.SecurityException){return Missing("cmd-dir-inherited-environment");}
                    }
                }
                foreach(string a in argv)
                {
                    if(!end && !dos && !tree && a=="--"){end=true;continue;}
                    if(!end && a.StartsWith("/") && (dos || tree))
                    {
                        string opt=a.ToLowerInvariant();
                        if(tree){if(opt=="/f")withFiles=true;else if(opt!="/a")return Missing("tree-option");continue;}
                        if(opt=="/b")bare=true;else if(opt=="/s")recurse=true;else if(opt=="/l")lower=true;
                        else if(opt.StartsWith("/a"))
                        {
                            hidden=true; bool negate=false;
                            foreach(char c in opt.Substring(2).TrimStart(':'))
                            {
                                if(c=='-' && !negate){negate=true;continue;}
                                var flag=c switch{'d'=>FileAttributes.Directory,'h'=>FileAttributes.Hidden,'s'=>FileAttributes.System,
                                    'r'=>FileAttributes.ReadOnly,'a'=>FileAttributes.Archive,'l'=>FileAttributes.ReparsePoint,'i'=>FileAttributes.NotContentIndexed,_=>(FileAttributes)0};
                                if(flag==0)return Missing("cmd-dir-attribute");
                                if(negate)not|=flag;else must|=flag;negate=false;
                            }
                            if(negate)return Missing("cmd-dir-attribute");
                        }
                        else if(opt is not ("/on" or "/o:n" or "/o-n" or "/o:-n" or "/o" or "/4" or "/n" or "/-c" or "/c"))
                            return Missing("cmd-dir-option");
                    }
                    else if(!end && !dos && !tree && a.StartsWith("-") && a.Length>1)
                    {
                        foreach(char c in a.Substring(1))
                        {
                            switch(c){case '1':break;case 'a':hidden=true;dot=true;break;case 'A':hidden=true;break;
                                case 'R':recurse=true;break;case 'd':self=true;break;case 'l':longForm=true;break;
                                case 'r':case 't':case 'S':break;default:return Missing("ls-format-or-option");}
                        }
                    }
                    else operands.Add(a);
                }
                if(operands.Count==0)operands.Add(".");
                if(tree && operands.Count!=1)return Missing("tree-operands");
                if(!hidden && dos)not|=FileAttributes.Hidden|FileAttributes.System;
                IEnumerable<Payload> Rows()
                {
                    foreach(var operand in operands)
                    {
                        if(!Budget()){yield return Missing("directory-list-budget");yield break;}
                        var root=Disk.Bind(operand,cwd);string? mask=null;
                        if(root==null && dos)
                        {
                            string? parent=Path.GetDirectoryName(operand);
                            var leaf=Path.GetFileName(operand);
                            if(leaf.Length>0 && leaf.Length<=Limits.MaxFilter && leaf.IndexOfAny("*?".ToCharArray())>=0)
                            {root=Disk.Bind(string.IsNullOrEmpty(parent)?".":parent,cwd);mask=FileSystemName.TranslateWin32Expression(leaf);}
                        }
                        if(root==null || InspectMetadata(root) is not FsMetadata info){yield return Missing("directory-list-path");continue;}
                        bool directory=info.Attributes.HasFlag(FileAttributes.Directory);
                        if(tree && !directory){yield return Missing("tree-root");continue;}
                        if(!directory || self)
                        {
                            if(dos && ((info.Attributes&must)!=must || (info.Attributes&not)!=0))continue;
                            string name=dos?(recurse?root:Path.GetFileName(root)):operand;
                            yield return Name(name);
                            if(longForm || dos&&!bare)yield return Missing("directory-list-rendering");
                            continue;
                        }
                        if(tree || dos && !bare) yield return UnknownValue("directory-heading",Text(root,"directory heading"));
                        if(dot && !dos && !tree){yield return Name(".");yield return Name("..");}
                        foreach(var (entry,issue) in EnumerateFiles(root,recurse,includeHidden:!dos||hidden,includeDirectories:true,
                            matchesName:n=>mask==null||FileSystemName.MatchesWin32Expression(mask,n,true),
                            matchesAttributes:at=>(at&must)==must && (at&not)==0,providerOrder:false,
                            descend:(p,at)=>dos?hidden || (at&(FileAttributes.Hidden|FileAttributes.System))==0 :
                                tree || hidden || !Path.GetFileName(p).StartsWith(".")))
                        {
                            if(entry==null){yield return Missing(issue??"directory-list-entry");continue;}
                            var leaf=Path.GetFileName(entry.Path);
                            if(tree && !withFiles && entry.Kind!=PathKind.DirectoryInfo ||
                                !dos && !tree && !hidden && leaf.StartsWith("."))continue;
                            if(!dos && !tree && recurse && dot && entry.Kind==PathKind.DirectoryInfo){yield return Name(".");yield return Name("..");}
                            var name=dos&&bare&&recurse?entry.Path:leaf;
                            var field=Name(name);
                            if(tree || longForm || dos&&!bare)
                            {
                                var parts=new List<Payload>{field};
                                if((longForm || dos) && entry.Kind==PathKind.FileInfo && InspectMetadata(entry.Path)?.Length is long size)
                                    parts.Add(Text(size.ToString(dos?CultureInfo.CurrentCulture:CultureInfo.InvariantCulture),"file size"));
                                yield return UnknownValue("directory-row-format",parts.ToArray());
                            }
                            else yield return field;
                        }
                        if(tree || dos&&!bare || longForm || !dos && recurse || operands.Count>1)yield return Missing("directory-list-layout");
                        if(mask!=null && mask!="*" && mask.Contains('~'))yield return Missing("directory-short-names");
                    }
                }
                Payload Name(string s)=>s.Any(char.IsControl)?Missing("directory-name-rendering"):Text(lower?s.ToLower(CultureInfo.CurrentCulture):s,"directory entry name");
                return UtilityRows(Rows(),tool,uncertainOrder:true);
            }
            Payload WhereOutput(string[] argv)
            {
                bool quiet=false,quote=false,details=false;string? rec=null;var names=new List<string>();
                for(int i=0;i<argv.Length;i++)
                {
                    switch(argv[i].ToLowerInvariant()){
                        case "/q":quiet=true;break;case "/f":quote=true;break;case "/t":details=true;break;
                        case "/r":if(rec!=null||++i==argv.Length)return Missing("where-root");rec=argv[i];break;
                        default:if(argv[i].StartsWith("/"))return Missing("where-option");names.Add(argv[i]);break;}
                }
                if(names.Count==0)return Missing("where-pattern");
                if(quiet)return CollectElements(Array.Empty<Payload>());
                IEnumerable<Payload> Rows()
                {
                    foreach(string name in names)
                    {
                        string mask=name;string? search;bool addCwd=false;
                        int colon=name.LastIndexOf(':');
                        if(colon>=0)
                        {
                            if(rec!=null || colon==0 || colon+1==name.Length){yield return Missing("where-pattern");continue;}
                            string scope=name.Substring(0,colon);mask=name.Substring(colon+1);
                            if(scope.StartsWith("$")){search=ExactString(ProcessEnvironmentValue(scope.Substring(1)));}
                            else search=scope;
                        }
                        else if(rec!=null)search=rec;
                        else{search=ExactString(ProcessEnvironmentValue("PATH"));addCwd=true;}
                        if(mask.IndexOfAny("/\\:[]\"".ToCharArray())>=0 || mask.Length==0 || mask.Length>Limits.MaxFilter)
                        {yield return Missing("where-mask");continue;}
                        var roots=new List<string>();
                        if(addCwd&&cwd!=null)roots.Add(cwd);
                        if(search!=null)roots.AddRange(search.Split(';',StringSplitOptions.RemoveEmptyEntries));
                        if(search==null || addCwd&&cwd==null)yield return Missing("where-search-path");
                        var masks=new List<string>();
                        if(Path.GetExtension(mask).Length!=0)masks.Add(mask);
                        else
                        {
                            string? ext=ExactString(ProcessEnvironmentValue("PATHEXT"));
                            if(ext==null){yield return Missing("where-pathext");continue;}
                            foreach(var e in ext.Split(';',StringSplitOptions.RemoveEmptyEntries))
                                if(e.StartsWith(".")&&e.Length<=Limits.MaxFilter&&e.Skip(1).All(char.IsLetterOrDigit))masks.Add(mask+e);
                                else yield return Missing("where-extension");
                        }
                        var patterns=masks.Select(FileSystemName.TranslateWin32Expression).ToArray();
                        foreach(var raw in roots.Distinct(StringComparer.OrdinalIgnoreCase))
                        {
                            if(!Budget()){yield return Missing("where-budget");yield break;}
                            var root=Disk.Bind(raw.Trim('"'),cwd);
                            if(root==null || InspectMetadata(root)?.Attributes.HasFlag(FileAttributes.Directory)!=true)
                            {yield return Missing("where-directory-unobserved");continue;}
                            foreach(var (entry,issue) in EnumerateFiles(root,rec!=null,includeHidden:true,
                                matchesName:n=>patterns.Any(p=>FileSystemName.MatchesWin32Expression(p,n,true)),providerOrder:false))
                            {
                                if(entry==null){yield return Missing(issue??"where-entry");continue;}
                                var path=Text(quote?"\""+entry.Path+"\"":entry.Path,"where file path");
                                if(!details)yield return path;
                                else yield return UnknownValue("where-time-rendering",path,InspectMetadata(entry.Path)?.Length is long size?
                                    Text(size.ToString(CultureInfo.InvariantCulture),"where file size"):null);
                            }
                        }
                    }
                }
                return UtilityRows(Rows(),"where",uncertainOrder:true);
            }
            Payload StatOutput(string[] args)
            {
                bool end=false;string? format=null;var files=new List<string>();
                for(int i=0;i<args.Length;i++)
                {
                    var a=args[i];
                    if(!end && a=="--"){end=true;continue;}
                    if(!end && (a=="-c" || a=="--format"))
                    {if(format!=null || ++i==args.Length)return Missing("stat-format");format=args[i];}
                    else if(!end && a.StartsWith("--format=") && format==null)format=a.Substring(9);
                    else if(!end && a.Length>2 && a.StartsWith("-c") && format==null)format=a.Substring(2);
                    else if(!end && a.StartsWith("-"))return Missing("stat-option-or-stdin");
                    else files.Add(a);
                }
                if(files.Count==0 || format!=null&&(format.Length>Limits.MaxFilter || format.Any(char.IsControl)))return Missing("stat-operands");
                IEnumerable<Payload> Rows()
                {
                    foreach(string raw in files)
                    {
                        var path=Disk.Bind(raw,cwd);
                        if(path==null || InspectMetadata(path) is not FsMetadata meta){yield return Missing("stat-metadata");continue;}
                        if(format==null){yield return UnknownValue("stat-platform-rendering",Text(raw,"stat filename"),
                            meta.Length is long s?Text(s.ToString(CultureInfo.InvariantCulture),"stat size"):null);continue;}
                        var output=new StringBuilder();bool complete=true;
                        for(int i=0;i<format.Length;i++)
                        {
                            if(format[i]!='%'){output.Append(format[i]);continue;}
                            string? v=++i==format.Length?null:format[i] switch{
                                '%'=>"%",'n'=>raw,'s'=>meta.Length?.ToString(CultureInfo.InvariantCulture),
                                'X'=>Seconds(meta.Accessed),'Y'=>Seconds(meta.Modified),_=>null};
                            if(v==null || output.Length+(long)v.Length>MaxContent/sizeof(char)){complete=false;break;}output.Append(v);
                        }
                        yield return complete?Text(output.ToString(),"stat metadata"):UnknownValue("stat-field-not-observed",Text(output.ToString(),"stat known prefix"));
                    }
                }
                static string? Seconds(DateTime? t)=>t.HasValue?new DateTimeOffset(t.Value).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture):null;
                return UtilityRows(Rows(),"stat");
            }
        }
    }
}

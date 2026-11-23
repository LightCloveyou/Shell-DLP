using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        static class OpenGrepScan
        {
            internal sealed class Result
            {
                internal readonly Dictionary<Rule,int> Hits = new Dictionary<Rule,int>();
                internal string Issue="";
            }
            internal static readonly SemaphoreSlim Slots=new SemaphoreSlim(2,2);
            [DllImport("advapi32.dll")]
            static extern bool GetTokenInformation(IntPtr token,int kind,out int value,int size,out int used);
            static string Executable(Policy p)
            {
                var dir=p.PythonOpenGrepDir;
                if(dir==null || !Disk.Local(dir))throw new PyGap("opengrep-invalid-directory");
                // A scanner selected from a user directory must not inherit a service or elevated host token.
                using var host=Process.GetCurrentProcess();
                const int TokenElevation=20;
                var processToken=new IntPtr(-4); // Windows GetCurrentProcessToken() pseudo-handle
                if(host.SessionId==0 || !GetTokenInformation(processToken,TokenElevation,out int elevated,sizeof(int),out _) || elevated!=0)
                    throw new PyGap("opengrep-privileged-host");
                return Path.Combine(dir,"opengrep.exe");
            }
            [StructLayout(LayoutKind.Sequential)] struct Security {internal int Length;internal IntPtr Descriptor;internal int Inherit;}
            [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
            static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string s,uint rev,out IntPtr sd,IntPtr size);
            [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
            static extern bool CreateDirectoryW(string path,ref Security sa);
            [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
            static string PrivateDirectory()
            {
                var parent=Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if(!Disk.ClearAncestors(parent))throw new PyGap("opengrep-private-directory");
                var path=Path.Combine(parent,"PS7Guard-OpenGrep-"+Guid.NewGuid().ToString("N"));
                if(!ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",1,out var sd,IntPtr.Zero))
                    throw new PyGap("opengrep-private-directory");
                try {var sa=new Security{Length=Marshal.SizeOf<Security>(),Descriptor=sd};
                    if(!CreateDirectoryW(path,ref sa))throw new PyGap("opengrep-private-directory");
                }finally{LocalFree(sd);}
                return path;
            }
            static void Put(string file,byte[] bytes)
            {using var w=new FileStream(file,FileMode.CreateNew,FileAccess.Write,FileShare.None);w.Write(bytes,0,bytes.Length);}

            static async Task<byte[]> Drain(Stream stream,int limit,bool keep)
            {
                using var m=new MemoryStream();var buf=new byte[8192];int total=0,n;
                while((n=await stream.ReadAsync(buf,0,buf.Length).ConfigureAwait(false))!=0)
                {if((total+=n)>limit)throw new PyGap("opengrep-output-limit");if(keep)m.Write(buf,0,n);}
                return m.ToArray();
            }
            static (byte[] Output,int Code) Execute(string exe,string dir,Stopwatch timer,int ms)
            {
                var kill=typeof(Process).GetMethod("Kill",new[]{typeof(bool)});
                if(kill==null)throw new PyGap("opengrep-process-control");
                var info=new ProcessStartInfo(exe){WorkingDirectory=Path.GetDirectoryName(exe)!,UseShellExecute=false,
                    CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
                foreach(var arg in new[]{"scan","--json","--strict","--no-rewrite-rule-ids","--disable-nosem",
                    "--no-git-ignore","--project-root",dir,"--jobs","1","--max-memory","512","--taint-intrafile",
                    "--config",Path.Combine(dir,"rules.yaml"),Path.Combine(dir,"input.py")})info.ArgumentList.Add(arg);
                // In particular, don't pass through proxy credentials, OCaml/Python
                // load paths, registry settings or inherited instrumentation.
                info.Environment.Clear();var sys=Environment.SystemDirectory;var win=Path.GetDirectoryName(sys)!;
                info.Environment["SystemRoot"]=win;info.Environment["WINDIR"]=win;
                info.Environment["PATH"]=Path.GetDirectoryName(exe)+";"+sys;
                foreach(var k in new[]{"TEMP","TMP","HOME","USERPROFILE","LOCALAPPDATA","APPDATA"})info.Environment[k]=dir;
                foreach(var k in new[]{"SEMGREP","OPENGREP"})
                {info.Environment[k+"_SEND_METRICS"]="off";info.Environment[k+"_ENABLE_VERSION_CHECK"]="0";info.Environment[k+"_SETTINGS_FILE"]=Path.Combine(dir,"settings.yml");}
                if(timer.ElapsedMilliseconds>=ms)throw new PyGap("opengrep-timeout");
                using var child=Process.Start(info)??throw new PyGap("opengrep-start");
                Task<byte[]>? output=null,error=null;
                try
                {
                    child.StandardInput.Close();
                    output=Drain(child.StandardOutput.BaseStream,2*1024*1024,true);
                    error=Drain(child.StandardError.BaseStream,128*1024,false);
                    while(!child.HasExited || !output.IsCompleted || !error.IsCompleted)
                    {
                        if(output.IsFaulted || error.IsFaulted)throw new PyGap("opengrep-output-limit");
                        if(timer.ElapsedMilliseconds>=ms)throw new PyGap("opengrep-timeout");
                        Thread.Sleep(5);
                    }
                    error.GetAwaiter().GetResult();
                    return (output.GetAwaiter().GetResult(),child.ExitCode);
                }
                finally
                {
                    if(!child.HasExited){kill.Invoke(child,new object[]{true});child.WaitForExit(200);}
                    foreach(var t in new[]{output,error}.OfType<Task<byte[]>>())
                        _=t.ContinueWith(f=>{_ = f.Exception;},TaskContinuationOptions.OnlyOnFaulted);
                }
            }
            static XElement Field(XElement x,string name,string type)
            {
                var field=x.Elements(name).SingleOrDefault();
                return (string?)field?.Attribute("type")==type?field!:throw new PyGap("opengrep-invalid-json");
            }
            static bool SameTarget(string s,string dir,string working)
            {
                if(s.Length==0 || s.Length>=32768)return false;
                var expected=Path.Combine(dir,"input.py");
                return PathEq(Path.GetFullPath(s,dir),expected) || PathEq(Path.GetFullPath(s,working),expected);
            }
            static bool Clean(string dir)
            {
                string root=Path.GetFullPath(dir);
                if(!PathEq(Path.GetDirectoryName(root)!,Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)) ||
                    !Path.GetFileName(root).StartsWith("PS7Guard-OpenGrep-",StringComparison.Ordinal) || !Disk.ClearAncestors(root))return false;
                bool ok=true;int count=0;
                // Independently remove both sensitive files even if another cleanup step fails.
                foreach(var name in new[]{"input.py","rules.yaml"})try{File.Delete(Path.Combine(root,name));}catch{ok=false;}
                void RemovePrivate(DirectoryInfo d,int depth)
                {
                    if(depth>6 || !Disk.ClearAncestors(d.FullName)){ok=false;return;}
                    foreach(var e in d.EnumerateFileSystemInfos())
                    {
                        if(++count>256 || !Path.GetFullPath(e.FullName).StartsWith(root+"\\",StringComparison.OrdinalIgnoreCase))
                        {ok=false;return;}
                        // Never traverse junctions. Unexpected links are left for inspection.
                        if((e.Attributes&FileAttributes.ReparsePoint)!=0){ok=false;continue;}
                        if(e is DirectoryInfo sub)RemovePrivate(sub,depth+1);
                        else e.Delete();
                    }
                    d.Delete(false);
                }
                RemovePrivate(new DirectoryInfo(root),0);
                return ok;
            }
            static Result Decode(byte[] json,int exit,string dir,string working,OpenGrepRules rules,int lines)
            {
                using var reader=JsonReaderWriterFactory.CreateJsonReader(json,new XmlDictionaryReaderQuotas{
                    MaxDepth=48,MaxArrayLength=2*1024*1024,MaxStringContentLength=2*1024*1024,MaxNameTableCharCount=32768});
                var root=XDocument.Load(reader).Root??throw new PyGap("opengrep-invalid-json");
                var hits=Field(root,"results","array");
                var r=new Result();
                foreach(var h in hits.Elements())
                {
                    if(!rules.Ids.TryGetValue(Field(h,"check_id","string").Value,out var rule) ||
                        !SameTarget(Field(h,"path","string").Value,dir,working) ||
                        !int.TryParse(Field(Field(h,"start","object"),"line","number").Value,NumberStyles.None,CultureInfo.InvariantCulture,out var line) ||
                        line<1 || line>lines)throw new PyGap("opengrep-unbound-result");
                    if(!r.Hits.ContainsKey(rule))r.Hits.Add(rule,line);
                }
                var paths=Field(root,"paths","object");var scanned=Field(paths,"scanned","array").Elements().ToArray();
                if(exit!=0 || Field(root,"errors","array").HasElements || root.Elements("skipped_rules").Any(s=>s.HasElements) ||
                    paths.Elements("skipped").Any(s=>s.HasElements) ||
                    scanned.Length!=1 || !SameTarget(scanned[0].Value,dir,working))r.Issue="opengrep-incomplete";
                else if(rules.Partial)r.Issue="opengrep-policy-partial";
                return r;
            }
            internal static Result Run(Policy p,string code,string? cwd,Stopwatch timer,int ms)
            {
                if(!Slots.Wait(0))return new Result{Issue="opengrep-busy"};
                string? dir=null;var result=new Result();
                try
                {
                    var exe=Executable(p);var rules=new OpenGrepRules(p,cwd);
                    if(rules.Ids.Count==0){result.Issue="opengrep-no-applicable-rules";return result;}
                    dir=PrivateDirectory();
                    var input=Path.Combine(dir,"input.py"); var config=Path.Combine(dir,"rules.yaml");
                    Put(input,StrictUtf8.GetBytes(code));Put(config,rules.Config);
                    using var holdInput=File.Open(input,FileMode.Open,FileAccess.Read,FileShare.Read);
                    using var holdConfig=File.Open(config,FileMode.Open,FileAccess.Read,FileShare.Read);
                    var (output,exit)=Execute(exe,dir,timer,ms);
                    result=Decode(output,exit,dir,Path.GetDirectoryName(exe)!,rules,1+code.Count(ch=>ch=='\n' || ch=='\r'));
                }
                catch(PyGap gap){result.Issue=gap.Message;}
                catch(System.ComponentModel.Win32Exception e) when(e.NativeErrorCode is 2 or 3)
                {result.Issue="opengrep-not-installed";}
                catch(System.ComponentModel.Win32Exception){result.Issue="opengrep-start";}
                catch(Exception e) when(e is not (OutOfMemoryException or AccessViolationException or StackOverflowException))
                {result.Issue="opengrep-unavailable-or-invalid-result";}
                finally
                {
                    if(dir!=null)try
                    {
                        if(!Clean(dir))throw new IOException();
                    }catch{if(result.Issue.Length==0)result.Issue="opengrep-cleanup";}
                    Slots.Release();
                }
                return result;
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        // Original, closed rule templates. Policy supplies literal data, never YAML,
        // Python patterns, rule IDs from a remote registry, or executable arguments.
        sealed class OpenGrepRules
        {
            internal readonly Dictionary<string,Rule> Ids = new Dictionary<string,Rule>(StringComparer.Ordinal);
            internal bool Partial;
            internal readonly byte[] Config;
            static object Pattern(string p) => Data("pattern",p);
            const string Sep = @"(?:/|\\{1,2})";
            static string Esc(string s) => Regex.Escape(s);
            static string PathPattern(string p) => string.Join(Sep,p.Split('\\','/').Select(Esc));
            static IEnumerable<string> Paths(string p,string? cwd,bool folder)
            {
                // Only lexical forms that unambiguously denote the configured location.
                const string component = @"(?!\.{1,2}(?:[/\\]|\z))[^/\\:\r\n]+";
                var suffix=folder? Sep+component+"(?:"+Sep+component+")*":"";
                var trimmed=p.TrimEnd('\\','/');
                yield return PathPattern(trimmed)+suffix;
                if(cwd==null)yield break;
                var rel=Path.GetRelativePath(cwd,p);
                if(Path.IsPathRooted(rel))yield break;
                if(folder && (rel=="." || cwd.StartsWith(trimmed+"\\",StringComparison.OrdinalIgnoreCase)))
                    yield return "(?:\\."+Sep+")?"+component+"(?:"+Sep+component+")*";
                else if(rel!="." && rel!=".." && !rel.StartsWith("..\\",StringComparison.Ordinal))
                    yield return "(?:\\."+Sep+")?"+PathPattern(rel.TrimEnd('\\','/'))+suffix;
            }
            static object Source(string mv,string re,params string[] patterns) =>
                Data("exact",true,"patterns",new object[]{Data("pattern-either",patterns.Select(Pattern).ToArray()),
                    Data("metavariable-regex",Data("metavariable",mv,"regex",re))});
            static object[] Sinks()
            {
                var patterns=new List<object>();
                foreach(var lib in new[]{"requests","httpx"})
                    foreach(var method in new[]{"post","put","patch"})
                    {
                        var fn=lib+"."+method;
                        foreach(var key in lib=="requests"?new[]{"data","json","files"}:new[]{"content","data","json","files"})
                            patterns.Add(Pattern(fn+"(..., "+key+"=$BODY, ...)"));
                        if(lib=="requests")patterns.Add(Pattern(fn+"($URL, $BODY, ...)"));
                    }
                return new[]{
                    Data("patterns",new object[]{Data("pattern-either",patterns),Data("focus-metavariable","$BODY")}),
                    Data("patterns",new object[]{
                        Data("pattern-inside","with socket.create_connection(...) as $SOCK:\n    ..."),
                        Data("pattern-either",new[]{Pattern("$SOCK.sendall($BODY, ...)"),Pattern("$SOCK.send($BODY, ...)")}),
                        Data("focus-metavariable","$BODY")})};
            }
            internal OpenGrepRules(Policy policy,string? cwd)
            {
                var generated=new List<object>();
                var sinks=Sinks();
                int count=0;
                foreach(var rule in policy.Rules)
                {
                    var sources=new List<object>();
                    string Alternatives(IEnumerable<string> terms)
                    {
                        var list=terms.Distinct(StringComparer.Ordinal).ToArray();
                        if(list.Sum(x=>(long)x.Length+1)>32768)throw new PyGap("opengrep-rule-limit");
                        return "(?:"+string.Join("|",list)+")";
                    }
                    if(rule.Texts.Length!=0)
                        sources.Add(Source("$LIT","(?s).*?"+Alternatives(rule.Texts.Select(Esc)),"\"$LIT\""));
                    if(rule.Files.Length!=0 || rule.Folders.Length!=0)
                    {
                        var paths=rule.Files.SelectMany(p=>Paths(p,cwd,false)).Concat(rule.Folders.SelectMany(p=>Paths(p,cwd,true)));
                        sources.Add(Source("$P",@"(?i)\A"+Alternatives(paths)+@"\z","open(\"$P\")",
                            "open(\"$P\", \"r\", ...)","open(\"$P\", \"rb\", ...)","open(\"$P\", \"rt\", ...)",
                            "pathlib.Path(\"$P\").read_text(...)","pathlib.Path(\"$P\").read_bytes()"));
                    }
                    var names=rule.Sources.Where(s=>s.StartsWith("env:",StringComparison.OrdinalIgnoreCase) && s.IndexOf(':',4)<0)
                        .Select(s=>s.Substring(4)).ToArray();
                    if(names.Length!=0)sources.Add(Source("$KEY",@"(?i)\A"+Alternatives(names.Select(Esc))+@"\z",
                        "os.getenv(\"$KEY\", ...)","os.environ.get(\"$KEY\", ...)","os.environ[\"$KEY\"]"));
                    Partial |= names.Length!=rule.Sources.Length || rule.Copies.Count!=0;
                    if(sources.Count==0)continue;
                    var id="ps7guard.python.r"+(++count).ToString(CultureInfo.InvariantCulture);
                    Ids.Add(id,rule);
                    generated.Add(Data("id",id,"mode","taint","languages",new[]{"python"},
                        "message","Guard configured source reaches a network payload","severity","WARNING",
                        "pattern-sources",sources,"pattern-sinks",sinks));
                }
                // System.Text.Json is provided by the PowerShell host; no new DLL in the provider.
                var doc=Data("rules",generated);
                var writer=Type.GetType("System.Text.Json.JsonSerializer, System.Text.Json",true)!.GetMethods()
                    .Single(m=>m.Name=="Serialize" && m.IsGenericMethodDefinition && m.ReturnType==typeof(string) &&
                        m.GetParameters().Length==2 && m.GetParameters()[1].ParameterType.Name=="JsonSerializerOptions");
                Config=StrictUtf8.GetBytes((string)writer.MakeGenericMethod(doc.GetType()).Invoke(null,new object?[]{doc,null})!);
                if(Config.Length>1024*1024)throw new PyGap("opengrep-rule-limit");
            }
        }
    }
}

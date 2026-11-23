using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        // Deliberately small Python 3 grammar. Parse the complete supported syntax before
        // looking for sources or sends: strings/comments are data, not executable statements.
        sealed class PyGap : Exception { internal PyGap(string issue = "python-unsupported-syntax") : base(issue) { } }
        sealed class PyNode
        {
            internal readonly string Kind, Name;
            internal readonly int Line;
            internal PyNode? Child;
            internal readonly List<(string Key, PyNode Expr)> Args = new List<(string, PyNode)>();
            internal List<PyNode>? Body;
            internal PyNode(string kind, string name, int line) { Kind=kind; Name=name; Line=line; }
        }
        sealed class PySyntax
        {
            readonly List<(string K,string V,int Line)> tokens = new List<(string,string,int)>();
            readonly Func<bool> time;
            int pos, statements;
            static bool Letter(char c) => c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or '_';
            static bool Digit(char c) => c >= '0' && c <= '9';
            static bool Reserved(string n) => n is "False" or "None" or "True" or "and" or "as" or "assert" or "async" or "await" or
                "break" or "class" or "continue" or "def" or "del" or "elif" or "else" or "except" or "finally" or "for" or "from" or
                "global" or "if" or "import" or "in" or "is" or "lambda" or "nonlocal" or "not" or "or" or "pass" or "raise" or
                "return" or "try" or "while" or "with" or "yield";
            void Limit(bool ok) { if (!ok || !time()) throw new PyGap("python-analysis-limit"); }
            internal PySyntax(string source, Func<bool> time)
            {
                this.time=time;
                if (source.IndexOf('\0') >= 0) throw new PyGap();
                var indent=new Stack<int>(); indent.Push(0);
                int parens=0, line=0;
                void Add(string k,string v="") { Limit(tokens.Count < Math.Min(32768,Limits.MaxPolicyNodes)); tokens.Add((k,v,line)); }
                foreach (var s in source.Replace("\r\n","\n").Replace('\r','\n').Split('\n'))
                {
                    line++; Limit(true);
                    int i=0; while (i<s.Length && s[i]==' ') i++;
                    if (i==s.Length || s[i]=='#') continue;
                    if (parens==0)
                    {
                        if (s[i]=='\t') throw new PyGap();
                        if (i>indent.Peek()) { Limit(indent.Count<32); indent.Push(i); Add("indent"); }
                        else { while (i<indent.Peek()) { indent.Pop(); Add("dedent"); } if (indent.Peek()!=i) throw new PyGap(); }
                    }
                    while (i<s.Length)
                    {
                        char c=s[i++];
                        if (c=='#') break;
                        if (c is ' ' or '\t') continue;
                        bool raw=(c is 'r' or 'R') && i<s.Length && (s[i] is '"' or '\'');
                        bool bytes=(c is 'b' or 'B') && i<s.Length && (s[i] is '"' or '\'');
                        if (raw || bytes) c=s[i++];
                        if (c is '"' or '\'')
                        {
                            if (i+1<s.Length && s[i]==c && s[i+1]==c) throw new PyGap();
                            var b=new StringBuilder(); bool closed=false;
                            while (i<s.Length)
                            {
                                char ch=s[i++];
                                if (ch==c) {closed=true;break;}
                                if (ch=='\\')
                                {
                                    if (i>=s.Length) throw new PyGap();
                                    ch=s[i++];
                                    if(raw) b.Append('\\');
                                    else ch=ch switch {'\\'=>'\\','\''=>'\'','"'=>'"','n'=>'\n','r'=>'\r','t'=>'\t',_=>throw new PyGap()};
                                }
                                if(bytes && ch>127)throw new PyGap();
                                b.Append(ch);
                            }
                            if (!closed) throw new PyGap();
                            Add(bytes?"bytes":"str",b.ToString()); continue;
                        }
                        if (Letter(c) || Digit(c))
                        {
                            int start=i-1;
                            while (i<s.Length && (Digit(s[i]) || Letter(s[i]))) i++;
                            var word=s.Substring(start,i-start);
                            if (Digit(c) && (!word.All(Digit) || word.Length>1 && c=='0'))throw new PyGap();
                            Add(Digit(c)?"int":"id",word); continue;
                        }
                        if (c is '(' or '{') { Limit(++parens<=32); }
                        else if(c is ')' or '}') { if (--parens<0)throw new PyGap(); }
                        else if(c=='=' && i<s.Length && s[i]=='='){i++;Add("==");continue;}
                        else if(c==':' && i<s.Length && s[i]=='='){i++;Add(":=");continue;}
                        else if (".,=:;".IndexOf(c)<0)throw new PyGap();
                        Add(c.ToString());
                    }
                    if(parens==0) Add("nl");
                }
                if(parens!=0)throw new PyGap();
                while(indent.Count>1){indent.Pop();Add("dedent");}
                Add("eof");
            }
            string K => tokens[pos].K;
            bool Take(string k) { if(K!=k)return false; pos++; return true; }
            void Need(string k) { if(!Take(k))throw new PyGap(); }
            bool Word(string w) { if(K!="id" || tokens[pos].V!=w)return false;pos++;return true; }
            string Id() { var t=tokens[pos]; if(t.K!="id" || Reserved(t.V))throw new PyGap();pos++;return t.V; }
            internal List<PyNode> Parse() { var result=Suite(0); Need("eof");return result; }
            List<PyNode> Suite(int depth)
            {
                Limit(depth<=Math.Min(32,Limits.MaxExpressionDepth));
                var list=new List<PyNode>();
                bool afterSemi=false;
                while(K!="eof" && K!="dedent")
                {
                    Limit(++statements<=Limits.MaxStatements);
                    int line=tokens[pos].Line; PyNode stmt;
                    if(Word("while"))
                    {
                        // PyFlow accepts only a proven read-until-EOF / forward-every-chunk body.
                        if(afterSemi)throw new PyGap();
                        bool grouped=Take("(");
                        var name=Id();Need(":=");stmt=new PyNode("drain",name,line){Child=Expr(0)};
                        if(grouped)Need(")");
                        Need(":");Need("nl");Need("indent");stmt.Body=Suite(depth+1);Need("dedent");
                        list.Add(stmt);continue;
                    }
                    if(Word("if"))
                    {
                        if(afterSemi || !Word("__name__"))throw new PyGap();
                        Need("==");if(tokens[pos].K!="str" || tokens[pos].V!="__main__")throw new PyGap();pos++;
                        Need(":");Need("nl");Need("indent");
                        stmt=new PyNode("main","",line){Body=Suite(depth+1)};Need("dedent");list.Add(stmt);continue;
                    }
                    if(Word("with"))
                    {
                        if(afterSemi)throw new PyGap();
                        var e=Expr(0); if(!Word("as"))throw new PyGap();
                        stmt=new PyNode("with",Id(),line){Child=e};
                        Need(":");Need("nl");Need("indent");stmt.Body=Suite(depth+1);Need("dedent");
                        list.Add(stmt);continue;
                    }
                    if(Word("import") || Word("from"))
                    {
                        bool from=tokens[pos-1].V=="from"; var mod=Id(); var name=mod;
                        if(from){if(!Word("import"))throw new PyGap();name=Id();mod+="."+name;}
                        stmt=new PyNode("import",Word("as")?Id():name,line){Child=new PyNode("module",mod,line)};
                    }
                    else if(Word("pass"))stmt=new PyNode("pass","",line);
                    else if(K=="id" && tokens[pos+1].K=="=")
                    {stmt=new PyNode("assign",Id(),line);Need("=");stmt.Child=Expr(0);}
                    else stmt=Expr(0);
                    list.Add(stmt);
                    afterSemi=Take(";");
                    if(!afterSemi || K=="nl"){Need("nl");afterSemi=false;}
                }
                return list;
            }
            PyNode Expr(int depth)
            {
                int cap=Math.Min(32,Limits.MaxExpressionDepth);
                Limit(depth<cap); var t=tokens[pos]; PyNode n;
                if(t.K=="id") n=new PyNode("id",Id(),t.Line);
                else if(t.K is "str" or "bytes" or "int"){pos++;n=new PyNode(t.K,t.V,t.Line);}
                else if(Take("("))
                {
                    var first=Expr(depth+1);
                    if(Take(",")){
                        n=new PyNode("pair","",t.Line);
                        n.Args.Add(("",first));n.Args.Add(("",Expr(depth+1)));Take(",");
                    }else n=first;
                    Need(")");
                }
                else if(Take("{"))
                {
                    n=new PyNode("dict","",t.Line);
                    var keys=new HashSet<string>(StringComparer.Ordinal);
                    while(K!="}")
                    {
                        Limit(n.Args.Count<Limits.MaxCollection);
                        var key=tokens[pos];Need("str");Need(":");
                        if(!keys.Add(key.V))throw new PyGap();
                        n.Args.Add((key.V,Expr(depth+1)));if(!Take(","))break;
                    }
                    Need("}");
                }
                else throw new PyGap();
                int links=0;
                while(K is "." or "(")
                {
                    Limit(depth + ++links<=cap);
                    if(Take(".")){n=new PyNode("member",Id(),t.Line){Child=n};continue;}
                    Need("(");n=new PyNode("call","",t.Line){Child=n};bool keywords=false;
                    while(K!=")")
                    {
                        Limit(n.Args.Count<Limits.MaxArguments);
                        var key="";
                        if(K=="id" && tokens[pos+1].K=="="){key=Id();Need("=");keywords=true;if(n.Args.Any(a=>a.Key==key))throw new PyGap();}
                        else if(keywords)throw new PyGap();
                        n.Args.Add((key,Expr(depth+1)));
                        if(!Take(","))break;
                    }
                    Need(")");
                }
                return n;
            }
        }
    }
}

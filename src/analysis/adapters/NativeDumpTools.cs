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
        sealed partial class AdapterContext
        {
            static bool DumpInteger(string? text, out int n)
            {
                n=0;
                if (text==null || text.Length==0) return false;
                int radix=text.StartsWith("0x",StringComparison.OrdinalIgnoreCase)?16:text.Length>1 && text[0]=='0'?8:10;
                string digits=radix==16?text.Substring(2):text;
                if(digits.Length==0) return false;
                foreach(char c in digits)
                {
                    int d=c is >= '0' and <= '9'?c-'0':c is >= 'a' and <= 'f'?c-'a'+10:c is >= 'A' and <= 'F'?c-'A'+10:99;
                    if(d>=radix || n>(int.MaxValue-d)/radix) return false; n=n*radix+d;
                }
                return true;
            }
            static string DumpDigits(long value, char mode, int width) =>
                (mode=='x'?value.ToString("x",CultureInfo.InvariantCulture):mode=='d'?value.ToString(CultureInfo.InvariantCulture):
                Convert.ToString(value,8)).PadLeft(width,'0');
            Payload DumpTool(string tool, string[] args, Payload? pipe)
            {
                if (tool.StartsWith("strings",StringComparison.Ordinal)) return PrintableStrings(tool,args,pipe);
                var paths=new List<string>();
                bool od=tool=="od", all=false, endArgs=false; string mode=od?"o2":tool=="hd"?"C":"default";
                char address=od?'o':'x'; int skip=0,length=int.MaxValue,width=16; bool setMode=false;
                for (int i=0;i<args.Length;i++)
                {
                    string a=args[i];
                    if(!endArgs && a=="--") { endArgs=true; continue; }
                    if(endArgs || !a.StartsWith("-") || a=="-") {paths.Add(a); continue;}
                    if(a is "-v" or "--output-duplicates" or "--output-duplicate-lines") {all=true;continue;}
                    if (!od && a is ("-C" or "--canonical" or "-x" or "-b" or "-d" or "-o" or "-X"))
                    {
                        if(setMode) return Missing("hexdump-multiple-formats");
                        mode=a=="--canonical"?"C":a.Substring(1); setMode=true; continue;
                    }
                    if(od && a is ("-x" or "-b" or "-o" or "-d"))
                    {
                        if(setMode) return Missing("od-multiple-formats");
                        mode=a switch {"-x"=>"x2","-b"=>"o1","-o"=>"o2",_=>"u2"}; setMode=true; continue;
                    }
                    if(a.Length<2) return Missing("dump-option");
                    char option=a[1]; string? v=a.Length>2?a.Substring(2):args.ElementAtOrDefault(++i);
                    if(od && option=='A' && v is ("n" or "o" or "d" or "x")) address=v[0];
                    else if(od && option=='t' && v is ("x1" or "x2" or "x4" or "o1" or "o2" or "u1" or "u2"))
                    {if(setMode)return Missing("od-multiple-formats");mode=v;setMode=true;}
                    else if((od?option=='j':option=='s') && DumpInteger(v,out int off)) skip=off;
                    else if((od?option=='N':option=='n') && DumpInteger(v,out int count)) length=count;
                    else if(od && option=='w' && DumpInteger(v,out int w) && w is >0 and <=256) width=w;
                    else return Missing("dump-format-or-options");
                }
                if(paths.Count==0) paths.Add("-");
                if(paths.Count(n=>n=="-")>1 || od && width%(mode[1]-'0')!=0) return Missing("dump-input-shape");
                using var buffer=new MemoryStream();
                var spans=new List<(int Start,int End,Mark[] Marks)>();
                foreach(string path in paths)
                {
                    var bytes=UtilityBytes(path,pipe,out var source);
                    if(bytes==null || !Budget() || bytes.Length>MaxContent-buffer.Length) return Missing("dump-byte-input");
                    int start=(int)buffer.Length;
                    buffer.Write(bytes,0,bytes.Length); spans.Add((start,(int)buffer.Length,FileRecordMarks(source)));
                }
                var data=buffer.ToArray();
                if(skip>data.Length) return Missing("dump-skip-past-input");
                int stop=(int)Math.Min(data.Length,(long)skip+length);
                IEnumerable<Payload> Rows()
                {
                    bool star=false;
                    for(int pos=skip;pos<stop;)
                    {
                        if(!Budget()) {yield return Missing("dump-budget");yield break;}
                        int take=Math.Min(width,stop-pos);
                        if(!all && take==width && pos-skip>=width &&
                            data.AsSpan(pos,width).SequenceEqual(data.AsSpan(pos-width,width)))
                        { if(!star) yield return Text("*","duplicate dump row");star=true;pos+=take;continue; }
                        star=false;
                        var marks=Merge(spans.Where(s=>s.Start<pos+take && s.End>pos).SelectMany(s=>s.Marks));
                        if(mode=="C")
                        {
                            var hex=new string[16]; var ascii=new char[take];
                            for(int i=0;i<16;i++) { hex[i]=i<take?data[pos+i].ToString("x2",CultureInfo.InvariantCulture):"  ";
                                if(i<take)ascii[i]=data[pos+i] is >=32 and <=126?(char)data[pos+i]:'.'; }
                            string line=DumpDigits(pos,'x',8)+"  "+string.Join(" ",hex,0,8)+"  "+string.Join(" ",hex,8,8)+"  |"+new string(ascii)+"|";
                            yield return Text(line,"hexdump canonical row",marks);
                        }
                        else
                        {
                            int unit=od?mode[1]-'0':mode is "b" or "X"?1:2;
                            char radix=od?mode[0]:mode is "b" or "o"?'o':mode=="d"?'u':'x';
                            int digits=radix=='x'?unit*2:radix=='o'?(unit*8+2)/3:unit==1?3:5;
                            string head=address=='n'?"":DumpDigits(pos,address,od && address=='x'?6:7);
                            var cols=new List<string>();
                            for(int i=0;i<take;i+=unit)
                            {
                                long number=0;for(int j=0;j<unit && i+j<take;j++)number|=(long)data[pos+i+j]<<(8*j);
                                string col=radix=='u' && od?number.ToString(CultureInfo.InvariantCulture).PadLeft(digits):
                                    DumpDigits(number,radix=='u'?'d':radix,digits);
                                cols.Add(col);
                            }
                            string padding=od || mode is "b" or "default"?" ":mode is "X" or "o"?"  ":mode=="d"?"   ":"    ";
                            var row=Text(head+padding+string.Join(padding,cols),"dump row",marks);
                            if(!od && take<width) yield return UnknownValue("hexdump-final-padding",row);
                            else yield return row;
                        }
                        pos+=take;
                    }
                    if(address!='n' && (od || stop>0)) yield return Text(DumpDigits(stop,address,mode=="C"?8:od && address=='x'?6:7),"dump end offset");
                }
                return UtilityRows(Rows(),tool);
            }

            Payload PrintableStrings(string tool,string[] args,Payload? pipe)
            {
                bool sys=tool!="strings",gnu=false,asciiOnly=false,wideOnly=false,end=false,forceAll=false,quiet=false;
                char encoding='s',radix='\0'; bool offsets=false; int minimum=0,start=0,length=int.MaxValue;
                var paths=new List<string>();
                for(int i=0;i<args.Length;i++)
                {
                    string a=args[i];
                    if(!end && a=="--") {end=true;continue;}
                    if(end || a=="-" || !a.StartsWith("-")) {paths.Add(a);continue;}
                    string? v;
                    if(a=="-a") {asciiOnly=true;forceAll=true;}
                    else if(a=="--all") {gnu=true;forceAll=true;}
                    else if(a=="-q") {sys=true;quiet=true;}
                    else if(a=="-u" && sys) wideOnly=true;
                    else if(a=="-n" || a.StartsWith("--bytes=") || a.Length>2 && a.StartsWith("-n"))
                    {v=a.StartsWith("--bytes=")?a.Substring(8):a.Length>2?a.Substring(2):args.ElementAtOrDefault(++i);
                        if(!UtilityInt(v,out minimum)||minimum==0)return Missing("strings-minimum");}
                    else if(a.StartsWith("-e") || a.StartsWith("--encoding="))
                    {v=a.StartsWith("--encoding=")?a.Substring(11):a.Length>2?a.Substring(2):args.ElementAtOrDefault(++i);
                        if(v is not ("s" or "l" or "b" or "L" or "B")) return Missing("strings-encoding");
                        gnu=true;encoding=v[0];}
                    else if(a.StartsWith("-t") || a.StartsWith("--radix="))
                    {v=a.StartsWith("--radix=")?a.Substring(8):a.Length>2?a.Substring(2):args.ElementAtOrDefault(++i);
                        if(v is not ("d" or "o" or "x"))return Missing("strings-radix");gnu=true;offsets=true;radix=v[0];}
                    else if(sys && a is ("-f" or "-b"))
                    {if(!UtilityInt(args.ElementAtOrDefault(++i),out int n))return Missing("strings-range"); if(a=="-f")start=n;else length=n;}
                    else if(sys && a=="-o") offsets=true;
                    else return Missing("strings-dialect-or-option");
                }
                if(sys && gnu || asciiOnly && wideOnly) return Missing("strings-conflicting-modes");
                if(paths.Count==0) {if(sys)return Missing("strings-file-operand");paths.Add("-");gnu=true;}
                bool ambiguous=!sys&&!gnu;
                int min=minimum==0?(sys?3:4):minimum;
                IEnumerable<Payload> Rows()
                {
                    foreach(var path in paths)
                    {
                        if(!Budget()) {yield return Missing("strings-budget");yield break;}
                        var bytes=UtilityBytes(path,pipe,out var src);
                        if(bytes==null) {yield return Missing("strings-byte-input");continue;}
                        int stop=(int)Math.Min(bytes.Length,(long)start+length);
                        var inherited=FileRecordMarks(src);
                        // Without an all-data option GNU builds may consult object sections. Do not scan arbitrary
                        // sections and present their strings as confirmed stdout of the default invocation.
                        if(!sys && !forceAll && path!="-" && bytes.Any(b=>b!=0 && b!=9 && b!=10 && b!=13 && (b<32 || b>126)))
                        {yield return Missing("strings-object-sections");continue;}
                        var forms=sys && !asciiOnly && !wideOnly?new[]{'s','l'}:new[]{wideOnly?'l':encoding};
                        foreach(char form in forms)
                        {
                            int unit=form=='s'?1:form is 'l' or 'b'?2:4;
                            bool little=form is 'l' or 'L';
                            int pos=Math.Min(start,stop);
                            bool CharAt(int at,out char c)
                            {
                                c=default;if(at<0 || at>stop-unit)return false;
                                int k=form=='s'||little?at:at+unit-1;byte b=bytes[k];
                                if(b<32 && !(gnu && b==9) || b>126)return false;
                                for(int j=at;j<at+unit;j++)if(j!=k && bytes[j]!=0)return false;
                                c=(char)b;return true;
                            }
                            while(pos<stop)
                            {
                                if(!Budget()) {yield return Missing("strings-budget");yield break;}
                                int from=pos;var run=new StringBuilder();
                                while(CharAt(pos,out char c))
                                {
                                    if(run.Length>=MaxContent/sizeof(char) || (run.Length&1023)==0 && !Budget())
                                    {yield return Missing("strings-output-limit");yield break;}
                                    run.Append(c);pos+=unit;
                                }
                                if(run.Length>=min)
                                {
                                    var value=Text(run.ToString(),src.SourceRef,inherited);
                                    if(gnu && offsets) value=Text(DumpDigits(from,radix,1).PadLeft(7)+" "+run,src.SourceRef,inherited);
                                    if(ambiguous || sys && offsets) yield return UnknownValue("strings-edition-or-offset-format",value);
                                    else yield return value;
                                }
                                if(from==pos)pos++; // Wide runs can start at an unaligned byte offset.
                            }
                        }
                        if(ambiguous || sys && (!quiet || forms.Length!=1))yield return Missing("strings-edition-banner-or-wide-order");
                    }
                }
                return UtilityRows(Rows(),tool);
            }
        }
    }
}

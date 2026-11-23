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
            byte[]? UtilityBytes(string path, Payload? pipe, out Payload src)
            {
                Disk.Sample? sample = null;
                src = path == "-" ? pipe ?? Missing("native-stdin-not-observed") :
                    File(path, false, out sample, forceBytes: true, inspectArchive: false);
                return src.InspectionPartial || src.MayReadOriginal || src.Issue is "copy-stale" or "copy-generation" ?
                    null : sample?.Bytes ?? src.Bytes;
            }
            long? UtilitySize(string operand, Payload? pipe)
            {
                if (operand == "-") return pipe?.InspectionPartial == false ? pipe.Bytes?.LongLength : null;
                string? path = Disk.Bind(operand, cwd);
                if (path == null || barrier || PendingFiles.ContainsKey(path) || UncertainFileTree(Path.GetDirectoryName(path))) return null;
                if (predictedWrites.TryGetValue(path, out var p))
                    return p.MayReadOriginal || p.InspectionPartial || p.Issue == "file-moved" ? null : p.Bytes?.LongLength;
                if (plannedFiles.Contains(path) || !BeginFile()) return null;
                try { return Disk.ResolveLocalPath(path, () => FileTimeAvailable) is string file ? new FileInfo(file).Length : null; }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException) { return null; }
            }
            // Output records, not the input file's marks. A missing record may stand for zero or many rows.
            Payload UtilityRows(IEnumerable<Payload> rows, string origin, bool uncertainOrder = false)
            {
                var kept = new List<Payload>();
                var tags = new Dictionary<(string,string),Mark>();
                int? gap = null;
                long chars = 0, count = 0;
                bool countKnown = true;
                string issue = "";
                foreach (var row in rows)
                {
                    foreach (var mark in row.Tags) tags[(mark.Id, mark.Origin)] = mark;
                    count++;
                    if (!row.Complete || row.InspectionPartial || row.Text == null)
                    { countKnown = false; gap ??= kept.Count; if (issue.Length == 0) issue = row.Issue; }
                    chars += (row.Text?.Length ?? 0) + 1L;
                    if (kept.Count < Limits.MaxCollection && chars <= MaxContent / sizeof(char)) kept.Add(row);
                    else { gap ??= kept.Count; issue = "native-output-limit"; }
                    if (!Budget()) { countKnown = false; issue = "native-read-budget"; gap ??= kept.Count; break; }
                }
                bool order = uncertainOrder && count > 1;
                if (order && issue.Length == 0) issue = "native-sort-collation";
                if (!order && gap == null && kept.Count == 1) return kept[0];
                return new Payload { Elements = kept.ToArray(), RecordCount = countKnown ? count : null, FirstUncertainIndex = order ? 0 : gap,
                    RecordRemainder = gap == null ? null : Missing(issue), Complete = gap == null && !order, InspectionPartial = gap != null || order,
                    Tags = Merge(tags.Values), SourceRef = origin, Issue = issue };
            }

            static bool UtilityInt(string? s, out int n) => int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out n);
            Payload TextTool(string tool, string[] args, Payload? pipe)
            {
                var operands = new List<string>();
                bool end = false, repeat = false, unique = false, ignoreCase = false, countPrefix = false, reverse = false;
                var columns = new HashSet<char>();
                string style = "t", align = "rn", sep = "\t";
                int width = 6, first = 1, inc = 1;
                for (int i = 0; i < args.Length; i++)
                {
                    var arg = args[i];
                    if (!end && arg == "--") { end = true; continue; }
                    if (tool == "sort" && !end && (arg.Equals("/O", StringComparison.OrdinalIgnoreCase) || arg == "-o" || arg == "--output" || arg.StartsWith("--output=")))
                        return UncertainWrite("native-sort-output-file", arg.StartsWith("--output=") ? arg.Substring(9) : args.ElementAtOrDefault(i+1));
                    if (!end && ((arg.Length > 1 && arg[0] == '-') || tool == "sort" && arg.StartsWith("/")))
                    {
                        if (tool == "wc")
                        {
                            var flags = arg switch { "--bytes" => "c", "--lines" => "l", "--words" => "w",
                                "--chars" => "m", "--max-line-length" => "L", _ => arg.Substring(1) };
                            if (flags.Any(c => !"clwmL".Contains(c))) return Missing("wc-option");
                            foreach (char c in flags) columns.Add(c);
                        }
                        else if (tool == "uniq")
                        {
                            var flags = arg switch { "--count" => "c", "--repeated" => "d", "--unique" => "u",
                                "--ignore-case" => "i", _ => arg.Substring(1) };
                            if (flags.Any(c => !"cdui".Contains(c))) return Missing("uniq-option");
                            countPrefix |= flags.Contains('c'); repeat |= flags.Contains('d'); unique |= flags.Contains('u'); ignoreCase |= flags.Contains('i');
                        }
                        else if (tool == "sort")
                        {
                            if (arg.Equals("/R", StringComparison.OrdinalIgnoreCase) || arg is "-r" or "--reverse") reverse = true;
                            else if (arg is "-u" or "--unique") unique = true;
                            else return Missing("sort-option-or-dialect");
                        }
                        else
                        {
                            if (arg.Length < 2 || !"bnwvis".Contains(arg[1])) return Missing("nl-option");
                            string? v = arg.Length > 2 ? arg.Substring(2) : args.ElementAtOrDefault(++i);
                            if (v == null || v.Length > Limits.MaxFilter) return Missing("nl-option-value");
                            switch (arg[1])
                            {
                                case 'b': if (v is not ("a" or "t" or "n")) return Missing("nl-body-style"); style = v; break;
                                case 'n': if (v is not ("ln" or "rn" or "rz")) return Missing("nl-number-format"); align=v; break;
                                case 's': if (v.Any(char.IsControl) && v != "\t") return Missing("nl-separator"); sep=v; break;
                                case 'w': if (!UtilityInt(v,out width) || width > 128 || width == 0) return Missing("nl-width"); break;
                                case 'v': if (!UtilityInt(v,out first)) return Missing("nl-start"); break;
                                case 'i': if (!UtilityInt(v,out inc)) return Missing("nl-increment"); break;
                            }
                        }
                    }
                    else operands.Add(arg);
                }
                bool implicitStdin = operands.Count == 0;
                if (implicitStdin) operands.Add("-");
                if (operands.Count(n => n == "-") > 1) return Missing("native-stdin-reuse");
                if (tool == "uniq" && operands.Count > 1)
                {
                    if (operands.Count != 2) return Missing("uniq-operands");
                    if (operands[1] != "-") return UncertainWrite("native-uniq-output-file", operands[1]);
                    operands.RemoveAt(1);
                }
                if (tool == "wc") return WordCount(operands, columns, pipe, implicitStdin);
                var lines = new List<Payload>();
                long totalChars=0;
                foreach (var path in operands)
                {
                    var data = UtilityBytes(path, pipe, out var src);
                    string? body = null;
                    if (data != null)
                    {
                        try { body = StrictUtf8.GetString(data); }
                        catch (DecoderFallbackException) { }
                    }
                    else if (path == "-" && pipe != null && !pipe.InspectionPartial && pipe.FirstUncertainIndex == null)
                        body = pipe.PipeText ?? ExactString(pipe);
                    if (body == null || body.Contains('\0') || (totalChars += body.Length) > MaxContent / sizeof(char))
                        return Missing("native-text-input-or-limit");
                    var marks = FileRecordMarks(src);
                    int pos=0;
                    while (pos < body.Length)
                    {
                        if (lines.Count >= Limits.MaxLines || !Budget()) return Missing("native-text-record-limit");
                        int stop=body.IndexOf('\n',pos); if (stop<0) stop=body.Length;
                        // CR in CRLF is a record terminator to the PowerShell text consumer.
                        int last = stop>pos && stop<body.Length && body[stop-1]=='\r' ? stop-1 : stop;
                        var line=body.Substring(pos,last-pos);
                        if (line.Contains('\r')) return Missing("native-text-lone-cr");
                        lines.Add(Text(line,src.SourceRef,marks)); pos=stop+1;
                    }
                }
                if (tool == "sort")
                {
                    // Collation depends on the executable/locale. Keep witnessed members, not a fictitious order.
                    if (unique && lines.Any(p => p.Text!.Any(c => c > 127 || char.IsLetter(c))))
                        return Missing("native-sort-unique-collation");
                    var list=unique ? lines.GroupBy(p=>p.Text,StringComparer.Ordinal).Select(g=>g.First()).ToList() : lines;
                    if (reverse) list.Reverse();
                    return UtilityRows(list, tool, uncertainOrder:true);
                }
                IEnumerable<Payload> Output()
                {
                    if (tool == "uniq")
                    {
                        if (ignoreCase && lines.Any(p=>p.Text!.Any(c=>c>127))) { yield return Missing("uniq-case-locale"); yield break; }
                        for (int i=0; i<lines.Count;)
                        {
                            int j=i+1; while (j<lines.Count && string.Equals(lines[j].Text,lines[i].Text,
                                ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)) j++;
                            if ((!repeat || j-i>1) && (!unique || j-i==1))
                                yield return countPrefix ? Text((j-i).ToString(CultureInfo.InvariantCulture).PadLeft(7)+" "+lines[i].Text,
                                    lines[i].SourceRef,FileRecordMarks(lines[i])) : lines[i];
                            i=j;
                        }
                        yield break;
                    }
                    long number=first; string section="body";
                    foreach (var p in lines)
                    {
                        if (!Budget()) { yield return Missing("nl-budget"); yield break; }
                        var s=p.Text!;
                        if (s is "\\:\\:\\:" or "\\:\\:" or "\\:")
                        {
                            section=s.Length==6?"header":s.Length==4?"body":"footer";
                            number=first;
                            yield return Text("", "nl page separator"); continue;
                        }
                        bool numbered= section=="body" && (style=="a" || style=="t" && s.Length!=0);
                        string prefix;
                        if (numbered)
                        {
                            var n=number.ToString(CultureInfo.InvariantCulture);
                            prefix=(align=="ln"?n.PadRight(width):n.PadLeft(width,align=="rz"?'0':' '))+sep;
                            number+=inc;
                        }
                        else prefix=new string(' ',width+sep.Length);
                        yield return Text(prefix+s,p.SourceRef,FileRecordMarks(p));
                    }
                }
                return UtilityRows(Output(),tool);
            }

            Payload WordCount(List<string> paths, HashSet<char> flags, Payload? pipe, bool implicitStdin)
            {
                if (flags.Count==0) flags.UnionWith("lwc");
                var ids = "lwmcL".Where(flags.Contains).ToArray();
                var rows = new List<(string? Name, long?[] Values)>();
                long grandSize=0;
                bool sizesKnown=true;
                foreach (var path in paths)
                {
                    if (!Budget()) return Missing("wc-budget");
                    long? size; byte[]? data=null;
                    if (ids.Length==1 && ids[0]=='c') size=UtilitySize(path,pipe);
                    else { data=UtilityBytes(path,pipe,out _); size=data?.LongLength; }
                    if (size==null || long.MaxValue-grandSize<size) sizesKnown=false; else grandSize+=size.Value;
                    long lf=0,words=0,longest=0,col=0; bool inWord=false,ascii=true;
                    if (data!=null)
                    for (int i=0;i<data.Length;i++)
                    {
                        if ((i&1023)==0 && !Budget()) return Missing("wc-budget");
                        byte b=data[i]; if(b>=128) ascii=false;
                        if(b==10) lf++;
                        bool white=b==32 || b is >=9 and <=13;
                        if(!white && !inWord) words++; inWord=!white;
                        if(b is 10 or 13 or 12) { longest=Math.Max(col,longest); col=0; }
                        else if (b==9) col+=8-col%8;
                        else if (b>=32 && b!=127) col++;
                    }
                    longest=Math.Max(longest,col);
                    rows.Add((implicitStdin?null:path, ids.Select(c => c switch { 'c'=>size, 'l' when data!=null=>lf,
                        'w' when data!=null && ascii=>words, 'm' when ascii && data!=null=>size, 'L' when data!=null && ascii=>longest,_=>(long?)null }).ToArray()));
                }
                if (rows.Count>1)
                {
                    long?[] totals=new long?[ids.Length];
                    for(int i=0;i<ids.Length;i++)
                    {
                        var values=rows.Select(r=>r.Values[i]).ToArray();
                        if(values.All(v=>v.HasValue)) totals[i]=ids[i]=='L'?values.Max():sizesKnown?values.Sum():null;
                    }
                    rows.Add(("total",totals));
                }
                // GNU wc pads multi-column reports to the width of total regular file size; pipes have no stat size.
                bool pipeSize=paths.Contains("-");
                int pad=implicitStdin || paths.Count==1 && ids.Length==1?1:Math.Max(pipeSize?7:1,grandSize.ToString(CultureInfo.InvariantCulture).Length);
                IEnumerable<Payload> Output()
                {
                    foreach(var r in rows)
                    {
                        var tokens=r.Values.Where(v=>v.HasValue).Select(v=>Text(v!.Value.ToString(CultureInfo.InvariantCulture),"wc count")).ToList();
                        if (tokens.Count!=r.Values.Length || !sizesKnown || pipeSize && paths.Count>1 || r.Name?.Any(char.IsControl)==true)
                        { yield return UnknownValue("wc-count-or-format",tokens.ToArray()); continue; }
                        string value=string.Join(" ",tokens.Select(p=>p.Text!.PadLeft(pad)))+(r.Name!=null?" "+r.Name:"");
                        // Counts and supplied filenames are metadata. Never copy content/path-origin labels to them.
                        yield return Text(value,"wc report");
                    }
                }
                return UtilityRows(Output(),"wc");
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            static readonly HashSet<string> NativeReaders = new HashSet<string>(new[] {
                "cat", "head", "tail", "more", "less", "cmd", "grep", "rg", "find", "findstr", "cut", "xxd", "sed", "awk", "jq",
                "reg", "wevtutil", "certutil", "tar", "bsdtar", "7z", "7za", "7zz",
                "tasklist", "systeminfo", "hostname", "whoami", "ipconfig", "printenv",
                "wc", "nl", "uniq", "sort", "od", "hexdump", "hd", "strings", "strings64", "strings64a", "unzip", "zipinfo",
                "gzip", "gunzip", "zcat", "bzip2", "bunzip2", "bzcat", "xz", "unxz", "xzcat",
                "where", "ls", "stat", "tree"
            }, StringComparer.Ordinal);

            // This is an argument/record model. Never spawn a shell, open a device,
            // or probe an executable while the host is in its AMSI callback.
            Payload NativeRead(object command, string tool, Payload? pipe)
            {
                var argv = FlattenNative(command, out _);
                if (argv.Length > Limits.MaxArguments || argv.Any(a => a == null)) return Missing(tool + "-reader-arguments");
                var tokens = argv.Select(a => a!).ToArray();
                if (tool is "where" or "ls" or "stat" or "tree") return DirectoryTool(tool,tokens);
                if (tool is "gzip" or "gunzip" or "zcat" or "bzip2" or "bunzip2" or "bzcat" or "xz" or "unxz" or "xzcat")
                    return CompressionRead(tool, tokens, pipe);
                if (tool is "wc" or "nl" or "uniq" or "sort") return TextTool(tool, tokens, pipe);
                if (tool is "od" or "hexdump" or "hd" or "strings" or "strings64" or "strings64a")
                    return DumpTool(tool, tokens, pipe);
                if (tool is "tar" or "bsdtar" or "7z" or "7za" or "7zz" or "unzip" or "zipinfo") return NativeArchive(tool, tokens, pipe);
                if (tool is "sed" or "awk" or "jq") return FilterRead(tool, tokens, pipe);
                if (tool is "reg" or "wevtutil" or "certutil") return NativeLocalSource(tool, tokens, pipe);
                if (tool is "tasklist" or "systeminfo" or "hostname" or "whoami" or "ipconfig")
                    return NativeSystemReport(tool, tokens);
                if (tool == "printenv") return NativeEnvironment(tokens, false);
                int start = 0;
                if (tool == "cmd")
                {
                    while (start < tokens.Length && new[] { "/d", "/q" }.Contains(tokens[start], StringComparer.OrdinalIgnoreCase)) start++;
                    if(start+1<tokens.Length && tokens[start].Equals("/c",StringComparison.OrdinalIgnoreCase) &&
                        tokens[start+1].Equals("dir",StringComparison.OrdinalIgnoreCase))
                        return DirectoryTool("dir",tokens.Skip(start+2).ToArray());
                    if (start + 1 < tokens.Length && tokens[start].Equals("/c", StringComparison.OrdinalIgnoreCase) &&
                        tokens[start + 1].Equals("set", StringComparison.OrdinalIgnoreCase))
                        return NativeEnvironment(tokens.Skip(start + 2).ToArray(), true);
                    if (start + 2 >= tokens.Length || !tokens[start++].Equals("/c", StringComparison.OrdinalIgnoreCase) ||
                        !tokens[start++].Equals("type", StringComparison.OrdinalIgnoreCase) ||
                        tokens.Skip(start).Any(t => t.IndexOfAny("&|<>^%!()\"\r\n*?".ToCharArray()) >= 0 || t.StartsWith("/")))
                        return Missing("unsupported-propagation");
                }
                var paths = new List<string>();
                var expressions = new List<string>();
                string? cutRange = null, cutDelimiter = null;
                int take = 10, offset = 0, byteLimit = int.MaxValue, columns = 0, group = 2;
                bool count = false, filesOnly = false, quiet = false, inverse = false, insensitive = false,
                    fixedText = false, positional = false, fromLine = false, onlyDelimited = false, plainHex = false, lineNumbers = false;
                bool search = tool is "grep" or "rg" or "find" or "findstr";
                for (int i = start; i < tokens.Length; i++)
                {
                    var t = tokens[i];
                    bool windows = tool is "find" or "findstr" or "more";
                    if (t == "--" && !windows && !positional) { positional = true; continue; }
                    if (!positional && t.Length > 1 && (t[0] == '-' || windows && t[0] == '/'))
                    {
                        if (tool is "head" or "tail")
                        {
                            string? value = t is "-n" or "--lines" ? tokens.ElementAtOrDefault(++i) :
                                t.StartsWith("--lines=", StringComparison.Ordinal) ? t.Substring(8) :
                                t.StartsWith("-n", StringComparison.Ordinal) ? t.Substring(2) : t.Substring(1);
                            fromLine = value?.StartsWith("+", StringComparison.Ordinal) == true;
                            if (fromLine && tool != "tail" || !int.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out take) ||
                                take < 0) return Missing(tool + "-line-count");
                        }
                        else if (tool is "grep" or "rg")
                        {
                            switch (t)
                            {
                                case "-e": case "--regexp": if (++i >= tokens.Length) return Missing("search-pattern"); expressions.Add(tokens[i]); break;
                                case "-F": case "--fixed-strings": fixedText = true; break;
                                case "-i": case "--ignore-case": insensitive = true; break;
                                case "-v": case "--invert-match": inverse = true; break;
                                case "-q": case "--quiet": quiet = true; break;
                                case "-l": case "--files-with-matches": filesOnly = true; break;
                                case "-c": case "--count": count = true; break;
                                case "-n": case "--line-number": lineNumbers = true; break;
                                default: return Missing(tool + "-reader-option");
                            }
                        }
                        else if (tool is "find" or "findstr")
                        {
                            switch (t.ToUpperInvariant())
                            {
                                case "/I": insensitive = true; break;
                                case "/V": inverse = true; break;
                                case "/N": lineNumbers = true; break;
                                case "/C" when tool == "find": count = true; break;
                                case "/M" when tool == "findstr": filesOnly = true; break;
                                case "/L" when tool == "findstr": fixedText = true; break;
                                default:
                                    if (tool != "findstr" || !t.StartsWith("/C:", StringComparison.OrdinalIgnoreCase)) return Missing(tool + "-reader-option");
                                    fixedText = true; expressions.Add(t.Substring(3)); break;
                            }
                        }
                        else if (tool == "cut")
                        {
                            if (t == "-s" || t == "--only-delimited") onlyDelimited = true;
                            else if (t.StartsWith("-d", StringComparison.Ordinal)) cutDelimiter = t.Length == 2 ? tokens.ElementAtOrDefault(++i) : t.Substring(2);
                            else if (t.StartsWith("-f", StringComparison.Ordinal)) cutRange = t.Length == 2 ? tokens.ElementAtOrDefault(++i) : t.Substring(2);
                            else return Missing("cut-fields");
                        }
                        else if (tool == "xxd")
                        {
                            if (t == "-p" || t == "-plain") plainHex = true;
                            else if (t is "-s" or "-l" or "-c" or "-g")
                            {
                                if (!int.TryParse(tokens.ElementAtOrDefault(++i), NumberStyles.None, CultureInfo.InvariantCulture, out int n))
                                    return Missing("xxd-range");
                                if (t == "-s") offset = n;
                                else if (t == "-l") byteLimit = n;
                                else if (n > 256 || t == "-c" && n == 0) return Missing("xxd-width");
                                else if (t == "-c") columns = n;
                                else group = n;
                            }
                            else return Missing("xxd-option");
                        }
                        else return Missing(tool + "-reader-option");
                        continue;
                    }
                    if (search && expressions.Count == 0)
                    {
                        if (tool == "findstr" && !fixedText) expressions.AddRange(t.Split(' ', StringSplitOptions.RemoveEmptyEntries));
                        else expressions.Add(t);
                    }
                    else paths.Add(t);
                }
                if (search && expressions.Count == 0) return Missing("search-pattern");
                // ripgrep without an operand can walk the working tree; do not start
                // a scan-time enumeration in lieu of an explicitly named file.
                if (paths.Count == 0 && pipe == null) return Missing(tool + "-reader-input");
                if (paths.Count == 0) paths.Add("-");
                if (quiet) return new Payload { Complete = true, Elements = Array.Empty<Payload>(), SourceRef = tool + " quiet" };
                if (tool == "xxd" && paths.Count != 1) return Missing("xxd-output-shape");
                var regex = new List<Regex>();
                foreach (var pattern in expressions)
                {
                    if (pattern.Length > Limits.MaxFilter) return Missing("search-pattern-limit");
                    var literal = fixedText || tool == "find";
                    // POSIX BRE, findstr and ripgrep use different regex dialects.
                    // The common literal, dot, anchor and star subset is unambiguous.
                    if (!literal && pattern.IndexOfAny(@"\[]()+?|{}".ToCharArray()) >= 0) return Missing("native-regex-dialect");
                    try { regex.Add(new Regex(literal ? Regex.Escape(pattern) : pattern,
                        insensitive ? RegexOptions.IgnoreCase | RegexOptions.CultureInvariant : RegexOptions.CultureInvariant,
                        TimeSpan.FromMilliseconds(Math.Max(1, Math.Min(50, Limits.FileScanBudgetMs))))); }
                    catch (ArgumentException) { return Missing("native-regex"); }
                }
                int lo = 0, hi = 0;
                if (tool == "cut")
                {
                    cutDelimiter ??= "\t";
                    var fields = cutRange?.Split('-');
                    if (cutDelimiter.Length != 1 || fields == null || fields.Length > 2 ||
                        !int.TryParse(fields[0], NumberStyles.None, CultureInfo.InvariantCulture, out lo) || lo < 1) return Missing("cut-fields");
                    if (fields.Length == 1) hi = lo;
                    else if (fields[1].Length == 0) hi = int.MaxValue;
                    else if (!int.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out hi) || hi < lo) return Missing("cut-fields");
                }
                IEnumerable<Payload> Records()
                {
                    foreach (var path in paths)
                    {
                        if (!Budget()) { yield return Missing("native-read-budget"); yield break; }
                        bool stdin = path == "-" && tool != "cmd";
                        if (tool == "xxd")
                        {
                            Disk.Sample? sample = null;
                            var source = stdin ? pipe : File(path, false, out sample, forceBytes: true, inspectArchive: false);
                            var bytes = sample?.Bytes ?? source?.Bytes;
                            if (bytes == null || source == null || source.InspectionPartial) { yield return Missing("xxd-bytes"); continue; }
                            int end = (int)Math.Min(bytes.Length, (long)offset + byteLimit);
                            var origins = FileRecordMarks(source);
                            for (int i = offset; i < end;)
                            {
                                if (!Budget()) { yield return Missing("xxd-budget"); yield break; }
                                int width = columns == 0 ? (plainHex ? 30 : 16) : columns;
                                int n = Math.Min(width, end - i);
                                var part = new byte[n]; Buffer.BlockCopy(bytes, i, part, 0, n);
                                var segmentMarks = Bytes(part, source.SourceRef, origins).Tags;
                                string hex = BitConverter.ToString(part).Replace("-", "").ToLowerInvariant();
                                if (!plainHex)
                                {
                                    int step = group == 0 ? width : group;
                                    hex = string.Join(" ", Enumerable.Range(0, (n + step - 1) / step)
                                        .Select(k => hex.Substring(2 * k * step, 2 * Math.Min(step, n - k * step))));
                                    hex = i.ToString("x8", CultureInfo.InvariantCulture) + ": " +
                                        hex.PadRight(width * 2 + (width - 1) / step) + "  " +
                                        new string(part.Select(b => b >= 32 && b < 127 ? (char)b : '.').ToArray());
                                }
                                yield return Text(hex, source.SourceRef, segmentMarks);
                                i += n;
                            }
                            continue;
                        }
                        var src = stdin ? pipe : File(path, true, out _);
                        if (src == null) { yield return Missing("native-read-stdin"); continue; }
                        if (tool is "cat" or "cmd" or "more" or "less") { yield return src.Via(tool + " read"); continue; }
                        if ((src.PipeText ?? src.Text) is not string text || !src.Complete || src.InspectionPartial)
                        { yield return Missing("native-records-not-materialized"); continue; }
                        using var reader = new StringReader(text);
                        var records = new List<string>();
                        string? line;
                        while (records.Count < Limits.MaxLines && (line = reader.ReadLine()) != null) records.Add(line);
                        bool truncated = reader.Peek() >= 0;
                        if (truncated && (tool == "tail" && !fromLine || count || filesOnly)) { yield return Missing("native-record-limit"); continue; }
                        var marks = FileRecordMarks(src);
                        var selected = tool == "head" ? records.Take(take) : tool == "tail" ?
                            (fromLine ? records.Skip(Math.Max(0, take - 1)) : records.TakeLast(take)) : records.AsEnumerable();
                        int hits = 0, number = 0;
                        foreach (var s in selected)
                        {
                            if (!Budget()) { yield return Missing("native-read-budget"); yield break; }
                            number++;
                            if (tool == "cut")
                            {
                                var cols = s.Split(cutDelimiter![0]);
                                if (cols.Length == 1 && onlyDelimited) continue;
                                yield return Text(cols.Length == 1 ? s : string.Join(cutDelimiter, cols.Skip(lo - 1).Take(hi - lo + 1)), src.SourceRef, marks);
                            }
                            else if (search)
                            {
                                bool? matched;
                                try { matched = regex.Any(p => p.IsMatch(s)); }
                                catch (RegexMatchTimeoutException) { matched = null; }
                                if (matched == null) { yield return Missing("native-regex-budget"); yield break; }
                                if (matched == inverse) continue;
                                hits++;
                                if (filesOnly) { yield return Text(stdin ? "(standard input)" : path, "matched filename"); break; }
                                if (!count) yield return Text(lineNumbers ? number.ToString(CultureInfo.InvariantCulture) + ":" + s : s, src.SourceRef, marks);
                            }
                            else yield return Text(s, src.SourceRef, marks);
                        }
                        if (count && !filesOnly) yield return Text(hits.ToString(CultureInfo.InvariantCulture), "match count");
                        if (truncated && !(tool == "head" && records.Count >= take)) yield return Missing("native-record-limit");
                    }
                }
                return ReadOutput(Records(), tool);
            }
        }
    }
}

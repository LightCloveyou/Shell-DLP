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
            Payload Number(long value) => new Payload { Text = value.ToString(CultureInfo.InvariantCulture),
                Complete = true, NumericType = "Int64", ScalarTruth = value != 0 };
            static bool CountValue(Payload p, out int n)
            {
                n = 0;
                return p.Complete && int.TryParse(p.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out n) && n >= 0;
            }

            Payload SearchText(object command, Payload? pipe)
            {
                using var args = new Args(this, command, Paths.Concat(new[] { "Pattern", "InputObject", "Context", "Include", "Exclude" }).ToArray(),
                    new[] { "SimpleMatch", "CaseSensitive", "NotMatch", "Quiet", "Raw", "List" });
                int pos = 0;
                var pat = args.Get("Pattern") ?? args.Plain.ElementAtOrDefault(pos++);
                var path = args.Get("LiteralPath") ?? args.Get("Path");
                if (path == null && pos < args.Plain.Count) path = args.Plain[pos++];
                var obj = args.Get("InputObject");
                if (!args.Valid || pat == null || pos != args.Plain.Count || args.Has("LiteralPath") && args.Has("Path") ||
                    (path != null ? 1 : 0) + (obj != null ? 1 : 0) + (pipe != null ? 1 : 0) != 1 ||
                    args.Has("Quiet") && args.Has("Raw")) return Missing("select-string-binding");
                var patternValue = Value(pat);
                var patterns = (patternValue.Elements ?? new[] { patternValue }).Select(ExactString).ToArray();
                if (!patternValue.Complete || patternValue.InspectionPartial || patterns.Length == 0 ||
                    patterns.Any(p => p == null || p.Length > Limits.MaxFilter)) return Missing("select-string-pattern");
                var options = args.Has("CaseSensitive") ? RegexOptions.None : RegexOptions.IgnoreCase;
                Regex[] filters;
                try { filters = patterns.Select(p => new Regex(args.Has("SimpleMatch") ? Regex.Escape(p!) : p!, options,
                    TimeSpan.FromMilliseconds(Math.Max(1, Math.Min(50, Limits.FileScanBudgetMs))))).ToArray(); }
                catch (ArgumentException) { return Missing("select-string-pattern"); }
                int pre = 0, post = 0;
                if (args.Has("Context"))
                {
                    var counts = Value(args.Get("Context"));
                    var n = counts.Elements ?? new[] { counts };
                    if (n.Length is < 1 or > 2 || !CountValue(n[0], out pre) || !CountValue(n[n.Length - 1], out post) ||
                        Math.Max(pre, post) > Limits.MaxCollection || path == null) return Missing("select-string-context");
                }
                var input = path != null ? Value(path) : obj != null ? Value(obj) : pipe!;
                bool quiet = args.Has("Quiet"), inverse = args.Has("NotMatch");
                IEnumerable<Payload> Matches()
                {
                    long inputLine = 0;
                    var items = path == null ? input.Files?.Records ?? input.Elements ?? new[] { input } : SelectFilePaths(input, args);
                    foreach (var item in items)
                    {
                        if (!Budget()) { yield return Missing("select-string-budget"); yield break; }
                        bool file = path != null || item.FileObject != null;
                        if (item.FileObject?.Kind == PathKind.DirectoryInfo) continue;
                        var src = file ? ReadFileArgument(item, true) : item;
                        var text = src.PipeText ?? src.Text;
                        if (!src.Complete || text == null || src.InspectionPartial || item.InspectionPartial)
                        { yield return Missing("select-string-input"); continue; }
                        bool lines = file || src.PipeText != null;
                        var all = new List<string>();
                        bool cut = false;
                        if (lines)
                        {
                            using var reader = new StringReader(text);
                            while (reader.ReadLine() is string line)
                            {
                                if (all.Count >= Limits.MaxLines || !Budget()) { cut = true; break; }
                                all.Add(line);
                            }
                        }
                        else all.Add(text);
                        var marks = FileRecordMarks(src);
                        for (int i = 0; i < all.Count; i++)
                        {
                            inputLine++;
                            int hit = -1;
                            bool timedOut = false;
                            for (int k = 0; k < filters.Length; k++)
                            {
                                if (!Budget()) { timedOut = true; break; }
                                try { if (filters[k].IsMatch(all[i])) { hit = k; break; } }
                                catch (RegexMatchTimeoutException) { timedOut = true; break; }
                            }
                            if (timedOut) { yield return Missing("select-string-budget"); yield break; }
                            if ((hit >= 0) == inverse) continue;
                            if (quiet) { yield return new Payload { Text = "True", Complete = true, ScalarTruth = true }; yield break; }
                            var line = Text(all[i], src.SourceRef, marks);
                            if (args.Has("Raw")) yield return line;
                            else
                            {
                                var filename = file ? item.FileObject?.Path ?? Disk.Bind(item.Text, cwd) : "InputStream";
                                var match = ReadObject("MatchInfo", ("Line", line), ("LineNumber", Number(file ? i + 1 : inputLine)),
                                    ("Pattern", Text(patterns[Math.Max(0, hit)], "search pattern")), ("Path", Text(filename, "match path")),
                                    ("Filename", Text(Path.GetFileName(filename), "match filename")));
                                match.Tags = line.Tags;
                                if (args.Has("Context"))
                                {
                                    Payload Window(int start, int end) => CollectElements(all.Skip(start).Take(end - start)
                                        .Select(s => Text(s, src.SourceRef, marks)));
                                    match.Map!["Context"] = ReadObject("MatchInfoContext",
                                        ("PreContext", Window(Math.Max(0, i - pre), i)), ("PostContext", Window(i + 1, Math.Min(all.Count, i + 1 + post))));
                                }
                                yield return match;
                            }
                            if (args.Has("List")) break;
                        }
                        if (cut) yield return Missing("select-string-line-limit");
                    }
                    if (input.InspectionPartial) yield return Missing("select-string-input");
                }
                return ReadOutput(Matches(), "Select-String");
            }

            Payload FormatHex(object command, Payload? pipe)
            {
                using var args = new Args(this, command, Paths.Concat(new[] { "InputObject", "Offset", "Count" }).ToArray(), Empty);
                var path = PathArg(args, 0, out int count);
                var obj = args.Get("InputObject");
                if (!args.Valid || args.Has("Path") && args.Has("LiteralPath") || args.Plain.Count != (path == null ? 0 : count) ||
                    (path != null ? 1 : 0) + (obj != null ? 1 : 0) + (pipe != null ? 1 : 0) != 1) return Missing("hex-binding");
                int offset = 0, length = int.MaxValue;
                if (args.Has("Offset") && !CountValue(Value(args.Get("Offset")), out offset) ||
                    args.Has("Count") && !CountValue(Value(args.Get("Count")), out length)) return Missing("hex-range");
                var input = path != null ? Value(path) : obj != null ? Value(obj) : pipe!;
                IEnumerable<Payload> Rows()
                {
                    var items = path != null ? SelectFilePaths(input, args) : input.Files?.Records ?? input.Elements ?? new[] { input };
                    foreach (var item in items)
                    {
                        var file = path != null || item.FileObject != null;
                        if (!Budget()) { yield return Missing("hex-budget"); yield break; }
                        var raw = item.FileObject?.Path ?? item.Text;
                        var source = item;
                        byte[]? bytes;
                        if (file)
                        {
                            source = File(raw, false, out var sample, forceBytes: true);
                            bytes = sample?.Bytes ?? source.Bytes;
                        }
                        else bytes = item.Bytes ?? (ExactString(item) is string s ? StrictUtf8.GetBytes(s) : null);
                        if (bytes == null || item.InspectionPartial) { yield return Missing("hex-input"); continue; }
                        var marks = FileRecordMarks(source);
                        var end = Math.Min((long)bytes.Length, (long)offset + length);
                        for (int i = offset; i < end;)
                        {
                            if (!Budget()) { yield return Missing("hex-budget"); yield break; }
                            int size = (int)Math.Min(16, end - i);
                            var data = new byte[size]; Buffer.BlockCopy(bytes, i, data, 0, size);
                            var part = Bytes(data, source.SourceRef, marks);
                            var row = ReadObject("ByteCollection", ("Bytes", part), ("Offset", Number(i)),
                                ("Path", file ? Text(Disk.Bind(raw, cwd), "hex source path") : Missing("hex-no-file")));
                            row.Tags = part.Tags;
                            yield return row;
                            i += size;
                        }
                    }
                }
                return ReadOutput(Rows(), "Format-Hex");
            }
        }
    }
}

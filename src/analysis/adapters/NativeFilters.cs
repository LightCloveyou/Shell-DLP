using System;
using System.Collections.Generic;
using System.Globalization;
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
            // Inspect a small, explicit data-selection grammar; never evaluate filter programs.
            Payload FilterInput(string path, Payload? pipe)
            {
                if (path != "-") return File(path, true, out _);
                if (pipe == null || pipe.InspectionPartial || pipe.RecordRemainder != null || pipe.FirstUncertainIndex != null) return Missing("filter-stdin");
                if (pipe.Bytes is byte[] bytes)
                    return Text(Disk.Decode(bytes), pipe.SourceRef, FileRecordMarks(pipe));
                if (pipe.PipeText is string wire) return Text(wire, pipe.SourceRef, FileRecordMarks(pipe));
                if (pipe.Elements == null) return pipe;
                var text = new StringBuilder();
                Mark[]? origins = null;
                foreach (var item in pipe.Elements)
                {
                    var tags = FileRecordMarks(item);
                    if (origins != null && !origins.Select(t => (t.Id, t.Origin)).SequenceEqual(tags.Select(t => (t.Id, t.Origin))))
                        return UnknownValue("filter-mixed-record-origins", pipe);
                    origins = tags;
                    if (!Budget() || !item.Complete || item.InspectionPartial || item.Text == null ||
                        (long)text.Length + item.Text.Length + 1 > MaxContent / 2) return Missing("filter-input-records");
                    text.Append(item.Text).Append('\n');
                }
                return Text(text.ToString(), pipe.SourceRef, origins);
            }

            static readonly TimeSpan FilterTimeout = TimeSpan.FromMilliseconds(30);
            static Regex? FilterPattern(string pattern)
            {
                // Only BRE/ERE syntax whose meaning is the same in both dialects and in .NET.
                if (pattern.Length > Limits.MaxFilter || pattern.IndexOfAny(@"\[]()+?|{}".ToCharArray()) >= 0) return null;
                try { return new Regex(pattern, RegexOptions.CultureInvariant, FilterTimeout); }
                catch (ArgumentException) { return null; }
            }
            Payload FilterRead(string tool, string[] args, Payload? pipe)
            {
                string? program = null, fs = null;
                bool quiet = false, raw = false, compact = false, endFlags = false;
                var paths = new List<string>();
                for (int i = 0; i < args.Length; i++)
                {
                    var a = args[i];
                    if (!endFlags && a == "--") { endFlags = true; continue; }
                    if (!endFlags && a.StartsWith("-", StringComparison.Ordinal) && a.Length > 1)
                    {
                        if (tool == "sed" && a is ("-n" or "--quiet" or "--silent")) quiet = true;
                        else if (tool == "sed" && a == "-e" && program == null && ++i < args.Length) program = args[i];
                        else if (tool == "awk" && a.StartsWith("-F", StringComparison.Ordinal) && fs == null)
                        {
                            fs = a.Length > 2 ? a.Substring(2) : ++i < args.Length ? args[i] : null;
                            if (fs == @"\t") fs = "\t";
                            if (fs == null || fs.Length != 1 || fs[0] > 127) return Missing("awk-field-separator");
                        }
                        else if (tool == "jq" && a is ("--raw-output" or "--compact-output" or "--monochrome-output" or "--exit-status"))
                        { raw |= a == "--raw-output"; compact |= a == "--compact-output"; }
                        else if (tool == "jq" && a.Skip(1).All(c => "rceM".Contains(c)))
                        { raw |= a.Contains('r'); compact |= a.Contains('c'); }
                        else return Missing(tool + "-filter-option");
                    }
                    else if (program == null) program = a;
                    else
                    {
                        if (tool == "awk" && a.Contains('=')) return Missing("awk-variable-binding");
                        paths.Add(a);
                    }
                }
                if (program == null || program.Length > Limits.MaxFilter) return Missing(tool + "-filter");
                if (paths.Count == 0) paths.Add("-");
                if (paths.Count(p => p == "-") > 1 || paths.Contains("-") && pipe == null) return Missing(tool + "-stdin");
                if (tool == "jq") return JqRead(program, paths, pipe, raw, compact);

                Regex? match = null;
                int lo = 1, hi = int.MaxValue;
                bool last = false, perFile = false;
                string? literal = null, replacement = null;
                bool global = false, print = false, delete = false, changedOnly = false;
                string[] fields = Array.Empty<string>();
                try
                {
                    if (tool == "sed")
                    {
                        var p = program.Trim();
                        var substitution = Regex.Match(p, @"^s/([^/]+)/([^/&\\]*)/(g?p?|pg)$", RegexOptions.CultureInvariant, FilterTimeout);
                        if (substitution.Success)
                        {
                            literal = substitution.Groups[1].Value; replacement = substitution.Groups[2].Value;
                            if (literal.IndexOfAny(@"\.*^$[]".ToCharArray()) >= 0) return Missing("sed-substitution-pattern");
                            var flags = substitution.Groups[3].Value;
                            global = flags.Contains('g'); print = flags.Contains('p'); changedOnly = true;
                        }
                        else
                        {
                            if (p.Length == 0 || p[p.Length - 1] is not ('p' or 'd')) return Missing("sed-script");
                            print = p[p.Length - 1] == 'p'; delete = !print;
                            var address = p.Substring(0, p.Length - 1).Trim();
                            if (address == "$") last = true;
                            else if (address.StartsWith("/") && address.EndsWith("/") && address.Length > 2)
                            {
                                var pattern = address.Substring(1, address.Length - 2);
                                if (pattern.Contains('/') || (match = FilterPattern(pattern)) == null) return Missing("sed-address-regex");
                            }
                            else if (address.Length != 0)
                            {
                                var range = address.Split(',');
                                if (range.Length > 2 || !int.TryParse(range[0], NumberStyles.None, CultureInfo.InvariantCulture, out lo) || lo < 1)
                                    return Missing("sed-address");
                                if (range.Length == 1) hi = lo;
                                else if (range[1] != "$")
                                {
                                    if (!int.TryParse(range[1], NumberStyles.None, CultureInfo.InvariantCulture, out hi) || hi < 1) return Missing("sed-address");
                                    hi = Math.Max(lo, hi);
                                }
                            }
                        }
                    }
                    else
                    {
                        var body = Regex.Match(program.Trim(), @"^(.*?)\{\s*print(?:\s+([^;{}]+?))?\s*;?\s*\}$", RegexOptions.CultureInvariant, FilterTimeout);
                        if (!body.Success) return Missing("awk-program");
                        var guard = body.Groups[1].Value.Trim();
                        if (guard.StartsWith("/") && guard.EndsWith("/") && guard.Length >= 2)
                        {
                            var pattern = guard.Substring(1, guard.Length - 2);
                            if (pattern.Contains('/') || (match = FilterPattern(pattern)) == null) return Missing("awk-pattern");
                        }
                        else if (guard.Length != 0)
                        {
                            var test = Regex.Match(guard, @"^(F?NR)\s*==\s*([0-9]+)$", RegexOptions.CultureInvariant, FilterTimeout);
                            if (!test.Success || !int.TryParse(test.Groups[2].Value, NumberStyles.None, CultureInfo.InvariantCulture, out lo)) return Missing("awk-condition");
                            hi = lo; perFile = test.Groups[1].Value == "FNR";
                        }
                        fields = body.Groups[2].Success ? body.Groups[2].Value.Split(',').Select(s => s.Trim()).ToArray() : new[] { "$0" };
                        if (fields.Length > Limits.MaxArguments || fields.Any(s => s is not ("NF" or "NR" or "FNR" or "$NF" or "$0") &&
                            !(s.Length > 1 && s[0] == '$' && int.TryParse(s.Substring(1), NumberStyles.None, CultureInfo.InvariantCulture, out _))))
                            return Missing("awk-print");
                    }
                }
                catch (RegexMatchTimeoutException) { return Missing(tool + "-program-budget"); }
                if (last && paths.Count != 1) return Missing("sed-last-across-files");

                IEnumerable<Payload> Rows()
                {
                    int total = 0;
                    foreach (string path in paths)
                    {
                        var src = FilterInput(path, pipe);
                        if (!src.Complete || src.InspectionPartial || src.Text == null)
                        { yield return UnknownValue("filter-input-not-materialized", src); yield break; }
                        var marks = FileRecordMarks(src);
                        using var reader = new StringReader(src.Text);
                        string? line;
                        int nr = 0;
                        while ((line = reader.ReadLine()) != null)
                        {
                            if (++total > Limits.MaxLines || !Budget()) { yield return Missing("filter-record-budget"); yield break; }
                            nr++;
                            int n = perFile ? nr : total;
                            bool? selected;
                            try { selected = lo <= n && n <= hi && (!last || reader.Peek() < 0) && (match == null || match.IsMatch(line)); }
                            catch (RegexMatchTimeoutException) { selected = null; }
                            if (selected == null) { yield return Missing("filter-regex-budget"); yield break; }
                            if (tool == "sed")
                            {
                                bool changed = false;
                                if (selected.Value && literal != null)
                                {
                                    int at = line.IndexOf(literal, StringComparison.Ordinal);
                                    changed = at >= 0;
                                    if (changed)
                                    {
                                        var dst = new StringBuilder(); int from = 0;
                                        while (at >= 0)
                                        {
                                            if ((long)dst.Length + at - from + replacement!.Length > MaxContent / 2 || !Budget())
                                            { yield return Missing("sed-output-budget"); yield break; }
                                            dst.Append(line, from, at - from).Append(replacement); from = at + literal.Length;
                                            at = global ? line.IndexOf(literal, from, StringComparison.Ordinal) : -1;
                                        }
                                        if ((long)dst.Length + line.Length - from > MaxContent / 2) { yield return Missing("sed-output-budget"); yield break; }
                                        line = dst.Append(line, from, line.Length - from).ToString();
                                    }
                                }
                                if (selected.Value && print && (!changedOnly || changed)) yield return Text(line, src.SourceRef, marks);
                                if (!quiet && !(selected.Value && delete)) yield return Text(line, src.SourceRef, marks);
                            }
                            else if (selected.Value)
                            {
                                var cols = (fs == null || fs == " ") ? line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries) :
                                    line.Length == 0 ? Array.Empty<string>() : line.Split(fs[0]);
                                string Column(string s)
                                {
                                    if (s == "$0") return line;
                                    if (s is "NR" or "FNR" or "NF") return (s == "NR" ? total : s == "FNR" ? nr : cols.Length).ToString(CultureInfo.InvariantCulture);
                                    if (s == "$NF") return cols.Length == 0 ? line : cols[cols.Length - 1];
                                    int i = int.Parse(s.Substring(1), CultureInfo.InvariantCulture);
                                    return i == 0 ? line : i <= cols.Length ? cols[i - 1] : "";
                                }
                                var pieces = fields.Select(Column).ToArray();
                                if (pieces.Sum(s => (long)s.Length + 1) > MaxContent / 2) { yield return Missing("awk-output-budget"); yield break; }
                                yield return Text(string.Join(" ", pieces), src.SourceRef, fields.Any(s => s[0] == '$') ? marks : Array.Empty<Mark>());
                            }
                        }
                    }
                }
                return ReadOutput(Rows(), tool);
            }

            // jq keys are case-sensitive. Only parse literal paths, indexes, iterators
            // and their pipelines. No jq runtime, filter imports or user definitions.
            List<(char Kind, string Key, int Index)>? JqSteps(string expression)
            {
                var steps = new List<(char, string, int)>();
                foreach (var raw in expression.Split('|'))
                {
                    var s = raw.Trim();
                    if (s == "length") { steps.Add(('l', "", 0)); continue; }
                    if (s.Length == 0 || s[0] != '.') return null;
                    int i = 0;
                    while (i < s.Length)
                    {
                        if (!Budget() || steps.Count >= MaxExpressionDepth) return null;
                        if (s[i] == '.')
                        {
                            i++;
                            if (i == s.Length) { if (i == 1) break; return null; }
                            if (s[i] != '[')
                            {
                                int start = i;
                                if (!(s[i] == '_' || s[i] <= 127 && char.IsLetter(s[i]))) return null;
                                while (i < s.Length && (s[i] == '_' || s[i] <= 127 && char.IsLetterOrDigit(s[i]))) i++;
                                steps.Add(('k', s.Substring(start, i - start), 0)); continue;
                            }
                        }
                        if (s[i++] != '[') return null;
                        int closing = s.IndexOf(']', i); if (closing < 0) return null;
                        string token = s.Substring(i, closing - i); i = closing + 1;
                        if (token.Length == 0) steps.Add(('*', "", 0));
                        else if (token.Length >= 2 && token[0] == '"' && token[token.Length - 1] == '"' &&
                            token.Substring(1, token.Length - 2).IndexOfAny("\"\\\r\n".ToCharArray()) < 0)
                            steps.Add(('k', token.Substring(1, token.Length - 2), 0));
                        else if (int.TryParse(token, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out int n) && !token.StartsWith("+"))
                            steps.Add(('i', "", n));
                        else return null;
                    }
                }
                return steps.Count <= MaxExpressionDepth ? steps : null;
            }
            IEnumerable<Payload> JsonInputs(Payload source)
            {
                if (!source.Complete || source.InspectionPartial || source.Text == null) { yield return Missing("jq-input"); yield break; }
                var s = source.Text;
                int pos = 0, count = 0;
                bool White(char c) => c is ' ' or '\t' or '\r' or '\n';
                while (pos < s.Length)
                {
                    while (pos < s.Length && White(s[pos])) pos++;
                    if (pos == s.Length) yield break;
                    int start = pos, depth = 0;
                    bool quoted = false;
                    if (s[pos] is '{' or '[' or '"')
                    {
                        do
                        {
                            char c = s[pos++];
                            if (quoted && c == '\\') { if (pos < s.Length) pos++; }
                            else if (c == '"') quoted = !quoted;
                            else if (!quoted)
                            {
                                if (c is '{' or '[') depth++;
                                else if (c is '}' or ']') depth--;
                            }
                            if (depth > MaxExpressionDepth || (pos & 1023) == 0 && !Budget()) { yield return Missing("jq-input-budget"); yield break; }
                        } while (pos < s.Length && (quoted || depth > 0));
                        if (quoted || depth != 0) { yield return Missing("jq-json"); yield break; }
                    }
                    else while (pos < s.Length && !White(s[pos])) pos++;
                    if (++count > Limits.MaxJsonElements || !Budget()) { yield return Missing("jq-input-budget"); yield break; }
                    var doc = Text(s.Substring(start, pos - start), source.SourceRef, FileRecordMarks(source));
                    yield return ParseReadDocument("jq", doc, null, null, hashtable: true);
                }
            }
            Payload JqOutput(Payload value, bool raw, bool compact)
            {
                var text = new StringBuilder();
                var labels = new List<Mark>();
                var positions = new List<(int Start, Mark Tag)>();
                int visits = 0;
                bool Put(string s)
                {
                    if (text.Length + (long)s.Length > MaxContent / 2) return false;
                    text.Append(s); return true;
                }
                bool Quote(string s)
                {
                    if (!Put("\"")) return false;
                    foreach (var c in s)
                    {
                        if (text.Length >= MaxContent / 2 || (text.Length & 1023) == 0 && !Budget()) return false;
                        string? esc = c switch {
                            '"' => "\\\"", '\\' => "\\\\", '\n' => "\\n", '\r' => "\\r", '\t' => "\\t",
                            '\f' => "\\f", '\b' => "\\b", _ when c < 0x20 || c == 0x7f => "\\u" + ((int)c).ToString("x4"), _ => null };
                        if (esc != null) { if (!Put(esc)) return false; } else text.Append(c);
                    }
                    return Put("\"");
                }
                bool Indent(int depth) => compact || Put("\n" + new string(' ', depth * 2));
                bool Render(Payload v, int depth)
                {
                    if (++visits > Limits.MaxJsonElements || depth > MaxExpressionDepth || !StackAvailable || !Budget() ||
                        !v.Complete || v.InspectionPartial) return false;
                    if (v.Map != null || v.Elements != null)
                    {
                        bool obj = v.Map != null;
                        if (!Put(obj ? "{" : "[")) return false;
                        int i = 0;
                        foreach (var child in obj ? v.Map! : v.Elements!.Select(x => new KeyValuePair<string, Payload>("", x)))
                        {
                            if (i++ > 0 && !Put(",") || !Indent(depth + 1) || obj && (!Quote(child.Key) || !Put(compact ? ":" : ": ")) ||
                                !Render(child.Value, depth + 1)) return false;
                        }
                        return (i == 0 || Indent(depth)) && Put(obj ? "}" : "]");
                    }
                    labels.AddRange(v.Tags);
                    if (raw && depth == 0 && v.IsString && v.TagPositions != null)
                        positions.AddRange(v.TagPositions.Take(Math.Max(0, Limits.MaxPositions - positions.Count)));
                    else foreach (var tag in v.Tags.Take(Math.Max(0, Limits.MaxPositions - positions.Count))) positions.Add((text.Length, tag));
                    if (v.Issue == "json-null") return Put("null");
                    if (v.IsString && v.Text != null) return raw && depth == 0 ? Put(v.Text) : Quote(v.Text);
                    if (v.NumericType != null)
                    {
                        // Decimal/exponent spelling varies with jq's version and build.
                        if (v.Text == null || !long.TryParse(v.Text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long n) ||
                            n < -9007199254740991L || n > 9007199254740991L) return false;
                        return Put(n.ToString(CultureInfo.InvariantCulture));
                    }
                    return v.ScalarTruth != null && Put(v.ScalarTruth.Value ? "true" : "false");
                }
                if (!Render(value, 0)) return UnknownValue("jq-output-not-materialized", value);
                var result = Text(text.ToString(), value.SourceRef, Merge(labels));
                result.TagPositions = positions.ToArray();
                return result;
            }
            Payload JqRead(string program, List<string> paths, Payload? pipe, bool raw, bool compact)
            {
                var steps = JqSteps(program);
                if (steps == null) return Missing("jq-filter");
                int visits = 0;
                Payload Null() => new Payload { Complete = true, SourceRef = "jq null", Issue = "json-null" };
                IEnumerable<Payload> Run(Payload v, int step)
                {
                    if (!StackAvailable || !Budget() || ++visits > Limits.MaxJsonElements || !v.Complete || v.InspectionPartial)
                    { yield return UnknownValue("jq-selection", v); yield break; }
                    if (step == steps.Count) { yield return JqOutput(v, raw, compact); yield break; }
                    var (kind, key, i) = steps[step];
                    IEnumerable<Payload> selected;
                    if (kind == '*' && (v.Map != null || v.Elements != null))
                        selected = v.Map != null ? v.Map.Values : v.Elements!;
                    else
                    {
                        Payload result;
                        if (kind == 'k' && v.Map != null) result = v.Map.TryGetValue(key, out var f) ? f : Null();
                        else if (kind == 'i' && v.Elements != null)
                        {
                            long pos = i < 0 ? v.Elements.LongLength + i : i;
                            result = pos >= 0 && pos < v.Elements.Length ? v.Elements[(int)pos] : Null();
                        }
                        else if (kind == 'l')
                        {
                            if (v.Issue == "json-null") result = Number(0);
                            else if (v.Map != null) result = Number(v.Map.Count);
                            else if (v.Elements != null) result = Number(v.Elements.Length);
                            else if (v.IsString && v.Text != null) result = Number(v.Text.Count(c => !char.IsLowSurrogate(c)));
                            else if (v.NumericType != null && long.TryParse(v.Text, out long n) && n != long.MinValue) result = Number(Math.Abs(n));
                            else { yield return Missing("jq-length-type"); yield break; }
                        }
                        else if (v.Issue == "json-null" && kind is ('i' or 'k')) result = Null();
                        else { yield return Missing("jq-filter-input-type"); yield break; }
                        selected = new[] { result };
                    }
                    foreach (var child in selected)
                        foreach (var output in Run(child, step + 1)) yield return output;
                }
                IEnumerable<Payload> Rows()
                {
                    foreach (string path in paths)
                    {
                        foreach (var doc in JsonInputs(FilterInput(path, pipe)))
                        foreach (var value in Run(doc, 0))
                        {
                            if (value.Text == null || !value.Complete) { yield return value; continue; }
                            using var reader = new StringReader(value.Text + "\n");
                            string? line; int at = 0;
                            while ((line = reader.ReadLine()) != null)
                            {
                                if (!Budget()) { yield return Missing("jq-budget"); yield break; }
                                var selected = value.TagPositions?.Where(p => p.Start >= at && p.Start < at + line.Length).Select(p => p.Tag)
                                    ?? Enumerable.Empty<Mark>();
                                yield return Text(line, value.SourceRef, Merge(FileRecordMarks(value).Concat(selected)));
                                at += line.Length;
                                if (at < value.Text.Length && value.Text[at] == '\r') at++;
                                if (at < value.Text.Length && value.Text[at] == '\n') at++;
                            }
                        }
                    }
                }
                return ReadOutput(Rows(), "jq");
            }
        }
    }
}

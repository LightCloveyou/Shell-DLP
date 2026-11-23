using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed class Mark
        {
            internal readonly string Id, Origin, Route;
            internal Mark(string id, string origin, string route) { Id = id; Origin = origin; Route = route; }
            internal Mark Via(string step) => new Mark(Id, Origin, Short(Route + " → " + step, Limits.MaxReportChars));
            internal object Report() => Data("ruleId", Id, "origin", Origin, "route", Route);
        }

        sealed class Section
        {
            internal string Name = "";
            internal int Begin, End;
            internal readonly Dictionary<string, object> Fields = new Dictionary<string, object>(StringComparer.Ordinal);
            internal string Get(string k) => Fields.TryGetValue(k, out var v) && v is string s ? s : "";
            internal string[] Array(string k) => !Fields.TryGetValue(k, out var v) ? System.Array.Empty<string>() :
                v is string[] a ? a : throw new FormatException("expected array: " + k);
        }

        // Deliberately limited to the policy schema: tables, string arrays,
        // single-line TOML strings, integers, booleans and ISO timestamps.
        // The original source is kept for surgical updates of managed sections.
        sealed class Toml
        {
            internal readonly string Text;
            internal readonly List<Section> Sections = new List<Section>();
            int i;
            internal Toml(string text)
            {
                Text = text;
                var current = new Section();
                Sections.Add(current);
                while (true)
                {
                    Skip(true);
                    if (i >= Text.Length) break;
                    var start = i;
                    if (Text[i] == '[')
                    {
                        var end = Text.IndexOf(']', i + 1);
                        if (end < 0) throw Bad();
                        bool array = i + 1 < Text.Length && Text[i + 1] == '[';
                        if (array && (end + 1 >= Text.Length || Text[end + 1] != ']')) throw Bad();
                        var name = Text.Substring(i + (array ? 2 : 1), end - i - (array ? 2 : 1)).Trim();
                        if (!Regex.IsMatch(name, @"^[a-z][a-z_.-]*$")) throw Bad();
                        current.End = start;
                        current = new Section { Name = (array ? "[[" : "[") + name, Begin = start };
                        Sections.Add(current);
                        i = end + (array ? 2 : 1);
                    }
                    else
                    {
                        while (i < Text.Length && (char.IsLetterOrDigit(Text[i]) || Text[i] == '_')) i++;
                        var key = Text.Substring(start, i - start);
                        Skip(false);
                        if (key.Length == 0 || !Take('=')) throw Bad();
                        Skip(false);
                        if (current.Fields.ContainsKey(key)) throw Bad();
                        current.Fields.Add(key, Value());
                    }
                    Skip(false);
                    if (i < Text.Length && Text[i] != '\n') throw Bad();
                }
                current.End = Text.Length;
            }
            FormatException Bad() => new FormatException("unsupported or invalid TOML at offset " + i);
            bool Take(char c) { if (i < Text.Length && Text[i] == c) { i++; return true; } return false; }
            void Skip(bool multiline)
            {
                while (i < Text.Length)
                {
                    if (Text[i] == ' ' || Text[i] == '\t' || Text[i] == '\r' || (multiline && Text[i] == '\n')) i++;
                    else if (Text[i] == '#') { while (i < Text.Length && Text[i] != '\n') i++; }
                    else break;
                }
            }
            object Value()
            {
                if (i >= Text.Length) throw Bad();
                if (Text[i] == '\'' || Text[i] == '"') return String();
                if (Take('['))
                {
                    var list = new List<string>();
                    Skip(true);
                    while (!Take(']'))
                    {
                        list.Add(String());
                        Skip(true);
                        if (Take(']')) break;
                        if (!Take(',')) throw Bad();
                        Skip(true);
                    }
                    return list.ToArray();
                }
                int from = i;
                while (i < Text.Length && !char.IsWhiteSpace(Text[i]) && Text[i] != '#') i++;
                var token = Text.Substring(from, i - from);
                if (token == "true" || token == "false") return token == "true";
                if (long.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n)) return n;
                if (Regex.IsMatch(token, @"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$") &&
                    DateTimeOffset.TryParse(token, CultureInfo.InvariantCulture, DateTimeStyles.None, out _)) return token;
                throw Bad();
            }
            string String()
            {
                if (i >= Text.Length || (Text[i] != '\'' && Text[i] != '"')) throw Bad();
                var quote = Text[i++];
                var result = new StringBuilder();
                while (i < Text.Length)
                {
                    var c = Text[i++];
                    if (c == quote) return result.ToString();
                    if (c < ' ' && c != '\t') throw Bad();
                    if (c != '\\' || quote == '\'') { result.Append(c); continue; }
                    if (i >= Text.Length) throw Bad();
                    c = Text[i++];
                    switch (c)
                    {
                        case '"': case '\\': result.Append(c); break;
                        case 'n': result.Append('\n'); break;
                        case 'r': result.Append('\r'); break;
                        case 't': result.Append('\t'); break;
                        case 'b': result.Append('\b'); break;
                        case 'f': result.Append('\f'); break;
                        case 'u': case 'U':
                            var len = c == 'u' ? 4 : 8;
                            if (i + len > Text.Length || !int.TryParse(Text.Substring(i, len), NumberStyles.HexNumber,
                                CultureInfo.InvariantCulture, out var cp) || cp < 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) throw Bad();
                            result.Append(char.ConvertFromUtf32(cp)); i += len; break;
                        default: throw Bad();
                    }
                }
                throw Bad();
            }
            internal static string Quote(string s)
            {
                var b = new StringBuilder("\"");
                foreach (char c in s)
                {
                    if (c == '"' || c == '\\') b.Append('\\').Append(c);
                    else if (c < 32 || c == 127) b.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else b.Append(c);
                }
                return b.Append('"').ToString();
            }
        }

        sealed class Rule
        {
            internal readonly string Id, Action;
            internal readonly string[] Files, Folders, Texts, Sources;
            internal readonly Section Section;
            internal readonly List<Section> Copies = new List<Section>();
            internal Rule(Section section, string directory, int maxText)
            {
                Section = section;
                Id = section.Get("id");
                Action = section.Get("action");
                if (!Regex.IsMatch(Id, @"^[A-Za-z0-9_.-]{1,80}$") || (Action != "block" && Action != "warn"))
                    throw new FormatException("invalid rule id or action");
                Files = section.Array("files").Select(v => ConfigPath(v, directory)).ToArray();
                Folders = section.Array("folders").Select(v => ConfigPath(v, directory)).ToArray();
                Texts = section.Array("texts");
                Sources = section.Array("sources");
                if (Sources.Any(s => s.Length == 0 || s.Length > maxText || s.Any(char.IsControl) ||
                    s.IndexOfAny(new[] { '*', '?' }) >= 0 ||
                    !(s.Equals("clipboard", StringComparison.OrdinalIgnoreCase) ||
                      new[] { "registry:", "eventlog:", "cim:", "env:", "acl:", "system:", "session:" }.Any(p => s.Length > p.Length && s.StartsWith(p, StringComparison.OrdinalIgnoreCase)))))
                    throw new FormatException("invalid local source selector");
                if (Texts.Any(t => t.Length == 0 || t.Length > maxText)) throw new FormatException("invalid text rule");
            }
        }

        static string ConfigPath(string value, string directory)
        {
            if (string.IsNullOrWhiteSpace(value) || value.IndexOfAny(new[] { '*', '?', '\0' }) >= 0)
                throw new FormatException("invalid rule path");
            if (value.Length >= 2 && value[1] == ':' && (value.Length < 3 || (value[2] != '\\' && value[2] != '/')))
                throw new FormatException("drive-relative rule path");
            var full = Path.GetFullPath(Path.IsPathRooted(value) ? value : Path.Combine(directory, value));
            return full == Path.GetPathRoot(full) ? full : full.TrimEnd('\\');
        }

        static bool StackAvailable => System.Runtime.CompilerServices.RuntimeHelpers.TryEnsureSufficientExecutionStack();
        static int ProbeCount(int limit) => limit == int.MaxValue ? limit : limit + 1;
        static AnalysisLimits Limits => Store.CachedPolicy ?? AnalysisLimits.Defaults;

        class AnalysisLimits
        {
            internal static readonly AnalysisLimits Defaults = new AnalysisLimits(null);
            internal readonly int MaxAmsiBytes;
            internal readonly int MaxScriptBytes;
            internal readonly int MaxStatements;
            internal readonly int MaxExpressionDepth;
            internal readonly int MaxMaterializedBytes;
            internal readonly int MaxLoopIterations;
            internal readonly int MaxForEachIterations;
            internal readonly int MaxOutVariableRecords;
            internal readonly int MaxJsonElements;
            internal readonly int MaxFilesPerScan;
            internal readonly int FileScanBudgetMs;
            internal readonly int GitMaxCommits;
            internal readonly int GitMaxObjects;
            internal readonly int GitMaxPathBindings;
            internal readonly int MaxEffects;
            internal readonly int MaxVars;
            internal readonly int MaxReportNodes;
            internal readonly int MaxPolicyNodes;
            internal readonly int MaxArguments;
            internal readonly int MaxParts;
            internal readonly int MaxDestinations;
            internal readonly int MaxCollection;
            internal readonly int MaxLines;
            internal readonly int MaxPositions;
            internal readonly int MaxPackedEntries;
            internal readonly int MaxPackedDepth;
            internal readonly int MaxExpanded;
            internal readonly int MaxGitTime;
            internal readonly int MaxGitCommandTime;
            internal readonly int MaxGitCache;
            internal readonly int MaxRuntimeChars;
            internal readonly int MaxVariableName;
            internal readonly int MaxRuleText;
            internal readonly int MaxPathDepth;
            internal readonly int MaxWildcard;
            internal readonly int MaxFilter;
            internal readonly int MaxRepoDepth;
            internal readonly int MaxArchivePath;
            internal readonly int MaxEncodedFields;
            internal readonly int MaxFieldName;
            internal readonly int MaxJsonNames;
            internal readonly int MaxFormParts;
            internal readonly int MaxReportChars;
            internal readonly int MaxReportMarks;
            internal readonly int MaxParseErrors;
            internal readonly int MaxUsingTokens;
            internal readonly int MaxReportBytes;
            internal readonly int MaxGitProofBytes;
            internal readonly int MaxArchiveVisits;
            internal readonly int MaxWitnesses;
            internal readonly int MaxRules;
            internal readonly int MaxGitRefs;
            internal readonly int MaxGitConfigs;
            internal readonly int MaxGitBaseline;
            internal readonly int MaxStateBytes;
            internal readonly int MaxGitMetadataBytes;
            internal readonly int GitProofLifetime;

            internal readonly long MaxFileBytes, MaxTotalFileBytes;

            internal AnalysisLimits(Section? section)
            {
                long Read(string key, long fallback, long min = 1, long max = int.MaxValue, string? legacy = null)
                {
                    if (section == null) return fallback;
                    if (!section.Fields.TryGetValue(key, out var value) &&
                        (legacy == null || !section.Fields.TryGetValue(legacy, out value))) return fallback;
                    return value is long n && n >= min && n <= max ? n : throw new FormatException("invalid limit: " + key);
                }
                MaxAmsiBytes = (int)Read("max_amsi_content_bytes", 65536);
                MaxScriptBytes = (int)Read("max_script_bytes", 65536);
                MaxStatements = (int)Read("max_ast_statements", 256);
                MaxExpressionDepth = (int)Read("max_expression_depth", 16);
                MaxMaterializedBytes = (int)Read("max_materialized_bytes", 131072);
                MaxLoopIterations = (int)Read("max_loop_iterations", 16);
                MaxForEachIterations = (int)Read("max_foreach_iterations", 16);
                MaxOutVariableRecords = (int)Read("max_outvariable_records", 32);
                MaxJsonElements = (int)Read("max_json_elements", 128);
                MaxFilesPerScan = (int)Read("max_files", 512, 0, legacy: "max_files_per_scan");
                FileScanBudgetMs = (int)Read("max_analysis_time_ms", 350, legacy: "file_scan_budget_ms");
                GitMaxCommits = (int)Read("git_max_commits", 128);
                GitMaxObjects = (int)Read("max_git_objects", 2048, legacy: "git_max_objects");
                GitMaxPathBindings = (int)Read("git_max_path_bindings", 4096);
                MaxEffects = (int)Read("max_effects", 32);
                MaxVars = (int)Read("max_tracked_variables", 64);
                MaxReportNodes = (int)Read("max_report_nodes", 512);
                MaxPolicyNodes = (int)Read("max_ast_nodes", 4096);
                MaxArguments = (int)Read("max_command_arguments", 128);
                MaxParts = (int)Read("max_payload_parts", 64);
                MaxDestinations = (int)Read("max_destinations", 16);
                MaxCollection = (int)Read("max_collection_elements", 512);
                MaxLines = (int)Read("max_content_records", 4096);
                MaxPositions = (int)Read("max_tag_positions", 256);
                MaxPackedEntries = (int)Read("max_archive_entries", 64);
                MaxPackedDepth = (int)Read("max_archive_depth", 2);
                MaxExpanded = (int)Read("max_expanded_archive_bytes", 262144);
                MaxGitTime = (int)Read("max_git_preflight_time_ms", 25000);
                MaxGitCommandTime = (int)Read("max_git_command_time_ms", 8000);
                MaxGitCache = (int)Read("max_git_cache_bytes", 16777216);
                MaxRuntimeChars = (int)Read("max_runtime_value_chars", 4096);
                MaxVariableName = (int)Read("max_variable_name_chars", 128);
                MaxRuleText = (int)Read("max_rule_text_chars", 4096);
                MaxPathDepth = (int)Read("max_file_path_depth", 64);
                MaxWildcard = (int)Read("max_wildcard_chars", 128);
                MaxFilter = (int)Read("max_filesystem_filter_chars", 260);
                MaxRepoDepth = (int)Read("max_git_search_depth", 12);
                MaxArchivePath = (int)Read("max_archive_path_chars", 512);
                MaxEncodedFields = (int)Read("max_encoded_fields", 18);
                MaxFieldName = (int)Read("max_encoded_field_name_chars", 64);
                MaxJsonNames = (int)Read("max_json_name_table_chars", 8192);
                MaxFormParts = (int)Read("max_curl_form_components", 8);
                MaxReportChars = (int)Read("max_report_field_chars", 2048);
                MaxReportMarks = (int)Read("max_report_flow_marks", 8);
                MaxParseErrors = (int)Read("max_report_parse_errors", 64);
                MaxUsingTokens = (int)Read("max_using_directive_tokens", 128);
                MaxReportBytes = (int)Read("max_report_bytes", 196608);
                MaxGitProofBytes = (int)Read("max_git_proof_bytes", 262144);
                MaxArchiveVisits = (int)Read("max_archive_visits", 96);
                MaxWitnesses = (int)Read("max_witnesses", 128);
                MaxRules = (int)Read("max_sensitive_rules", 128);
                MaxGitRefs = (int)Read("max_git_local_refs", 511);
                MaxGitConfigs = (int)Read("max_git_config_files", 20);
                MaxGitBaseline = (int)Read("max_git_baseline_refs", 128);
                MaxStateBytes = (int)Read("max_state_file_bytes", 524288);
                MaxGitMetadataBytes = (int)Read("max_git_metadata_bytes", 524288);
                GitProofLifetime = (int)Read("git_proof_lifetime_seconds", 60);
                MaxFileBytes = Read("max_file_bytes", 16777216, 0, long.MaxValue);
                MaxTotalFileBytes = Read("max_total_file_bytes", 67108864, 0, long.MaxValue);
            }
        }

        sealed class Policy : AnalysisLimits
        {
            internal readonly Toml Document;
            internal readonly bool TrustLoopback;
            internal readonly HashSet<string> GitRemoteAllowlist = new HashSet<string>(StringComparer.Ordinal);
            internal readonly bool InvalidGitRemoteAllowlist;
            internal readonly (string Id, string[] Needles)[] FileTextRules;
            internal readonly int LongestFileNeedle;
            internal readonly List<Rule> Rules = new List<Rule>();
            internal Policy(string text, string directory) : this(new Toml(text), directory) { }
            Policy(Toml document, string directory) : base(document.Sections.FirstOrDefault(s => s.Name == "[policy"))
            {
                Document = document;
                Rule? rule = null;
                int gitUrls = 0;
                bool seenPolicy = false;
                foreach (var s in Document.Sections)
                {
                    if (s.Name == "[[rules")
                    {
                        rule = new Rule(s, directory, MaxRuleText);
                        if (Rules.Any(r => r.Id == rule.Id) || Rules.Count >= MaxRules) throw new FormatException("duplicate or too many rules");
                        Rules.Add(rule);
                    }
                    else if (s.Name == "[[rules.copy" && rule != null)
                    {
                        ConfigPath(s.Get("path"), directory);
                        rule.Copies.Add(s);
                    }
                    else if (s.Name == "[[allow-git-url")
                    {
                        if (++gitUrls <= 256 && s.Fields.Count == 1 && GitProof.RemoteAddressKey(s.Get("url")) is string key)
                            GitRemoteAllowlist.Add(key);
                        else InvalidGitRemoteAllowlist = true; // keep content rules active; grant no exceptions
                    }
                    else if (s.Name == "[policy")
                    {
                        if (seenPolicy) throw new FormatException("duplicate policy section");
                        seenPolicy = true;
                        if (s.Get("on_missing") != "warn") throw new FormatException("on_missing must be warn");
                        if (s.Fields.TryGetValue("trust_loopback", out var trust))
                            TrustLoopback = trust is bool enabled ? enabled : throw new FormatException("trust_loopback must be boolean");
                    }
                    else if (s.Name != "") throw new FormatException("unsupported policy section");
                }
                if (!Document.Sections[0].Fields.TryGetValue("version", out var version) || !Equals(version, 1L))
                    throw new FormatException("unsupported policy version");
                FileTextRules = Rules.Where(r => r.Texts.Length != 0)
                    .Select(r => (r.Id, r.Texts.Distinct(StringComparer.Ordinal).ToArray())).ToArray();
                LongestFileNeedle = FileTextRules.SelectMany(r => r.Needles).Select(n => n.Length).DefaultIfEmpty(0).Max();
            }
        }

        static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);
        static string Short(string value, int limit) => value.Length <= limit ? value : value.Substring(0, limit);

        static class Store
        {
            static readonly string Root = typeof(AstBridge).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
                .FirstOrDefault(x => x.Key == "GuardPolicyRoot")?.Value ?? "";
            internal static string Config => Path.Combine(Root, "config", "sensitive.toml");
            internal static string Durable => Path.Combine(Root, "state", "persistent-variables.toml");
            internal static string GitDir => Path.Combine(Root, "state", "git-preflight");
            static string JournalFile(string key) => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "PowerShell7Guard", "git-journal", key + ".toml");
            internal static string? ReadJournal(string key)
            {
                try { var path = JournalFile(key); return Disk.ClearAncestors(path) ? ReadBounded(path, Limits.MaxGitProofBytes) : null; }
                catch { return null; }
            }
            internal static bool AppendJournal(string key, string entry)
            {
                var path=JournalFile(key);
                var parent=Path.GetDirectoryName(path)!;
                var app=Path.GetDirectoryName(parent)!;
                if (!Disk.ClearAncestors(Path.GetDirectoryName(app)!)) return false;
                foreach (var dir in new[] { app, parent })
                {
                    Directory.CreateDirectory(dir);
                    if (!Disk.ClearAncestors(dir)) return false;
                }
                return Change(path, true, old =>
                {
                    const string header = "version = 1\n";
                    var cap = Limits.MaxGitProofBytes;
                    int left = cap - StrictUtf8.GetByteCount(header) - StrictUtf8.GetByteCount(entry);
                    if (left < 0) throw new IOException("git journal entry limit");
                    var keep = new Stack<string>();
                    foreach (var section in new Toml(old).Sections.Where(s => s.Name == "[[observation").Reverse().Take(255))
                    {
                        var block = old.Substring(section.Begin, section.End - section.Begin);
                        left -= StrictUtf8.GetByteCount(block);
                        if (left < 0) break;
                        keep.Push(block);
                    }
                    return header + string.Concat(keep) + entry;
                }, Limits.MaxGitProofBytes);
            }
            static readonly object ReloadGate = new object();
            sealed class Snapshot
            {
                internal readonly Policy? Policy;
                internal readonly Section[] Persistent;
                internal readonly string Issue;
                internal readonly string? PolicyGeneration, DurableGeneration;
                internal Snapshot(Policy? policy, Section[] persistent, string issue, string? policyGeneration, string? durableGeneration)
                { Policy = policy; Persistent = persistent; Issue = issue; PolicyGeneration = policyGeneration; DurableGeneration = durableGeneration; }
            }
            static volatile Snapshot current = new Snapshot(null, System.Array.Empty<Section>(), "policy-loading", null, null);
            internal static Policy? CachedPolicy => current.Policy;
            static int next, inFlight, initialized;
            internal static Policy? Current(out string problem)
            {
                if (Interlocked.CompareExchange(ref initialized, 1, 0) == 0)
                {
                    Refresh(); // bounded cold start only; later reads use the in-memory snapshot
                    Volatile.Write(ref next, unchecked(Environment.TickCount + 500));
                }
                int now = Environment.TickCount;
                if ((Volatile.Read(ref next) == 0 || unchecked(now - Volatile.Read(ref next)) >= 0) &&
                    Interlocked.CompareExchange(ref inFlight, 1, 0) == 0)
                {
                    Volatile.Write(ref next, unchecked(now + 500));
                    if (!ThreadPool.QueueUserWorkItem(_ => { try { Refresh(); } finally { Volatile.Write(ref inFlight, 0); } }))
                        Volatile.Write(ref inFlight, 0);
                }
                var snapshot = current;
                problem = snapshot.Issue;
                return snapshot.Policy;
            }
            static int PolicyFileBudget()
            {
                int fallback = Limits.MaxStateBytes;
                if (new FileInfo(Config).Length <= fallback) return fallback;
                // A policy can raise its own size limit on cold start. Inspect only
                // the section and integer before allocating a buffer for the file.
                using var reader = new StreamReader(Config, StrictUtf8, true);
                var token = new StringBuilder();
                bool inPolicy = false, discard = false;
                int c;
                do
                {
                    c = reader.Read();
                    if (c == '\n' || c < 0)
                    {
                        var line = token.ToString();
                        if (line.StartsWith("[", StringComparison.Ordinal)) inPolicy = line == "[policy]";
                        else if (inPolicy && line.StartsWith("max_state_file_bytes=", StringComparison.Ordinal) &&
                            int.TryParse(line.Substring("max_state_file_bytes=".Length), NumberStyles.Integer,
                                CultureInfo.InvariantCulture, out var size) && size > 0) return size;
                        token.Clear();
                        discard = false;
                    }
                    else if (c == '#' || token.Length > "max_state_file_bytes=".Length + 20) discard = true;
                    else if (!discard && !char.IsWhiteSpace((char)c)) token.Append((char)c);
                } while (c >= 0);
                return AnalysisLimits.Defaults.MaxStateBytes;
            }

            static string ReadBounded(string path, int cap)
            {
                using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                long length = file.Length;
                if (length > cap) throw new IOException("file too large");
                var bytes = new byte[(int)length];
                int cursor = 0;
                while (cursor < bytes.Length)
                {
                    int read = file.Read(bytes, cursor, bytes.Length - cursor);
                    if (read == 0) throw new IOException("file changed during read");
                    cursor += read;
                }
                if (file.ReadByte() != -1) throw new IOException("file changed during read");
                return StrictUtf8.GetString(bytes).TrimStart('\ufeff');
            }
            static string? lastPolicy, lastDurable;

            static string? MetadataGeneration(string path)
            {
                try
                {
                    // Prefer file identity. Some hosts deny ancestor enumeration;
                    // use stable metadata on the configured file in that case.
                    var identity = Disk.TargetStamp(path);
                    if (identity != null) return "id:" + identity;
                    try
                    {
                        var attributes = File.GetAttributes(path);
                        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0) return null;
                        var info = new FileInfo(path);
                        return "meta:" + info.CreationTimeUtc.Ticks + ":" + info.LastWriteTimeUtc.Ticks + ":" + info.Length;
                    }
                    catch (FileNotFoundException) { return "absent"; }
                    catch (DirectoryNotFoundException) { return "absent"; }
                }
                catch { return null; }
            }

            internal static bool RefreshDerived(bool file)
            {
                var path = file ? Config : Durable;
                var generation = MetadataGeneration(path);
                if (generation == null) return false;
                var snapshot = current;
                if (generation != (file ? snapshot.PolicyGeneration : snapshot.DurableGeneration))
                {
                    Refresh();
                    snapshot = current;
                }
                return generation == (file ? snapshot.PolicyGeneration : snapshot.DurableGeneration);
            }
            internal static void Refresh()
            {
                lock (ReloadGate)
                {
                    var previous = current;
                    var policy = previous.Policy;
                    var persistent = previous.Persistent;
                    string issue = "";
                    string? policyGeneration = null, durableGeneration = null;
                    try
                    {
                        if (!Path.IsPathRooted(Root)) throw new IOException();
                        var before = MetadataGeneration(Config);
                        var text = ReadBounded(Config, PolicyFileBudget());
                        var after = MetadataGeneration(Config);
                        if (before == null || before != after) throw new IOException("policy generation changed");
                        if (text != lastPolicy)
                        {
                            var parsed = new Policy(text, Path.GetDirectoryName(Config)!);
                            if (new FileInfo(Config).Length > parsed.MaxStateBytes) throw new IOException("policy size limit");
                            policy = parsed;
                        }
                        lastPolicy = text;
                        policyGeneration = after;
                    }
                    catch { issue = "policy-unavailable-or-invalid"; }
                    try
                    {
                        var before = MetadataGeneration(Durable);
                        var text = File.Exists(Durable) ? ReadBounded(Durable, (policy ?? AnalysisLimits.Defaults).MaxStateBytes) : "";
                        var after = MetadataGeneration(Durable);
                        if (before != after) throw new IOException("durable generation changed");
                        if (lastDurable != text)
                        {
                            persistent = new Toml(text).Sections.Where(s => s.Name == "[[variables").ToArray();
                            lastDurable = text;
                        }
                        durableGeneration = after;
                    }
                    catch { durableGeneration = null; persistent = System.Array.Empty<Section>(); lastDurable = null; }
                    current = new Snapshot(policy, persistent, issue, policyGeneration, durableGeneration);
                }
            }
            internal static IEnumerable<Section> Persistent(string scope, string owner, string name) => current.Persistent.Where(
                s => s.Get("scope") == scope && s.Get("owner") == owner && s.Get("name").Equals(name, StringComparison.OrdinalIgnoreCase));
            internal static string? ReadGit(string key)
            {
                try { return ReadBounded(Path.Combine(GitDir, key + ".toml"), Limits.MaxGitProofBytes); }
                catch { return null; }
            }
            internal static bool SaveGit(string key, string data) => StrictUtf8.GetByteCount(data) <= Limits.MaxGitProofBytes &&
                Change(Path.Combine(GitDir, key + ".toml"), true, _ => data, Limits.MaxGitProofBytes);

            static string LockName(string path)
            {
                ulong hash = 14695981039346656037UL;
                foreach (var c in path.ToUpperInvariant()) hash = unchecked((hash ^ c) * 1099511628211UL);
                return "Local\\PowerShell7Guard-" + hash.ToString("x", CultureInfo.InvariantCulture);
            }
            static bool Change(string path, bool create, Func<string, string?> make, int? byteLimit = null)
            {
                if (!Path.IsPathRooted(Root)) return false;
                int cap = byteLimit ?? Limits.MaxStateBytes;
                using var mu = new Mutex(false, LockName(path));
                bool held = false;
                string? temp = null;
                try
                {
                    try { held = mu.WaitOne(500); } catch (AbandonedMutexException) { held = true; }
                    if (!held) return false;
                    var parent = Path.GetDirectoryName(path)!;
                    if (create) Directory.CreateDirectory(parent);
                    if ((File.GetAttributes(parent) & FileAttributes.ReparsePoint) != 0) return false;
                    bool exists = File.Exists(path);
                    if (!exists && !create) return false;
                    if (exists && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) return false;
                    var original = exists ? ReadBounded(path, cap) : "version = 1\n";
                    var changed = make(original);
                    if (changed == null || changed == original) return true;
                    if (StrictUtf8.GetByteCount(changed) > cap) return false;
                    temp = Path.Combine(parent, ".guard-" + Guid.NewGuid().ToString("N") + ".tmp");
                    using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    using (var writer = new StreamWriter(stream, StrictUtf8)) writer.Write(changed);
                    if (File.Exists(path) != exists || (exists && ReadBounded(path, cap) != original)) return false;
                    if (exists) File.Replace(temp, path, null);
                    else File.Move(temp, path);
                    return true;
                }
                catch { return false; }
                finally
                {
                    if (temp != null) try { File.Delete(temp); } catch { }
                    if (held) mu.ReleaseMutex();
                }
            }
            static string Entry(string table, params string[] pairs)
            {
                var b = new StringBuilder("\n[[" + table + "]]\n");
                for (int i = 0; i < pairs.Length; i += 2)
                    b.Append(pairs[i]).Append(" = ").Append(Toml.Quote(pairs[i + 1])).Append('\n');
                return b.ToString();
            }
            static string Remove(string text, IEnumerable<Section> old)
            {
                foreach (var s in old.OrderByDescending(x => x.Begin))
                {
                    // Keep comments and whitespace even when an old managed entry is removed.
                    var original = text.Substring(s.Begin, s.End - s.Begin);
                    var comments = string.Concat(Regex.Matches(original, @"(?m)^[ \t]*#[^\r\n]*(?:\r?\n|$)").Cast<Match>().Select(m => m.Value));
                    text = text.Remove(s.Begin, s.End - s.Begin).Insert(s.Begin, comments);
                }
                return text;
            }
            internal static bool SaveCopies(string path, string from, string stamp, IReadOnlyList<Mark> marks, string eventId)
            {
                var result = Change(Config, false, original =>
                {
                    var directory = Path.GetDirectoryName(Config)!;
                    var p = new Policy(original, directory);
                    var old = p.Rules.SelectMany(r => r.Copies).Where(s => PathEq(ConfigPath(s.Get("path"), directory), path)).ToArray();
                    var text = Remove(original, old);
                    p = new Policy(text, directory);
                    foreach (var r in p.Rules.AsEnumerable().Reverse())
                    {
                        int position = r.Copies.Count == 0 ? r.Section.End : r.Copies.Last().End;
                        foreach (var label in marks.Where(m => m.Id == r.Id).GroupBy(m => m.Origin).Select(g => g.First()))
                            text = text.Insert(position, Entry("rules.copy", "path", path, "copied_from", from, "origin", label.Origin,
                                "route", label.Route, "stamp", stamp, "event_id", eventId,
                                "confirmed_at", DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture)));
                    }
                    _ = new Policy(text, directory);
                    return text;
                });
                Refresh();
                return result;
            }
            internal static bool SavePersistent(string scope, string owner, string name, string stamp, IReadOnlyList<Mark> marks, string eventId)
            {
                var result = Change(Durable, true, original =>
                {
                    var old = new Toml(original).Sections.Where(s => s.Name == "[[variables" &&
                        s.Get("scope") == scope && s.Get("owner") == owner && s.Get("name").Equals(name, StringComparison.OrdinalIgnoreCase));
                    var text = Remove(original, old);
                    foreach (var label in marks.GroupBy(m => (m.Id, m.Origin)).Select(g => g.First()))
                        text += Entry("variables", "scope", scope, "owner", owner, "name", name, "stamp", stamp,
                            "rule_id", label.Id, "origin", label.Origin, "route", label.Route, "event_id", eventId,
                            "confirmed_at", DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
                    _ = new Toml(text);
                    return text;
                });
                Refresh();
                return result;
            }
        }
    }
}

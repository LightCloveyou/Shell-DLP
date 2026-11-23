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
            static readonly Dictionary<string, NativeOption> SftpOptions = NativeOptions(
                "+batch -b", "+port -P", "+jump -J", "+config -F", "+ssh-option -o", "+direct -D",
                "+program -S", "+subsystem -s", "+identity -i", "+cipher -c", "+buffer -B", "+requests -R",
                "+rate -l", "+extension -X", "recurse -r", "resume -a", "ordinary -4 -6 -A -C -f -N -p -q -v");

            static string? SftpHost(string? spec, out bool hasPath)
            {
                hasPath = false;
                if (string.IsNullOrWhiteSpace(spec)) return null;
                if (spec!.StartsWith("sftp://", StringComparison.OrdinalIgnoreCase))
                {
                    if (!Uri.TryCreate(spec, UriKind.Absolute, out var uri) || uri.Host.Length == 0 ||
                        uri.UserInfo.Contains(":") || uri.Query.Length != 0 || uri.Fragment.Length != 0) return null;
                    hasPath = uri.AbsolutePath.Length > 1;
                    return uri.Host;
                }
                var m = Regex.Match(spec, @"^(?:[\w.-]+@)?(?<host>[A-Za-z0-9._-]+|\[[0-9A-Fa-f:.]+\])(?::(?<path>[^\r\n]*))?\z");
                if (!m.Success) return null;
                hasPath = m.Groups["path"].Length != 0;
                return m.Groups["host"].Value;
            }

            // A bounded subset of OpenSSH makeargv, not a shell or a PowerShell parser.
            static List<string>? SftpWords(string line)
            {
                if (line.IndexOf('\0') >= 0 || Encoding.UTF8.GetByteCount(line) >= 8192) return null;
                var words = new List<string>(); var word = new StringBuilder();
                char quote = '\0'; bool active = false;
                for (int i = 0; i < line.Length; ++i)
                {
                    char c = line[i];
                    if (quote == 0 && c == '#') break;
                    if (quote == 0 && (c == ' ' || c == '\t'))
                    {
                        if (active) { words.Add(word.ToString()); word.Clear(); active = false; }
                        if (words.Count >= Math.Min(128, Limits.MaxArguments)) return null;
                        continue;
                    }
                    active = true;
                    if (c == quote) { quote = '\0'; continue; }
                    if (quote == 0 && c is ('\'' or '"')) { quote = c; continue; }
                    if (c == '\\')
                    {
                        if (++i == line.Length) return null;
                        c = line[i];
                        // Don't confuse a quoted or escaped glob with an active glob.
                        if (c is '*' or '?' or '[') return null;
                        if (quote == 0 && char.IsLetterOrDigit(c)) return null; // platform-specific path escaping
                        if (quote != 0 && c != quote) word.Append('\\');
                    }
                    else if (quote != 0 && c is ('*' or '?' or '[')) return null;
                    word.Append(c);
                }
                if (quote != 0) return null;
                if (active) words.Add(word.ToString());
                return words;
            }

            IEnumerable<Payload> SftpUpload(string src, string? local, bool recursive)
            {
                if (src.IndexOfAny(new[] { '*', '?' }) < 0)
                {
                    foreach (var part in TransferSource(src, local, recursive, "sftp:local-source")) yield return part;
                    yield break;
                }
                var split = src.LastIndexOfAny(new[] { '/', '\\' });
                string leaf = src.Substring(split + 1);
                var folder = split < 0 ? local : Disk.Bind(src.Substring(0, split + 1), local);
                if (folder == null || barrier || src.Contains("[") || leaf.Length > 255)
                { yield return Missing("sftp-source-glob"); yield break; }
                bool Match(string name) => (leaf.StartsWith(".", StringComparison.Ordinal) || !name.StartsWith(".", StringComparison.Ordinal)) &&
                    System.IO.Enumeration.FileSystemName.MatchesSimpleExpression(leaf, name, ignoreCase: false);
                bool found = false;
                foreach (var (entry, error) in EnumerateFiles(folder, false, includeDirectories: true, matchesName: Match))
                {
                    if (entry == null) { yield return Missing(error ?? "sftp-source-glob"); continue; }
                    found = true;
                    if (entry.Kind == PathKind.DirectoryInfo && !recursive) { yield return Missing("sftp-directory-needs-recursion"); continue; }
                    foreach (var p in TransferSource(entry.Path, null, recursive, "sftp:local-source")) yield return p;
                }
                // Case-folding/glob dialects and no-match behavior differ between clients.
                if (!found || leaf.Any(char.IsLetter)) yield return Missing("sftp-glob-platform");
            }

            void SftpDownload(string? local, string? directory, string remote, bool recursive)
            {
                string basename = remote.Substring(remote.LastIndexOf('/') + 1);
                if (recursive || basename.Length == 0 || Disk.Bind(local ?? basename, directory) is not string path)
                { InvalidateFileFacts(); return; }
                if (InspectMetadata(path)?.Attributes.HasFlag(FileAttributes.Directory) == true)
                {
                    if (Disk.Bind(basename, path) is not string child) { InvalidateFileFacts(); return; }
                    path = child;
                }
                InvalidateOutputFile(Text(path, "sftp:download-output"));
            }

            void Sftp(object command, Payload? pipe)
            {
                var call = ReadNative(command, SftpOptions, longEquals: false);
                var arg = call.Position.FirstOrDefault();
                var host = SftpHost(arg?.Text, out bool initialPath);
                string? issue = call.Error;
                if (call.Has("direct") || call.Has("program") || call.Has("subsystem"))
                { Send("sftp", null, Array.Empty<Payload>(), "sftp-custom-transport"); return; }
                if (arg == null || call.Position.Count > 2 || call.Position.Count == 2 && !initialPath ||
                    call.Options.Count(o => o.Name == "batch") > 1 || call.Error == "missing-option-value" ||
                    call.Options.Any(o => o.Name == "port" && (!ushort.TryParse(o.Arg.Text, NumberStyles.None, CultureInfo.InvariantCulture, out var p) || p == 0)))
                { Send("sftp", null, Array.Empty<Payload>(), "sftp-arguments"); return; }
                bool customRoute = call.Has("jump") || call.Has("config") || call.Options.Any(o => o.Name == "ssh-option" &&
                    !ScpLocalOptions.Contains(o.Arg.Text?.Split(new[] { '=', ' ', '\t' }, 2)[0], StringComparer.OrdinalIgnoreCase));
                if (customRoute || call.UncertainOperandOrder) { host = null; issue ??= "sftp-route"; }
                void Emit(IEnumerable<Payload> parts, string? missing = null)
                {
                    if (host != null && !barrier && issue == null && TrustLoopback && LoopbackHost(host))
                        SkipLoopback("sftp", host);
                    else Send("sftp", host, parts, missing ?? issue);
                }
                Emit(new[] { SshOperand(arg, "sftp:destination") });
                var local = cwd;
                var batch = call.Options.LastOrDefault(o => o.Name == "batch").Arg;
                var controls = batch == null || batch.Text == "-" ? pipe :
                    batch.Text == null ? null : File(batch.Text, true, out _, inspectArchive: false);
                if (initialPath && call.Position.Count == 2)
                {
                    var dest = call.Position[1].Text;
                    if (dest == null) InvalidateFileFacts(); else SftpDownload(dest, local, arg.Text!, call.Has("recurse"));
                    return; // two operands mean download; no command interpreter follows.
                }
                if (initialPath)
                {
                    // A remote directory enters the interpreter; a file downloads and exits.
                    // Metadata isn't fetched by the scanner.
                    issue ??= "sftp-initial-remote-type";
                    if (controls == null) { InvalidateFileFacts(); Emit(Array.Empty<Payload>()); return; }
                }
                int operations = 0;
                foreach (var record in TransferLines(controls, "sftp-command-input"))
                {
                    var line = record.Text?.TrimStart(' ', '\t').TrimStart('-', '@').TrimStart(' ', '\t');
                    var words = line == null ? null : SftpWords(line);
                    if (words == null)
                    { Emit(Array.Empty<Payload>(), record.Text == null ? record.Issue : "sftp-command-syntax"); local = null; InvalidateFileFacts(); continue; }
                    if (words.Count == 0) continue;
                    if (++operations > Limits.MaxArguments)
                    { Emit(Array.Empty<Payload>(), "sftp-command-budget"); InvalidateFileFacts(); break; }
                    var verb = words[0].ToLowerInvariant();
                    if (verb is "exit" or "bye" or "quit") break;
                    if (verb is "lcd" or "lchdir")
                    {
                        var candidate = words.Count == 2 ? Disk.Bind(words[1], local) : null;
                        local = candidate != null && InspectMetadata(candidate)?.Attributes.HasFlag(FileAttributes.Directory) == true ? candidate : null;
                        if (local == null) Emit(Array.Empty<Payload>(), "sftp-local-directory");
                        continue;
                    }
                    if (verb is "pwd" or "lpwd" or "help" or "?" or "progress" or "version") continue;
                    if (verb is not ("put" or "mput" or "reput" or "get" or "mget" or "reget"))
                    {
                        if (verb is "cd" or "chdir" && words.Count == 2) Emit(new[] { Text(words[1], "sftp:remote-path", FileRecordMarks(record)) });
                        else
                        {
                            Emit(Array.Empty<Payload>(), "sftp-control-command");
                            if (verb.StartsWith("!", StringComparison.Ordinal) || verb is "lls" or "lmkdir") InvalidateFileFacts();
                        }
                        continue;
                    }
                    bool recursively = call.Has("recurse"), resume = call.Has("resume") || verb == "reput";
                    int i = 1;
                    for (; i < words.Count && words[i].StartsWith("-", StringComparison.Ordinal) && words[i].Length > 1; i++)
                    {
                        if (words[i] == "--") { i++; break; }
                        if (words[i].Substring(1).Any(c => !"afpPrR".Contains(c))) break;
                        recursively |= words[i].IndexOfAny(new[] { 'R', 'r' }) >= 0;
                        resume |= words[i].Contains('a');
                    }
                    if (i >= words.Count || words.Count - i > 2 || words[i].StartsWith("-", StringComparison.Ordinal) && words.ElementAtOrDefault(i-1) != "--")
                    { Emit(Array.Empty<Payload>(), "sftp-file-operands"); continue; }
                    string src = words[i], remoteOrLocal = words.ElementAtOrDefault(i + 1) ?? "";
                    if (verb is "get" or "mget" or "reget")
                    {
                        Emit(new[] { Text(src, "sftp:remote-path", FileRecordMarks(record)) });
                        SftpDownload(remoteOrLocal.Length == 0 ? null : remoteOrLocal, local, src, recursively);
                        continue;
                    }
                    var remoteName = remoteOrLocal.Length == 0 ? Path.GetFileName(src) : remoteOrLocal;
                    var parts = new List<Payload>();
                    if (remoteOrLocal.Length != 0 || src.IndexOfAny(new[] { '*', '?', '[' }) < 0)
                        parts.Add(Text(remoteName, "sftp:remote-path", FileRecordMarks(record)));
                    // On resume the remote file size controls the transmitted suffix.
                    if (resume)
                        parts.Add(policy != null && Disk.Bind(src, local) is string path ? FilePathEvidence(path, "sftp-resume-offset") : Missing("sftp-resume-offset"));
                    else if (src.StartsWith("~", StringComparison.Ordinal) || src.Contains("{"))
                        parts.Add(Missing("sftp-source-expansion"));
                    else parts.Add(AggregateFileEvidence(SftpUpload(src, local, recursively), "sftp:upload"));
                    Emit(parts);
                }
                if (initialPath) InvalidateFileFacts(); // the other branch downloaded and exited
            }
        }
    }
}

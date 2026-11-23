using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            // Lexical only. Never probe a share, a mapped drive's remote target, or a PSSession.
            static string? ShareHost(string? value)
            {
                if (string.IsNullOrEmpty(value)) return null;
                var path = value!.Replace('/', '\\');
                const string provider = "Microsoft.PowerShell.Core\\FileSystem::";
                if (path.StartsWith(provider, StringComparison.OrdinalIgnoreCase)) path = path.Substring(provider.Length);
                else if (path.StartsWith("FileSystem::", StringComparison.OrdinalIgnoreCase)) path = path.Substring(12);
                if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) path = @"\\" + path.Substring(8);
                if (!path.StartsWith(@"\\", StringComparison.Ordinal)) return null;
                var segments = path.Substring(2).Split(new[] { '\\' }, 3);
                if (segments.Length < 2 || segments[0].Length == 0 || segments[1].Length == 0 ||
                    segments[0] is "." or ".." || segments[1] is "." or ".." ||
                    segments[0].Any(c => !(char.IsLetterOrDigit(c) || c is '.' or '-' or '_'))) return null;
                return segments[0];
            }

            void ShareSend(string name, string host, IEnumerable<Payload> parts, string? issue)
            {
                if (!barrier && TrustLoopback && LoopbackHost(host)) SkipLoopback(name, host);
                else Send(name, host, parts, issue);
            }

            Payload ShareBody(Payload p)
            {
                if (p.IsString || p.PipeText != null || p.Bytes != null) return p;
                if (p.Elements != null && p.Elements.All(e => e.IsString))
                {
                    var data = AggregateFileEvidence(p.Elements, "share:text-records");
                    return p.InspectionPartial || !p.Complete || p.RecordRemainder != null ? Partial(data, "share-output-records") : data;
                }
                return new Payload { Tags = FileRecordMarks(p), Issue = "share-output-format", InspectionPartial = true };
            }

            Payload? RemoteCopy(string name, Args args, Payload from, Payload destination)
            {
                var session = args.Has("ToSession");
                var host = session ? null : ShareHost(destination.Text);
                var issue = session ? "copy-session-endpoint" : args.Has("Confirm") ? "confirmation" : null;
                IEnumerable<Payload> Sources()
                {
                    foreach (var selected in SelectFilePaths(from, args, includeDirectories: true))
                    {
                        if (!selected.Complete || selected.InspectionPartial || selected.Text == null)
                        { yield return Missing("copy-source-selection"); continue; }
                        if (args.Has("Recurse") && (args.Has("Filter") || args.Has("Include") || args.Has("Exclude")))
                        { yield return Missing("copy-recursive-filter"); continue; }
                        if (!args.Has("Recurse"))
                        { foreach (var p in TransferSource(selected.Text, cwd, false, "copy:local-source")) yield return p; continue; }
                        var path = Disk.Bind(selected.Text, cwd);
                        if (path == null || barrier) { yield return Missing("copy-source-directory"); continue; }
                        foreach (var (entry, problem) in EnumerateFiles(path, true, includeHidden: args.Has("Force"), providerOrder: false))
                        {
                            if (!FileCountAvailable) { yield return Missing("file-count-budget"); yield break; }
                            yield return entry == null ? Missing(problem ?? "copy-source-entry") : File(entry.Path, false, out _);
                        }
                    }
                }
                var parts = new[] { destination, AggregateFileEvidence(Sources(), "copy:local-sources") };
                if (host == null) Send(name, null, parts, issue ?? "copy-destination");
                else ShareSend(name, host, parts, issue);
                if (name == "move-item")
                    foreach (var source in from.Elements ?? new[] { from })
                        if (Disk.Bind(source.FileObject?.Path ?? source.Text, cwd) is string path) MarkPossibleWrite(path, null);
                return args.Has("PassThru") ? Missing("copy-remote-output") : null;
            }

            Payload? BitsTransfer(object command, Payload? pipe)
            {
                using var args = new Args(this, command, new[] { "Source", "Destination", "TransferType", "DisplayName",
                    "Description", "Priority", "Credential", "Authentication", "ProxyUsage", "ProxyList", "ProxyBypass",
                    "CustomHeaders", "RetryInterval", "RetryTimeout", "ProxyCredential", "ProxyAuthentication" },
                    new[] { "Asynchronous", "WhatIf", "Confirm", "Dynamic", "Suspended" });
                if (args.Has("WhatIf")) return null;
                const string name = "start-bitstransfer";
                string? problem = !args.Valid ? "bits-arguments" : args.Has("Suspended") ? "bits-suspended" :
                    args.Has("Asynchronous") ? "bits-scheduled" : args.Has("Confirm") ? "confirmation" : null;
                int pos = 0;
                Payload? Bind(string key)
                {
                    var node = args.Get(key) ?? args.Plain.ElementAtOrDefault(pos);
                    if (!args.Has(key) && node != null) pos++;
                    return node == null ? null : Value(node);
                }
                var source = Bind("Source"); var destination = Bind("Destination");
                if (!args.Valid || args.Plain.Count != pos || pipe != null || source == null ||
                    args.Has("Suspended"))
                { Send(name, null, Array.Empty<Payload>(), problem ?? "bits-input-binding"); return Missing("bits-job"); }
                var kind = args.Has("TransferType") ? Value(args.Get("TransferType")).Text?.ToLowerInvariant() : "download";
                if (kind is not ("upload" or "uploadreply" or "download"))
                { Send(name, null, Array.Empty<Payload>(), "bits-direction"); return Missing("bits-job"); }
                var sources = source.Elements ?? new[] { source };
                var targets = destination?.Elements ?? (destination == null ? Array.Empty<Payload>() : new[] { destination });
                if (destination != null && targets.Length != sources.Length || kind != "download" && targets.Length != 1)
                { Send(name, null, Array.Empty<Payload>(), "bits-pairing"); return Missing("bits-job"); }
                if (args.Has("Credential") || args.Has("ProxyCredential") || args.Has("ProxyList")) problem ??= "bits-auth-or-proxy";
                for (int i = 0; i < Math.Min(sources.Length, Limits.MaxDestinations); i++)
                {
                    var src = sources[i]; var dst = targets.ElementAtOrDefault(i);
                    var remote = kind == "download" ? src : dst;
                    var endpoint = Http(remote?.Text); var share = ShareHost(remote?.Text);
                    var parts = new List<Payload>();
                    if (remote != null && endpoint != null) AddRequestTarget(parts, remote);
                    else if (remote != null && share != null) parts.Add(remote);
                    if (args.Has("CustomHeaders"))
                        parts.AddRange(TransmittedValues(Value(args.Get("CustomHeaders"))));
                    if (kind != "download") parts.Add(File(src.Text, false, out _));
                    else if (ShareHost(dst?.Text) is string outputHost)
                        ShareSend(name, outputHost, new[] { dst!, Missing("bits-download-content") }, problem);
                    else if (dst != null) InvalidateOutputFile(dst);
                    else InvalidateFileFacts();
                    // BITS may use configured proxies/redirects; a syntactically local
                    // initial HTTP URL alone is not evidence that bytes remain local.
                    if (share != null) ShareSend(name, share, parts, problem);
                    else Send(name, endpoint, parts, problem ?? (LoopbackUri(endpoint) ? "bits-redirect-destination" : null));
                }
                if (sources.Length > Limits.MaxDestinations || source.InspectionPartial || destination?.InspectionPartial == true)
                    Send(name, null, Array.Empty<Payload>(), "bits-pairing-limit");
                return args.Has("Asynchronous") ? Missing("bits-job") : null;
            }

            void WindowsCopyTool(string name, object command)
            {
                var argv = FlattenNative(command, out var bound);
                if (argv.Length > Limits.MaxArguments || argv.Any(s => s == null))
                { Send(name, null, Array.Empty<Payload>(), "copy-tool-operands"); return; }
                var paths = new List<NativeArgument>(); bool tree = false, listOnly = false, info = false;
                string? problem = null;
                for (int i = 0; i < argv.Length; i++)
                {
                    var s = argv[i]!;
                    if (!s.StartsWith("/", StringComparison.Ordinal) || s.StartsWith("//", StringComparison.Ordinal))
                    { paths.Add(new NativeArgument(s, bound[i])); continue; }
                    var flag = s.ToUpperInvariant();
                    if (flag == "/?") info = true;
                    else if (flag == "/L") listOnly = true;
                    else if (flag is "/E" or "/S" || name == "robocopy" && flag == "/MIR") tree = true;
                    else if (name == "robocopy" && (flag is "/Z" or "/NP" or "/NJH" or "/NJS" or "/NFL" or "/NDL" or "/MT" ||
                        new[] { "/R:", "/W:", "/MT:" }.Any(p => flag.StartsWith(p, StringComparison.Ordinal) && uint.TryParse(flag.Substring(p.Length), out _)))) { }
                    else if (name == "xcopy" && flag is ("/I" or "/Y" or "/Q" or "/F" or "/H" or "/K" or "/R")) { }
                    else problem ??= "copy-tool-options";
                }
                if (info) return;
                if (paths.Count < 2 || name == "xcopy" && paths.Count != 2)
                { Send(name, null, Array.Empty<Payload>(), "copy-tool-operands"); return; }
                var dst = paths[1].Text!;
                if (ShareHost(dst) is not string host)
                {
                    if (!listOnly)
                    {
                        if (name == "robocopy" || tree) InvalidateFileFacts();
                        else if (Disk.Bind(dst, cwd) is string path) MarkPossibleWrite(path, null);
                    }
                    if (problem != null) Send(name, null, Array.Empty<Payload>(), problem);
                    return;
                }
                var metadata = NativeText(paths[1], "copy:remote-destination");
                if (listOnly || problem != null)
                { ShareSend(name, host, new[] { metadata }, problem); return; }
                string src = paths[0].Text!;
                var masks = paths.Skip(2).Select(p => p.Text!).ToList();
                if (name == "xcopy" && src.IndexOfAny(new[] { '*', '?' }) >= 0)
                {
                    int sep = src.LastIndexOfAny(new[] { '/', '\\' });
                    masks.Add(src.Substring(sep + 1)); src = sep < 0 ? "." : src.Substring(0, sep + 1);
                }
                IEnumerable<Payload> FilesForCopy()
                {
                    if (Disk.Bind(src, cwd) is not string source || barrier || masks.Any(m => m.Length == 0 || m.Length > 255 ||
                        m.IndexOfAny(new[] { '\\', '/', '[', ']', ':' }) >= 0))
                    { yield return Missing("copy-tool-source"); yield break; }
                    // DOS wildcard and short-name expansion are broader than simple Unicode
                    // matching. Keep residual uncertainty rather than inventing extra files.
                    bool Match(string leaf) => masks.Count == 0 || masks.Any(m => m is "*" or "*.*" ||
                        System.IO.Enumeration.FileSystemName.MatchesSimpleExpression(m, leaf, ignoreCase: true));
                    bool hidden = name == "robocopy" || argv.Any(a => string.Equals(a, "/H", StringComparison.OrdinalIgnoreCase));
                    foreach (var (entry, error) in EnumerateFiles(source, tree, includeHidden: hidden, matchesName: Match,
                        matchesAttributes: a => hidden || !a.HasFlag(FileAttributes.System), providerOrder: false))
                    {
                        if (!FileCountAvailable) { yield return Missing("file-count-budget"); yield break; }
                        yield return entry == null ? Missing(error ?? "copy-tool-entry") : File(entry.Path, false, out _);
                    }
                    if (masks.Count != 0) yield return Missing("copy-tool-name-selection");
                }
                ShareSend(name, host, new[] { metadata, AggregateFileEvidence(FilesForCopy(), "copy-tool:local-sources") },
                    "copy-tool-remote-state");
            }
        }
    }
}

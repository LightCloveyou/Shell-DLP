using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed class GitProof
        {
            internal string Endpoint = "";
            internal bool Network, Loopback;
            internal Payload[] Parts = Array.Empty<Payload>();
            static int BlobCacheBudget => Limits.MaxGitCache;
            static readonly string[] OverrideVariables = { "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR",
                "GIT_CONFIG", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM",
                "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_REPLACE_REF_BASE" };
            static bool NoOverrides() => OverrideVariables.All(x => string.IsNullOrEmpty(Environment.GetEnvironmentVariable(x)));
            static bool ObjectId(string s) => Regex.IsMatch(s, @"^(?:[0-9a-f]{40}|[0-9a-f]{64})$");
            static bool GitRef(string s) => Regex.IsMatch(s, @"^refs/(?:heads|tags)/[A-Za-z0-9_./-]{1,160}\z") &&
                !s.Contains("..") && !s.Contains("//") && !s.EndsWith("/", StringComparison.Ordinal) &&
                !s.EndsWith(".", StringComparison.Ordinal) && !s.EndsWith(".lock", StringComparison.OrdinalIgnoreCase);
            static bool Args(string?[] args) => args.Length >= 2 && args.Length - 1 <= Limits.MaxGitRefs && args[0] != null &&
                PushRemote(args[0]!) &&
                args.Skip(1).All(a => a != null && a.Split(':').Length == 2 &&
                    GitRef(a.Split(':')[0].TrimStart('+')) && GitRef(a.Split(':')[1]));
            static bool PushRemote(string value) => RemoteName(value) || NetworkTarget(value);
            static bool RemoteName(string value) => Regex.IsMatch(value, @"^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,63}\z");

            static string[]? CanonicalPush(string?[] arguments, out List<string> unqualifiedDestinations, out string[] selectors)
            {
                unqualifiedDestinations = new List<string>();
                selectors = Array.Empty<string>();
                var options = new SortedSet<string>(StringComparer.Ordinal);
                if (arguments.Any(a => a == null)) return null;
                var operands = new List<string>();
                bool separator = false;
                foreach (var arg in arguments.OfType<string>())
                {
                    if (!separator && arg == "--") { separator = true; continue; }
                    // These options change tracking/permission to update the ref,
                    // not the source/destination pair or the candidate object set.
                    if (!separator && arg is ("-u" or "--set-upstream" or "-f" or "--force")) continue;
                    if (!separator && (arg == "--force-with-lease" || arg.StartsWith("--force-with-lease=", StringComparison.Ordinal))) continue;
                    if (!separator && arg is ("--tags" or "--follow-tags" or "--all" or "--branches"))
                    { options.Add(arg == "--branches" ? "--all" : arg); continue; }
                    if (!separator && arg.StartsWith("-", StringComparison.Ordinal)) return null;
                    operands.Add(arg);
                }
                var args = operands.ToArray();
                selectors = options.ToArray();
                if (options.Contains("--all") && (options.Contains("--tags") || args.Length > 1)) return null;
                if (args.Length == 0) return args;
                if (!PushRemote(args[0])) return null;
                if (args.Length == 1) return args; // resolve default refspec for the selected remote
                for (int i = 1; i < args.Length; i++)
                {
                    var spec = args[i].StartsWith("+", StringComparison.Ordinal) ? args[i].Substring(1) : args[i];
                    var pair = spec.Split(':');
                    if (pair.Length > 2 || pair.Any(p => p.Length == 0 || p.StartsWith("-", StringComparison.Ordinal))) return null;
                    var source = pair[0] == "HEAD" || pair[0].StartsWith("refs/", StringComparison.Ordinal) ? pair[0] : "refs/heads/" + pair[0];
                    var target = pair.Length == 1 ? source :
                        pair[1].StartsWith("refs/", StringComparison.Ordinal) ? pair[1] : "refs/heads/" + pair[1];
                    if ((source != "HEAD" && !GitRef(source)) || (target != "HEAD" && !GitRef(target))) return null;
                    if (pair.Length == 2 && !pair[1].StartsWith("refs/", StringComparison.Ordinal))
                        unqualifiedDestinations.Add(pair[1]);
                    args[i] = source + ":" + target;
                }
                return args.Length - 1 <= Limits.MaxGitRefs ? args : null;
            }

            static bool UnambiguousDestinations(IEnumerable<string> shortNames, IEnumerable<string> advertised)
            {
                var refs = new HashSet<string>(advertised, StringComparer.Ordinal);
                return shortNames.All(name => !refs.Contains(name) && !refs.Contains("refs/" + name) &&
                    !refs.Contains("refs/tags/" + name) && !refs.Contains("refs/remotes/" + name) &&
                    !refs.Contains("refs/remotes/" + name + "/HEAD"));
            }

            static string? HeadRef(string dot)
            {
                var head = Disk.TrySample(Path.Combine(dot, "HEAD"), true)?.Text?.TrimEnd();
                return head != null && head.StartsWith("ref: ", StringComparison.Ordinal) && head.StartsWith("ref: refs/heads/", StringComparison.Ordinal) && GitRef(head.Substring(5))
                    ? head.Substring(5) : null;
            }

            static string[]? ResolveDefaultPush(string head, Dictionary<string, List<string>> config, string? selectedRemote)
            {
                string? Get(string key)
                {
                    if (!config.TryGetValue(key, out var values)) return null;
                    if (values.Count != 1) throw new IOException("ambiguous Git push configuration: " + key);
                    return values[0];
                }
                var branch = "branch." + head.Substring("refs/heads/".Length) + ".";
                var fetchRemote = Get(branch + "remote");
                var remotes = config.Keys.Where(k => k.StartsWith("remote.", StringComparison.Ordinal) &&
                    k.EndsWith(".url", StringComparison.Ordinal)).Select(k => k.Substring(7, k.Length - 11)).ToArray();
                var baselineRemote = fetchRemote ?? (remotes.Length == 1 ? remotes[0] : "origin");
                var remote = selectedRemote ?? Get(branch + "pushremote") ?? Get("remote.pushdefault") ?? baselineRemote;
                if (!remotes.Contains(remote, StringComparer.Ordinal)) return null;
                if (config.TryGetValue("remote." + remote + ".push", out var configured))
                {
                    var resolved = CanonicalPush(new[] { remote }.Concat(configured).ToArray(), out var shorts, out var configuredOptions);
                    return resolved?.Length >= 2 && Args(resolved) && configuredOptions.Length == 0 && shorts.Count == 0 &&
                        configured.All(x => x.Length != 0 && !x.StartsWith("-", StringComparison.Ordinal)) ? resolved : null;
                }
                var mode = Get("push.default") ?? "simple";
                string destination = head;
                if (mode is "simple" or "upstream" or "tracking")
                {
                    var merge = Get(branch + "merge");
                    bool triangular = !string.Equals(remote, baselineRemote, StringComparison.Ordinal);
                    if (triangular && mode != "simple") return null;
                    if (!triangular)
                    {
                        var auto = Get("push.autosetupremote");
                        if (merge == null && auto is ("true" or "yes" or "on" or "1")) merge = head;
                        if (merge == null || !GitRef(merge) || (mode == "simple" && merge != head)) return null;
                        destination = merge;
                    }
                }
                else if (mode != "current") return null;
                var result = new[] { remote, head + ":" + destination };
                return Args(result) ? result : null;
            }

            static string? Repo(string? cwd)
            {
                if (cwd == null || !Disk.ClearAncestors(cwd)) return null;
                for (int i = 0; i < Limits.MaxRepoDepth && cwd != null; i++, cwd = Path.GetDirectoryName(cwd))
                {
                    var dot = Path.Combine(cwd, ".git");
                    if (Directory.Exists(dot)) return Disk.ClearAncestors(dot) ? cwd : null;
                    if (File.Exists(dot)) return null; // linked worktree: not yet covered
                }
                return null;
            }
            static string ProofKey(string repo, IEnumerable<string?> args)
            {
                ulong hash = 14695981039346656037UL;
                foreach (char c in repo.ToUpperInvariant() + "\0" + string.Join("\0", args))
                    hash = unchecked((hash ^ c) * 1099511628211UL);
                return hash.ToString("x16", CultureInfo.InvariantCulture);
            }
            static bool NetworkTarget(string url)
            {
                if (url.Any(char.IsControl)) return false;
                if (url.Contains("://"))
                    return Uri.TryCreate(url, UriKind.Absolute, out var u) && u.Scheme is ("https" or "http" or "ssh") &&
                        u.Host.Length != 0 && u.UserInfo.IndexOf(':') < 0 && string.IsNullOrEmpty(u.Query);
                return Regex.IsMatch(url, @"^(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9.-]{2,}:[^:\s]+$");
            }
            static string? ConfigStamp(string path)
            {
                path = Path.GetFullPath(path);
                if (!Disk.Local(path)) return null;
                for (string? parent = path; parent != null; parent = Path.GetDirectoryName(parent))
                {
                    try
                    {
                        if ((File.GetAttributes(parent) & FileAttributes.ReparsePoint) != 0 || !Disk.ClearAncestors(parent)) return null;
                        return parent == path ? Disk.TargetStamp(path) : "";
                    }
                    catch (FileNotFoundException) { }
                    catch (DirectoryNotFoundException) { }
                }
                return null;
            }
            static string? ReadRef(string dot, string name, Disk.Sample? packed)
            {
                var path = Path.Combine(dot, name.Replace('/', '\\'));
                var file = Disk.TrySample(path, true);
                var direct = file?.Text?.Trim();
                if (direct != null) return ObjectId(direct) ? direct : null;
                if (Disk.TargetStamp(path) != "" || packed?.Text == null) return null;
                return Lines(packed.Text).Select(l => l.Split(' ')).Where(x => x.Length == 2 && x[1] == name && ObjectId(x[0]))
                    .Select(x => x[0]).FirstOrDefault();
            }
            static string[] LocalRefInventory(string dot, Policy policy)
            {
                var refs = new SortedDictionary<string, string>(StringComparer.Ordinal);
                var packed = Disk.TrySample(Path.Combine(dot, "packed-refs"), true);
                if (packed?.Text == null && Disk.TargetStamp(Path.Combine(dot, "packed-refs")) != "")
                    throw new IOException("packed refs unavailable");
                foreach (var line in Lines(packed?.Text ?? ""))
                {
                    var fields = line.Split(' ');
                    if (fields.Length == 2 && (fields[1].StartsWith("refs/heads/") || fields[1].StartsWith("refs/tags/")))
                    {
                        if (!GitRef(fields[1]) || !ObjectId(fields[0])) throw new IOException("unsupported packed ref");
                        refs[fields[1]] = fields[0];
                        if (refs.Count > policy.MaxGitRefs) throw new IOException("ref inventory limit");
                    }
                }
                var timer = Stopwatch.StartNew();
                foreach (var prefix in new[] { "refs/heads", "refs/tags" })
                {
                    var root = Path.Combine(dot, prefix);
                    if (!Directory.Exists(root))
                    { if (Disk.TargetStamp(root) != "") throw new IOException("ref directory unavailable"); continue; }
                    var dirs = new Stack<string>();
                    dirs.Push(root);
                    while (dirs.Count != 0)
                    {
                        string directory = dirs.Pop();
                        if (!Disk.ClearAncestors(directory)) throw new IOException("ref directory unavailable");
                        foreach (var file in Directory.EnumerateFileSystemEntries(directory))
                        {
                            if (timer.ElapsedMilliseconds > policy.FileScanBudgetMs || refs.Count > policy.MaxGitRefs)
                                throw new IOException("ref inventory limit");
                            if (Directory.Exists(file)) { dirs.Push(file); continue; }
                            string name = Path.GetRelativePath(dot, file).Replace((char)92, '/');
                            if (!GitRef(name) || ReadRef(dot, name, packed) is not string oid) throw new IOException("unstable local ref");
                            refs[name] = oid;
                        }
                    }
                }
                if (refs.Count > policy.MaxGitRefs) throw new IOException("ref inventory limit");
                return refs.Select(kv => kv.Key + "=" + kv.Value).ToArray();
            }

            static string[] Lines(string value) => value.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
            internal static GitProof? TryRead(string? cwd, string?[] args, Policy? policy)
            {
                try
                {
                    var input = CanonicalPush(args, out var shortDestinations, out var selectors);
                    if (policy == null || input == null || !NoOverrides() || Repo(cwd) is not string repo) return null;
                    var data = Store.ReadGit(ProofKey(repo, input.Concat(selectors)));
                    if (data == null) return null;
                    var doc = new Toml(data);
                    var receipt = doc.Sections.Single(s => s.Name == "[proof");
                    if (receipt.Get("coverage") != "reachable-v2" || !receipt.Array("selectors").SequenceEqual(selectors) ||
                        !PathEq(receipt.Get("repo"), repo) || !receipt.Array("args").SequenceEqual(input) ||
                        !DateTime.TryParse(receipt.Get("time"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var time) ||
                        time > DateTime.UtcNow || (DateTime.UtcNow - time).TotalSeconds > policy.GitProofLifetime ||
                        ConfigStamp(Store.Config) != receipt.Get("policy_stamp")) return null;
                    var configPaths = receipt.Array("config_paths");
                    var configStamps = receipt.Array("config_stamps");
                    if (configPaths.Length == 0 || configPaths.Length != configStamps.Length || configPaths.Length > policy.MaxGitConfigs) return null;
                    for (int i = 0; i < configPaths.Length; i++)
                        if (ConfigStamp(configPaths[i]) != configStamps[i]) return null;
                    var dot = Path.Combine(repo, ".git");
                    var effective = receipt.Array("resolved_args");
                    if (!Args(effective) && !(selectors.Length != 0 && effective.Length == 1 && PushRemote(effective[0]))) return null;
                    if (receipt.Get("head_ref") != "" && HeadRef(dot) != receipt.Get("head_ref")) return null;
                    if (input.Length > 0 && effective[0] != input[0]) return null;
                    if (selectors.Length != 0 && !LocalRefInventory(dot, policy).SequenceEqual(receipt.Array("inventory"))) return null;
                    if (shortDestinations.Count != 0 && !UnambiguousDestinations(shortDestinations,
                        receipt.Array("baseline").Select(x => x.Split('=')[0]))) return null;
                    var packed = Disk.TrySample(Path.Combine(dot, "packed-refs"), true);
                    var sources = receipt.Array("sources");
                    if (sources.Length != effective.Length - 1) return null;
                    for (int i = 0; i < sources.Length; i++)
                        if (ReadRef(dot, effective[i + 1].Split(':')[0].TrimStart('+'), packed) != sources[i]) return null;
                    var endpoint = receipt.Get("endpoint");
                    bool network = NetworkTarget(endpoint);
                    if (receipt.Get("complete") is not ("yes" or "no") || !network && Disk.Bind(endpoint, repo) == null ||
                        NetworkTarget(effective[0]) && effective[0] != endpoint) return null;
                    var markSections = doc.Sections.Where(s => s.Name == "[[marks").ToArray();
                    if (markSections.Any(s => !policy.Rules.Any(r => r.Id == s.Get("rule_id")) ||
                        string.IsNullOrEmpty(s.Get("origin")))) return null;
                    var marks = markSections
                        .Select(s => new Mark(s.Get("rule_id"), s.Get("origin"), s.Get("route"))).ToArray();
                    return new GitProof { Endpoint = endpoint, Network = network, Loopback = LoopbackSsh(endpoint),
                        Parts = new[] { new Payload
                    { Complete = receipt.Get("complete") == "yes", Issue = "git-object-content", Tags = marks } } };
                }
                catch { return null; }
            }

            static string Arg(string s) => "\"" + Regex.Replace(s, @"(\\*)""", "$1$1\\\"").Replace("\0", "") +
                new string('\\', s.Reverse().TakeWhile(c => c == '\\').Count()) + "\"";
            static byte[] Limited(Stream stream, int cap)
            {
                using var output = new MemoryStream();
                var buf = new byte[4096];
                int n;
                while ((n = stream.Read(buf, 0, buf.Length)) != 0)
                {
                    if (output.Length + n > cap) throw new IOException("Git output limit");
                    output.Write(buf, 0, n);
                }
                return output.ToArray();
            }
            static Process StartGit(string executable, string repo, params string[] arguments)
            {
                var info = new ProcessStartInfo(executable, string.Join(" ", arguments.Select(Arg)))
                { WorkingDirectory = repo, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
                info.EnvironmentVariables["GIT_TERMINAL_PROMPT"] = "0";
                info.EnvironmentVariables["GIT_OPTIONAL_LOCKS"] = "0";
                return Process.Start(info) ?? throw new IOException("git process");
            }
            static byte[] Git(string executable, string repo, int cap, params string[] arguments)
            {
                using var child = StartGit(executable, repo, arguments);
                var output = Task.Run(() => Limited(child.StandardOutput.BaseStream, cap));
                var error = Task.Run(() => Limited(child.StandardError.BaseStream, Limits.MaxGitMetadataBytes));
                try
                {
                    if (!child.WaitForExit(Limits.MaxGitCommandTime) || !Task.WaitAll(new Task[] { output, error }, Limits.MaxGitCommandTime) || child.ExitCode != 0)
                        throw new IOException("git preflight command failed: " + arguments.First());
                    return output.Result;
                }
                finally { if (!child.HasExited) child.Kill(); }
            }
            static (string[] RuleIds, bool Complete) ScanBlobStream(string executable, string repo, string oid,
                long size, long byteBudget, Policy policy, Stopwatch deadline)
            {
                var remaining = Math.Min(policy.MaxGitCommandTime, policy.MaxGitTime - deadline.ElapsedMilliseconds);
                if (remaining <= 0) return (Array.Empty<string>(), false);
                using var child = StartGit(executable, repo, "cat-file", "blob", oid);
                var wait = Stopwatch.StartNew();
                using var stderr = child.StandardError.BaseStream;
                using var stdout = child.StandardOutput.BaseStream;
                var drain = Task.Run(() =>
                {
                    try { return Limited(stderr, Limits.MaxGitMetadataBytes).Length; }
                    catch (IOException) { return -1; }
                    catch (ObjectDisposedException) { return -1; }
                });
                var output = Task.Run(() =>
                {
                    var found = MatchTextStream(stdout, size, policy, byteBudget, "git-blob:" + oid,
                        () => wait.ElapsedMilliseconds < remaining);
                    return (found.Marks, found.Issue, End: found.Issue.Length == 0 && stdout.ReadByte() == -1);
                });
                try
                {
                    if (!output.Wait((int)remaining)) return (Array.Empty<string>(), false);
                    var result = output.Result;
                    if (result.Issue == "file-truncated") return (Array.Empty<string>(), false);
                    bool full = result.Issue.Length == 0;
                    if (full && (!result.End ||
                        !child.WaitForExit((int)Math.Max(0, remaining - wait.ElapsedMilliseconds)) ||
                        child.ExitCode != 0 || !drain.Wait((int)Math.Max(0, remaining - wait.ElapsedMilliseconds)) || drain.Result < 0))
                        return (Array.Empty<string>(), false);
                    // A deliberate prefix/encoding cutoff does not negate literal hits
                    // already decoded from this object; the proof remains partial.
                    return (result.Marks.Select(m => m.Id).ToArray(), full);
                }
                catch (AggregateException) { return (Array.Empty<string>(), false); }
                catch (IOException) { return (Array.Empty<string>(), false); }
                finally
                {
                    if (!child.HasExited)
                    {
                        try { child.Kill(); }
                        catch (InvalidOperationException) { } // exited between the check and Kill
                    }
                    // Observe late exceptions after a timeout without holding the proof open.
                    _ = output.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
                }
            }

            static string StringList(IEnumerable<string> values) => "[" + string.Join(", ", values.Select(Toml.Quote)) + "]";
            static string Field(string n, string v) => n + " = " + Toml.Quote(v) + "\n";

            internal static string Prepare(string executable, string location, string remote, string[] refspecs)
            {
                if (string.IsNullOrWhiteSpace(executable)) throw new ArgumentException("Specify the Git executable.", nameof(executable));
                if (string.IsNullOrWhiteSpace(location)) throw new ArgumentException("Specify the repository location.", nameof(location));
                if (refspecs == null) throw new ArgumentNullException(nameof(refspecs));
                if (!string.IsNullOrEmpty(remote) && !PushRemote(remote)) throw new ArgumentException("Invalid remote.", nameof(remote));
                if (refspecs.Any(string.IsNullOrWhiteSpace)) throw new ArgumentException("Empty Git argument.", nameof(refspecs));
                var flags = refspecs.Where(a => a is "--tags" or "--all" or "--follow-tags").ToArray();
                var specsInput = refspecs.Where(a => !flags.Contains(a)).ToArray();
                if (remote.Length == 0 && specsInput.Length != 0) throw new ArgumentException("Refspecs require a remote.");
                Store.Refresh();
                var args = flags.Concat(remote.Length == 0 ? Array.Empty<string>() : new[] { "--", remote })
                    .Concat(specsInput).ToArray();
                var input = CanonicalPush(args, out var shortDestinations, out var selectors);
                if (input == null || !NoOverrides() || Repo(location) is not string repo)
                    throw new ArgumentException("Use a supported repository and default push, or a named remote with branch refspecs.");
                var dot = Path.Combine(repo, ".git");
                var deadline = Stopwatch.StartNew();
                string[] Run(int max, params string[] cmd)
                {
                    if (deadline.ElapsedMilliseconds > Limits.MaxGitTime) throw new IOException("preflight time limit");
                    return Lines(StrictUtf8.GetString(Git(executable, repo, max, cmd)));
                }
                var policy = Store.Current(out string issue) ?? throw new IOException(issue);
                var policyStamp = ConfigStamp(Store.Config);
                if (!string.IsNullOrEmpty(issue) || string.IsNullOrEmpty(policyStamp)) throw new IOException("policy-unavailable");
                var configs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { Path.Combine(dot, "config"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".gitconfig") };
                var xdg = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME");
                configs.Add(Path.Combine(string.IsNullOrEmpty(xdg) ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config") : xdg!,
                    "git", "config"));
                var configLines = Run(policy.MaxGitMetadataBytes, "config", "--list", "--show-origin");
                var effectiveConfig = new Dictionary<string, List<string>>(StringComparer.Ordinal);
                foreach (var line in configLines)
                {
                    var pair = line.Split(new[] { '\t' }, 2);
                    if (pair.Length != 2 || !pair[0].StartsWith("file:", StringComparison.Ordinal))
                        throw new IOException("unsupported config origin");
                    var item = pair[1].Split(new[] { '=' }, 2);
                    var key = item[0];
                    if (!effectiveConfig.TryGetValue(key, out var values))
                        effectiveConfig.Add(key, values = new List<string>());
                    values.Add(item.Length == 2 ? item[1] : "true");
                    if (key.StartsWith("include", StringComparison.OrdinalIgnoreCase) || key.StartsWith("url.", StringComparison.OrdinalIgnoreCase) ||
                        key.Equals("extensions.worktreeconfig", StringComparison.OrdinalIgnoreCase) || key.EndsWith(".mirror", StringComparison.OrdinalIgnoreCase) ||
                        key.Equals("push.followtags", StringComparison.OrdinalIgnoreCase))
                        throw new IOException("configuration can change the set or destination of pushed objects");
                    configs.Add(Path.GetFullPath(Path.Combine(repo, pair[0].Substring(5).Trim('"'))));
                }
                if (configs.Count > policy.MaxGitConfigs) throw new IOException("configuration set limit");
                var viableConfigs = configs.ToArray();
                var stamps = viableConfigs.Select(ConfigStamp).ToArray();
                if (stamps.Any(s => s == null)) throw new IOException("configuration unavailable");
                bool bulk = selectors.Contains("--all") || selectors.Contains("--tags");
                bool explicitHead = input.Skip(1).Any(spec => spec.StartsWith("HEAD:", StringComparison.Ordinal));
                bool needHead = explicitHead || input.Length == 0 || input.Length == 1 && !bulk;
                var preparedHead = needHead ? HeadRef(dot) : null;
                if (needHead && preparedHead == null) throw new IOException("default push requires a symbolic branch HEAD");
                if (!bulk && input.Length <= 1)
                    args = ResolveDefaultPush(preparedHead!, effectiveConfig, input.SingleOrDefault()) ??
                        throw new IOException("default push configuration is ambiguous or unsupported");
                else if (input.Length != 0)
                    args = input.Take(1).Concat(input.Skip(1).Select(spec =>
                        string.Join(":", spec.Split(':').Select(part => part == "HEAD" ? preparedHead : part)))).ToArray();
                else
                {
                    var branch = "branch." + preparedHead!.Substring("refs/heads/".Length) + ".";
                    string? Config(string key) => effectiveConfig.TryGetValue(key, out var entries) ? entries.Single() : null;
                    var remotes = Run(policy.MaxGitMetadataBytes, "remote");
                    args = new[] { Config(branch + "pushremote") ?? Config("remote.pushdefault") ?? Config(branch + "remote") ??
                        (remotes.Length == 1 ? remotes[0] : "origin") };
                }
                var inventory = selectors.Length == 0 ? Array.Empty<string>() : LocalRefInventory(dot, policy);
                var chosen = new HashSet<string>(args.Skip(1), StringComparer.Ordinal);
                foreach (var entry in inventory)
                {
                    var name = entry.Split('=')[0];
                    if (selectors.Contains("--all") && name.StartsWith("refs/heads/") ||
                        selectors.Contains("--tags") && name.StartsWith("refs/tags/")) chosen.Add(name + ":" + name);
                }
                if (selectors.Contains("--follow-tags"))
                {
                    foreach (var source in chosen.Select(x => x.Split(':')[0]).ToArray())
                    {
                        var reachable = Run(policy.MaxGitMetadataBytes, "for-each-ref", "--merged=" + source, "--format=%(objecttype) %(refname)", "refs/tags");
                        foreach (var tag in reachable.Where(x => x.StartsWith("tag ", StringComparison.Ordinal)).Select(x => x.Substring(4)))
                            chosen.Add(tag + ":" + tag);
                    }
                }
                args = new[] { args[0] }.Concat(chosen.OrderBy(x => x, StringComparer.Ordinal)).ToArray();
                if (args.Length - 1 > policy.MaxGitRefs || args.Length > 1 && !Args(args)) throw new IOException("refspec limit");
                var endpoints = NetworkTarget(args[0]) ? new[] { args[0] } : Run(policy.MaxGitMetadataBytes, "remote", "get-url", "--push", "--all", args[0]);
                if (endpoints.Length != 1 || (!NetworkTarget(endpoints[0]) && Disk.Bind(endpoints[0], repo) == null))
                    throw new IOException("unsupported remote");
                var endpoint = endpoints[0];
                var queryStart = DateTime.UtcNow;
                var network = NetworkTarget(endpoint);
                var loopback = network && policy.TrustLoopback && LoopbackSsh(endpoint);
                string[] advertised;
                if (loopback)
                    advertised = Array.Empty<string>();
                else if (network)
                    advertised = Run(policy.MaxGitMetadataBytes, "ls-remote", "--refs", "--", endpoint);
                else
                {
                    var local = Disk.Bind(endpoint, repo)!;
                    var localDot = Directory.Exists(Path.Combine(local, ".git")) ? Path.Combine(local, ".git") : local;
                    if (!Disk.ClearAncestors(localDot)) throw new IOException("local remote unavailable");
                    advertised = Run(policy.MaxGitMetadataBytes, "--git-dir=" + localDot, "for-each-ref", "--format=%(objectname)%09%(refname)");
                }
                var baselines = advertised.Select(l => l.Split('\t')).ToArray();
                if (baselines.Length > policy.MaxGitBaseline || baselines.Any(p => p.Length != 2 || !ObjectId(p[0]) || !p[1].StartsWith("refs/", StringComparison.Ordinal)))
                    throw new IOException("remote baseline limit");
                if (!UnambiguousDestinations(shortDestinations, baselines.Select(p => p[1])))
                    throw new IOException("unqualified Git push destination matches a non-branch ref; use a full ref name");
                var specs = args.Skip(1).Select(a => a.Split(':')[0].TrimStart('+')).ToArray();
                var packed = Disk.TrySample(Path.Combine(dot, "packed-refs"), true);
                var sources = specs.Select(s => ReadRef(dot, s, packed) ?? throw new IOException("local ref unavailable")).ToArray();
                // Remote refs can disappear after preflight. A receipt based on exclusions
                // cannot certify the object set a later push may transfer.
                var revisions = sources.Distinct().ToArray();
                var commits = loopback || revisions.Length == 0 ? Array.Empty<string>() :
                    Run((int)Math.Min(int.MaxValue, 66L * ProbeCount(policy.GitMaxCommits)), new[] { "rev-list", "--max-count=" + ProbeCount(policy.GitMaxCommits) }.Concat(revisions).ToArray());
                if (commits.Length > policy.GitMaxCommits || commits.Any(c => !ObjectId(c))) throw new IOException("git_max_commits exceeded");
                var allObjects = loopback || revisions.Length == 0 ? Array.Empty<string>() :
                    Run((int)Math.Min(int.MaxValue, 66L * ProbeCount(policy.GitMaxObjects)), new[] { "rev-list", "--objects", "--no-object-names" }.Concat(revisions).ToArray());
                if (allObjects.Length > policy.GitMaxObjects || allObjects.Any(x => !ObjectId(x))) throw new IOException("git_max_objects exceeded");
                var outgoing = new HashSet<string>(allObjects, StringComparer.Ordinal);
                var marks = new Dictionary<string, Mark>(StringComparer.Ordinal);
                var inspected = new HashSet<string>(StringComparer.Ordinal);
                var blobBytes = new Dictionary<string, byte[]?>(StringComparer.Ordinal);
                var streamedBlobs = new Dictionary<string, (string[] RuleIds, bool Complete)>(StringComparer.Ordinal);
                long blobByteBudget = policy.MaxFileBytes == 0 ? long.MaxValue : policy.MaxFileBytes;
                long remainingBlobBytes = policy.MaxTotalFileBytes == 0 ? long.MaxValue : policy.MaxTotalFileBytes;
                int cachedBytes = 0;
                bool complete = true;
                bool NeedsText() => policy.Rules.Any(r => r.Texts.Length != 0 && !marks.ContainsKey(r.Id));
                void MatchPath(string name)
                {
                    foreach (var r in policy.Rules)
                        if (!marks.ContainsKey(r.Id) && (r.Files.Any(f => PathEq(f, name)) ||
                            r.Folders.Any(f => name.StartsWith(f.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase))))
                            marks[r.Id] = new Mark(r.Id, name, name);
                }
                void MatchText(string name, string? text, bool streamChecked = false)
                {
                    if (text == null) { if (!streamChecked && NeedsText()) complete = false; return; }
                    foreach (var r in policy.Rules)
                    {
                        if (marks.ContainsKey(r.Id)) continue;
                        if (r.Texts.Any(t => text.IndexOf(t, StringComparison.Ordinal) >= 0))
                            marks[r.Id] = new Mark(r.Id, name, name);
                    }
                }
                // Annotated tag messages are separate objects. A tag that ultimately
                // targets a blob or tree also needs coverage outside a commit's tree.
                foreach (var source in specs.Where(name => name.StartsWith("refs/tags/", StringComparison.Ordinal)))
                {
                    string oid = sources[Array.IndexOf(specs, source)];
                    var seen = new HashSet<string>(StringComparer.Ordinal);
                    while (!loopback && seen.Add(oid))
                    {
                        var kind = Run(policy.MaxGitMetadataBytes, "cat-file", "-t", oid).Single();
                        if (kind == "commit") break;
                        if (kind != "tag")
                        {
                            if (kind == "blob" && NeedsText()) MatchText("git-blob:" + oid, Disk.Decode(Git(executable, repo, MaxContent, "cat-file", "blob", oid)));
                            complete = false;
                            break;
                        }
                        var tag = Disk.Decode(Git(executable, repo, MaxContent, "cat-file", "tag", oid));
                        MatchText("git-tag:" + source, tag);
                        var first = tag == null ? null : Lines(tag).FirstOrDefault();
                        if (first == null || !first.StartsWith("object ") || !ObjectId(first.Substring(7))) { complete = false; break; }
                        oid = first.Substring(7);
                    }
                }
                foreach (var commit in commits)
                {
                    if (deadline.ElapsedMilliseconds > Limits.MaxGitTime) throw new IOException("preflight time limit");
                    if (NeedsText())
                    {
                        var content = Disk.Decode(Git(executable, repo, MaxContent, "cat-file", "commit", commit));
                        MatchText("commit:" + commit, content);
                    }
                    var treeData = StrictUtf8.GetString(Git(executable, repo, policy.MaxGitMetadataBytes, "ls-tree", "-r", "-z", commit));
                    foreach (var row in treeData.Split(new[] { '\0' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        var tab = row.IndexOf('\t');
                        if (tab < 0) throw new IOException("invalid git tree");
                        var head = row.Substring(0, tab).Split(' ');
                        if (head.Length != 3 || head[1] != "blob" || !outgoing.Contains(head[2])) continue;
                        var relative = row.Substring(tab + 1);
                        var target = Disk.Bind(relative, repo);
                        if (target == null || !target.StartsWith(repo.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase))
                        { complete = false; continue; }
                        if (!inspected.Add(head[2] + "\0" + target)) continue;
                        if (inspected.Count > policy.GitMaxPathBindings) throw new IOException("git_max_path_bindings exceeded");
                        MatchPath(target); // Verified tree binding: a path rule needs no blob read.
                        bool textRules = NeedsText();
                        var copies = policy.Rules.Where(r => !marks.ContainsKey(r.Id)).SelectMany(r => r.Copies.Where(entry =>
                            PathEq(ConfigPath(entry.Get("path"), Path.GetDirectoryName(Store.Config)!), target))
                            .Select(entry => (rule: r, entry))).ToArray();
                        string oid = head[2];
                        byte[]? raw = null;
                        if ((textRules || copies.Length != 0) && !streamedBlobs.ContainsKey(oid) && !blobBytes.TryGetValue(oid, out raw))
                        {
                            var bytes = Run(policy.MaxGitMetadataBytes, "cat-file", "-s", oid);
                            if (bytes.Length == 1 && long.TryParse(bytes[0], NumberStyles.None, CultureInfo.InvariantCulture, out var length))
                            {
                                long allowance = Math.Min(blobByteBudget, remainingBlobBytes);
                                remainingBlobBytes -= Math.Min(length, allowance);
                                if (length <= MaxContent && length <= allowance)
                                    raw = Git(executable, repo, MaxContent, "cat-file", "blob", oid);
                                else if (textRules)
                                    streamedBlobs.Add(oid, ScanBlobStream(executable, repo, oid, length, allowance, policy, deadline));
                            }
                            if (!streamedBlobs.ContainsKey(oid) && (raw == null || raw.Length <= BlobCacheBudget - cachedBytes))
                            {
                                blobBytes[oid] = raw;
                                cachedBytes += raw?.Length ?? 0;
                            }
                        }
                        bool checkedStream = false;
                        if (streamedBlobs.TryGetValue(oid, out var streamed))
                        {
                            foreach (var id in streamed.RuleIds)
                                if (!marks.ContainsKey(id)) marks.Add(id, new Mark(id, target, target).Via("git-blob:" + oid));
                            checkedStream = streamed.Complete;
                        }
                        if (textRules) MatchText(target, raw == null ? null : Disk.Decode(raw), checkedStream);
                        if (copies.Length != 0)
                        {
                            var current = Disk.TrySample(target, true);
                            foreach (var copy in copies)
                            {
                                if (raw == null || current?.Bytes == null || current.Stamp != copy.entry.Get("stamp") ||
                                    !raw.SequenceEqual(current.Bytes)) { complete = false; continue; }
                                var origin = copy.entry.Get("origin");
                                if (origin.Length == 0) origin = copy.entry.Get("copied_from");
                                if (!marks.ContainsKey(copy.rule.Id)) marks[copy.rule.Id] =
                                    new Mark(copy.rule.Id, origin, copy.entry.Get("route")).Via("git:" + target);
                            }
                        }
                    }
                }
                var finalPacked = Disk.TrySample(Path.Combine(dot, "packed-refs"), true);
                if ((selectors.Length != 0 && !LocalRefInventory(dot, policy).SequenceEqual(inventory)) ||
                    specs.Where((name, i) => ReadRef(dot, name, finalPacked) != sources[i]).Any() ||
                    ConfigStamp(Store.Config) != policyStamp || viableConfigs.Select(ConfigStamp).Where((s, i) => s != stamps[i]).Any() ||
                    (preparedHead != null && HeadRef(dot) != preparedHead) || !Run(policy.MaxGitMetadataBytes, "config", "--list", "--show-origin").SequenceEqual(configLines))
                    throw new IOException("policy or configuration changed during preflight");
                var b = new StringBuilder("[proof]\n").Append(Field("repo", repo)).Append(Field("endpoint", endpoint))
                    .Append(Field("time", queryStart.ToString("O", CultureInfo.InvariantCulture))).Append(Field("policy_stamp", policyStamp!))
                    .Append(Field("coverage", "reachable-v2")).Append("selectors = ").AppendLine(StringList(selectors))
                    .Append("inventory = ").AppendLine(StringList(inventory))
                    .Append(Field("complete", complete ? "yes" : "no")).Append("args = ").AppendLine(StringList(input))
                    .Append("resolved_args = ").AppendLine(StringList(args)).Append(Field("head_ref", preparedHead ?? ""))
                    .Append("sources = ").AppendLine(StringList(sources))
                    .Append("baseline = ").AppendLine(StringList(baselines.Select(p => p[1] + "=" + p[0])))
                    .Append("config_paths = ").AppendLine(StringList(viableConfigs))
                    .Append("config_stamps = ").AppendLine(StringList(stamps.Select(s => s!)));
                foreach (var mark in marks.Values)
                    b.Append("\n[[marks]]\n").Append(Field("rule_id", mark.Id)).Append(Field("origin", mark.Origin)).Append(Field("route", mark.Route));
                if (!Store.SaveGit(ProofKey(repo, input.Concat(selectors)), b.ToString())) throw new IOException("preflight storage unavailable");
                return "preflight-ready; commits=" + commits.Length + "; objects=" + allObjects.Length + "; matched-rules=" + marks.Count +
                    "; complete=" + complete + "; network=" + (network && !loopback) + (loopback ? "; loopback=True" : "");
            }
        }

        // The optional preflight entry point is only called by the separate
        // command-line helper, never by the AMSI callback.
        public static string PrepareGitPush(string gitExe, string repository, string remote, string[] refspecs) =>
            GitProof.Prepare(gitExe, repository, remote, refspecs);
    }
}

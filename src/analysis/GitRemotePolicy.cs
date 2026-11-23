using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class GitProof
        {
            // Compare the configured push URL, never the redacted endpoint used for display.
            // In particular scp's relative path is not an ssh:// absolute path.
            static readonly Regex AddressUrl = new Regex(
                @"\A(?<scheme>https?|ssh)://(?:(?<user>[A-Za-z0-9._-]+)@)?(?<host>[A-Za-z0-9.-]+)(?::(?<port>[0-9]{1,5}))?/(?<path>[A-Za-z0-9._~/-]+)\z",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            static readonly Regex AddressScp = new Regex(
                @"\A(?:(?<user>[A-Za-z0-9._-]+)@)?(?<host>[A-Za-z0-9.-]+):(?<path>/?[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*)\z");

            internal static string? RemoteAddressKey(string value)
            {
                if (value.Length == 0 || value.Length > 1024 || value.Any(c => c > 127)) return null;
                var m = AddressUrl.Match(value);
                bool scp = !m.Success;
                if (scp) m = AddressScp.Match(value);
                if (!m.Success) return null;
                var scheme = m.Groups["scheme"].Value.ToLowerInvariant();
                var host = m.Groups["host"].Value.ToLowerInvariant();
                var user = m.Groups["user"].Value;
                var port = m.Groups["port"].Value;
                var path = m.Groups["path"].Value;
                if (host.Length > 253 || host.Split('.').Any(s => s.Length == 0 || s.Length > 63 || s[0] == '-' || s[s.Length-1] == '-') ||
                    scp && host.Length == 1 || !scp && scheme != "ssh" && user.Length != 0 ||
                    (scp && path.StartsWith("/", StringComparison.Ordinal) ? path.Substring(1) : path)
                        .Split('/').Any(s => s.Length == 0 || s is "." or "..")) return null;
                if (port.Length != 0 && (!int.TryParse(port, NumberStyles.None, CultureInfo.InvariantCulture, out var n) ||
                    n < 1 || n > 65535 || n.ToString(CultureInfo.InvariantCulture) != port)) return null;
                var authority = (user.Length == 0 ? "" : user + "@") + host;
                return scp ? authority + ":" + path :
                    scheme + "://" + authority + (port.Length == 0 ? "" : ":" + port) + "/" + path;
            }

            internal static bool PermitsSensitivePush(string? directory, string?[] args, string reportedEndpoint, Policy policy, Func<bool> time)
            {
                try
                {
                    if (policy.InvalidGitRemoteAllowlist || policy.GitRemoteAllowlist.Count == 0 || !time() || !NoOverrides() ||
                        Repo(directory) is not string repo || !Store.RefreshDerived(true) ||
                        !ReferenceEquals(policy, Store.Current(out var issue)) || issue.Length != 0) return false;
                    var input = CanonicalPush(args, out _, out _);
                    if (input == null) return false;
                    var dot = Path.Combine(repo, ".git");
                    if (ConfigStamp(Path.Combine(dot, "commondir")) != "") return false;
                    var cfg = JournalConfig.Load(repo, forAllowlist: true);
                    if (cfg == null) return false;
                    var head = input.Length == 0 ? HeadRef(dot) : null;
                    if (input.Length == 0)
                    {
                        if (head == null) return false;
                        var branch = "branch." + head.Substring("refs/heads/".Length) + ".";
                        if (!cfg.Values.ContainsKey(branch + "pushremote") && !cfg.Values.ContainsKey("remote.pushdefault") &&
                            !cfg.Values.ContainsKey(branch + "remote")) return false; // never guess a trusted default
                    }
                    var operand = input.FirstOrDefault() ?? (head == null ? null : ResolveDefaultPush(head, cfg.Values, null)?.FirstOrDefault());
                    if (operand == null || cfg.RawTarget(operand) is not string raw || RemoteAddressKey(raw) is not string key ||
                        !policy.GitRemoteAllowlist.Contains(key)) return false;
                    // A URL-named remote is ambiguous with a literal URL. Never grant an exception for it.
                    if (NetworkTarget(operand) && cfg.Values.Keys.Any(k => k.StartsWith("remote." + operand + ".", StringComparison.Ordinal))) return false;
                    if (reportedEndpoint != raw && reportedEndpoint != cfg.Target(operand)) return false;
                    return (head == null || head == HeadRef(dot)) && cfg.Current() && time();
                }
                catch (Exception e) when (e is not (OutOfMemoryException or StackOverflowException or AccessViolationException))
                { return false; }
            }
        }

        sealed partial class AdapterContext
        {
            // Only use the disk routing snapshot for an isolated literal command. A preceding
            // statement/subexpression can change Git configuration or process environment.
            static bool StandaloneGitCommand(object command)
            {
                var pipeline = Prop(command, "Parent");
                var block = Prop(pipeline, "Parent");
                var script = Prop(block, "Parent");
                return Kind(pipeline) == "PipelineAst" && Items(Prop(pipeline, "PipelineElements")).Count() == 1 &&
                    Kind(block) == "NamedBlockAst" && Items(Prop(block, "Statements")).Count() == 1 &&
                    !Items(Prop(block, "Traps")).Any() && Kind(script) == "ScriptBlockAst" &&
                    Prop(script, "Parent") == null && ReferenceEquals(block, Prop(script, "EndBlock")) &&
                    Prop(script, "ParamBlock") == null && Prop(script, "BeginBlock") == null && Prop(script, "ProcessBlock") == null &&
                    Prop(script, "DynamicParamBlock") == null && Prop(script, "CleanBlock") == null &&
                    !Items(Prop(script, "UsingStatements")).Any() && !Items(Prop(command, "Redirections")).Any() &&
                    Items(Prop(command, "CommandElements")).All(e => Kind(e) == "StringConstantExpressionAst" ||
                        Kind(e) == "CommandParameterAst" && Prop(e, "Argument") == null);
            }
        }
    }
}

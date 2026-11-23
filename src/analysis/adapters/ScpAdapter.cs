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
            static readonly Dictionary<string, NativeOption> ScpOptions = NativeOptions(
                "+port -P", "+jump -J", "+ssh-config -F", "+rate -l", "+identity -i", "+cipher -c", "+ssh-option -o",
                "recursive -r", "mode -O -s", "transport -3 -4 -6 -B -C -p -q -v -A -T -R", "+sftp-option -X", "+ssh-program -S", "+sftp-server -D");
            static readonly string[] ScpLocalOptions = {
                "Compression", "BatchMode", "ConnectTimeout", "ConnectionAttempts", "ServerAliveInterval", "ServerAliveCountMax",
                "StrictHostKeyChecking", "IdentitiesOnly", "UserKnownHostsFile", "GlobalKnownHostsFile", "LogLevel"
            };

            static string? ScpHost(string value)
            {
                if (value.StartsWith("scp://", StringComparison.Ordinal))
                    return Uri.TryCreate(value, UriKind.Absolute, out var url) && url.Host.Length != 0 &&
                        !url.UserInfo.Contains(":") ? url.Host : null;
                // Win32 OpenSSH reserves drive prefixes, including drive-relative paths.
                // Only the colon after the host is structural; later colons belong to the path.
                if (value.Length >= 2 && value[1] == ':') return null;
                var match = Regex.Match(value, @"^(?:[A-Za-z0-9._-]+@)?(?<host>[A-Za-z0-9._-]+|\[[0-9a-fA-F:]+\]):");
                return match.Success ? match.Groups["host"].Value : null;
            }

            // Inspect remote request metadata independently from local file bytes. Never
            // open a remote path, or inspect a local download destination as an upload.
            Payload SshOperand(NativeArgument arg, string role)
            {
                if (arg.Text == null) return Missing(role);
                string user, host, path;
                if ((arg.Text.StartsWith("sftp://", StringComparison.OrdinalIgnoreCase) ||
                     arg.Text.StartsWith("scp://", StringComparison.OrdinalIgnoreCase)) &&
                    Uri.TryCreate(arg.Text, UriKind.Absolute, out var uri))
                {
                    user = Uri.UnescapeDataString(uri.UserInfo); host = uri.Host; path = Uri.UnescapeDataString(uri.AbsolutePath);
                }
                else
                {
                    var m = Regex.Match(arg.Text, @"^(?:(?<user>[\w.-]+)@)?(?<host>[A-Za-z0-9._-]+|\[[0-9A-Fa-f:.]+\])(?::(?<path>[^\r\n]*))?\z");
                    if (!m.Success) return Missing(role + "-syntax");
                    user = m.Groups["user"].Value; host = m.Groups["host"].Value; path = m.Groups["path"].Value;
                }
                var origins = arg.Value == null ? Array.Empty<Mark>() : FileRecordMarks(arg.Value);
                return AggregateFileEvidence(new[] { user, host, path }.Where(v => v.Length != 0)
                    .Select(v => Text(v, role, origins)), role);
            }

            IEnumerable<Payload> TransferSource(string raw, string? directory, bool recursive, string role)
            {
                if (policy == null) { yield return Missing("policy-unavailable"); yield break; }
                if (barrier && !Path.IsPathFullyQualified(raw)) { yield return Missing(role + "-cwd"); yield break; }
                var source = Disk.Bind(raw, directory);
                if (source == null)
                {
                    yield return !recursive && Disk.ExternalRulePath(raw) is string external
                        ? FilePathEvidence(external, role + "-external-content") : Missing(role + "-path");
                    yield break;
                }
                if (!recursive)
                {
                    if (!barrier && !plannedFiles.Contains(source) && FileTimeAvailable && Disk.ClearAncestors(source) &&
                        DiskAttributes(source)?.HasFlag(FileAttributes.Directory) == true) yield return Missing(role + "-directory");
                    else yield return File(source, false, out _).Via(role);
                    yield break;
                }
                if (barrier) { yield return Missing(role + "-recursive"); yield break; }
                foreach (var (entry, problem) in EnumerateFiles(source, recurse: true, providerOrder: false))
                {
                    if (entry == null) { yield return Missing(problem ?? role + "-unavailable"); continue; }
                    // Enumeration and content reads have independent bounds. A yielded file
                    // may still match a configured path even when its bytes cannot be inspected.
                    yield return File(entry.Path, false, out _).Via(role);
                }
            }

            void Scp(object command)
            {
                var call = ReadNative(command, ScpOptions, longEquals: false);
                string? issue = call.Error;
                foreach (var (name, arg) in call.Options)
                {
                    if (name == "port" && (!ushort.TryParse(arg.Text, NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port == 0))
                        issue ??= "port-value";
                    if (name == "rate" && (!uint.TryParse(arg.Text, NumberStyles.None, CultureInfo.InvariantCulture, out var rate) || rate == 0))
                        issue ??= "rate-value";
                    if ((name is "identity" or "cipher" or "jump" or "ssh-config") && string.IsNullOrWhiteSpace(arg.Text))
                        issue ??= name + "-value";
                    if (name is "ssh-program" or "sftp-server") issue ??= "custom-transport";
                    if (name == "ssh-option" && (arg.Text == null || !ScpLocalOptions.Contains(
                        arg.Text.Split(new[] { '=', ' ', '\t' }, 2)[0], StringComparer.OrdinalIgnoreCase)))
                        issue ??= "ssh-option";
                }
                string? target = call.Position.LastOrDefault()?.Text;
                if (call.Has("sftp-server") || call.Has("ssh-program"))
                { Send("scp", null, Array.Empty<Payload>(), "scp-custom-transport"); return; }
                if (issue is "missing-option-value" or "port-value" or "rate-value" || target == null || call.Position.Count < 2)
                { Send("scp", null, Array.Empty<Payload>(), "scp-" + (issue ?? "operands")); return; }
                var host = ScpHost(target);
                if (host == null)
                {
                    foreach (var operand in call.Position.Take(call.Position.Count - 1))
                        if (operand.Text != null && ScpHost(operand.Text) is string remote)
                        {
                            var metadata = SshOperand(operand, "scp:remote-request");
                            if (TrustLoopback && !barrier && issue == null && LoopbackHost(remote) && !call.Has("jump") && !call.Has("ssh-config"))
                                SkipLoopback("scp", remote);
                            else Send("scp", remote, new[] { metadata }, issue);
                        }
                    var destination = Disk.Bind(target, cwd);
                    if (destination == null || issue != null) Send("scp", null, Array.Empty<Payload>(), issue ?? "scp-destination");
                    if (destination == null || call.Position.Count > 2 || call.Has("recursive") ||
                        InspectMetadata(destination)?.Attributes.HasFlag(FileAttributes.Directory) == true)
                        InvalidateFileFacts();
                    else InvalidateOutputFile(Text(target, "scp-output"));
                    return; // a local output path is never inspected as upload input
                }
                if (issue == null && !barrier && TrustLoopback && LoopbackHost(host) && !call.Has("jump") && !call.Has("ssh-config") &&
                    call.Position.Take(call.Position.Count - 1).All(v => v.Text != null && ScpHost(v.Text) == null)) { SkipLoopback("scp", host); return; }
                bool recursive = call.Has("recursive");
                IEnumerable<Payload> Sources()
                {
                    foreach (var operand in call.Position.Take(call.Position.Count - 1))
                    {
                        if (operand.Text == null || ScpHost(operand.Text) != null) { yield return Missing("scp-remote-source"); continue; }
                        foreach (var part in TransferSource(operand.Text, cwd, recursive, "scp:local-source")) yield return part;
                    }
                }
                Send("scp", host, new[] { SshOperand(call.Position[call.Position.Count - 1], "scp:remote-request"),
                    AggregateFileEvidence(Sources(), "scp:sources") }, issue);
            }
        }
    }
}

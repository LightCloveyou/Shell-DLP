using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            static readonly Dictionary<string, NativeOption> WgetOptions = NativeOptions(
                "+post-data --post-data", "+post-file --post-file", "+body-data --body-data", "+body-file --body-file",
                "+header --header", "+http-user --http-user", "+http-password --http-password",
                "+user --user", "+password --password",
                "+proxy-user --proxy-user", "+proxy-password --proxy-password", "auth --auth-no-challenge", "+user-agent --user-agent -U", "+referer --referer",
                "+method --method", "+output --output-document -O",
                "+input --input-file -i", "html --force-html -F", "+base --base -B",
                "+log --output-file -o --append-output -a", "+directory --directory-prefix -P",
                "+timing --timeout -T --tries -t --dns-timeout --connect-timeout --read-timeout --wait -w --waitretry",
                "+max-redirect --max-redirect", "display --quiet -q --no-verbose -nv --verbose -v --debug -d",
                "informational --help -h --version -V", "download --continue -c --server-response -S --timestamping -N --no-clobber -nc", "spider --spider",
                "+tls --secure-protocol", "tls-flags --no-check-certificate --https-only --no-http-keep-alive",
                "no-config --no-config", "network --no-proxy --inet4-only -4 --inet6-only -6");
            static readonly Dictionary<string, bool> WgetArity = new Dictionary<string, bool>(StringComparer.Ordinal)
            {
                ["--config"] = true, ["-e"] = true, ["--execute"] = true
            };

            void Wget(object command, Payload? pipe)
            {
                var call = ReadNative(command, WgetOptions, longEquals: true, exactShort: true, otherArity: WgetArity);
                if (call.Has("informational")) return;
                if (call.Error == "missing-option-value")
                { Send("wget", null, Array.Empty<Payload>(), call.Error); return; }
                string? issue = call.Error;
                var arguments = new Dictionary<string, NativeArgument>(StringComparer.Ordinal);
                var headers = new Dictionary<string, NativeArgument>(StringComparer.OrdinalIgnoreCase);
                foreach (var (option, arg) in call.Options)
                {
                    if (option != "header") { arguments[option] = arg; continue; }
                    if (arg.Text == null) { issue ??= "header-value"; headers["\0" + headers.Count] = arg; continue; }
                    if (arg.Text.Length == 0) { headers.Clear(); continue; }
                    int colon = arg.Text.IndexOf(':');
                    if (colon <= 0 || arg.Text.Contains('\n') ||
                        arg.Text.Take(colon).Any(c => c is (' ' or '\t' or '\r' or '\v' or '\f')))
                    {
                        Send("wget", null, Array.Empty<Payload>(), "header-value");
                        return;
                    }
                    headers[arg.Text.Substring(0, colon)] = arg;
                }
                bool hasMethod = arguments.TryGetValue("method", out var method);
                bool hasPost = arguments.ContainsKey("post-data") || arguments.ContainsKey("post-file");
                bool hasBody = arguments.ContainsKey("body-data") || arguments.ContainsKey("body-file");
                bool missingMethod = hasBody && !hasMethod;
                bool conflictingBody = (hasPost && (hasMethod || hasBody)) || (missingMethod && call.Has("no-config")) ||
                    (arguments.ContainsKey("post-data") && arguments.ContainsKey("post-file")) ||
                    (arguments.ContainsKey("body-data") && arguments.ContainsKey("body-file"));
                if (conflictingBody && call.Error == null)
                {
                    Send("wget", null, Array.Empty<Payload>(), "option-conflict");
                    if (arguments.TryGetValue("log", out var log))
                        InvalidateOutputFile(NativeText(log, "wget-output"), dashMeansStdout: true);
                    return;
                }
                if (conflictingBody) issue ??= "option-conflict";
                if (missingMethod) issue ??= "wget-body-method";
                var methodText = method?.Text;
                if (hasMethod && (string.IsNullOrEmpty(methodText) || methodText.IndexOfAny(new[] { ' ', '\r', '\n', '\t' }) >= 0))
                    issue ??= "method-value";
                var targets = call.Position.Take(Limits.MaxDestinations).Select(t => NativeText(t, "wget-url")).ToList();
                string? remainingIssue = call.Position.Count > Limits.MaxDestinations ? "destination-limit" : null;
                if (arguments.TryGetValue("input", out var list))
                {
                    var listIssue = AddWgetListTargets(list, pipe, targets, call);
                    remainingIssue ??= listIssue;
                }
                var shared = new List<Payload>();
                foreach (var (name, arg) in arguments)
                {
                    if (name is "post-file" or "body-file") shared.Add(NativeFile(arg.Text, "wget:" + name));
                    else if (name is "post-data" or "body-data" or "user-agent" or "referer" or
                        "http-user" or "http-password" or "proxy-user" or "proxy-password")
                        shared.Add(NativeText(arg, "wget:" + name));
                }
                if (!arguments.ContainsKey("http-user") && arguments.TryGetValue("user", out var user))
                    shared.Add(NativeText(user, "wget:http-user"));
                if (!arguments.ContainsKey("http-password") && arguments.TryGetValue("password", out var password))
                    shared.Add(NativeText(password, "wget:http-password"));
                foreach (var header in headers.Values)
                    shared.Add(NativeText(header, "wget:header"));
                if (hasMethod && method != null)
                {
                    var requestMethod = NativeText(method, "wget:method");
                    if (requestMethod.Tags.Length != 0) shared.Add(requestMethod);
                }
                bool noRedirect = arguments.TryGetValue("max-redirect", out var redirects) &&
                    int.TryParse(redirects.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out int maxRedirects) && maxRedirects == 0;
                bool proxy = arguments.ContainsKey("proxy-user") || arguments.ContainsKey("proxy-password");
                var inspected = targets.Count > 1 ? new Dictionary<Payload, Payload>() : null;
                for (int i = 0; i < targets.Count; i++)
                {
                    var target = targets[i];
                    var endpoint = Http(target.Text);
                    var requestIssue = issue ?? (endpoint == null ? "destination" : null);
                    var parts = new List<Payload>();
                    AddRequestTarget(parts, target);
                    parts.AddRange(shared);
                    if (TrustLoopback && LoopbackUri(endpoint))
                    {
                        if (proxy) requestIssue ??= "proxy-destination";
                        if (!noRedirect && parts.Count != 0) requestIssue ??= "redirect-destination";
                    }
                    NativeSend("wget", endpoint, parts, requestIssue ?? (barrier && parts.Count != 0 ? "preceding-effects" : null), inspected, i + 1);
                }
                // Unknown list entries do not change the identity or trust of a known URL.
                if (remainingIssue != null || targets.Count == 0)
                    NativeSend("wget", null, shared, remainingIssue ?? issue ?? "destination", inspected);
                RecordWgetOutput(call, arguments);
            }

            string? AddWgetListTargets(NativeArgument arg, Payload? pipe, List<Payload> targets, NativeCall call)
            {
                // Never fetch remote input lists. The list request itself has a known target,
                // but that server is not necessarily the destination of subsequent requests.
                if (Http(arg.Text) != null)
                {
                    if (targets.Count >= Limits.MaxDestinations) return "destination-limit";
                    targets.Add(NativeText(arg, "wget-input-url"));
                    return "wget-remote-input-list";
                }
                if (call.Has("html") || call.Has("base") || arg.Text == null)
                    return "wget-input-list-format";
                var source = arg.Text == "-" ? pipe : File(arg.Text, true, out _);
                string? issue = null;
                foreach (var record in TransferLines(source, "wget-input-list"))
                {
                    if (record.Text == null) { issue ??= record.Issue; continue; }
                    var raw = record.Text.Trim();
                    if (raw.Length == 0) continue;
                    if (targets.Count >= Limits.MaxDestinations) return "destination-limit";
                    if (Http(raw) == null) { issue ??= "wget-input-list-url"; continue; }
                    targets.Add(Text(raw, "wget-input-url", FileRecordMarks(record)));
                }
                return issue;
            }

            void RecordWgetOutput(NativeCall call, Dictionary<string, NativeArgument> arguments)
            {
                foreach (var option in new[] { "output", "log" })
                    if (arguments.TryGetValue(option, out var arg))
                        InvalidateOutputFile(NativeText(arg, "wget-output"), dashMeansStdout: true);
                if (!call.Has("output") && !call.Has("spider"))
                    InvalidateFileFacts();
            }
        }
    }
}

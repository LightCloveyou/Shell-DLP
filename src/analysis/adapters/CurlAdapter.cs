using System;
using System.Collections.Generic;
using System.Linq;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            static readonly Dictionary<string, NativeOption> CurlOptions = NativeOptions(
                "+data --data --data-ascii -d", "+binary --data-binary", "+raw --data-raw",
                "+urlencode --data-urlencode", "+url-query --url-query", "+credentials --user -u", "+proxy-credentials --proxy-user -U", "+proxy --proxy -x", "+json --json", "+upload --upload-file -T", "+config --config -K",
                "+form --form -F", "+form-string --form-string",
                "+header --header -H", "+proxy-header --proxy-header", "+user-agent --user-agent -A", "+referer --referer -e",
                "+cookie --cookie -b", "+url --url", "+request --request -X",
                "+output --output -o", "+dump-header --dump-header -D", "+write-out --write-out -w",
                "+timing --max-time -m --connect-timeout --retry --retry-delay --retry-max-time --limit-rate --speed-limit -Y --speed-time -y --rate",
                "parallel --parallel -Z", "serial --no-parallel",
                "global --fail-early --no-fail-early --parallel-immediate --no-parallel-immediate --styled-output --trace-ids --trace-time",
                "+global-value --parallel-max --parallel-max-host --trace-config", "+global-output --trace --trace-ascii --libcurl --stderr",
                "display --silent -s --show-error -S --fail -f --fail-with-body --verbose -v --progress-bar -#",
                "direct --ipv4 -4 --ipv6 -6 --globoff -g --disable -q --no-progress-meter --compressed --insecure -k",
                "protocol --http1.0 -0 --http1.1 --http2 --http2-prior-knowledge --http3 --http3-only --http0.9 --no-alpn --no-npn",
                "+tls --tls-max", "tls-floor --tlsv1 -1 --tlsv1.0 --tlsv1.1 --tlsv1.2 --tlsv1.3",
                "retry-flags --retry-all-errors --no-retry-all-errors --retry-connrefused --no-retry-connrefused",
                "get --get -G", "head --head -I", "location --location -L --location-trusted --follow",
                "no-location --no-location --no-location-trusted --no-follow",
                "informational --help -h --manual -M --version -V", "remote-name --remote-name -O --remote-header-name -J", "next --next -:");

            // Arity only, from curl 8.22.0 --help all. These entries are not
            // declared safe or treated as modeled options: their effects remain uncertain.
            static readonly Dictionary<string, bool> CurlArity = BuildCurlArity();
            static Dictionary<string, bool> BuildCurlArity()
            {
                var map = new Dictionary<string, bool>(StringComparer.Ordinal);
                const string valueOptions =
                "--abstract-unix-socket --alt-svc --aws-sigv4 --cacert --capath --cert --cert-type --ciphers " +
                "--config --connect-timeout --connect-to --continue-at --cookie --cookie-jar --create-file-mode " +
                "--crlfile --curves --data --data-ascii --data-binary --data-raw --data-urlencode --delegation " +
                "--dns-interface --dns-ipv4-addr --dns-ipv6-addr --dns-servers --doh-url --dump-header --ech " +
                "--egd-file --engine --etag-compare --etag-save --expect100-timeout --form --form-string " +
                "--ftp-account --ftp-alternative-to-user --ftp-method --ftp-port --ftp-ssl-ccc-mode " +
                "--happy-eyeballs-timeout-ms --haproxy-clientip --header --help --hostpubmd5 --hostpubsha256 --hsts " +
                "--interface --ip-tos --ipfs-gateway --json --keepalive-cnt --keepalive-time --key --key-type " +
                "--knownhosts --krb --libcurl --limit-rate --local-port --login-options --mail-auth --mail-from " +
                "--mail-rcpt --max-filesize --max-redirs --max-time --netrc-file --noproxy --oauth2-bearer --output " +
                "--output-dir --parallel-max --parallel-max-host --pass --pinnedpubkey --preproxy --proto " +
                "--proto-default --proto-redir --proxy --proxy-cacert --proxy-capath --proxy-cert --proxy-cert-type " +
                "--proxy-ciphers --proxy-crlfile --proxy-header --proxy-key --proxy-key-type --proxy-pass " +
                "--proxy-pinnedpubkey --proxy-service-name --proxy-tls13-ciphers --proxy-tlsauthtype " +
                "--proxy-tlspassword --proxy-tlsuser --proxy-user --proxy1.0 --pubkey --quote --random-file --range " +
                "--rate --referer --request --request-target --resolve --retry --retry-delay --retry-max-time " +
                "--sasl-authzid --service-name --sigalgs --socks4 --socks4a --socks5 --socks5-gssapi-service " +
                "--socks5-hostname --speed-limit --speed-time --ssl-sessions --stderr --telnet-option --tftp-blksize " +
                "--time-cond --tls-max --tls13-ciphers --tlsauthtype --tlspassword --tlsuser --trace --trace-ascii " +
                "--trace-config --unix-socket --upload-file --upload-flags --url --url-query --user --user-agent " +
                "--variable --vlan-priority --write-out -A -b -c -C -d -D -e -E -F -h -H -K -m -o -P -Q -r -t -T -u " +
                "-U -w -x -X -y -Y -z";
                const string switches =
                "--anyauth --append --basic --ca-native --cert-status --compressed --compressed-ssh --create-dirs " +
                "--crlf --digest --disable --disable-eprt --disable-epsv --disallow-username-in-url " +
                "--doh-cert-status --doh-insecure --dump-ca-embed --fail --fail-early --fail-with-body --false-start " +
                "--follow --form-escape --ftp-create-dirs --ftp-pasv --ftp-pret --ftp-skip-pasv-ip --ftp-ssl-ccc " +
                "--ftp-ssl-control --get --globoff --haproxy-protocol --head --http0.9 --http1.0 --http1.1 --http2 " +
                "--http2-prior-knowledge --http3 --http3-only --ignore-content-length --insecure --ipv4 --ipv6 " +
                "--junk-session-cookies --list-only --location --location-trusted --mail-rcpt-allowfails --manual " +
                "--metalink --mptcp --negotiate --netrc --netrc-optional --next --no-alpn --no-buffer --no-clobber " +
                "--no-keepalive --no-npn --no-progress-meter --no-sessionid --ntlm --ntlm-wb --out-null --parallel " +
                "--parallel-immediate --path-as-is --post301 --post302 --post303 --progress-bar --proxy-anyauth " +
                "--proxy-basic --proxy-ca-native --proxy-digest --proxy-http2 --proxy-http3 --proxy-insecure " +
                "--proxy-negotiate --proxy-ntlm --proxy-ssl-allow-beast --proxy-ssl-auto-client-cert --proxy-tlsv1 " +
                "--proxytunnel --raw --remote-header-name --remote-name --remote-name-all --remote-time " +
                "--remove-on-error --retry-all-errors --retry-connrefused --sasl-ir --show-error --show-headers " +
                "--silent --skip-existing --socks5-basic --socks5-gssapi --socks5-gssapi-nec --ssl --ssl-allow-beast " +
                "--ssl-auto-client-cert --ssl-no-revoke --ssl-reqd --ssl-revoke-best-effort --sslv2 --sslv3 " +
                "--styled-output --suppress-connect-headers --tcp-fastopen --tcp-nodelay --tftp-no-options " +
                "--tls-earlydata --tlsv1 --tlsv1.0 --tlsv1.1 --tlsv1.2 --tlsv1.3 --tr-encoding --trace-ids " +
                "--trace-time --use-ascii --verbose --version --xattr -: -# -0 -1 -2 -3 -4 -6 -a -B -f -g -G -i -I " +
                "-j -J -k -l -L -M -n -N -O -p -q -R -s -S -v -V -Z";
                foreach (var value in valueOptions.Split(' ')) map[value] = true;
                foreach (var flag in switches.Split(' ')) map[flag] = false;
                return map;
            }
            void Curl(object command, Payload? pipe)
            {
                var groups = new List<NativeCall>();
                NativeCall Option(NativeCall group, string name, NativeArgument arg)
                {
                    if (name == "next")
                    {
                        if (group.Position.Count == 0) return group;
                        groups.Add(group);
                        return new NativeCall();
                    }
                    if (name == "config")
                    {
                        if (ReadCurlConfig(arg, out var options))
                            foreach (var option in options) group = Option(group, option.Name, option.Arg);
                        else
                        {
                            group.UncertainOperandOrder = true;
                            group.Error ??= "curl-config-file";
                            group.Options.Add((name, arg));
                        }
                    }
                    // Native positionals are appended during parsing. Insert explicit
                    // URLs (including config entries) into the same ordered sequence.
                    else if (name == "url")
                    {
                        group.Position.Add(arg);
                        // --url @file may insert zero or more slots at this position.
                        if (arg.Text == null || arg.Text.StartsWith("@", StringComparison.Ordinal))
                            group.UncertainOperandOrder = true;
                    }
                    else group.Options.Add((name, arg));
                    return group;
                }
                groups.Add(ReadNative(command, CurlOptions, longEquals: true, otherArity: CurlArity, handleOption: Option));
                if (groups.Any(g => g.Has("informational"))) return;
                if (groups.Any(g => g.Error == "missing-option-value"))
                { Send("curl", null, Array.Empty<Payload>(), "missing-option-value"); return; }
                bool parallel = groups.SelectMany(g => g.Options).LastOrDefault(o => o.Name is "parallel" or "serial").Name == "parallel";
                int targetBase = 0;
                foreach (var group in groups)
                {
                    CurlTransfer(group, pipe, targetBase);
                    targetBase += group.Position.Count;
                    // Data arguments reading @- are buffered during option parsing. An upload
                    // can fail before it opens stdin, and parallel transfers can race for it.
                    if (!parallel && group.Options.Any(o => o.Name is ("data" or "binary" or "json") && o.Arg.Text == "@-"))
                        pipe = null;
                    else if (pipe != null && group.Options.Any(o => o.Name == "upload" && o.Arg.Text is ("-" or ".")))
                        pipe = UnknownValue("curl-shared-stdin", pipe);
                }
                foreach (var option in groups.SelectMany(g => g.Options).Where(o => o.Name == "global-output"))
                    if (option.Arg.Text != "%") InvalidateOutputFile(NativeText(option.Arg, "curl-output"), dashMeansStdout: true);
            }

            void CurlTransfer(NativeCall call, Payload? pipe, int targetBase)
            {
                string? issue = call.Error;
                var targets = call.Position;
                if (targets.Count == 0 && issue == null)
                { Send("curl", null, Array.Empty<Payload>(), "destination"); return; }
                string? Endpoint(NativeArgument arg) => arg.Text?.IndexOfAny(new[] { '{', '}' }) == -1 ? Http(arg.Text) : null;
                var uploads = call.Options.Where(o => o.Name == "upload").Select(o => o.Arg).ToArray();
                // An empty -T occupies an upload slot but carries no file.
                bool hasUploads = uploads.Any(arg => arg.Text != "");
                var redirectSetting = call.Options.LastOrDefault(o => o.Name is "location" or "no-location").Name;
                bool proxy = call.Has("proxy") || call.Has("proxy-credentials") || call.Has("proxy-header");
                bool form = call.Has("form") || call.Has("form-string");
                bool data = call.Options.Any(o => o.Name is "data" or "binary" or "raw" or "urlencode" or "json");
                bool conflictingBody = ((form && data) || ((form || data) && hasUploads) ||
                    (call.Has("head") && (form || hasUploads || (data && !call.Has("get")))));
                if (conflictingBody && issue == null && targets.Count == 1)
                { Send("curl", Endpoint(targets[0]), Array.Empty<Payload>(), "option-conflict"); return; }
                if (conflictingBody) issue ??= "option-conflict";

                List<Payload>? shared = null;
                var inspected = targets.Count > 1 ? new Dictionary<Payload, Payload>() : null;
                bool hasSharedInput = call.Options.Any(o => o.Name is "data" or "binary" or "raw" or "json" or "urlencode" or
                    "url-query" or "credentials" or "header" or "form" or "form-string" or "user-agent" or "referer" or "cookie" or "request");
                bool repeatedStdin = uploads.Count(a => a.Text is "-" or ".") > 1;
                Payload Upload(NativeArgument arg)
                {
                    var payload = NativeFile(arg.Text == "." ? "-" : arg.Text, "curl:upload", pipe, stdin: true);
                    return repeatedStdin && arg.Text is ("-" or ".") ? Partial(payload, "curl-shared-stdin") : payload;
                }
                var count = Math.Min(targets.Count, Limits.MaxDestinations);
                // An unresolved config or argument list can introduce URL/upload slots.
                // Keep such uploads unattributed rather than assigning them to a named host.
                bool unboundUploads = hasUploads && call.UncertainOperandOrder;
                for (int i = 0; i < count; i++)
                {
                    var target = targets[i];
                    var endpoint = Endpoint(target);
                    int ordinal = targetBase + i + 1;
                    bool hasUpload = i < uploads.Length && uploads[i].Text != "";
                    var requestIssue = issue ?? (endpoint == null ? "destination" : null);
                    var parts = new List<Payload>();
                    AddRequestTarget(parts, NativeText(target, "curl-url"));
                    if (TrustLoopback && LoopbackUri(endpoint))
                    {
                        if (redirectSetting == "location") requestIssue ??= "redirect-destination";
                        if (proxy) requestIssue ??= "proxy-destination";
                        if (!barrier && requestIssue == null)
                        {
                            if (parts.Count != 0 || hasSharedInput || (!unboundUploads && hasUpload)) SkipLoopback("curl", endpoint, ordinal);
                            continue;
                        }
                    }
                    if (!unboundUploads && hasUpload) parts.Add(Upload(uploads[i]));
                    parts.AddRange(shared ??= CurlSharedParts(call, pipe));
                    NativeSend("curl", endpoint, parts, requestIssue ?? (barrier ? "preceding-effects" : null), inspected, ordinal);
                }
                if (targets.Count == 0 || targets.Count > count || unboundUploads)
                {
                    var parts = new List<Payload>();
                    var pending = unboundUploads || targets.Count == 0 ? uploads : uploads.Skip(count).Take(targets.Count - count);
                    parts.AddRange(pending.Where(arg => arg.Text != "").Select(Upload));
                    if (targets.Count == 0 || targets.Count > count) parts.AddRange(shared ??= CurlSharedParts(call, pipe));
                    NativeSend("curl", null, parts, issue ?? (targets.Count > count ? "destination-limit" :
                        unboundUploads ? "curl-upload-binding" : "destination"), inspected);
                }
                if (!unboundUploads && targets.Count != 0 && uploads.Length > targets.Count)
                    Send("curl", null, Array.Empty<Payload>(), "curl-upload-without-url");
                foreach (var (option, arg) in call.Options)
                    if (option is "output" or "dump-header")
                        InvalidateOutputFile(NativeText(arg, "curl-output"), dashMeansStdout: true);
                if (call.Has("remote-name") || (call.Has("config") && issue != null))
                    InvalidateFileFacts();
            }

            List<Payload> CurlSharedParts(NativeCall call, Payload? pipe)
            {
                var parts = new List<Payload>();
                var lastRequest = call.Options.LastOrDefault(o => o.Name == "request").Arg;
                // These string options replace previous values; data, headers, cookies
                // and multipart fields are additive and must stay in their original order.
                var effective = call.Options.Where(o => o.Name is "credentials" or "proxy-credentials" or "user-agent" or "referer")
                    .GroupBy(o => o.Name).ToDictionary(g => g.Key, g => g.Last().Arg);
                foreach (var option in call.Options)
                {
                    var arg = option.Arg;
                    if (effective.TryGetValue(option.Name, out var last) && !ReferenceEquals(arg, last)) continue;
                    var raw = arg.Text;
                    switch (option.Name)
                    {
                        case "data":
                        case "binary":
                        case "json":
                            parts.Add(raw?.StartsWith("@", StringComparison.Ordinal) == true
                                ? NativeFile(raw.Substring(1), "curl:" + option.Name, pipe, stdin: true) : NativeText(arg, "curl:" + option.Name));
                            break;
                        case "proxy-credentials":
                        case "credentials":
                        case "raw":
                        case "form-string":
                        case "user-agent":
                        case "referer":
                            parts.Add(NativeText(arg, "curl:" + option.Name)); break;
                        case "urlencode":
                        case "url-query":
                            int at = raw?.IndexOf('@') ?? -1, eq = raw?.IndexOf('=') ?? -1;
                            string role = "curl:" + option.Name;
                            parts.Add(at >= 0 && (eq < 0 || at < eq) && !(option.Name == "url-query" && raw!.StartsWith("+", StringComparison.Ordinal))
                                ? NativeFile(raw!.Substring(at + 1), role + "-file", pipe, stdin: true)
                                : NativeText(arg, role + "-text"));
                            break;
                        case "header":
                        case "proxy-header":
                            if (raw?.StartsWith("@", StringComparison.Ordinal) == true)
                                parts.Add(NativeFile(raw.Substring(1), "curl:" + option.Name + "-file", pipe, stdin: true));
                            else if (raw != null && (raw.IndexOf(':') > 0 || raw.EndsWith(";", StringComparison.Ordinal)))
                                parts.Add(NativeText(arg, "curl:" + option.Name));
                            else parts.Add(raw == null ? NativeText(arg, "curl:" + option.Name) : Missing("curl-" + option.Name + "-value"));
                            break;
                        case "cookie":
                            parts.Add(raw != null && !raw.Contains("=")
                                ? NativeFile(raw, "curl:cookie-file") : NativeText(arg, "curl:cookie"));
                            break;
                        case "form":
                            parts.Add(CurlForm(arg, pipe));
                            break;
                        case "request":
                            if (arg != lastRequest) break;
                            var method = NativeText(arg, "curl:request");
                            if (method.Tags.Length != 0) parts.Add(method);
                            break;
                    }
                }
                return parts;
            }

            bool ReadCurlConfig(NativeArgument source, out List<(string Name, NativeArgument Arg)> options)
            {
                options = new List<(string Name, NativeArgument Arg)>();
                if (barrier || source.Text == "-" || !Budget()) return false;
                var path = Disk.Bind(source.Text, cwd);
                if (path == null || plannedFiles.Contains(path) || PendingFiles.ContainsKey(path)) return false;
                var config = File(path, true, out var file);
                if (file?.Text == null || file.Bytes == null) return false;
                int count = 0;
                using var lines = new System.IO.StringReader(file.Text);
                string? line;
                while ((line = lines.ReadLine()) != null)
                {
                    if (++count > Limits.MaxLines || !Budget()) return false;
                    line = line.TrimStart();
                    if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                    int pos = 0;
                    while (pos < line.Length && !char.IsWhiteSpace(line[pos]) && line[pos] is not (':' or '=')) pos++;
                    if (pos == 0) return false;
                    var key = line.Substring(0, pos);
                    var rest = line.Substring(pos);
                    bool explicitDash = key[0] == '-';
                    if (!explicitDash) key = "--" + key;
                    if (!CurlOptions.TryGetValue(key, out var option) || option.Name == "config") return false;
                    rest = rest.TrimStart();
                    if (rest.Length > 0 && rest[0] is ':' or '=')
                    {
                        if (explicitDash) return false;
                        rest = rest.Substring(1).TrimStart();
                    }
                    if (option.TakesValue)
                    {
                        if (!ReadCurlConfigValue(rest, out var value)) return false;
                        options.Add((option.Name, new NativeArgument(value, Text(value, "curl:config-value", FileRecordMarks(config)))));
                    }
                    else
                    {
                        if (rest.Length != 0) return false;
                        options.Add((option.Name, new NativeArgument(null, null)));
                    }
                    if (options.Count > Limits.MaxArguments) return false;
                }
                return true;
            }
            static bool ReadCurlConfigValue(string rest, out string value)
            {
                value = "";
                if (rest.Length == 0) return false;
                if (rest[0] != '"')
                {
                    int end = 0;
                    while (end < rest.Length && !char.IsWhiteSpace(rest[end])) end++;
                    if (end == 0 || rest.Substring(end).Trim().Length != 0) return false;
                    value = rest.Substring(0, end);
                    return true;
                }
                var b = new System.Text.StringBuilder();
                for (int i = 1; i < rest.Length; i++)
                {
                    char c = rest[i];
                    if (c == '"')
                    {
                        if (rest.Substring(i + 1).Trim().Length != 0) return false;
                        value = b.ToString();
                        return true;
                    }
                    if (c == '\\')
                    {
                        if (++i >= rest.Length) return false;
                        c = rest[i] switch { 't' => '\t', 'n' => '\n', 'r' => '\r', 'v' => '\v', _ => rest[i] };
                    }
                    b.Append(c);
                }
                return false;
            }

            Payload CurlForm(NativeArgument arg, Payload? pipe)
            {
                var raw = arg.Text;
                int eq = raw?.IndexOf('=') ?? -1;
                if (raw == null) return NativeText(arg, "curl-form-value");
                if (eq <= 0) return Missing("curl-form-value");
                var value = raw.Substring(eq + 1);
                // Multipart extensions can introduce extra file inputs; distinguish simple fields first.
                if (value.IndexOfAny(new[] { '"', '\r', '\n' }) >= 0) return Missing("curl-form-components");
                if (value.StartsWith("@", StringComparison.Ordinal) && value.Contains(","))
                {
                    // The simple comma-separated file list; do not guess at per-part attributes.
                    if (value.Contains(";")) return Missing("curl-form-components");
                    var paths = value.Substring(1).Split(new[] { ',' }, ProbeCount(Limits.MaxFormParts));
                    if (paths.Length > Limits.MaxFormParts || paths.Any(p => p.Length == 0))
                        return Missing("curl-form-components");
                    return AggregateFileEvidence(new[] { Text(raw.Substring(0, eq), "curl:form-field") }.Concat(
                        paths.SelectMany(path => new[] { NativeFile(path, "curl:form-file", pipe, stdin: true),
                            Text(System.IO.Path.GetFileName(path), "curl:form-filename") })), "curl:form-files");
                }
                var fields = value.Split(';');
                if (fields.Length > Limits.MaxFormParts) return Missing("curl-form-components");
                foreach (var attribute in fields.Skip(1))
                {
                    var i = attribute.IndexOf('=');
                    if (i <= 0 || i == attribute.Length - 1) return Missing("curl-form-components");
                    var name = attribute.Substring(0, i);
                    if (name is not ("type" or "filename" or "encoder")) return Missing("curl-form-components");
                }
                if (!fields[0].StartsWith("@", StringComparison.Ordinal) && !fields[0].StartsWith("<", StringComparison.Ordinal))
                    return NativeText(arg, "curl:form-text");
                var path = fields[0].Substring(1);
                var parts = new List<Payload> { Text(raw.Substring(0, eq), "curl:form-field"),
                    NativeFile(path, "curl:form-file", pipe, stdin: true) };
                var filename = fields.Skip(1).LastOrDefault(f => f.StartsWith("filename=", StringComparison.Ordinal));
                if (filename != null || fields[0][0] == '@')
                    parts.Add(Text(filename?.Substring(9) ?? System.IO.Path.GetFileName(path), "curl:form-filename"));
                foreach (var attr in fields.Skip(1).Where(f => f.StartsWith("type=", StringComparison.Ordinal)))
                    parts.Add(Text(attr.Substring(5), "curl:form-content-type"));
                return AggregateFileEvidence(parts, "curl:form");
            }
        }
    }
}

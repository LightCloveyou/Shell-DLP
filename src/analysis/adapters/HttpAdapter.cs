using System;
using System.Collections.Generic;
using System.Linq;
using System.Globalization;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            static readonly string[] HttpArguments = ("Uri Body Headers Method CustomMethod InFile OutFile ContentType " +
                "ConnectionTimeoutSeconds OperationTimeoutSeconds MaximumRedirection " +
                "UserAgent WebSession SessionVariable Proxy ProxyCredential Credential Authentication Token Certificate " +
                "CertificateThumbprint MaximumRetryCount RetryIntervalSec SslProtocol TransferEncoding HttpVersion Form UnixSocket").Split(' ');
            static readonly string[] HttpFlags = ("SkipCertificateCheck SkipHeaderValidation SkipHttpErrorCheck " +
                "PreserveHttpMethodOnRedirect PreserveAuthorizationOnRedirect AllowInsecureRedirect AllowUnencryptedAuthentication " +
                "UseDefaultCredentials ProxyUseDefaultCredentials NoProxy DisableKeepAlive PassThru UseBasicParsing Resume").Split(' ');
            static readonly string[] RestArguments = { "MaximumFollowRelLink", "ResponseHeadersVariable", "StatusCodeVariable" };
            static readonly Dictionary<string, string> HttpAliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["TimeoutSec"] = "ConnectionTimeoutSeconds", ["CM"] = "CustomMethod", ["SV"] = "SessionVariable",
                ["FL"] = "FollowRelLink", ["ML"] = "MaximumFollowRelLink", ["RHV"] = "ResponseHeadersVariable"
            };

            static IEnumerable<(object Key, object? Value)> MapAst(object? node)
            {
                if (Kind(node) != "HashtableAst") yield break;
                foreach (var pair in Items(Prop(node, "KeyValuePairs")).Take(ProbeCount(Limits.MaxCollection)))
                    if (Prop(pair, "Item1") is object key)
                        yield return (key, Prop(pair, "Item2"));
            }
            Payload Query(Uri addr)
            {
                try
                {
                    var raw = addr.Query.Substring(1);
                    var decoded = Text(Uri.UnescapeDataString(raw.Replace("+", " ")), "url-query");
                    return Combine(decoded, DiscoverSendContent(Text(raw, "url-query-encoded")), preserveCompleteness: true);
                }
                catch (UriFormatException) { return Missing("http-query"); }
            }
            void AddRequestTarget(List<Payload> parts, Payload uri, string? effectiveUri = null)
            {
                if (uri.Text == null || !Uri.TryCreate(effectiveUri ?? uri.Text, UriKind.Absolute, out var address) ||
                    address.Scheme is not ("http" or "https")) return;
                if (address.AbsolutePath.Length > 1)
                {
                    var decoded = Text(Uri.UnescapeDataString(address.AbsolutePath), "url-path");
                    var raw = Text(address.AbsolutePath, "url-path-encoded");
                    // Do not turn ordinary download/GET paths into a policy event.
                    if (decoded.Tags.Length > 0 || raw.Tags.Length > 0)
                        parts.Add(Combine(decoded, raw, preserveCompleteness: true));
                }
                if (address.Query.Length > 1) parts.Add(Query(address));
                foreach (var component in new[] { (address.IdnHost, "url-host"), (address.UserInfo, "url-user-info") })
                {
                    if (component.Item1.Length == 0) continue;
                    var candidate = Text(Uri.UnescapeDataString(component.Item1), component.Item2);
                    if (candidate.Tags.Length > 0) parts.Add(candidate);
                }
                int fragmentStart = uri.Text!.IndexOf('#');
                IEnumerable<Mark> outgoing = fragmentStart < 0 ? uri.Tags :
                    uri.TagPositions?.Where(p => p.Start < fragmentStart).Select(p => p.Tag) ?? Array.Empty<Mark>();
                var provenance = Merge(outgoing).Select(t => t.Via("request target")).ToArray();
                if (provenance.Length != 0) parts.Add(Text("", "url-provenance", provenance));
            }
            // WebRequestPSCmdlet.CheckProtocol prepends http:// to a relative Uri.
            // Keep offsets in the original value for fragment/provenance filtering.
            static string? WebCmdletUri(string? text) =>
                Uri.TryCreate(text, UriKind.RelativeOrAbsolute, out var uri) && !uri.IsAbsoluteUri
                    ? "http://" + uri.OriginalString : text;

            void HttpCmd(object command, string name, Payload? pipe)
            {
                var named = new Dictionary<string, Payload>(StringComparer.OrdinalIgnoreCase);
                var splat = new Dictionary<string, Payload>(StringComparer.OrdinalIgnoreCase);
                var isRest = name == "invoke-restmethod";
                var arguments = HttpArguments.Concat(CommonArguments);
                if (isRest) arguments = arguments.Concat(RestArguments);
                var switches = HttpFlags.Concat(CommonFlags);
                if (isRest) switches = switches.Append("FollowRelLink");
                var parameters = arguments.Concat(switches).ToArray();
                string? uncertainty = null;
                string? bindingFailure = null;
                Payload? positional = null;
                bool positionalUncertain = false;
                var tokens = Items(Prop(command, "CommandElements")).Skip(1).Take(ProbeCount(Limits.MaxArguments)).ToArray();
                if (tokens.Length > Limits.MaxArguments) { Send(name, null, Array.Empty<Payload>(), "http-argument-limit"); return; }
                for (int i = 0; i < tokens.Length; i++)
                {
                    var node = tokens[i];
                    if (Equals(Prop(node, "Splatted"), true))
                    {
                        var expanded = Value(node);
                        var table = expanded.Map;
                        if (table == null && expanded.Elements is { } elements)
                        {
                            foreach (var element in elements)
                            {
                                if (positional == null) positional = element;
                                else uncertainty ??= "http-positional-binding";
                            }
                            continue;
                        }
                        if (table == null) uncertainty ??= "http-splat-value";
                        else foreach (var pair in table)
                        {
                            var k = ResolveParameter(pair.Key, parameters, out _, HttpAliases);
                            if (k == null || splat.ContainsKey(k)) uncertainty ??= "http-splat-key";
                            else splat[k] = pair.Value;
                        }
                        continue;
                    }
                    if (Kind(node) != "CommandParameterAst")
                    {
                        if (positional != null) uncertainty ??= "http-positional-binding";
                        else positional = Value(node);
                        continue;
                    }
                    var key = ResolveParameter(Str(Prop(node, "ParameterName")), parameters, out bool ambiguous, HttpAliases);
                    var arg = Prop(node, "Argument");
                    if (key == null)
                    {
                        if (ambiguous) bindingFailure ??= "http-ambiguous-parameter";
                        uncertainty ??= "http-parameter";
                        if (arg == null && i + 1 < tokens.Length && IsParameterValue(tokens[i + 1]))
                            positionalUncertain = true;
                        continue;
                    }
                    bool takesValue = arguments.Contains(key);
                    Payload? bareValue = null;
                    if (arg == null && takesValue && i + 1 < tokens.Length)
                    {
                        var next = tokens[i + 1];
                        if (IsParameterValue(next)) arg = tokens[++i];
                        else if (Kind(next) == "CommandParameterAst")
                        {
                            var nextKey = ResolveParameter(Str(Prop(next, "ParameterName")), parameters, out bool nextAmbiguous, HttpAliases);
                            if (nextKey != null || nextAmbiguous || Prop(next, "Argument") != null)
                                bindingFailure ??= "http-missing-parameter-value";
                            else if (Prop(Prop(next, "Extent"), "Text") is string spelling)
                            {
                                bareValue = Text(spelling, "literal");
                                i++;
                            }
                        }
                    }
                    if (named.ContainsKey(key)) { bindingFailure ??= "http-duplicate-parameter"; continue; }
                    if (arg != null) named[key] = Value(arg);
                    else if (bareValue != null) named[key] = bareValue;
                    else if (!takesValue) named[key] = new Payload { Text = "True", ScalarTruth = true, Complete = true };
                    else
                    {
                        if (i + 1 == tokens.Length) bindingFailure ??= "http-missing-parameter-value";
                        uncertainty ??= "http-missing-parameter-value";
                        named[key] = Missing("http-missing-parameter-value");
                    }
                }
                foreach (var pair in splat) if (!named.ContainsKey(pair.Key)) named.Add(pair.Key, pair.Value);
                if (positional != null)
                {
                    if (named.ContainsKey("Uri")) uncertainty ??= "http-positional-binding";
                    else named["Uri"] = positionalUncertain ? Missing("http-positional-binding") : positional;
                }
                if (named.ContainsKey("Method") && named.ContainsKey("CustomMethod")) bindingFailure ??= "http-method-conflict";
                if (named.ContainsKey("NoProxy") && new[] { "Proxy", "ProxyCredential", "ProxyUseDefaultCredentials" }.Any(named.ContainsKey))
                    bindingFailure ??= "http-proxy-parameter-set";
                foreach (var key in new[] { "ConnectionTimeoutSeconds", "OperationTimeoutSeconds" })
                    if (named.TryGetValue(key, out var timeout) && InvalidHttpTimeout(timeout))
                        bindingFailure ??= "http-timeout";
                if (bindingFailure != null) { Send(name, null, Array.Empty<Payload>(), bindingFailure); return; }
                var bindingIssue = ApplyHttpDefaults(name, parameters, named);
                uncertainty ??= bindingIssue;
                var uriValue = named.TryGetValue("Uri", out var uriArg) ? uriArg : Missing("http-destination");
                var effectiveUri = WebCmdletUri(uriValue.Text);
                var endpoint = Http(effectiveUri);
                var bodyParameters = new[] { "Body", "InFile", "Form" };
                var boundBodies = bodyParameters.Where(named.ContainsKey).Select(k => named[k]).ToArray();
                if (boundBodies.Count(p => p.Complete && (p.Text != null || p.Map != null || p.Elements != null || p.Bytes != null)) > 1)
                { Send(name, endpoint, Array.Empty<Payload>(), "http-body-conflict"); return; }
                if (boundBodies.Length > 1) uncertainty ??= "http-body-conflict";
                bool Enabled(string key) => named.TryGetValue(key, out var value) && value.Complete &&
                    value.ScalarTruth == true && !value.IsString && value.NumericType == null;
                if (uncertainty == null && !named.ContainsKey("OutFile") && (Enabled("PassThru") || Enabled("Resume")))
                { Send(name, endpoint, Array.Empty<Payload>(), "http-outfile-required"); return; }
                var outputKeys = new[] { "OutFile", "SessionVariable", "ResponseHeadersVariable", "StatusCodeVariable" };
                void RecordOutputEffects()
                {
                    if (capture?.Command == command && named.TryGetValue("OutVariable", out var capturedOutput))
                    {
                        capture.Destination = capturedOutput;
                        if (named.ContainsKey("OutFile") && !Enabled("PassThru")) capture.Records = CollectElements(Array.Empty<Payload>());
                    }
                    foreach (var key in outputKeys)
                        if (named.TryGetValue(key, out var output))
                        {
                            if (key == "OutFile") InvalidateOutputFile(output);
                            else InvalidateOutputVariable(output);
                        }
                    foreach (var key in CommonOutputVariables)
                        if (named.TryGetValue(key, out var capturedStream))
                            InvalidateOutputVariable(capturedStream, allowAppend: key != "PipelineVariable");
                }
                bool followLinks = named.TryGetValue("FollowRelLink", out var follow) &&
                    (!follow.Complete || follow.IsString || follow.NumericType != null || follow.ScalarTruth != false);
                if (named.TryGetValue("MaximumFollowRelLink", out var maxLinks) && maxLinks.Complete &&
                    int.TryParse(maxLinks.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out int maxLinkCount) && maxLinkCount == 1)
                    followLinks = false;
                if (followLinks) uncertainty ??= "http-follow-link-destination";
                if (named.ContainsKey("UnixSocket")) uncertainty ??= "http-unix-socket-destination";
                if (endpoint != null && TrustLoopback && LoopbackUri(endpoint))
                {
                    if (!barrier && uncertainty == null && named.TryGetValue("MaximumRedirection", out var redirects) &&
                        redirects.Complete && int.TryParse(redirects.Text, out int max) && max == 0 &&
                        !named.ContainsKey("Proxy") && !named.ContainsKey("WebSession"))
                    { SkipLoopback(name, endpoint); RecordOutputEffects(); return; }
                    uncertainty ??= "redirect-destination";
                }
                var parts = new List<Payload>();
                AddRequestTarget(parts, uriValue, effectiveUri);
                if (named.TryGetValue("CustomMethod", out var custom))
                {
                    if (custom.Complete && custom.Text is string verb && verb.Length > 0)
                    {
                        // HttpClient accepts a method token, not an arbitrary field value.
                        var wireVerb = verb.ToUpperInvariant();
                        try { _ = new System.Net.Http.HttpMethod(wireVerb); }
                        catch (FormatException) { Send(name, endpoint, Array.Empty<Payload>(), "http-custom-method"); return; }
                        catch (ArgumentException) { Send(name, endpoint, Array.Empty<Payload>(), "http-custom-method"); return; }
                        var field = verb == wireVerb ? custom : Text(wireVerb, "HTTP request method", FileRecordMarks(custom));
                        if (field.Tags.Length != 0) parts.Add(field.Via("HTTP request method"));
                    }
                    else uncertainty ??= "http-custom-method";
                }
                foreach (var key in new[] { "Headers", "Body", "UserAgent", "ContentType" })
                    if (named.TryGetValue(key, out var p)) parts.AddRange(TransmittedValues(p));
                if (named.TryGetValue("Form", out var form)) parts.AddRange(FormValues(form));
                if (named.TryGetValue("InFile", out var file))
                    parts.Add(ReadFileArgument(file, false));
                if (named.ContainsKey("WebSession")) uncertainty ??= "http-session-content";
                if (named.ContainsKey("Token") || named.ContainsKey("Credential") || named.ContainsKey("ProxyCredential"))
                    uncertainty ??= "http-authentication-content";
                if (pipe != null && !named.ContainsKey("Body") && !named.ContainsKey("InFile") && !named.ContainsKey("Form"))
                    parts.AddRange(TransmittedValues(pipe));
                if (parts.Count != 0 || uncertainty != null || endpoint == null)
                    Send(name, endpoint, parts, uncertainty);
                else if (named.TryGetValue("CustomMethod", out var method) || named.TryGetValue("Method", out method))
                {
                    if (!method.Complete || method.Text == null ||
                        !new[] { "get", "head", "default" }.Contains(method.Text, StringComparer.OrdinalIgnoreCase))
                        Send(name, endpoint, Array.Empty<Payload>(), "http-body");
                }
                RecordOutputEffects();
            }

            static bool InvalidHttpTimeout(Payload timeout) => timeout.Complete &&
                long.TryParse(timeout.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds) &&
                (seconds < 0 || seconds > int.MaxValue);

            string? ApplyHttpDefaults(string name, string[] parameters, Dictionary<string, Payload> named)
            {
                var p = Variable("PSDefaultParameterValues");
                if (p.Map is not { } defaults)
                    return p.Issue == "variable-value" ? null : "http-default-parameters";
                if (defaults.TryGetValue("Disabled", out var disabled))
                {
                    var disabledState = Truth(disabled);
                    if (disabledState == null) return "http-default-disabled";
                    if (disabledState == true) return null;
                }
                var candidates = new Dictionary<string, List<Payload>>(StringComparer.OrdinalIgnoreCase);
                var defaultNames = parameters.Select(k => (Name: k, Parameter: k))
                    .Concat(ParameterAliases.Concat(HttpAliases).Where(a => parameters.Contains(a.Value))
                        .Select(a => (Name: a.Key, Parameter: a.Value))).ToArray();
                var stockAlias = name == "invoke-restmethod" ? "irm" : "iwr";
                var hasStockAlias = defaults.Count != 0 && !barrier && flow.StockAlias(stockAlias, name, "Microsoft.PowerShell.Utility");
                foreach (var pair in defaults)
                {
                    int colon = pair.Key.LastIndexOf(':');
                    if (colon <= 0) continue;
                    var commandPattern = pair.Key.Substring(0, colon).Trim();
                    var matchesCommand = CompileWildcard(commandPattern);
                    if (matchesCommand == null ||
                        !(matchesCommand(name) || (hasStockAlias && matchesCommand(stockAlias)) ||
                          (!barrier && SafeName(commandPattern) && flow.StockAlias(commandPattern, name, "Microsoft.PowerShell.Utility"))))
                        continue;
                    var param = pair.Key.Substring(colon + 1).Trim();
                    var matchesParameter = param.IndexOfAny(new[] { '*', '?', '[' }) >= 0 ? CompileWildcard(param) : null;
                    var matches = defaultNames.Where(p => matchesParameter != null ? matchesParameter(p.Name) :
                        p.Name.Equals(param, StringComparison.OrdinalIgnoreCase)).Take(2).ToArray();
                    if (matches.Length != 1 || named.ContainsKey(matches[0].Parameter)) continue;
                    var key = matches[0].Parameter;
                    if (!candidates.TryGetValue(key, out var values)) candidates[key] = values = new List<Payload>();
                    values.Add(pair.Value);
                }
                string? issue = null;
                foreach (var pair in candidates)
                {
                    var first = pair.Value[0];
                    if (pair.Value.Count > 1 &&
                        (first.Text == null || !first.Complete || pair.Value.Skip(1).Any(p2 => !p2.Complete ||
                         p2.Text != first.Text || p2.IsString != first.IsString || p2.NumericType != first.NumericType ||
                         p2.ScalarTruth != first.ScalarTruth)))
                    { issue = "http-default-conflict"; continue; }
                    if (!first.Complete) issue ??= "http-default-dynamic";
                    if (pair.Key is ("ConnectionTimeoutSeconds" or "OperationTimeoutSeconds") && InvalidHttpTimeout(first))
                    { issue ??= "http-default-timeout"; continue; }
                    if ((pair.Key == "Method" && named.ContainsKey("CustomMethod")) ||
                        (pair.Key == "CustomMethod" && named.ContainsKey("Method")) ||
                        (pair.Key == "NoProxy" && new[] { "Proxy", "ProxyCredential", "ProxyUseDefaultCredentials" }.Any(named.ContainsKey)) ||
                        (pair.Key is ("Proxy" or "ProxyCredential" or "ProxyUseDefaultCredentials") && named.ContainsKey("NoProxy")))
                    { issue ??= "http-default-parameter-set"; continue; }
                    named.Add(pair.Key, first);
                }
                return issue;
            }

            static Func<string, bool>? CompileWildcard(string pattern)
            {
                if (pattern.Length > Limits.MaxWildcard) return null;
                try
                {
                    var host = Type.GetType("System.Management.Automation.WildcardPattern, System.Management.Automation", false);
                    var opts = host?.Assembly.GetType("System.Management.Automation.WildcardOptions");
                    if (host == null || opts == null) return null;
                    var wildcard = Activator.CreateInstance(host, pattern, Enum.Parse(opts, "IgnoreCase,CultureInvariant"));
                    var method = host.GetMethod("IsMatch", new[] { typeof(string) });
                    if (wildcard == null || method == null) return null;
                    var match = (Func<string, bool>)method.CreateDelegate(typeof(Func<string, bool>), wildcard);
                    _ = match(""); // Validate the pattern before enumeration.
                    return match;
                }
                catch { return null; }
            }
            Payload ContentSummary(string issue, IEnumerable<Payload?> parts, HashSet<Payload>? visited = null) =>
                new Payload { Issue = issue, InspectionPartial = true, Tags = Merge(KnownMarks(parts, visited)) };

            IEnumerable<Payload> TransmittedValues(Payload root)
            {
                var active = new HashSet<Payload>();
                var visitedDepth = new Dictionary<Payload, int>();
                var summarized = new HashSet<Payload>();
                IEnumerable<Payload> Walk(Payload p, int depth)
                {
                    if (active.Contains(p)) { yield return Missing("http-content-cycle"); yield break; }
                    if (visitedDepth.TryGetValue(p, out var previous) && previous <= depth) yield break;
                    visitedDepth[p] = depth;
                    if (!StackAvailable || depth >= MaxExpressionDepth)
                    { yield return ContentSummary("content-depth", new[] {p}, summarized); yield break; }
                    if (p.Map == null && p.Elements == null) { yield return p; yield break; }
                    if (p.Tags.Length != 0 || p.InspectionPartial || !p.Complete)
                        yield return new Payload { Tags = p.Tags, Complete = p.Complete, InspectionPartial = p.InspectionPartial, Issue = p.Issue };
                    active.Add(p);
                    if (p.Map != null)
                    {
                        foreach (var pair in p.Map.Take(Limits.MaxCollection))
                        {
                            yield return Text(pair.Key, "http-field-name");
                            foreach (var item in Walk(pair.Value, depth + 1)) yield return item;
                        }
                        if (p.Map.Count > Limits.MaxCollection)
                            yield return ContentSummary("http-field-limit", p.Map.Skip(Limits.MaxCollection).Select(kv => kv.Value), summarized);
                    }
                    else if (p.Elements != null)
                    {
                        foreach (var value in p.Elements.Take(Limits.MaxCollection))
                            foreach (var item in Walk(value, depth + 1)) yield return item;
                        if (p.Elements.Length > Limits.MaxCollection)
                            yield return ContentSummary("http-item-limit", p.Elements.Skip(Limits.MaxCollection), summarized);
                    }
                    if (p.RecordRemainder != null)
                        yield return ContentSummary("http-record-remainder", new[] { p.RecordRemainder }, summarized);
                    active.Remove(p);
                }
                return Walk(root, 0);
            }
        }
    }
}

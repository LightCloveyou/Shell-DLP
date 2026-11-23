using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            static readonly Dictionary<string, NativeOption> NcatOptions = NativeOptions(
                "listen -l --listen", "receive --recv-only", "zero-io -z", "udp -u --udp",
                "flags --send-only --no-shutdown -4 -6 -v --verbose -n --nodns --ssl --ssl-verify -C --crlf -k --keep-open --append-output --broker --chat",
                "+ssl-trust --ssl-trustfile", "+ssl-certificate --ssl-cert", "+ssl-key --ssl-key",
                "+ssl-ciphers --ssl-ciphers", "+ssl-protocols --ssl-proto", "+ssl-name --ssl-servername", "+ssl-alpn --ssl-alpn",
                "no-stdin --help -h --version", "+exec -e --exec", "+shell-exec --sh-exec -c --lua-exec",
                "+timing -w --wait -q -i --idle-timeout -d --delay", "+max-connections -m --max-conns",
                "+source-port -p --source-port", "+source-address -s --source",
                "+output -o --output", "+hex-dump -x --hex-dump");
            void Ncat(object command, Payload? pipe)
            {
                var call = ReadNative(command, NcatOptions, longEquals: true);
                if (call.Has("no-stdin") || call.Has("exec") || call.Has("shell-exec")) return;
                if (call.Error == "missing-option-value") { Send("ncat", null, Array.Empty<Payload>(), "ncat-" + call.Error); return; }
                bool listen = call.Has("listen");
                var sourcePort = call.Options.LastOrDefault(o => o.Name == "source-port").Arg?.Text;
                if ((sourcePort != null && !ushort.TryParse(sourcePort, NumberStyles.Integer, CultureInfo.InvariantCulture, out _)) ||
                    (listen && (call.Has("source-address") || (sourcePort != null && call.Position.Count == 2))))
                { Send("ncat", null, Array.Empty<Payload>(), "ncat-source-binding"); return; }
                var host = call.Position.Count is 1 or 2 ? call.Position[0].Text : null;
                var port = call.Position.Count == 2 ? call.Position[1].Text : "31337";
                if (listen && sourcePort != null) port = sourcePort;
                if (listen && call.Position.Count == 0) host = "0.0.0.0";
                if (listen && sourcePort == null && call.Position.Count == 1 && host is { Length: > 0 and <= 5 } &&
                    host.All(c => c >= '0' && c <= '9'))
                {
                    port = host;
                    host = "0.0.0.0";
                }
                string? endpoint = null;
                if (host != null && !host.Contains("/") && !host.Contains("@") && !host.Contains("%") &&
                    ushort.TryParse(port, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number) && (number > 0 || listen))
                {
                    var address = host.Trim('[', ']');
                    if (Uri.CheckHostName(address) != UriHostNameType.Unknown)
                    {
                        var protocol = call.Has("udp") ? "udp" : "tcp";
                        endpoint = new UriBuilder(listen ? protocol + "-listen" : protocol, address, number).Uri.AbsoluteUri;
                    }
                }
                if (!call.Has("receive") && !call.Has("zero-io"))
                {
                    if (pipe == null && !listen) Send("ncat", endpoint, Array.Empty<Payload>(), "ncat-stdin");
                    else if (pipe != null) NativeSend("ncat", endpoint, new List<Payload> { pipe }, call.Error);
                }
                foreach (var option in new[] { "output", "hex-dump" })
                    if (call.Options.LastOrDefault(o => o.Name == option).Arg is { } output)
                        InvalidateOutputFile(NativeText(output, "ncat-output"));
            }
        }
    }
}

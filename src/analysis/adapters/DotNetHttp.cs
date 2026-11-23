using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        // Immutable request state keeps aliases and alternate control-flow paths independent.
        enum HttpObjectKind { WebClient, Client, Message, Content, Multipart, Fields, Pair, PairList, Headers, Request, RequestStream, Writer, FileStream, TextReader, BinaryReader, SafeReadHandle, AsyncLines, AsyncLineCursor, ZipArchive, ZipEntry, RegistryKey, XmlDocument }
        sealed class HttpObject
        {
            internal readonly HttpObjectKind Kind;
            internal readonly HttpObject Identity;
            internal readonly Payload? Address, Body;
            internal readonly string? Method;
            internal readonly HttpObject? Owner;
            internal readonly Dictionary<string, Payload> Fields;
            internal readonly string Tail;
            internal readonly byte[] ByteTail;
            internal HttpObject(HttpObjectKind kind, Payload? address = null, Payload? body = null, HttpObject? identity = null, string? method = null,
                HttpObject? owner = null, Dictionary<string, Payload>? fields = null, string tail = "", byte[]? byteTail = null)
            { Kind = kind; Address = address; Body = body; Identity = identity ?? this; Method = method;
              Owner = owner; Fields = fields ?? new Dictionary<string, Payload>(StringComparer.OrdinalIgnoreCase); Tail = tail; ByteTail = byteTail ?? Array.Empty<byte>(); }
            internal HttpObject WithBody(Payload body, string tail = "", byte[]? byteTail = null) =>
                new HttpObject(Kind, Address, body, Identity, Method, Owner, Fields, tail, byteTail);
            internal HttpObject WithFields(Dictionary<string, Payload> fields) =>
                new HttpObject(Kind, Address, Body, Identity, Method, Owner, fields, Tail, ByteTail);
        }

        sealed partial class AdapterContext
        {
            static Payload HttpObjectValue(HttpObject state) => new Payload { HttpObject = state,
                SourceRef = state.Kind.ToString(), Tags = IsReadHandle(state) || AuxReader(state) || ZipHandle(state) ? Array.Empty<Mark>() : state.Body?.Tags ?? Array.Empty<Mark>(), Issue = "dotnet-object" };

            readonly Dictionary<HttpObject, HttpObject> httpStates = new Dictionary<HttpObject, HttpObject>();
            readonly HashSet<string> httpNamespaces = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            HttpObject? CurrentHttp(HttpObject? obj) => obj != null && httpStates.TryGetValue(obj.Identity, out var state) ? state : obj;
            Payload SnapshotHttpValue(Payload value)
            {
                var state = CurrentHttp(value.HttpObject);
                if (state == null || ReferenceEquals(state, value.HttpObject)) return value;
                var copy = value.Copy();
                copy.HttpObject = state;
                if (!IsReadHandle(state) && !AuxReader(state) && !ZipHandle(state)) copy.Tags = Merge(KnownMarks(state.Fields.Values.Append(state.Body)));
                return copy;
            }
            void SaveHttp(HttpObject state) => httpStates[state.Identity] = state;

            static HttpObject JoinHttp(HttpObject left, HttpObject right)
            {
                if (ReferenceEquals(left, right)) return left;
                var fields = new Dictionary<string, Payload>(left.Fields, left.Fields.Comparer);
                foreach (var key in left.Fields.Keys.Union(right.Fields.Keys, fields.Comparer))
                {
                    left.Fields.TryGetValue(key, out var a);
                    right.Fields.TryGetValue(key, out var b);
                    fields[key] = ReferenceEquals(a, b) ? a! : UnknownValue("conditional-http-field", a, b);
                }
                return new HttpObject(left.Kind, left.Address?.Text == right.Address?.Text ? left.Address : null,
                    ReferenceEquals(left.Body, right.Body) ? left.Body : UnknownValue("conditional-http-content", left.Body, right.Body),
                    left.Identity == right.Identity ? left.Identity : null, left.Method == right.Method ? left.Method : null,
                    left.Owner?.Identity == right.Owner?.Identity ? left.Owner : null, fields, left.Tail == right.Tail ? left.Tail : "",
                    left.ByteTail.SequenceEqual(right.ByteTail) ? left.ByteTail : null);
            }

            string HttpType(string name)
            {
                if (name.StartsWith("system.", StringComparison.Ordinal)) return name.Substring(7);
                if (httpNamespaces.Contains("System.IO.Compression") && (CompressionTypes.Contains(name) ||
                    name is "compressionmode" or "compressionlevel")) return "io.compression." + name;
                if (httpNamespaces.Contains("System.Net.Http") && name is ("httpclient" or "httprequestmessage" or "stringcontent" or
                    "bytearraycontent" or "streamcontent" or "multipartformdatacontent" or "formurlencodedcontent")) return "net.http." + name;
                if (httpNamespaces.Contains("System.Net.Http.Headers") && name == "authenticationheadervalue") return "net.http.headers." + name;
                if (httpNamespaces.Contains("System.Net") && name is ("webrequest" or "webclient" or "httpwebrequest")) return "net." + name;
                if (httpNamespaces.Contains("System.IO.Compression") && name is ("zipfile" or "ziparchive")) return "io.compression." + name;
                if (httpNamespaces.Contains("System.IO") && name is ("file" or "directory" or "randomaccess" or "fileinfo" or "stream" or "filestream" or "streamreader" or "binaryreader" or "streamwriter" or "memorystream" or "filemode" or "fileaccess" or "fileshare" or "fileoptions" or "seekorigin" or "searchoption")) return "io." + name;
                if (httpNamespaces.Contains("System.Collections.Generic") && (name.StartsWith("dictionary[") || name.StartsWith("keyvaluepair[") || name.StartsWith("list[")))
                    return "collections.generic." + name;
                return name;
            }

            Payload HttpContent(Payload? value, int depth = 0)
            {
                if (value == null) return Missing("http-content");
                if (!StackAvailable || depth > MaxExpressionDepth) return UnknownValue("http-content-depth", value);
                var obj = CurrentHttp(value.HttpObject);
                if (obj == null) return value;
                if (IsReadHandle(obj) || AuxReader(obj) || ZipHandle(obj)) return Missing("reader-object-not-content");
                var parts = new List<Payload>();
                if (obj.Kind == HttpObjectKind.Content && obj.Owner?.Kind == HttpObjectKind.FileStream)
                    parts.Add(RemainingStream(CurrentHttp(obj.Owner)!, consume: false));
                foreach (var field in obj.Fields)
                {
                    parts.Add(Text(field.Key, "http-header-name"));
                    parts.Add(field.Value);
                }
                if (obj.Kind == HttpObjectKind.Multipart && obj.Body?.Elements is { } members)
                    parts.AddRange(members.Select(part => HttpContent(part, depth + 1)));
                else if (obj.Body != null) parts.Add(HttpContent(obj.Body, depth + 1));
                if (obj.Kind == HttpObjectKind.Pair && obj.Address != null) parts.Add(obj.Address);
                if (obj.Body?.InspectionPartial == true) parts.Add(obj.Body);
                return AggregateFileEvidence(parts, "HTTP content");
            }

            Payload SetField(HttpObject obj, Payload key, Payload? value, bool append)
            {
                obj = CurrentHttp(obj)!;
                var fields = new Dictionary<string, Payload>(obj.Fields, obj.Fields.Comparer);
                string name = key.Text ?? "\0unknown";
                if (value == null) { if (key.Complete) fields.Remove(name); }
                else
                {
                    var tagged = new Payload { Tags = Merge(KnownMarks(new[] { key, value })), Text = value.Text,
                        IsString = value.IsString, Complete = key.Complete && value.Complete, Issue = "http-field-value" };
                    fields[name] = append && fields.TryGetValue(name, out var old) ?
                        AggregateFileEvidence(new[] { old, tagged }, "HTTP field") : tagged;
                }
                SaveHttp(obj.WithFields(fields));
                return Missing("no-expression-output");
            }

            Payload UrlEncoded(Payload source)
            {
                var obj = CurrentHttp(source.HttpObject);
                var parts = new List<Payload>();
                var pairs = new List<(Payload Key, Payload Value)>();
                if (obj?.Kind == HttpObjectKind.Fields)
                    pairs.AddRange(obj.Fields.Select(f => (Text(f.Key, "form key"), f.Value)));
                else
                    foreach (var item in (obj?.Kind == HttpObjectKind.PairList ? obj.Body?.Elements : source.Elements) ?? new[] { source })
                    {
                        var pair = CurrentHttp(item.HttpObject);
                        if (pair?.Kind == HttpObjectKind.Pair && pair.Address != null && pair.Body != null)
                            pairs.Add((pair.Address, pair.Body));
                        else parts.Add(UnknownValue("form-urlencoded-pair", item));
                    }
                var fields = new List<string>();
                long length = 0;
                string Encode(string text) => Uri.EscapeDataString(text).Replace("%20", "+");
                foreach (var (key, value) in pairs)
                {
                    parts.Add(key);
                    parts.Add(value);
                    if (key.Text != null && value.Text != null && length <= MaxContent)
                    {
                        string encoded = Encode(key.Text) + "=" + Encode(value.Text);
                        parts.Add(Text(encoded, "form-urlencoded field"));
                        fields.Add(encoded);
                        length += encoded.Length + 1L;
                    }
                }
                if (length <= MaxContent && fields.Count == pairs.Count) parts.Add(Text(string.Join("&", fields), "form-urlencoded body"));
                if (source.InspectionPartial || obj?.Body?.InspectionPartial == true) parts.Add(UnknownValue("form-urlencoded-elements", source, obj?.Body));
                return AggregateFileEvidence(parts, "form-urlencoded content");
            }

            Payload? ConstructHttpObject(string type, object[] args, int depth)
            {
                type = HttpType(type);
                Payload Arg(int index) => Value(args[index], depth + 1);
                type = type.Replace("system.string,", "string,").Replace(",system.string]", ",string]");
                if (type is ("xml" or "xml.xmldocument") && args.Length == 0)
                    return HttpObjectValue(new HttpObject(HttpObjectKind.XmlDocument, body: Missing("empty-xml-document")));
                if (type == "io.memorystream") return NewMemoryStream(args, depth);
                if (CompressionType(type, out var codec)) return NewCodecStream(codec, args, depth);
                if (type is "io.fileinfo" or "io.filestream" or "io.streamreader" or "io.binaryreader" or "byte[]" or "char[]")
                    return ConstructReader(type, args, depth);
                switch (type)
                {
                    case "net.webclient" when args.Length == 0:
                        return HttpObjectValue(new HttpObject(HttpObjectKind.WebClient));
                    case "net.http.httpclient" when args.Length == 0:
                        return HttpObjectValue(new HttpObject(HttpObjectKind.Client));
                    case "net.http.httprequestmessage" when args.Length == 0 || args.Length == 2:
                        return HttpObjectValue(new HttpObject(HttpObjectKind.Message, args.Length == 2 ? Arg(1) : null));
                    case "net.http.stringcontent" when args.Length >= 1 && args.Length <= 3:
                    case "net.http.bytearraycontent" when args.Length == 1:
                        return HttpObjectValue(new HttpObject(HttpObjectKind.Content, body: Arg(0)));
                    case "net.http.bytearraycontent" when args.Length == 3:
                        return HttpObjectValue(new HttpObject(HttpObjectKind.Content, body: ByteSegment(Arg(0), Arg(1), Arg(2))));
                    case "net.http.streamcontent" when args.Length == 1 || args.Length == 2:
                        var stream = Arg(0);
                        return HttpObjectValue(stream.HttpObject?.Kind == HttpObjectKind.FileStream
                            ? new HttpObject(HttpObjectKind.Content, owner: stream.HttpObject)
                            : new HttpObject(HttpObjectKind.Content, body: Missing("http-stream-content")));
                    case "net.http.headers.authenticationheadervalue" when args.Length is 1 or 2:
                        var scheme = Arg(0);
                        if (args.Length == 1) return scheme;
                        var parameter = Arg(1);
                        return scheme.Text != null && parameter.Text != null ?
                            Text(scheme.Text + " " + parameter.Text, "Authorization header", Merge(scheme.Tags.Concat(parameter.Tags))) :
                            UnknownValue("authentication-header", scheme, parameter);
                    case "net.http.multipartformdatacontent" when args.Length <= 1:
                        return HttpObjectValue(new HttpObject(HttpObjectKind.Multipart,
                            body: new Payload { Elements = Array.Empty<Payload>(), Complete = true }));
                    case "net.http.formurlencodedcontent" when args.Length == 1:
                        return HttpObjectValue(new HttpObject(HttpObjectKind.Content, body: UrlEncoded(Arg(0))));
                    case "collections.generic.dictionary[string,string]" when args.Length == 0:
                        return HttpObjectValue(new HttpObject(HttpObjectKind.Fields, fields: new Dictionary<string, Payload>(StringComparer.Ordinal)));
                    case "collections.generic.list[system.collections.generic.keyvaluepair[string,string]]" when args.Length == 0:
                    case "collections.generic.list[collections.generic.keyvaluepair[string,string]]" when args.Length == 0:
                    case "collections.generic.list[keyvaluepair[string,string]]" when args.Length == 0:
                        return HttpObjectValue(new HttpObject(HttpObjectKind.PairList, body: new Payload { Complete = true, Elements = Array.Empty<Payload>() }));
                    case "collections.generic.keyvaluepair[string,string]" when args.Length == 2:
                        return HttpObjectValue(new HttpObject(HttpObjectKind.Pair, Arg(0), Arg(1)));
                    case "io.streamwriter" when args.Length >= 1 && args.Length <= 4:
                        var output = Arg(0).HttpObject;
                        return output?.Kind == HttpObjectKind.RequestStream ?
                            HttpObjectValue(new HttpObject(HttpObjectKind.Writer, output.Address, owner: output.Owner)) : null;
                    case "uri" when args.Length == 1:
                        return Arg(0);
                    default: return null;
                }
            }

            Payload ByteSegment(Payload source, Payload offset, Payload count)
            {
                if (!int.TryParse(offset.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out int start) ||
                    !int.TryParse(count.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out int length))
                    return UnknownValue("http-stream-write-range", source);
                if (start < 0 || length < 0) return Missing("invalid-stream-write-range");
                if (source.Bytes is not { } bytes) return length == 0 ? Bytes(Array.Empty<byte>(), "empty segment") : UnknownValue("stream-byte-range", source);
                if (start > bytes.Length - length) return Missing("invalid-stream-write-range");
                if (length == 0) return Bytes(Array.Empty<byte>(), "empty request segment");
                if (start == 0 && length == bytes.Length) return source;
                return Bytes(bytes.Skip(start).Take(length).ToArray(), "request stream segment", FileRecordMarks(source));
            }

            bool UpdateHttpProperty(object node, int depth)
            {
                var left = Prop(node, "Left");
                if (Str(Prop(node, "Operator")) != "Equals" || Kind(left) is not ("MemberExpressionAst" or "IndexExpressionAst")) return false;
                bool index = Kind(left) == "IndexExpressionAst";
                var receiver = Prop(left, index ? "Target" : "Expression");
                var obj = CurrentHttp(Value(receiver, depth + 1).HttpObject);
                if (obj == null) return false;
                var member = Literal(Prop(left, "Member"))?.ToLowerInvariant();
                if (obj.Kind == HttpObjectKind.XmlDocument && member == "preservewhitespace")
                {
                    var flag = Pipeline(Prop(node, "Right"), depth + 1);
                    SaveHttp(ReaderSet(obj, ("whitespace", flag ?? Missing("xml-whitespace-option")))); return true;
                }
                if (IsReadHandle(obj) && !index && member == "position" && obj.Kind == HttpObjectKind.FileStream)
                {
                    var pos = Pipeline(Prop(node, "Right"), depth + 1);
                    if (IsCodec(obj) || !ReaderOpen(obj)) return true;
                    MoveReader(obj, pos != null && CountValue(pos, out int n) ? Number(n) : Missing("stream-position"));
                    return true;
                }
                var value = Pipeline(Prop(node, "Right"), depth + 1) ?? Missing("http-property");
                if (obj.Kind == HttpObjectKind.Headers && obj.Owner != null || index && obj.Kind == HttpObjectKind.Fields)
                {
                    SetField(obj.Owner ?? obj, index ? Value(Prop(left, "Index"), depth + 1) : Text(member, "HTTP header"), value, false);
                    return true;
                }
                var address = obj.Address;
                var body = obj.Body;
                var method = obj.Method;
                if (obj.Kind == HttpObjectKind.Message && member == "content")
                    body = value.HttpObject?.Kind is HttpObjectKind.Content or HttpObjectKind.Multipart ? value : Missing("http-request-content");
                else if (obj.Kind == HttpObjectKind.Message && member == "requesturi" ||
                    obj.Kind is (HttpObjectKind.WebClient or HttpObjectKind.Client) && member == "baseaddress") address = value;
                else if (obj.Kind == HttpObjectKind.Request && member == "method") method = value.Text?.ToUpperInvariant();
                else if (obj.Kind == HttpObjectKind.Request && member == "contenttype")
                { SetField(obj, Text("Content-Type", "header"), value, false); return true; }
                else if (obj.Kind == HttpObjectKind.Request && member is ("contentlength" or "sendchunked")) return true;
                else return false;
                SaveHttp(new HttpObject(obj.Kind, address, body, obj.Identity, method, obj.Owner, obj.Fields, obj.Tail, obj.ByteTail));
                return true;
            }

            Payload AppendRequest(HttpObject owner, Payload chunk, bool newline)
            {
                var req = CurrentHttp(owner)!;
                string? piece = chunk.Text ?? (chunk.Bytes == null ? null : Disk.Decode(chunk.Bytes));
                if (newline && piece != null) piece += Environment.NewLine;
                var boundary = piece == null ? null : req.Tail + piece;
                var evidence = Text(boundary, "HTTP request stream", Merge(KnownMarks(new[] { req.Body, chunk })));
                int retain = Math.Max(0, (policy?.LongestFileNeedle ?? 0) - 1);
                string tail = boundary == null ? "" : boundary.Substring(Math.Max(0, boundary.Length - retain));
                // Only the trailing characters are needed to find a future cross-write match.
                var body = new Payload { Tags = evidence.Tags, Complete = req.Body?.Complete != false && piece != null,
                    SourceRef = "HTTP request stream", Issue = "http-stream-content" };
                byte[]? byteTail = null;
                if (chunk.Bytes is { } bytes)
                {
                    // A UTF-8 code point can straddle two raw Stream.Write calls.
                    var window = req.ByteTail.Concat(bytes).ToArray();
                    var crossing = new List<Mark>();
                    if (policy != null)
                        foreach (var rule in policy.FileTextRules)
                            if (rule.Needles.Any(needle => window.AsSpan().IndexOf(System.Text.Encoding.UTF8.GetBytes(needle)) >= 0))
                                crossing.Add(new Mark(rule.Id, "HTTP request stream", "HTTP request stream"));
                    body.Tags = Merge(body.Tags.Concat(crossing));
                    int keep = (int)Math.Min(window.Length, 4L * (retain + 1L));
                    byteTail = window.Skip(window.Length - keep).ToArray();
                }
                SaveHttp(req.WithBody(body, tail, byteTail));
                return body;
            }

            Payload? DotNetExpression(object? node, int depth)
            {
                if (Kind(node) != "InvokeMemberExpressionAst") return null;
                var member = Literal(Prop(node, "Member"))?.ToLowerInvariant();
                var receiver = Prop(node, "Expression");
                var args = Items(Prop(node, "Arguments")).ToArray();
                Payload Arg(int index) => Value(args[index], depth + 1);
                if (Equals(Prop(node, "Static"), true))
                {
                    if (Kind(receiver) != "TypeExpressionAst") return null;
                    var type = HttpType(TypeName(receiver));
                    if (type is ("io.file" or "io.directory") && member is ("getattributes" or "getlastwritetime" or "getlastwritetimeutc" or "getcreationtime" or "getcreationtimeutc" or "getlastaccesstime" or "getlastaccesstimeutc"))
                        return args.Length==1 && (type=="io.file" || member!="getattributes") ? DotNetFsField(Arg(0),member.Substring(3)) : Missing("filesystem-metadata-overload");
                    if (type == "io.randomaccess" && member == "read") return ReadAtOffset(args,depth);
                    if (type == "io.file" && member == "openhandle" && args.Length>0)
                    {
                        var stream=OpenReader(Arg(0),args.Length==1?"openread":"open",args.Skip(1).ToArray(),depth);
                        return stream.HttpObject is HttpObject owner ? SafeHandleValue(owner) : stream;
                    }
                    if (type == "io.file" && member == "readlinesasync") return OpenAsyncLines(args,depth);
                    if (type == "io.file" && member == "writeallbytes" && args.Length == 2)
                    {
                        var path=Arg(0); var bytesToWrite=Arg(1);
                        if (bytesToWrite.Bytes==null && bytesToWrite.Model?.Kind!=ModelKind.PackedBytes) return UncertainWrite("file-byte-input",path.Text,bytesToWrite);
                        if (ShareHost(path.Text) is string host) ShareSend("File.WriteAllBytes",host,new[]{path,bytesToWrite},null);
                        else PlanWrite(path.Text,bytesToWrite,bytesToWrite.Bytes,false);
                        return Missing("no-expression-output");
                    }
                    if (type == "io.directory" && member is ("getfiles" or "getdirectories" or "getfilesystementries" or
                        "enumeratefiles" or "enumeratedirectories" or "enumeratefilesystementries"))
                        return DirectoryRead(member, args, depth);
                    if (type == "microsoft.win32.registry" && member == "getvalue") return ReadRegistryCall(null, member, args, depth);
                    if (type == "environment" && member is ("getenvironmentvariable" or "getenvironmentvariables"))
                        return ReadEnvironmentMethod(member, args, depth);
                    if (member == "new") return ConstructHttpObject(type, args, depth);
                    if (type == "xml.linq.xdocument" && member == "load" && args.Length == 1)
                        return LoadXmlSource(Arg(0), "linq-xml", true, false);
                    if (type == "io.compression.zipfile" && member == "openread" && args.Length == 1)
                        return OpenZip(Arg(0), depth);
                    if (type == "io.file" && member is ("openread" or "open" or "opentext" or "create" or "openwrite"))
                        return args.Length == 0 ? Missing("file-open-overload") : OpenReader(Arg(0), member, args.Skip(1).ToArray(), depth);
                    if (args.Length == 1 && member is ("create" or "createhttp") &&
                        type is ("net.webrequest" or "system.net.webrequest" or "net.httpwebrequest" or "system.net.httpwebrequest"))
                        return HttpObjectValue(new HttpObject(HttpObjectKind.Request, Arg(0), method: "GET"));
                    if (type is ("io.file" or "system.io.file") && member is ("readallbytes" or "readalltext" or
                        "readlines" or "readalllines" or "readalltextasync" or "readalllinesasync" or "readallbytesasync"))
                        return DotNetFileRead(member, args, depth);
                    return null;
                }
                if (member is not ("add" or "tryaddwithoutvalidation" or "remove" or "clear" or "uploadstring" or "uploadfile" or "uploaddata" or "postasync" or "putasync" or "patchasync" or "sendasync" or "getresponse" or "getresponseasync" or "getrequeststream" or
                    "write" or "writeasync" or "writebyte" or "getbuffer" or "writeto" or "flush" or "flushasync" or "writeline" or "writelineasync" or "copyto" or "copytoasync" or "getawaiter" or "getresult" or "wait" or
                    "open" or "openread" or "opentext" or "read" or "readasync" or "readbyte" or "readbytes" or "readline" or "readlineasync" or
                    "readtoend" or "readtoendasync" or "peek" or "close" or "dispose" or "seek" or "setlength" or "getentry" or "toarray" or
                    "getvalue" or "opensubkey" or "getvaluenames" or "getsubkeynames" or "getenumerator" or "load" or "loadxml" or
                    "readexactly" or "readexactlyasync" or "readatleast" or "readatleastasync" or "getasyncenumerator" or "movenextasync" or "disposeasync" or "astask")) return null;
                var target = Value(receiver, depth + 1);
                if (target.Issue == "environment-map" && member == "getenumerator" && args.Length == 0) return EnvironmentMapMembers(target, "entries");
                if (target.FileObject is { Kind: PathKind.FileInfo } info && member is ("open" or "openread" or "opentext" or "create" or "openwrite"))
                    return OpenReader(Text(info.Path, "FileInfo.FullName"), member, args, depth);
                if (target.FileTaskResult is Payload completedRead && args.Length == 0)
                {
                    if (target.Issue == "file-read-valuetask" && member == "astask")
                    { var asTask=target.Copy(); asTask.Issue="file-read-task"; return asTask; }
                    if (target.Issue is ("file-read-valuetask" or "file-read-task") && member == "getawaiter")
                        return new Payload { FileTaskResult = completedRead, DeferredRead = target.DeferredRead, Issue = "file-read-awaiter" };
                    if (target.Issue == "file-read-awaiter" && member == "getresult") return FinishRead(target);
                    if (target.Issue == "file-read-task" && member == "wait") { FinishRead(target); return Missing("no-expression-output"); }
                }
                if (member is "getawaiter" or "getresult" or "wait")
                    return target.Issue == "dotnet-http-response" ? target : null;
                var state = CurrentHttp(target.HttpObject);
                if (state == null) return null;
                if (state.Kind == HttpObjectKind.RequestStream)
                {
                    if (member is ("close" or "dispose") && args.Length == 0) return CloseStream(state);
                    if (!ReaderOpen(state)) return Missing("request-stream-closed");
                }
                if (AuxReader(state)) return AuxReadMember(state,member!,args,depth);
                if (state.Kind == HttpObjectKind.XmlDocument && member is ("load" or "loadxml"))
                {
                    var option = Slot(state, "whitespace");
                    var xml = args.Length != 1 || option != null && option.ScalarTruth == null ? Missing("xml-load-overload-or-option") :
                        LoadXmlSource(Arg(0), "dom-xml", member == "load", option?.ScalarTruth == true);
                    SaveHttp(state.WithBody(xml)); return Missing("no-expression-output");
                }
                if (state.Kind == HttpObjectKind.RegistryKey) return ReadRegistryCall(state, member!, args, depth);
                if (state.Method == "memory" && member == "toarray" && args.Length == 0) return StreamArray(state);
                if (state.Kind == HttpObjectKind.FileStream && StreamOperation(state, member!, args, depth) is Payload streamResult)
                    return streamResult;
                if (ZipHandle(state))
                {
                    if (state.Kind == HttpObjectKind.ZipArchive && member == "dispose" && args.Length == 0)
                    { SaveHttp(ReaderSet(state, ("closed", Number(1)))); return Missing("no-expression-output"); }
                    if (state.Kind == HttpObjectKind.ZipArchive && member == "getentry" && args.Length == 1)
                        return ZipSelection(state, ExactString(Arg(0)), find: true);
                    if (state.Kind == HttpObjectKind.ZipEntry && member == "open" && args.Length == 0)
                        return OpenZipEntry(state);
                    return Missing("archive-method");
                }
                if (IsReadHandle(state) && member is not ("copyto" or "copytoasync"))
                    return ReadMember(state, member!, args, depth);
                Payload? address = null, data = null;
                string operation;
                HttpObject? request = null;
                HttpObject? streamOwner = null;
                if ((state.Kind == HttpObjectKind.Headers && state.Owner != null) || state.Kind == HttpObjectKind.Fields)
                {
                    var owner = CurrentHttp(state.Owner ?? state)!;
                    if (member is ("add" or "tryaddwithoutvalidation") && args.Length == 2)
                    {
                        var result = SetField(owner, Arg(0), Arg(1), true);
                        return member == "tryaddwithoutvalidation" ? Missing("http-header-add-result") : result;
                    }
                    if (member == "remove" && args.Length == 1)
                    {
                        var result = SetField(owner, Arg(0), null, false);
                        return owner.Kind is HttpObjectKind.WebClient or HttpObjectKind.Request ? result : Missing("http-field-remove-result");
                    }
                    if (member == "clear" && args.Length == 0)
                    { SaveHttp(owner.WithFields(new Dictionary<string, Payload>(owner.Fields.Comparer))); return Missing("no-expression-output"); }
                }
                if (member == "add" && (state.Kind == HttpObjectKind.Multipart && args.Length is >= 1 and <= 3 ||
                    state.Kind == HttpObjectKind.PairList && args.Length == 1))
                {
                    var added = args.Select((_, i) => Arg(i)).ToArray();
                    if (added[0].HttpObject?.Identity == state.Identity) return Missing("multipart-cycle");
                    var previous = state.Body;
                    var items = CollectElements((previous?.Elements ?? Array.Empty<Payload>()).Concat(added));
                    items.Tags = Merge(KnownMarks(added.Select(item => HttpContent(item))).Concat(previous?.Tags ?? Array.Empty<Mark>()));
                    if (previous?.InspectionPartial == true) items = Partial(items, "multipart-element-limit");
                    SaveHttp(state.WithBody(items));
                    return Missing("no-expression-output");
                }
                switch (state.Kind)
                {
                    case HttpObjectKind.WebClient when member is ("uploadstring" or "uploadfile" or "uploaddata") && args.Length is 2 or 3:
                        address = Arg(0);
                        var argument = Arg(args.Length - 1);
                        data = member == "uploadfile" ? ReadFileArgument(argument, false) : argument;
                        operation = member == "uploadfile" ? "WebClient.UploadFile" : member == "uploaddata" ? "WebClient.UploadData" : "WebClient.UploadString";
                        break;
                    case HttpObjectKind.Client when member is ("postasync" or "putasync" or "patchasync") && args.Length is 2 or 3:
                        address = Arg(0);
                        var post = Arg(1);
                        data = post.HttpObject?.Kind is HttpObjectKind.Content or HttpObjectKind.Multipart ? HttpContent(post) : Missing("http-content-type");
                        operation = member == "postasync" ? "HttpClient.PostAsync" : member == "putasync" ? "HttpClient.PutAsync" : "HttpClient.PatchAsync";
                        break;
                    case HttpObjectKind.Client when member == "sendasync" && args.Length >= 1 && args.Length <= 3:
                        request = CurrentHttp(Arg(0).HttpObject);
                        address = request?.Address;
                        data = HttpContent(request?.Body);
                        operation = "HttpClient.SendAsync";
                        break;
                    case HttpObjectKind.Request when member is ("getresponse" or "getresponseasync") && args.Length == 0:
                        address = state.Address;
                        data = state.Body;
                        operation = "HttpWebRequest.GetResponse";
                        break;
                    case HttpObjectKind.Request when member == "getrequeststream" && args.Length == 0:
                        visitedHttpMethods.Add(node!);
                        if (state.Method is "GET" or "HEAD") return Missing("request-method-has-no-stream");
                        if (state.Fields.Count != 0)
                            Send("HttpWebRequest.GetRequestStream", Http(state.Address?.Text),
                                state.Fields.SelectMany(f => new[] { Text(f.Key, "HTTP header name"), f.Value }));
                        return HttpObjectValue(new HttpObject(HttpObjectKind.RequestStream, state.Address, owner: state));
                    case HttpObjectKind.RequestStream when member is ("write" or "writeasync") && args.Length == 1:
                        address = state.Address;
                        data = Arg(0);
                        operation = "HttpWebRequest.GetRequestStream.Write";
                        break;
                    case HttpObjectKind.RequestStream when member is ("write" or "writeasync") && args.Length is 3 or 4:
                        address = state.Address;
                        data = ByteSegment(Arg(0), Arg(1), Arg(2));
                        operation = "HttpWebRequest.GetRequestStream.Write";
                        break;
                    case HttpObjectKind.Writer when member is ("write" or "writeasync" or "writeline" or "writelineasync") && args.Length == 1:
                    case HttpObjectKind.Writer when member is ("writeline" or "writelineasync") && args.Length == 0:
                        address = state.Address;
                        data = args.Length == 0 ? Text("", "StreamWriter") : Arg(0);
                        operation = "HttpWebRequest.GetRequestStream.StreamWriter";
                        break;
                    default: return null;
                }
                streamOwner ??= state.Owner;
                if (streamOwner != null && data != null)
                {
                    data = AppendRequest(streamOwner, data, member is "writeline" or "writelineasync");
                    request = CurrentHttp(streamOwner);
                }
                string? url = address?.Text;
                if (state.Kind is HttpObjectKind.Client or HttpObjectKind.WebClient && state.Address?.Text is string baseUri &&
                    Uri.TryCreate(baseUri, UriKind.Absolute, out var origin) && url != null && Uri.TryCreate(origin, url, out var full))
                    url = full.AbsoluteUri;
                var parts = new List<Payload> { data ?? Missing("http-content") };
                var headers = request == null ? state.Fields : state.Fields.Where(f => !request.Fields.ContainsKey(f.Key)).Concat(request.Fields);
                foreach (var header in headers)
                {
                    parts.Add(Text(header.Key, "HTTP header name"));
                    parts.Add(header.Value);
                }
                if (address != null) AddRequestTarget(parts, address);
                visitedHttpMethods.Add(node!);
                Send(operation, Http(url), parts);
                return Missing(operation.StartsWith("HttpWebRequest.GetRequestStream.", StringComparison.Ordinal) &&
                    member is ("write" or "writeline" or "copyto") ? "no-expression-output" : "dotnet-http-response");
            }
        }
    }
}

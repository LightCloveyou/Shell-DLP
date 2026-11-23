using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Xml;
using System.Text;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            static int MaxPackedEntries => Limits.MaxPackedEntries;
            static int MaxExpanded => Limits.MaxExpanded;
            static int MaxPackedDepth => Limits.MaxPackedDepth;

            static string TypeName(object? type) => Str(Prop(Prop(type, "TypeName"), "FullName")).ToLowerInvariant();

            Payload Bytes(byte[] data, string origin, Mark[]? marks = null)
            {
                var text = Disk.Decode(data);
                var result = Text(text, origin, marks);
                result.Bytes = data;
                result.Text = null; // byte[] and string bind differently in PowerShell
                result.IsString = false;
                return result;
            }

            Payload? Transform(object? node, int depth)
            {
                if (Kind(node) != "InvokeMemberExpressionAst") return null;
                var member = Literal(Prop(node, "Member"))?.ToLowerInvariant();
                var target = Prop(node, "Expression");
                var args = Items(Prop(node, "Arguments")).Take(5).ToArray();
                if (Equals(Prop(node, "Static"), true) && Kind(target) == "TypeExpressionAst" &&
                    TypeName(target) is "convert" or "system.convert" &&
                    member is "tobase64string" or "frombase64string")
                {
                    if (args.Length != 1 && !(member == "tobase64string" && args.Length == 3)) return Missing("base64-arguments");
                    var arg = Value(args[0], depth + 1);
                    if (args.Length==3)
                    {
                        arg=ByteSegment(arg,Value(args[1],depth+1),Value(args[2],depth+1));
                        if(arg.Issue=="invalid-stream-write-range")return arg;
                        if(arg.Bytes==null)arg=SymbolicBytes("base64-byte-range",arg);
                    }
                    string step = member == "tobase64string" ? "Base64 encode" : "Base64 decode";
                    var tags = arg.Tags.Select(m => m.Via(step)).ToArray();
                    if (member == "tobase64string" && arg.Model?.Kind == ModelKind.PackedBytes)
                        return Symbol(new ModelValue(ModelKind.Base64Text, tags), step);
                    if (member == "frombase64string" && arg.Model?.Kind == ModelKind.Base64Text && arg.Text==null)
                        return SymbolicBytes("decoded-bytes-not-materialized",arg.Via(step));
                    try
                    {
                        if (member == "tobase64string" && arg.Bytes != null && arg.Bytes.Length <= (MaxContent / 4) * 3)
                            return Text(Convert.ToBase64String(arg.Bytes), step, tags);
                        if (member == "frombase64string" && arg.IsString && arg.Text != null && arg.Text.Length <= MaxContent)
                            return Bytes(Convert.FromBase64String(arg.Text), step, tags);
                    }
                    catch (FormatException) { return Missing("base64-invalid"); }
                    return Missing("base64-input");
                }
                if (!Equals(Prop(node, "Static"), true) && Kind(target) == "MemberExpressionAst" &&
                    Equals(Prop(target, "Static"), true) && Kind(Prop(target, "Expression")) == "TypeExpressionAst" &&
                    TypeName(Prop(target, "Expression")) is "text.encoding" or "system.text.encoding" &&
                    member is "getbytes" or "getstring")
                {
                    var name = Literal(Prop(target, "Member"))?.ToLowerInvariant();
                    Encoding? encoding = name switch
                    {
                        "utf8" => StrictUtf8,
                        "unicode" => new UnicodeEncoding(false, false, true),
                        "bigendianunicode" => new UnicodeEncoding(true, false, true),
                        _ => null
                    };
                    if (encoding == null || args.Length != 1) return Missing("encoding-arguments");
                    var arg = Value(args[0], depth + 1);
                    string step = name + (member == "getbytes" ? " bytes" : " text");
                    var tags = arg.Tags.Select(m => m.Via(step)).ToArray();
                    try
                    {
                        if (member == "getbytes" && arg.IsString && arg.Text != null &&
                            encoding.GetByteCount(arg.Text) <= MaxContent)
                            return Bytes(encoding.GetBytes(arg.Text), step, tags);
                        if (member == "getstring" && arg.Bytes != null && arg.Bytes.Length <= MaxContent)
                            return Text(encoding.GetString(arg.Bytes), step, tags);
                    }
                    catch (ArgumentException) { return Missing("encoding-invalid"); }
                    if (member == "getbytes" && arg.IsString) return SymbolicBytes("encoded-bytes-not-materialized",arg.Via(step));
                    if (member == "getstring" && arg.Model?.Kind==ModelKind.PackedBytes)
                    { var opaque=UnknownValue("decoded-text-not-materialized",arg.Via(step));opaque.IsString=true;return opaque; }
                    return Missing("encoding-input");
                }
                return null;
            }

            static byte[]? CanonicalBase64(string? value)
            {
                if (value == null) return null;
                value = value.Trim();
                if (value.Length < 12 || value.Length > MaxContent || value.Length % 4 != 0) return null;
                foreach (char c in value)
                    if (!(c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '+' or '/' or '=')) return null;
                try
                {
                    var bytes = Convert.FromBase64String(value);
                    return Convert.ToBase64String(bytes) == value ? bytes : null;
                }
                catch (FormatException) { return null; }
            }

            static bool ZipMagic(byte[] bytes) => bytes.Length >= 4 && bytes[0] == 0x50 && bytes[1] == 0x4b &&
                ((bytes[2] == 3 && bytes[3] == 4) || (bytes[2] == 5 && bytes[3] == 6) || (bytes[2] == 7 && bytes[3] == 8));
            static bool GzipMagic(byte[] bytes) => bytes.Length >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b;

            static string? ArchiveKind(string path, byte[]? bytes)
            {
                if (bytes != null)
                {
                    if (ZipMagic(bytes)) return "zip";
                    if (GzipMagic(bytes)) return "gzip";
                }
                if (path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) return "zip";
                if (path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase))
                    return "gzip";
                foreach (var ext in new[] { ".7z", ".rar", ".tar", ".bz2", ".xz" })
                    if (path.EndsWith(ext, StringComparison.OrdinalIgnoreCase)) return "unknown";
                return null;
            }

            static byte[] ReadExpanded(Stream input, ref int remaining, Func<bool> withinTime)
            {
                using var result = new MemoryStream();
                var buffer = new byte[4096];
                while (true)
                {
                    if (!withinTime()) throw new IOException("archive-time");
                    int n = input.Read(buffer, 0, Math.Min(buffer.Length, remaining + 1));
                    if (n == 0) break;
                    if (n > remaining) throw new IOException("archive-expanded-limit");
                    remaining -= n;
                    result.Write(buffer, 0, n);
                }
                return result.ToArray();
            }

            static Dictionary<string, byte[]> ZipEntries(byte[] bytes, ref int remaining, ref int entries,
                Func<bool> withinTime)
            {
                using var stream = new MemoryStream(bytes, false);
                using var zip = new ZipArchive(stream, ZipArchiveMode.Read);
                var result = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var entry in zip.Entries)
                {
                    if (--entries < 0 || !withinTime()) throw new IOException("archive-entry-limit");
                    var path = entry.FullName.Replace('\\', '/');
                    var name = path.TrimEnd('/');
                    if (name.Length == 0 || name.Length > Limits.MaxArchivePath || name.IndexOf(':') >= 0 ||
                        name.Split('/').Any(x => x.Length == 0 || x == ".." || x == ".") || !names.Add(name) ||
                        ((entry.ExternalAttributes >> 16) & 0xf000) == 0xa000)
                        throw new IOException("archive-entry-name");
                    if (path.EndsWith("/", StringComparison.Ordinal))
                    {
                        if (entry.Length != 0) throw new IOException("archive-directory-data");
                        continue;
                    }
                    if (entry.Length > remaining || entry.Length > MaxContent) throw new IOException("archive-expanded-limit");
                    using var input = entry.Open();
                    var data = ReadExpanded(input, ref remaining, withinTime);
                    if (data.LongLength != entry.Length) throw new IOException("archive-entry-size");
                    result.Add(name, data);
                }
                return result;
            }

            internal static bool ConfirmsArchive(byte[] data, Dictionary<string, byte[]> expected)
            {
                try
                {
                    int remaining = MaxExpanded, entries = MaxPackedEntries;
                    var elapsed = System.Diagnostics.Stopwatch.StartNew();
                    var actual = ZipEntries(data, ref remaining, ref entries, () => elapsed.ElapsedMilliseconds <= Limits.FileScanBudgetMs);
                    return actual.Count == expected.Count && expected.All(pair =>
                        actual.TryGetValue(pair.Key, out var file) && file.SequenceEqual(pair.Value));
                }
                catch { return false; }
            }

            bool PlanArchive(object command, bool possibleDefinition = false)
            {
                using var args = new Args(this, command, Paths.Concat(new[] { "DestinationPath", "CompressionLevel" }).ToArray(), new[] { "Force" });
                var source = PathArg(args, 0, out int total);
                var dest = args.Get("DestinationPath") ?? args.Plain.ElementAtOrDefault(total++);
                if (!args.Valid || source == null || dest == null || args.Plain.Count != total || barrier ||
                    plan.Work.Count >= MaxEffects || policy == null || policyProblem.Length != 0) return false;
                if (args.Has("CompressionLevel") && !new[] { "Optimal", "Fastest", "NoCompression" }
                    .Contains(Value(args.Get("CompressionLevel")).Text, StringComparer.OrdinalIgnoreCase)) return false;
                var from = Disk.Bind(Value(source).Text, cwd);
                var to = Disk.Bind(Value(dest).Text, cwd);
                if (from == null || to == null || PathEq(from, to) || !to.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) ||
                    !Disk.ClearAncestors(from) || PendingFiles.ContainsKey(from) || plannedFiles.Contains(to)) return false;
                var stamp = Disk.TargetStamp(to);
                if (stamp == null || (stamp.Length != 0 && !args.Has("Force"))) return false;
                var expected = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
                var labels = new List<Mark>();
                int totalBytes = 0, visits = 0;
                bool complete = true, seenFile = false, exactArchive = !possibleDefinition;
                bool Collect(string path, string archivePath, int depth)
                {
                    if (++visits > Limits.MaxPackedEntries || !Budget() || depth > MaxExpressionDepth ||
                        !Disk.ClearAncestors(path) || PathEq(path, to)) return false;
                    var attributes = System.IO.File.GetAttributes(path);
                    if ((attributes & FileAttributes.Hidden) != 0) return false; // stock cmdlet omits hidden inputs
                    if ((attributes & FileAttributes.Directory) != 0)
                    {
                        foreach (var child in Directory.EnumerateFileSystemEntries(path))
                            if (!Collect(child, archivePath + "/" + Path.GetFileName(child), depth + 1)) return false;
                        return true;
                    }
                    var content = File(path, false, out var sample, forceBytes: exactArchive);
                    seenFile = true;
                    labels.AddRange(DiscoverSendContent(content).Tags);
                    complete &= content.Complete && !content.InspectionPartial;
                    if (exactArchive)
                    {
                        if (sample?.Bytes == null || expected.ContainsKey(archivePath) ||
                            (long)totalBytes + sample.Bytes.Length > MaxExpanded)
                        {
                            exactArchive = false;
                            expected.Clear();
                        }
                        else
                        {
                            totalBytes += sample.Bytes.Length;
                            expected.Add(archivePath, sample.Bytes);
                        }
                    }
                    return true;
                }
                bool collected;
                try
                {
                    collected = Collect(from, Path.GetFileName(from.TrimEnd('\\')), 0);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException)
                { collected = false; }
                if (!seenFile || !collected && labels.Count == 0) return false;
                var tags = Merge(labels).Select(t => t.Via(to)).ToArray();
                if (!exactArchive || !collected)
                {
                    // Carry candidate evidence within this analysis. This is not a witnessed
                    // archive and must not be committed to durable copy metadata.
                    MarkPossibleWrite(to, new Payload { SourceRef = to, Tags = tags, InspectionPartial = true });
                    if (!possibleDefinition) ReportMissing("archive-source-content");
                    return true;
                }
                plannedFiles.Add(to);
                plan.Work.Add(new PolicyWork { Target = to, From = from, Before = stamp, Archive = expected, Tags = tags });
                // With -Force either the new archive or the original can reach a later read.
                predictedWrites[to] = new Payload { SourceRef = to, Tags = tags, MayReadOriginal = stamp.Length != 0,
                    Complete = complete, Issue = complete ? "" : "archive-source-content" };
                return true;
            }

            Payload InspectPacked(byte[]? bytes, string path, string kind)
            {
                if (bytes == null) return Missing("archive-input-limit");
                if (kind == "unknown") return Missing("archive-format");
                var labels = new List<Mark>();
                int remaining = MaxExpanded, entries = MaxPackedEntries;
                bool WithinTime() => Budget();
                int visitLimit = Limits.MaxArchiveVisits;
                bool Walk(byte[] content, string origin, string? format, int depth)
                {
                    if (--visitLimit < 0) return false;
                    if (format == null)
                    {
                        var decoded = Disk.Decode(content);
                        if (decoded == null) return policy?.Rules.All(r => r.Texts.Length == 0) == true;
                        labels.AddRange(Text(decoded, origin).Tags);
                        var wrapped = CanonicalBase64(decoded);
                        if (wrapped != null && Disk.Decode(wrapped) is string clear)
                            labels.AddRange(Text(clear, origin + " → Base64").Tags);
                        return true;
                    }
                    if (!StackAvailable || depth >= MaxPackedDepth || format == "unknown") return false;
                    try
                    {
                        if (format == "zip")
                        {
                            bool complete = true;
                            foreach (var pair in ZipEntries(content, ref remaining, ref entries, WithinTime))
                                complete = Walk(pair.Value, origin + "!" + pair.Key, ArchiveKind(pair.Key, pair.Value), depth + 1) && complete;
                            return complete;
                        }
                        if (!GzipMagic(content)) return false;
                        using var input = new MemoryStream(content, false);
                        using var gzip = new GZipStream(input, CompressionMode.Decompress);
                        int before = remaining;
                        // GZipStream has no declared size: charge the expanded bytes as they are read.
                        var clear = ReadExpanded(gzip, ref remaining, WithinTime);
                        if (before - remaining > MaxContent) return false;
                        string name = origin.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ? origin.Substring(0, origin.Length - 3) : origin + "!gzip";
                        return Walk(clear, name, ArchiveKind(name, clear), depth + 1);
                    }
                    catch (InvalidDataException) { return false; }
                    catch (IOException) { return false; }
                    catch (NotSupportedException) { return false; }
                }
                bool checkedAll = Walk(bytes, path, kind, 0);
                return new Payload { Bytes = bytes, Complete = checkedAll, SourceRef = path,
                    Issue = checkedAll ? "" : "archive-unreadable-or-limit", Tags = Merge(labels) };
            }

            Payload DiscoverSendContent(Payload input)
            {
                if (input.Bytes != null && ArchiveKind("", input.Bytes) is string packed)
                {
                    var archive = InspectPacked(input.Bytes, input.SourceRef, packed);
                    if (!archive.Complete) archive.InspectionPartial = true;
                    return Combine(input, archive, preserveCompleteness: true);
                }
                var content = input.PipeText ?? input.Text;
                if (content == null || content.Length > MaxContent) return input;
                // Inspect whole-body Base64 and bounded form/query fields. Canonical syntax
                // identifies candidates, not proof that arbitrary decoded binary is harmless.
                var trimmed = content.TrimStart();
                if (trimmed.StartsWith("{", StringComparison.Ordinal) || trimmed.StartsWith("[", StringComparison.Ordinal))
                    return InspectJson(input, trimmed);
                var result = InspectEncoded(input, content, out bool whole);
                if (whole) return result;
                var fields = content.Split(new[] { '&', '\r', '\n' }, Limits.MaxEncodedFields);
                if (fields.Length == Limits.MaxEncodedFields && fields[fields.Length - 1].IndexOfAny(new[] { '&', '\r', '\n' }) >= 0)
                    result = Combine(result, new Payload { InspectionPartial = true, Issue = "encoded-field-limit" }, preserveCompleteness: true);
                foreach (var field in fields)
                {
                    int equals = field.IndexOf('=');
                    if (equals <= 0 || equals > Limits.MaxFieldName) continue;
                    var name = field.Substring(0, equals);
                    if (name.Any(ch => !char.IsLetterOrDigit(ch) && ch != '.' && ch != '_' && ch != '-')) continue;
                    var raw = field.Substring(equals + 1).Trim();
                    result = InspectEncoded(result, Uri.UnescapeDataString(raw), out _);
                }
                return result;
            }

            Payload InspectJson(Payload input, string content)
            {
                var output = input;
                try
                {
                    var limits = new XmlDictionaryReaderQuotas { MaxDepth = MaxExpressionDepth, MaxStringContentLength = MaxContent,
                        MaxArrayLength = MaxJsonElements, MaxNameTableCharCount = Limits.MaxJsonNames, MaxBytesPerRead = 4096 };
                    var data = StrictUtf8.GetBytes(content);
                    using var reader = JsonReaderWriterFactory.CreateJsonReader(data, limits);
                    var origin = input.SourceRef + " → JSON";
                    int visits = 0;
                    while (!reader.EOF)
                    {
                        if (++visits > MaxJsonElements || !Budget())
                            return Partial(output, "json-inspection-limit");
                        if (reader.NodeType != XmlNodeType.Element) { reader.Read(); continue; }
                        var key = reader.GetAttribute("item") ?? reader.LocalName;
                        if (reader.Depth > 0)
                            output = Combine(output, Text(key, origin), preserveCompleteness: true);
                        if (reader.GetAttribute("type") == "string")
                        {
                            var value = reader.ReadElementContentAsString();
                            output = Combine(output, Text(value, origin), preserveCompleteness: true);
                            output = InspectEncoded(output, value, out _);
                        }
                        else reader.Read();
                    }
                    return output;
                }
                catch (XmlException) { return Partial(output, "json-unreadable-or-limit"); }
                catch (ArgumentException) { return Partial(output, "json-unreadable-or-limit"); }
            }

            Payload Partial(Payload source, string reason) =>
                Combine(source, new Payload { InspectionPartial = true, Issue = reason }, preserveCompleteness: true);

            Payload InspectEncoded(Payload input, string content, out bool recognized)
            {
                var decoded = CanonicalBase64(content);
                recognized = decoded != null;
                if (decoded == null) return input;
                string origin = (string.IsNullOrEmpty(input.SourceRef) ? "body" : input.SourceRef) + " → Base64";
                if (ArchiveKind("", decoded) is string kind)
                    {
                    var unpacked = InspectPacked(decoded, origin, kind);
                    if (!unpacked.Complete) unpacked.InspectionPartial = true;
                    return Combine(input, unpacked, preserveCompleteness: true);
                }
                var decodedText = Disk.Decode(decoded);
                var result = Combine(input, Text(decodedText, origin), preserveCompleteness: true);
                if (decodedText == null)
                { result.InspectionPartial = true; result.Issue = "unrecognized-binary-encoding"; }
                return result;
            }

            Payload Combine(Payload source, Payload extra, bool preserveCompleteness)
            {
                var result = source.Copy();
                result.InspectionPartial |= extra.InspectionPartial;
                result.Tags = Merge(source.Tags.Concat(extra.Tags));
                if (!preserveCompleteness) result.Complete = extra.Complete;
                if (extra.InspectionPartial || !preserveCompleteness && !extra.Complete) result.Issue = extra.Issue;
                return result;
            }
        }
    }
}

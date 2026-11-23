using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            sealed class ArchiveMember
            {
                internal string Name = "";
                internal long Size;
                internal bool Directory, Special;
                internal Func<byte[]>? Content;
            }
            sealed class ArchiveCall
            {
                internal string? Input, Destination;
                internal string Mode = "", Format = "", Overwrite = "", Error = "";
                internal bool Seven, Stdout, Verbose, Slt, Bare, Recursive, Literal;
                internal string Compression = "";
                internal bool InfoZip, InfoNames, Quiet;
                internal readonly List<string> Excluded = new List<string>();
                internal int Strip;
                internal readonly List<string> Selection = new List<string>();
            }
            static ArchiveCall ArchiveArguments(string tool, string[] a)
            {
                if (tool is "unzip" or "zipinfo") return ZipArguments(tool, a);
                var call = new ArchiveCall { Seven = tool is "7z" or "7za" or "7zz" };
                bool end = false;
                void Error() => call.Error = "archive-arguments";
                void Compress(string kind) { if (call.Compression.Length>0 && call.Compression!=kind) Error(); call.Compression=kind; }
                void Mode(string m) { if (call.Mode.Length > 0) Error(); else call.Mode = m; }
                string Next(ref int i) { if (++i < a.Length) return a[i]; Error(); return ""; }
                for (int i = 0; i < a.Length; i++)
                {
                    string s = a[i];
                    if (!end && s == "--") { end = true; continue; }
                    if (call.Seven)
                    {
                        if (!end && s.Length > 1 && s[0] == '-')
                        {
                            string f = s.ToLowerInvariant();
                            if (f.StartsWith("-o") && s.Length > 2 && call.Destination == null) call.Destination = s.Substring(2);
                            else if (f is "-ttar" or "-tzip" or "-t7z") call.Format = f.Substring(2);
                            else if (f is "-y" or "-aoa" or "-aos") { if (f != "-y" || call.Overwrite == "") call.Overwrite = f == "-aos" ? "skip" : "replace"; }
                            else if (f == "-so") call.Stdout = true;
                            else if (f == "-slt") call.Slt = true;
                            else if (f == "-ba") call.Bare = true;
                            else if (f == "-spd") call.Literal = true;
                            else if (f is "-r" or "-r-") call.Recursive = f == "-r";
                            else if (f != "-bd") Error();
                        }
                        else if (call.Mode == "") Mode(s.ToLowerInvariant() switch { "l" => "list", "x" => "extract", "e" => "flat", _ => "other" });
                        else if (call.Input == null) call.Input = s;
                        else call.Selection.Add(s);
                        continue;
                    }
                    if (!end && s.StartsWith("--", StringComparison.Ordinal))
                    {
                        switch (s)
                        {
                            case "--list": Mode("list"); break;
                            case "--extract": case "--get": Mode("extract"); break;
                            case "--to-stdout": call.Stdout = true; break;
                            case "--verbose": call.Verbose = true; break;
                            case "--gzip": case "--gunzip": Compress("gzip"); break;
                            case "--bzip2": Compress("bzip2"); break;
                            case "--xz": Compress("xz"); break;
                            case "--file": if (call.Input != null) Error(); call.Input = Next(ref i); break;
                            case "--directory": if (call.Destination != null) Error(); call.Destination = Next(ref i); break;
                            case "--keep-old-files": case "--skip-old-files": call.Overwrite = "skip"; break;
                            case "--strip-components":
                                if (!int.TryParse(Next(ref i), NumberStyles.None, CultureInfo.InvariantCulture, out call.Strip)) Error(); break;
                            default:
                                if (s.StartsWith("--file=") && call.Input == null) call.Input = s.Substring(7);
                                else if (s.StartsWith("--directory=") && call.Destination == null) call.Destination = s.Substring(12);
                                else if (!s.StartsWith("--strip-components=") || !int.TryParse(s.Substring(19), NumberStyles.None, CultureInfo.InvariantCulture, out call.Strip)) Error();
                                break;
                        }
                    }
                    else if (!end && (s.Length > 1 && s[0] == '-' || i == 0 && s.Length > 0 && "tx".Contains(s[0])))
                    {
                        bool oldStyle = s[0] != '-';
                        for (int j = oldStyle ? 0 : 1; j < s.Length; j++)
                        {
                            switch (s[j])
                            {
                                case 't': Mode("list"); break;
                                case 'x': Mode("extract"); break;
                                case 'O': call.Stdout = true; break;
                                case 'v': call.Verbose = true; break;
                                case 'z': Compress("gzip"); break;
                                case 'j': Compress("bzip2"); break;
                                case 'J': Compress("xz"); break;
                                case 'k': call.Overwrite = "skip"; break;
                                case 'f': case 'C':
                                    char flag = s[j];
                                    string arg = !oldStyle && j + 1 < s.Length ? s.Substring(j + 1) : Next(ref i);
                                    if (flag == 'f') { if (call.Input != null) Error(); call.Input = arg; }
                                    else { if (call.Destination != null) Error(); call.Destination = arg; }
                                    if (!oldStyle) j = s.Length;
                                    break;
                                default: Error(); break;
                            }
                        }
                    }
                    else call.Selection.Add(s);
                }
                if (call.Mode is not ("list" or "extract" or "flat") || string.IsNullOrEmpty(call.Input) ||
                    call.Seven && call.Input == "-" || call.Mode == "list" && (call.Stdout || call.Strip != 0) ||
                    call.Seven && call.Slt && call.Mode != "list" || call.Input?.StartsWith("@") == true ||
                    call.Selection.Any(q => q.StartsWith("@") || q.Length == 0 || q.Length > Limits.MaxArchivePath)) Error();
                return call;
            }
            static ArchiveCall ZipArguments(string tool, string[] args)
            {
                var c=new ArchiveCall { InfoZip=true, Format="zip", Mode=tool=="zipinfo"?"list":"extract" };
                bool exclude=false, info=tool=="zipinfo", flat=false;
                foreach(var (a,index) in args.Select((s,i)=>(s,i)))
                {
                    if(index>0 && args[index-1]=="-d") {if(a.Length==0)c.Error="unzip-destination";else c.Destination=a;continue;}
                    if(a=="-d") {if(c.Destination!=null || index+1==args.Length)c.Error="unzip-destination";continue;}
                    if(a=="-x" && c.Input!=null) {exclude=true;continue;}
                    if(a.Length>0 && a[0]=='-')
                    {
                        if(a=="-Z1" || info && a=="-1") {c.InfoNames=true;info=true;c.Mode="list";continue;}
                        if(a=="-Z") {info=true;c.Mode="list";continue;}
                        if(a=="-") {c.Error="unzip-archive-path";continue;}
                        if(info) {c.Error="zipinfo-mode";continue;}
                        foreach(char f in a.Substring(1))
                        {
                            switch(f)
                            {
                                case 'l': case 'v': c.Mode="list";break;
                                case 'p': c.Stdout=true; break;
                                case 'c': c.Stdout=true;c.Error="unzip-text-output-format";break;
                                case 't': c.Mode="metadata";c.Error="unzip-integrity-report";break;
                                case 'q': c.Quiet=true;break;
                                case 'j': flat=true;break;
                                case 'o': c.Overwrite="replace";break;
                                case 'n': c.Overwrite="skip";break;
                                default:c.Error="unzip-options";break;
                            }
                        }
                    }
                    else if(c.Input==null)c.Input=a;
                    else (exclude?c.Excluded:c.Selection).Add(a);
                }
                if(flat && c.Mode=="extract")c.Mode="flat";
                if(c.Input==null || c.Stdout && c.Mode=="list" || c.Selection.Concat(c.Excluded).Any(s=>s.Length==0 || s.Length>Limits.MaxArchivePath))
                    c.Error="unzip-arguments";
                return c;
            }
            static void ArchiveCheck(bool ok) { if (!ok) throw new InvalidDataException("archive format, selection or budget"); }
            int ExpansionRoom() => Math.Max(0, MaxExpanded - expandedReadBytes);
            byte[] ExpandStream(Stream stream, long? expected, int max)
            {
                int remaining = Math.Min(max, ExpansionRoom()), initial = remaining;
                ArchiveCheck(expected == null || expected >= 0 && expected <= remaining);
                byte[] result;
                try { result = ReadExpanded(stream, ref remaining, Budget); }
                finally { expandedReadBytes += initial - remaining; }
                ArchiveCheck(expected == null || expected == result.LongLength);
                return result;
            }
            List<ArchiveMember> NativeZipMembers(ZipArchive zip)
            {
                var list = new List<ArchiveMember>();
                foreach (var entry in zip.Entries)
                {
                    ArchiveCheck(Budget() && list.Count < MaxPackedEntries && entry.FullName.Length <= Limits.MaxArchivePath);
                    int type = (entry.ExternalAttributes >> 16) & 0xf000;
                    bool dir = entry.FullName.EndsWith("/") || (entry.ExternalAttributes & 16) != 0 || type == 0x4000;
                    list.Add(new ArchiveMember { Name = entry.FullName, Size = entry.Length, Directory = dir,
                        Special = type is not (0 or 0x4000 or 0x8000) || (entry.ExternalAttributes & (int)FileAttributes.ReparsePoint) != 0,
                        Content = () => { using var s = entry.Open(); return ExpandStream(s, entry.Length, MaxContent); } });
                }
                return list;
            }
            static string ArchiveKey(string name)
            {
                name = name.Replace('\\', '/');
                while (name.StartsWith("./", StringComparison.Ordinal)) name = name.Substring(2);
                return name.TrimEnd('/');
            }
            bool SelectArchiveName(ArchiveCall c, ArchiveMember m)
            {
                if(c.InfoZip)
                {
                    // Info-ZIP matches archive paths, not the basename and not an implicit tar-style subtree.
                    bool Match(string p)
                    {
                        if(p.IndexOfAny("[]\\".ToCharArray())>=0)throw new InvalidDataException();
                        return p.IndexOfAny("*?".ToCharArray())<0 ? p==m.Name :
                            System.IO.Enumeration.FileSystemName.MatchesSimpleExpression(p,m.Name,ignoreCase:false);
                    }
                    return (c.Selection.Count==0 || c.Selection.Any(Match)) && !c.Excluded.Any(Match);
                }
                if (c.Selection.Count == 0) return true;
                string key = ArchiveKey(m.Name);
                var comparison = c.Seven ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
                foreach (string selector in c.Selection)
                {
                    string q = ArchiveKey(selector);
                    if (q == "." || q.Length == 0 && selector == "./") return true;
                    if (key.Equals(q, comparison) || key.StartsWith(q + "/", comparison)) return true;
                    if (c.Seven && c.Recursive && (key.EndsWith("/" + q, comparison) || key.IndexOf("/" + q + "/", comparison) >= 0)) return true;
                    if (!c.Literal && q.IndexOfAny("*?[".ToCharArray()) >= 0)
                    {
                        // Different tar frontends and 7-Zip have different recursive mask semantics.
                        // Interpret flat files / a literal parent and wildcard leaf; don't guess across directories.
                        ArchiveCheck(!q.Contains('[') && !q.Contains('\\'));
                        int pos = q.LastIndexOf('/'), kp = key.LastIndexOf('/');
                        string parent = pos < 0 ? "" : q.Substring(0, pos), baseName = key.Substring(kp + 1);
                        ArchiveCheck(parent.IndexOfAny("*?".ToCharArray()) < 0);
                        if (kp >= 0 && pos < 0 && !(c.Seven && c.Recursive)) throw new InvalidDataException();
                        if (pos >= 0 && !parent.Equals(kp < 0 ? "" : key.Substring(0, kp), comparison)) continue;
                        var pattern = q.Substring(pos + 1);
                        if (System.IO.Enumeration.FileSystemName.MatchesSimpleExpression(pattern, baseName, c.Seven)) return true;
                    }
                }
                return false;
            }
            Payload NativeArchive(string tool, string[] args, Payload? pipe)
            {
                var c = ArchiveArguments(tool, args);
                bool writes = c.Mode is ("flat" or "extract") && !c.Stdout;
                string? dest = c.Destination == null ? cwd : Disk.Bind(c.Destination, cwd);
                Payload Unavailable(string reason)
                {
                    if (!writes) return Missing(reason);
                    if (dest == null || !ArchiveDestination(dest, true, out _, new HashSet<string>(StringComparer.OrdinalIgnoreCase)))
                    { InvalidateFileFacts(); ReportMissing(reason); return Missing(reason); }
                    return UncertainWrite(reason, dest);
                }
                if (c.Error.Length != 0) return Unavailable(c.Error);
                var path = c.Input == "-" ? null : Disk.Bind(c.Input, cwd);
                if (policy == null || barrier || c.Input != "-" && path == null) return Unavailable("archive-source-selection");
                Payload source;
                if (path == null) source = pipe ?? Missing("archive-stdin");
                else
                {
                    var file = File(path, false, out var sample, forceBytes: true, inspectArchive: false);
                    var materialized = sample?.Bytes ?? file.Bytes;
                    if (materialized == null || file.InspectionPartial) return Unavailable("archive-input-not-materialized");
                    source = Bytes(materialized, file.SourceRef, FileRecordMarks(file));
                }
                if (source.Bytes is not byte[] data || data.Length > MaxContent || source.InspectionPartial) return Unavailable("archive-input-not-materialized");
                try
                {
                    string compression = GzipMagic(data) ? "gzip" : data.AsSpan().StartsWith(XzMagic) ? "xz" :
                        data.Length>=3 && data[0]==66 && data[1]==90 && data[2]==104 ? "bzip2" : "";
                    if (c.Compression.Length!=0 && c.Compression!=compression) return Unavailable("archive-compression");
                    if (compression.Length!=0)
                    {
                        if (c.Seven || c.InfoZip) return Unavailable("archive-compressed-layer");
                        int room=Math.Min(MaxExpanded,ExpansionRoom());
                        data = compression=="gzip"?GunzipBytes(data,room):compression=="xz"?UnxzBytes(data,room):BunzipBytes(data,room);
                    }
                    string format = SevenSignature(data) ? "7z" : ZipMagic(data) ? "zip" : "tar";
                    if (c.Format.Length > 0 && format != c.Format || compression.Length!=0 && format != "tar") return Unavailable("archive-format");
                    using var memory = new MemoryStream(data, false);
                    if (format == "zip") ArchiveCheck(BoundedZipDirectory(data));
                    using var zip = format == "zip" ? new ZipArchive(memory, ZipArchiveMode.Read) : null;
                    var all = zip != null ? NativeZipMembers(zip) : format == "7z" ? SevenMembers(data) : TarMembers(data);
                    var selected = all.Where(m => Budget() ? SelectArchiveName(c, m) : throw new InvalidDataException()).ToList();
                    return ArchiveOutput(c, path, dest, source, selected, Unavailable);
                }
                catch (Exception ex) when (ex is IOException or InvalidDataException or ArgumentException or OverflowException or NotSupportedException)
                { return Unavailable("archive-format-option-or-limit"); }
            }
            Payload ArchiveOutput(ArchiveCall c, string? path, string? dest, Payload source, List<ArchiveMember> selected, Func<string, Payload> missing)
            {
                if (c.Mode == "list")
                {
                    if ((!c.Seven && !c.InfoZip && !c.Verbose || c.InfoZip && c.InfoNames) &&
                        selected.All(e => !e.Name.Any(char.IsControl) && !e.Name.Contains('\\')))
                        return ReadOutput(selected.Select(e => Text(e.Name, "archive member name")), c.InfoZip ? "zipinfo names" : "tar list");
                    // Native table/banner, dates, CRCs, attributes and diagnostics vary. Expose only
                    // witnessed metadata, never fabricate exact lines or inherit archive-body labels.
                    var known = new List<Payload>();
                    if (c.Seven && !c.Bare || c.InfoZip && !c.Quiet && !c.InfoNames) known.Add(Text(c.Input, "archive filename"));
                    foreach (var e in selected)
                    {
                        string name = c.Seven ? ArchiveKey(e.Name).Replace('/', '\\') : e.Name;
                        known.Add(Text(c.Seven && c.Slt ? "Path = " + name : name, "archive member name"));
                        known.Add(Text((c.Seven && c.Slt ? "Size = " : "") + e.Size.ToString(CultureInfo.InvariantCulture), "archive member size"));
                    }
                    return UnknownValue("archive-list-rendering", known.ToArray());
                }
                if (selected.Any(e => e.Special)) return missing("archive-link-or-special-member");
                var inherited = FileRecordMarks(source);
                Payload Load(ArchiveMember m)
                {
                    string origin = source.SourceRef + "!" + m.Name;
                    try
                    {
                        ArchiveCheck(Budget() && m.Size >= 0 && m.Size <= MaxContent && m.Content != null);
                        var bytes = m.Content!(); ArchiveCheck(bytes.LongLength == m.Size);
                        return Bytes(bytes, origin, bytes.Length == 0 ? Array.Empty<Mark>() : inherited);
                    }
                    catch (Exception ex) when (ex is IOException or InvalidDataException or ArgumentException or OverflowException or NotSupportedException)
                    {
                        // The header identified this member, but its bytes weren't established.
                        // Keep its independently configured file origin, not other members' matches.
                        return new Payload { SourceRef = origin, InspectionPartial = true, Issue = "archive-member-not-materialized", Tags = inherited };
                    }
                }
                if (c.Stdout)
                {
                    using var buffer = new MemoryStream();
                    var marks = new List<Mark>();
                    bool partial = false;
                    void FlushKnown()
                    {
                        if (buffer.Length > 0) marks.AddRange(Bytes(buffer.ToArray(), "archive stdout segment").Tags);
                        buffer.SetLength(0); buffer.Position = 0;
                    }
                    foreach (var m in selected.Where(e => !e.Directory))
                    {
                        var member = Load(m);
                        marks.AddRange(member.Tags);
                        if (member.Bytes == null) { FlushKnown(); partial = true; continue; }
                        if (member.Bytes.Length > MaxContent - buffer.Length) { FlushKnown(); partial = true; }
                        buffer.Write(member.Bytes, 0, member.Bytes.Length);
                    }
                    if (partial)
                    { FlushKnown(); return new Payload { Issue = "archive-stdout-partial", SourceRef = "archive member stdout", Tags = Merge(marks), InspectionPartial = true }; }
                    var body = Bytes(buffer.ToArray(), "archive member stdout", Merge(marks));
                    body.PipeText = Disk.Decode(body.Bytes!);
                    return body;
                }
                var dirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (dest == null || !ArchiveDestination(dest, true, out bool exists, dirs) || !c.Seven && !c.InfoZip && !exists) return missing("archive-destination");
                var files = new Dictionary<string, (Payload Data, bool Exists)>(StringComparer.OrdinalIgnoreCase);
                var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var m in selected)
                {
                    if (!Budget() || m.Name.StartsWith("/") || m.Name.StartsWith("\\")) return missing("archive-member-destination");
                    string name = ArchiveKey(m.Name);
                    if (m.Directory && (name == "." || name.Length == 0)) continue;
                    var parts = name.Split('/');
                    if (parts.Any(p => !ArchivePart(p))) return missing("archive-member-path");
                    if (parts.Length <= c.Strip || c.Mode == "flat" && m.Directory) continue;
                    var relative = c.Mode == "flat" ? parts.TakeLast(1) : parts.Skip(c.Strip);
                    var target = relative.Aggregate(dest, Path.Combine);
                    if (!InFolder(target, dest) || path != null && PathEq(path, target) || !targets.Add(target) ||
                        !ArchiveDestination(target, m.Directory, out bool prior, dirs) || dirs.Count + files.Count >= MaxEffects)
                        return missing("archive-target-conflict-or-limit");
                    if (m.Directory || prior && c.Overwrite == "skip") continue;
                    if (prior && (c.Seven || c.InfoZip) && c.Overwrite != "replace") return missing("archive-overwrite-prompt");
                    files.Add(target, (Load(m), prior));
                }
                if (dirs.Overlaps(files.Keys) || files.Count + plan.Work.Count > MaxEffects) return missing("archive-plan-limit");
                foreach (string dir in dirs)
                {
                    plannedFiles.Add(dir);
                    predictedWrites[dir] = new Payload { Complete = true, FileObject = new FileReference(dir, PathKind.DirectoryInfo),
                        PredictedAttributes = FileAttributes.Directory, SourceRef = dir, Issue = "projected-archive-directory" };
                }
                bool partialFiles = false;
                foreach (var kv in files)
                {
                    if (!Budget()) return missing("archive-plan-budget");
                    if (kv.Value.Data.Bytes == null)
                    { MarkPossibleWrite(kv.Key, kv.Value.Data); partialFiles = true; continue; }
                    PlanWrite(kv.Key, kv.Value.Data, kv.Value.Data.Bytes, false);
                    if (!predictedWrites.TryGetValue(kv.Key, out var p)) return missing("archive-plan-budget");
                    p.MayReadOriginal |= kv.Value.Exists || partialFiles; p.PredictedAttributes ??= FileAttributes.Archive;
                }
                if (partialFiles) ReportMissing("archive-member-not-materialized");
                if (!c.Seven && !c.InfoZip && !c.Verbose || c.InfoZip && c.Quiet) return Missing("no-expression-output");
                return UnknownValue("archive-extraction-metadata", Text(c.Input, "archive filename"),
                    c.Verbose ? ReadOutput(selected.Select(e => Text(e.Name, "member name")), "archive verbose names") : null);
            }
        }
    }
}

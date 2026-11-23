using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            // Decompression is charged across all opens, including reopens of the same member.
            int expandedReadBytes;
            static bool ZipHandle(HttpObject s) => s.Kind is HttpObjectKind.ZipArchive or HttpObjectKind.ZipEntry;
            Payload OpenZip(Payload path, int depth)
            {
                var source = OpenReader(path, "openread", Array.Empty<object>(), depth).HttpObject;
                return source == null ? Missing("zip-file-path") : HttpObjectValue(new HttpObject(HttpObjectKind.ZipArchive, owner: source));
            }
            static int U16(byte[] b, int i) => b[i] | (b[i + 1] << 8);
            static uint U32(byte[] b, int i) => (uint)(U16(b, i) | (U16(b, i + 2) << 16));

            // ZipArchive.Entries materializes the entire directory. Bound the real record
            // count before constructing it; a forged count in the end record isn't a bound.
            bool BoundedZipDirectory(byte[] b)
            {
                if (b.Length < 22 || !Budget()) return false;
                int floor = Math.Max(0, b.Length - 22 - ushort.MaxValue);
                for (int end = b.Length - 22; end >= floor; end--)
                {
                    if (U32(b, end) != 0x06054b50) continue;
                    if (U16(b, end + 20) != b.Length - end - 22) return false;
                    int count = U16(b, end + 10);
                    long start = U32(b, end + 16), length = U32(b, end + 12), pos = start;
                    if (U32(b, end + 4) != 0 || U16(b, end + 8) != count || count > MaxPackedEntries ||
                        count == ushort.MaxValue || start + length != end) return false;
                    for (int k = 0; k < count; k++)
                    {
                        if (pos + 46 > end || !Budget()) return false;
                        int p = (int)pos;
                        if (U32(b, p) != 0x02014b50 || U16(b, p + 34) != 0 || U16(b, p + 28) > Limits.MaxArchivePath * 4L)
                            return false;
                        pos += 46 + U16(b, p + 28) + U16(b, p + 30) + U16(b, p + 32);
                    }
                    return pos == end;
                }
                return false;
            }
            Payload WithReadZip(HttpObject archive, Func<ZipArchive, Payload, Payload> run)
            {
                archive = CurrentHttp(archive)!;
                if (!ReaderOpen(archive) || archive.Owner == null) return Missing("archive-closed");
                var source = StreamSource(CurrentHttp(archive.Owner)!);
                if (source.Bytes is not byte[] bytes || !BoundedZipDirectory(bytes)) return Missing("archive-directory-format-or-budget");
                try
                {
                    using var memory = new MemoryStream(bytes, false);
                    using var zip = new ZipArchive(memory, ZipArchiveMode.Read);
                    return run(zip, source);
                }
                catch (InvalidDataException) { return Missing("archive-invalid"); }
                catch (NotSupportedException) { return Missing("archive-feature"); }
                catch (IOException) { return Missing("archive-read-limit"); }
                catch (ArgumentException) { return Missing("archive-name-or-size"); }
            }
            Payload ZipSelection(HttpObject archive, string? name, bool find)
            {
                if (find && string.IsNullOrEmpty(name)) return Missing("archive-entry-selector");
                return WithReadZip(archive, (zip, _) =>
                {
                    var entries = new List<Payload>();
                    int ordinal = 0;
                    foreach (var item in zip.Entries)
                    {
                        if (!Budget() || ordinal >= MaxPackedEntries) return Missing("archive-entry-budget");
                        int index = ordinal++;
                        if (find && !string.Equals(name, item.FullName, StringComparison.Ordinal)) continue;
                        var record = ReadObject("ZipArchiveEntry", ("FullName", Text(item.FullName, "archive member path")),
                            ("Name", Text(item.Name, "archive member name")), ("Length", Number(item.Length)),
                            ("CompressedLength", Number(item.CompressedLength)));
                        record.HttpObject = ReaderSet(new HttpObject(HttpObjectKind.ZipEntry, owner: archive),
                            ("index", Number(index)), ("name", record.Map!["FullName"]));
                        if (find) return record;
                        entries.Add(record);
                    }
                    // Entries is a collection even when it has exactly one member.
                    return find ? Missing("no-expression-output") : CollectElements(entries);
                });
            }
            Payload OpenZipEntry(HttpObject entry)
            {
                if (entry.Owner == null || Slot(entry, "index") is not Payload ordinal || !CountValue(ordinal, out int index))
                    return Missing("archive-entry-index");
                return WithReadZip(entry.Owner, (zip, source) =>
                {
                    if (index >= zip.Entries.Count) return Missing("archive-entry-identity");
                    var item = zip.Entries[index];
                    if (item.FullName != Slot(entry, "name")?.Text) return Missing("archive-entry-identity");
                    int remaining = Math.Min(MaxContent, Math.Max(0, MaxExpanded - expandedReadBytes));
                    if (item.Length < 0 || item.Length > remaining) return Missing("archive-entry-expansion-limit");
                    int initial = remaining;
                    byte[] bytes;
                    try
                    {
                        using var input = item.Open();
                        bytes = ReadExpanded(input, ref remaining, Budget);
                    }
                    finally { expandedReadBytes += initial - remaining; }
                    if (bytes.LongLength != item.Length) return Missing("archive-entry-incomplete");
                    var result = Bytes(bytes, source.SourceRef + "!" + item.FullName, FileRecordMarks(source));
                    // Opening returns a stream, not its expanded bytes or the other members' labels.
                    return HttpObjectValue(ReaderSet(new HttpObject(HttpObjectKind.FileStream, body: result, owner: entry),
                        ("pos", Number(0)), ("epoch", new Payload())));
                });
            }

            static bool ArchivePart(string part)
            {
                if (part.Length == 0 || part.Length > 255 || part.EndsWith(".", StringComparison.Ordinal) ||
                    part.EndsWith(" ", StringComparison.Ordinal) || part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
                    part.IndexOfAny("~[]".ToCharArray()) >= 0) return false;
                var device = part.Split('.')[0].TrimEnd(' ').ToUpperInvariant();
                if (device is "CON" or "AUX" or "NUL" or "PRN" or "CONIN$" or "CONOUT$" or "CLOCK$") return false;
                return !(device.Length == 4 && (device.StartsWith("COM", StringComparison.Ordinal) || device.StartsWith("LPT", StringComparison.Ordinal)) &&
                    "0123456789¹²³".IndexOf(device[3]) >= 0);
            }
            // Check components from the drive root outwards. Never inspect children of a
            // reparse point. Missing directories are symbolic, not filesystem operations.
            bool ArchiveDestination(string path, bool folder, out bool exists, HashSet<string> newDirs)
            {
                exists = false;
                var root = Path.GetPathRoot(path);
                if (root == null || !Disk.Local(path)) return false;
                string parent = root;
                var components = path.Substring(root.Length).Split('\\', StringSplitOptions.RemoveEmptyEntries);
                bool absent = false;
                if (components.Length > Limits.MaxPathDepth) return false;
                for (int i = 0; i < components.Length; i++)
                {
                    if (!Budget() || !ArchivePart(components[i])) return false;
                    parent = Path.Combine(parent, components[i]);
                    bool dir = folder || i + 1 < components.Length;
                    FileAttributes? attrs = null;
                    if (PendingFiles.ContainsKey(parent) || UncertainFileTree(parent)) return false;
                    if (plannedFiles.Contains(parent))
                    {
                        if (!predictedWrites.TryGetValue(parent, out var planned) || planned.MayReadOriginal ||
                            planned.InspectionPartial || planned.PredictedAttributes == null) return false;
                        attrs = planned.PredictedAttributes;
                    }
                    else if (!absent)
                    {
                        try { attrs = System.IO.File.GetAttributes(parent); }
                        catch (FileNotFoundException) { }
                        catch (DirectoryNotFoundException) { }
                        catch (IOException) { return false; }
                        catch (UnauthorizedAccessException) { return false; }
                    }
                    if (attrs == null)
                    {
                        absent = true;
                        if (dir) newDirs.Add(parent);
                    }
                    else if (attrs.Value.HasFlag(FileAttributes.ReparsePoint) || attrs.Value.HasFlag(FileAttributes.Directory) != dir)
                        return false;
                    if (i == components.Length - 1) exists = attrs != null;
                }
                return components.Length != 0;
            }
            Payload ExpandZipCommand(object command, Payload? pipe)
            {
                using var args = new Args(this, command, Paths.Append("DestinationPath").ToArray(), new[] { "Force", "PassThru", "WhatIf", "Confirm" });
                var source = PathArg(args, 0, out int used);
                if (source == null) used = 0;
                var target = args.Get("DestinationPath");
                if (target == null && used < args.Plain.Count) target = args.Plain[used++];
                if (!args.Valid || args.Has("Path") && args.Has("LiteralPath") || used != args.Plain.Count ||
                    (source == null) == (pipe == null)) return Missing("expand-archive-binding");
                if (args.Has("WhatIf")) return Missing("no-expression-output");
                var item = pipe ?? Value(source);
                var path = Disk.Bind(item.FileObject?.Path ?? ExactString(item), cwd);
                var dest = Disk.Bind(target == null ? Path.GetFileNameWithoutExtension(path) : ExactString(Value(target)), cwd);
                var dirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                // If the destination is not a certified local path, don't probe it even
                // to determine the extent of side effects.
                if (dest == null || !ArchiveDestination(dest, true, out _, dirs))
                { InvalidateFileFacts(); ReportMissing("archive-destination"); return Missing("archive-destination"); }
                if (args.Has("Confirm") || path == null || policy == null || barrier)
                    return UncertainWrite("expand-archive-selection", dest);
                var archive = OpenZip(Text(path, "zip path"), 0).HttpObject;
                if (archive == null) return UncertainWrite("archive-source", dest);
                var result = WithReadZip(archive, (zip, input) =>
                {
                    var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    var files = new Dictionary<string, (Payload Data, bool Existed)>(StringComparer.OrdinalIgnoreCase);
                    var output = new List<Payload>();
                    foreach (var e in zip.Entries)
                    {
                        string name = e.FullName.Replace('\\', '/');
                        bool dir = name.EndsWith("/", StringComparison.Ordinal);
                        var parts = (dir ? name.Substring(0, name.Length - 1) : name).Split('/');
                        int mode = (e.ExternalAttributes >> 16) & 0xf000;
                        if (mode is not (0 or 0x4000 or 0x8000) || (mode == 0x4000 && !dir) ||
                            (e.ExternalAttributes & (int)FileAttributes.ReparsePoint) != 0 || (dir && e.Length != 0) ||
                            !Budget() || name.Length > Limits.MaxArchivePath || parts.Any(p => !ArchivePart(p)))
                            return Missing("archive-entry-name-or-kind");
                        string entryPath = parts.Aggregate(dest, Path.Combine);
                        if (PathEq(path, entryPath) || !names.Add(entryPath) || !InFolder(entryPath, dest) ||
                            !ArchiveDestination(entryPath, dir, out bool existed, dirs)) return Missing("archive-entry-destination");
                        if (dirs.Count + files.Count >= MaxEffects || dirs.Overlaps(files.Keys) || !dir && dirs.Contains(entryPath))
                            return Missing("archive-destination-conflict-or-limit");
                        if (dir) continue;
                        if (existed && !args.Has("Force")) return Missing("archive-file-exists");
                        int remaining = Math.Min(MaxContent, Math.Max(0, MaxExpanded - expandedReadBytes));
                        if (e.Length > remaining) return Missing("archive-entry-expansion-limit");
                        int initial = remaining;
                        byte[] bytes;
                        try { using var rd = e.Open(); bytes = ReadExpanded(rd, ref remaining, Budget); }
                        finally { expandedReadBytes += initial - remaining; }
                        if (bytes.LongLength != e.Length) return Missing("archive-entry-incomplete");
                        var data = Bytes(bytes, input.SourceRef + "!" + e.FullName, FileRecordMarks(input));
                        files.Add(entryPath, (data, existed));
                        output.Add(new Payload { Complete = true, FileObject = new FileReference(entryPath), SourceRef = entryPath });
                    }
                    if (dirs.Overlaps(files.Keys) || files.Count + plan.Work.Count > MaxEffects) return Missing("archive-plan-limit");
                    foreach (var dir in dirs)
                    {
                        plannedFiles.Add(dir);
                        predictedWrites[dir] = new Payload { Complete = true, PredictedAttributes = FileAttributes.Directory,
                            FileObject = new FileReference(dir, PathKind.DirectoryInfo), SourceRef = dir, Issue = "projected-archive-directory" };
                    }
                    foreach (var pair in files)
                    {
                        if (!Budget()) return Missing("archive-plan-limit");
                        PlanWrite(pair.Key, pair.Value.Data, pair.Value.Data.Bytes, append: false);
                        if (!predictedWrites.TryGetValue(pair.Key, out var prediction)) return Missing("archive-plan-limit");
                        prediction.PredictedAttributes ??= FileAttributes.Archive;
                        if (pair.Value.Existed) prediction.MayReadOriginal = true;
                    }
                    return args.Has("PassThru") ? ReadOutput(output, "Expand-Archive -PassThru") : Missing("no-expression-output");
                });
                return result.Issue.StartsWith("archive-", StringComparison.Ordinal) ? UncertainWrite(result.Issue, dest) : result;
            }
        }
    }
}

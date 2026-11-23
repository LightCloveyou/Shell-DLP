using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed class DelimitedSelection
        {
            readonly string delimiter;
            readonly int[] fallback;
            readonly long? head;
            readonly int? tail;
            int matched;
            bool openRecord;
            StringBuilder? materialized;
            internal long Record { get; private set; }
            internal string? Text => materialized?.ToString();
            internal bool Done => head.HasValue && Record >= head.Value;

            internal DelimitedSelection(string delimiter, long? head, int? tail)
            {
                this.delimiter = delimiter;
                this.head = head;
                this.tail = tail;
                if (head.HasValue) materialized = new StringBuilder();
                // Prefix lengths preserve a partial delimiter across reads, including
                // delimiters with repeated prefixes. Consumed delimiters never overlap.
                fallback = new int[delimiter.Length];
                for (int i = 1, n = 0; i < delimiter.Length; i++)
                {
                    while (n > 0 && delimiter[i] != delimiter[n]) n = fallback[n - 1];
                    if (delimiter[i] == delimiter[n]) n++;
                    fallback[i] = n;
                }
            }
            internal int Next(ReadOnlySpan<char> text, out bool end)
            {
                int n = 0;
                end = false;
                while (n < text.Length)
                {
                    char c = text[n++];
                    while (matched > 0 && c != delimiter[matched]) matched = fallback[matched - 1];
                    if (c != delimiter[matched]) continue;
                    matched++;
                    if (matched == delimiter.Length) { matched = 0; end = true; break; }
                }
                if (materialized != null)
                {
                    if ((long)materialized.Length + n <= MaxContent / sizeof(char)) materialized.Append(text.Slice(0, n));
                    else materialized = null;
                }
                openRecord = !end && n > 0;
                return n;
            }
            internal void EndRecord() => Record++;
            internal bool Includes(long record, bool reachedEnd) => !tail.HasValue ||
                reachedEnd && record >= Record + (openRecord ? 1 : 0) - tail.Value;
        }

        static (Mark[] Marks, string Issue, byte[]? Probe) MatchTextStream(Stream stream, long size,
            Policy snapshot, long byteLimit, string source, Func<bool> canContinue, Encoding? encoding = null,
            bool detectBom = true, DelimitedSelection? selection = null)
        {
            const int Chunk = 32 * 1024;
            int overlap = Math.Max(0, snapshot.LongestFileNeedle - 1);
            long remaining = Math.Min(size, byteLimit);
            byte[] bytes = ArrayPool<byte>.Shared.Rent(Chunk);
            char[] chars = ArrayPool<char>.Shared.Rent(checked(Chunk + overlap + 4));
            var hits = new Dictionary<string, long>(StringComparer.Ordinal);
            byte[]? probe = null;
            Decoder? decoder = null;
            int carry = 0;
            string? issue = null;
            try
            {
                while (remaining > 0 && selection?.Done != true)
                {
                    if (!canContinue()) { issue = "file-time-budget"; break; }
                    int requested = (int)Math.Min(remaining, Chunk);
                    int count = 0;
                    while (count < requested)
                    {
                        int n = stream.Read(bytes, count, requested - count);
                        if (n == 0) break;
                        count += n;
                    }
                    if (count != requested) { issue = "file-truncated"; break; }
                    remaining -= count;
                    int start = 0;
                    if (decoder == null)
                    {
                        probe = new byte[Math.Min(count, 8)];
                        Array.Copy(bytes, probe, probe.Length);
                        var codec = encoding ?? StrictUtf8;
                        if (detectBom) codec = Disk.DetectEncoding(bytes, count, codec, out start);
                        decoder = codec.GetDecoder();
                        // A decoding error beyond the last selected delimiter must not hide a valid prefix.
                        if (selection != null && decoder.Fallback is DecoderExceptionFallback)
                            decoder.Fallback = new DecoderReplacementFallback("\0");
                    }
                    int written = decoder.GetChars(bytes, start, count - start, chars, overlap, flush: remaining == 0 && size <= byteLimit);
                    int end = overlap + written;
                    int invalid = Array.IndexOf(chars, (char)0, overlap, written);
                    if (invalid >= 0) end = invalid;
                    for (int pos = overlap; pos < end;)
                    {
                        if (!canContinue()) { issue = "file-time-budget"; break; }
                        bool boundary = false;
                        int n = selection == null ? end - pos : selection.Next(chars.AsSpan(pos, end - pos), out boundary);
                        ReadOnlySpan<char> window = chars.AsSpan(pos - carry, carry + n);
                        long record = selection?.Record ?? 0;
                        foreach (var (id, needles) in snapshot.FileTextRules)
                        {
                            if (hits.TryGetValue(id, out long last) && last == record) continue;
                            foreach (var needle in needles)
                            {
                                if (!canContinue()) { issue = "file-time-budget"; break; }
                                if (window.IndexOf(needle.AsSpan(), StringComparison.Ordinal) < 0) continue;
                                hits[id] = record;
                                break;
                            }
                            if (issue != null) break;
                        }
                        pos += n;
                        carry = boundary ? 0 : Math.Min(overlap, window.Length);
                        if (boundary) selection!.EndRecord();
                        if (issue != null || selection?.Done == true) break;
                    }
                    if (issue != null || selection?.Done == true) break;
                    if (invalid >= 0) { issue = "file-encoding"; break; }
                    chars.AsSpan(end - carry, carry).CopyTo(chars.AsSpan(overlap - carry));
                }
            }
            catch (DecoderFallbackException) { issue = "file-encoding"; }
            finally
            {
                ArrayPool<byte>.Shared.Return(bytes, clearArray: true);
                ArrayPool<char>.Shared.Return(chars, clearArray: true);
            }
            bool eof = issue == null && remaining == 0 && size <= byteLimit;
            var marks = hits.Where(hit => selection?.Includes(hit.Value, eof) != false).Select(hit => new Mark(hit.Key, source, source));
            return (marks.ToArray(), issue ?? (!eof && selection?.Done != true ? "file-byte-budget" : ""), probe);
        }

        sealed partial class AdapterContext
        {
            // Head and tail inspection can seek and read the same range twice. Charge each
            // physical read against the shared allowance, including reads that fail later.
            sealed class CountedFileStream : Stream
            {
                readonly Stream file;
                readonly AdapterContext context;
                readonly long maximum;
                internal CountedFileStream(Stream file, AdapterContext context, long maximum)
                { this.file = file; this.context = context; this.maximum = maximum; }
                public override bool CanRead => true;
                public override bool CanSeek => file.CanSeek;
                public override bool CanWrite => false;
                public override long Length => file.Length;
                public override long Position { get => file.Position; set => file.Position = value; }
                public override long Seek(long offset, SeekOrigin origin) => file.Seek(offset, origin);
                public override int Read(byte[] buffer, int offset, int count)
                {
                    long remaining = Math.Max(0, maximum - context.fileBytesReserved);
                    int n = file.Read(buffer, offset, (int)Math.Min(count, remaining));
                    context.fileBytesReserved += n;
                    return n;
                }
                public override void Flush() { }
                public override void SetLength(long value) => throw new NotSupportedException();
                public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            }

            bool FileTimeAvailable => policy != null && clock.ElapsedMilliseconds <= policy.FileScanBudgetMs;
            bool FileCountAvailable => policy != null && (policy.MaxFilesPerScan == 0 || filesRead < policy.MaxFilesPerScan);
            bool BeginFile()
            {
                if (!FileTimeAvailable || !FileCountAvailable) return false;
                filesRead++;
                return true;
            }

            void ScanFileStream(Stream stream, long size, Disk.Sample sample, Policy snapshot, long byteLimit, Encoding? encoding, bool detectBom = true, DelimitedSelection? selection = null)
            {
                var scanned = MatchTextStream(stream, size, snapshot, byteLimit, sample.Path, () => FileTimeAvailable, encoding, detectBom, selection);
                sample.StreamMarks = scanned.Marks;
                sample.StreamIssue = scanned.Issue;
                sample.StreamChecked = scanned.Issue.Length == 0;
                sample.Probe = scanned.Probe;
                if (selection != null)
                {
                    sample.LineSelectionApplied = true;
                    if (sample.StreamChecked) sample.Text = selection.Text;
                }
            }

            static bool ReadExactly(Stream stream, byte[] buffer, int count)
            {
                int offset = 0;
                while (offset < count)
                {
                    int read = stream.Read(buffer, offset, count - offset);
                    if (read == 0) return false;
                    offset += read;
                }
                return true;
            }

            void ScanFileHead(Stream stream, long size, Disk.Sample sample, Policy snapshot, long byteLimit, Encoding? encoding, long lines)
            {
                const int Chunk = 32 * 1024;
                var buffer = ArrayPool<byte>.Shared.Rent(Chunk);
                try
                {
                    long ceiling = Math.Min(size, byteLimit);
                    if (!ReadExactly(stream, buffer, (int)Math.Min(ceiling, 4)))
                    { sample.StreamIssue = "file-truncated"; return; }
                    var decoder = Disk.DetectEncoding(buffer, (int)Math.Min(ceiling, 4), encoding ?? StrictUtf8, out int bom);
                    int width = decoder.CodePage switch { 1200 or 1201 => 2, 12000 or 12001 => 4, 65001 or 20127 => 1, _ => 0 };
                    if (width == 0) { sample.StreamIssue = "file-head-encoding"; return; }
                    bool big = decoder.CodePage is 1201 or 12001;
                    long aligned = ceiling - (ceiling - bom) % width;
                    long selectedEnd = aligned;
                    bool previousCr = false, bounded = false;
                    stream.Position = bom;
                    for (long block = bom; block < aligned && !bounded;)
                    {
                        if (!FileTimeAvailable) { sample.StreamIssue = "file-time-budget"; return; }
                        int n = (int)Math.Min(Chunk, aligned - block);
                        if (!ReadExactly(stream, buffer, n)) { sample.StreamIssue = "file-truncated"; return; }
                        for (int i = 0; i < n; i += width)
                        {
                            int low = big ? i + width - 1 : i;
                            int c = buffer[low];
                            for (int j = i; j < i + width; j++)
                                if (j != low && buffer[j] != 0) { c = -1; break; }
                            bool crlf = c == 10 && previousCr;
                            previousCr = c == 13;
                            if (crlf || c is not (10 or 13) || --lines != 0) continue;
                            selectedEnd = block + i;
                            bounded = true;
                            break;
                        }
                        block += n;
                    }
                    bool covered = bounded || aligned == size;
                    stream.Position = bom;
                    long length = selectedEnd - bom;
                    sample.LineSelectionApplied = true;
                    if (covered && length <= MaxContent && FileTimeAvailable)
                    {
                        if (length > buffer.Length)
                        {
                            var larger = ArrayPool<byte>.Shared.Rent((int)length);
                            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
                            buffer = larger;
                        }
                        if (!ReadExactly(stream, buffer, (int)length)) { sample.StreamIssue = "file-truncated"; return; }
                        var text = decoder.GetString(buffer, 0, (int)length);
                        if (text.IndexOf((char)0) >= 0) { sample.StreamIssue = "file-head-encoding"; return; }
                        // Retain a terminal separator when there is a last empty record.
                        // StringReader then reconstructs exactly the selected record count.
                        sample.Text = bounded ? text + (char)10 : text;
                        return;
                    }
                    // Do not flush a decoder at an artificial cutoff inside a code point.
                    ScanFileStream(stream, covered ? length : size - bom, sample, snapshot, length, decoder, detectBom: false);
                    if (!covered)
                    {
                        sample.StreamChecked = false;
                        if (sample.StreamIssue == "file-byte-budget") sample.StreamIssue = "file-head-byte-budget";
                    }
                    else if (sample.StreamIssue.Length == 0) sample.StreamIssue = "file-head-records-not-materialized";
                }
                catch (DecoderFallbackException) { sample.StreamIssue = "file-head-encoding"; }
                finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
            }

            void ScanFileTail(Stream stream, long size, Disk.Sample sample, Policy snapshot, long byteLimit, Encoding? encoding, int lines)
            {
                const int Chunk = 32 * 1024;
                var buffer = ArrayPool<byte>.Shared.Rent(Chunk);
                try
                {
                    int header = (int)Math.Min(size, 4);
                    if (!ReadExactly(stream, buffer, header)) { sample.StreamIssue = "file-truncated"; return; }
                    var decoderEncoding = Disk.DetectEncoding(buffer, header, encoding ?? StrictUtf8, out int bom);
                    int width = decoderEncoding.CodePage switch { 1200 or 1201 => 2, 12000 or 12001 => 4, 65001 or 20127 => 1, _ => 0 };
                    if (width == 0 || (size - bom) % width != 0)
                    { sample.StreamIssue = "file-tail-encoding"; return; }
                    bool big = decoderEncoding.CodePage is 1201 or 12001;
                    long floor = Math.Max(bom, size - byteLimit);
                    floor += (width - (floor - bom) % width) % width;
                    if (floor >= size) { sample.StreamIssue = "file-tail-byte-budget"; return; }

                    // Scan in reverse for record boundaries. Work stops immediately once
                    // the beginning of the last N records is known; no prefix is decoded.
                    long start = floor;
                    bool covered = floor == bom, previousLf = false;
                    for (long end = size; end > floor;)
                    {
                        if (!FileTimeAvailable) { sample.StreamIssue = "file-time-budget"; return; }
                        int n = (int)Math.Min(Chunk, end - floor);
                        long block = end - n;
                        stream.Position = block;
                        if (!ReadExactly(stream, buffer, n)) { sample.StreamIssue = "file-truncated"; return; }
                        for (int i = n - width; i >= 0; i -= width)
                        {
                            int low = big ? i + width - 1 : i;
                            int c = buffer[low];
                            for (int j = i; j < i + width; j++)
                                if (j != low && buffer[j] != 0) { c = -1; break; }
                            bool crlf = c == 13 && previousLf;
                            previousLf = c == 10;
                            if (crlf || c is not (10 or 13)) continue;
                            long after = block + i + width;
                            if (after == size) continue; // a terminal separator doesn't create an extra record
                            if (--lines != 0) continue;
                            start = after;
                            covered = true;
                            break;
                        }
                        if (start != floor) break;
                        end = block;
                    }

                    // If the byte budget started mid-record, discard only an incomplete
                    // leading code unit, and retain confirmed matches in the suffix.
                    if (!covered)
                    {
                        stream.Position = start;
                        if (decoderEncoding.CodePage == 65001)
                        {
                            while (start < size)
                            {
                                int ch = stream.ReadByte();
                                if (ch < 0 || (ch & 0xc0) != 0x80) break;
                                if (++start - floor > 3)
                                { sample.StreamIssue = "file-tail-encoding"; return; }
                            }
                        }
                        else if (width == 2 && size - start >= 2 && ReadExactly(stream, buffer, 2))
                        {
                            int unit = big ? (buffer[0] << 8) | buffer[1] : buffer[0] | (buffer[1] << 8);
                            if (unit is >= 0xdc00 and <= 0xdfff) start += 2;
                        }
                    }
                    stream.Position = start;
                    long length = size - start;
                    sample.LineSelectionApplied = true;
                    if (covered && length <= MaxContent && FileTimeAvailable)
                    {
                        var selected = ArrayPool<byte>.Shared.Rent(Math.Max(1, (int)length));
                        try
                        {
                            if (!ReadExactly(stream, selected, (int)length)) { sample.StreamIssue = "file-truncated"; return; }
                            var plain = decoderEncoding.GetString(selected, 0, (int)length);
                            if (plain.IndexOf((char)0) >= 0) { sample.StreamIssue = "file-tail-encoding"; return; }
                            sample.Text = plain;
                            return;
                        }
                        finally { ArrayPool<byte>.Shared.Return(selected, clearArray: true); }
                    }
                    ScanFileStream(stream, length, sample, snapshot, length, decoderEncoding, detectBom: false);
                    if (!covered && sample.StreamIssue.Length == 0)
                    {
                        sample.StreamChecked = false;
                        sample.StreamIssue = "file-tail-byte-budget";
                    }
                    else if (sample.StreamIssue.Length == 0) sample.StreamIssue = "file-tail-records-not-materialized";
                }
                catch (DecoderFallbackException) { sample.StreamIssue = "file-tail-encoding"; }
                finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
            }

            static IEnumerable<string> DelimitedRecords(string text, string delimiter)
            {
                for (int start = 0; start < text.Length;)
                {
                    int end = text.IndexOf(delimiter, start, StringComparison.Ordinal);
                    end = end < 0 ? text.Length : end + delimiter.Length;
                    yield return text.Substring(start, end - start);
                    start = end;
                }
            }

            static string SliceLines(string input, int count, bool tail)
            {
                using var reader = new StringReader(input);
                var records = new List<string>();
                string? line;
                while ((tail || records.Count < count) && (line = reader.ReadLine()) != null) records.Add(line);
                var first = tail ? Math.Max(0, records.Count - count) : 0;
                return string.Join(Environment.NewLine, records.GetRange(first, records.Count - first));
            }

            Payload AggregateFileEvidence(IEnumerable<Payload> sources, string origin)
            {
                var labels = new Dictionary<(string Id, string Origin), Mark>();
                string? issue = null;
                foreach (var source in sources)
                {
                    var part = DiscoverSendContent(source);
                    foreach (var label in part.Tags)
                        labels[(label.Id, label.Origin)] = label;
                    if (!part.Complete || part.InspectionPartial)
                        issue ??= part.Issue.Length != 0 ? part.Issue : "file-inspection-partial";
                }
                return new Payload
                {
                    Tags = Merge(labels.Values), Complete = issue == null,
                    Issue = issue ?? "", SourceRef = origin
                };
            }

            static FileAttributes? DiskAttributes(string path)
            {
                try { return System.IO.File.GetAttributes(path); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
            }

            IEnumerable<(FileReference? Entry, string? Issue)> EnumerateFiles(string root, bool recurse, bool includeHidden = true, bool includeDirectories = false,
                Func<string, bool>? matchesName = null, Func<FileAttributes, bool>? matchesAttributes = null, uint maxDepth = uint.MaxValue, bool followLinks = false,
                bool providerOrder = true, Func<string,FileAttributes,bool>? descend = null)
            {
                var pending = new Stack<(string Path, uint Depth)>();
                var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                // Include only immediate children of directories that traversal actually reaches.
                var planned = predictedWrites.Keys.ToLookup(p => Path.GetDirectoryName(p), StringComparer.OrdinalIgnoreCase);
                if (UncertainFileTree(root)) yield return (null, "file-tree-after-unknown-write");
                if (Disk.ResolveLocalPath(Path.GetDirectoryName(root) ?? root, () => FileTimeAvailable) == null)
                { yield return (null, "file-tree-unavailable"); yield break; }

                FileAttributes? Attributes(string path, string diskPath)
                {
                    if (predictedWrites.TryGetValue(path, out var write) && write.PredictedAttributes.HasValue)
                        return write.PredictedAttributes;
                    return DiskAttributes(diskPath);
                }
                bool Matches(string path, FileAttributes attrs) => (includeHidden || (attrs & FileAttributes.Hidden) == 0) &&
                    (matchesAttributes?.Invoke(attrs) ?? true) && (matchesName?.Invoke(Path.GetFileName(path)) ?? true);
                if (predictedWrites.TryGetValue(root, out var rootWrite) && rootWrite.Issue == "file-moved") yield break;
                var rootAttrs = Attributes(root, root);
                if (rootAttrs == null && rootWrite == null) { yield return (null, "file-tree-unavailable"); yield break; }
                if (rootAttrs == null || (rootAttrs & FileAttributes.Directory) == 0)
                {
                    if (rootAttrs == null) yield return (null, "file-tree-attributes");
                    if (rootAttrs == null ? matchesName?.Invoke(Path.GetFileName(root)) != false : Matches(root, rootAttrs.Value))
                        yield return (new FileReference(root), null);
                    yield break;
                }

                pending.Push((root, 0));
                bool Admit() => policy?.MaxFilesPerScan is not int cap || cap == 0 || ++filesEnumerated <= cap;
                while (pending.Count != 0)
                {
                    if (!FileTimeAvailable) { yield return (null, "file-time-budget"); yield break; }
                    var (parent, depth) = pending.Pop();
                    var directory = Disk.ResolveLocalPath(parent, () => FileTimeAvailable);
                    bool projectedDirectory = directory == null && predictedWrites.TryGetValue(parent, out var directoryState) &&
                        directoryState.Issue == "projected-archive-directory";
                    if (directory == null && !projectedDirectory) { yield return (null, "file-tree-unavailable"); continue; }
                    if (followLinks && !visited.Add(directory ?? parent)) continue;
                    var children = new Dictionary<string, FileAttributes?>(StringComparer.OrdinalIgnoreCase);
                    string? issue = null;
                    var key = Path.GetDirectoryName(Path.Combine(parent, "."));
                    foreach (var path in planned[key])
                    {
                        if (!predictedWrites.TryGetValue(path, out var prediction) || prediction.Issue == "file-moved") continue;
                        if (!FileTimeAvailable || !Admit()) { issue = FileTimeAvailable ? "file-count-budget" : "file-time-budget"; break; }
                        children[path] = prediction.PredictedAttributes ?? DiskAttributes(path);
                    }
                    if (issue == null && directory != null)
                    {
                        try
                        {
                            foreach (var diskPath in Directory.EnumerateFileSystemEntries(directory))
                            {
                                if (!FileTimeAvailable) { issue = "file-time-budget"; break; }
                                var path = Path.Combine(parent, Path.GetFileName(diskPath));
                                if (children.ContainsKey(path)) continue;
                                if (!Admit()) { issue = "file-count-budget"; break; }
                                if (predictedWrites.TryGetValue(path, out var prediction) && prediction.Issue == "file-moved") continue;
                                children[path] = Attributes(path, diskPath);
                            }
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { issue = "file-tree-unavailable"; }
                    }
                    // A truncated set of siblings cannot establish the first sorted item.
                    if (issue != null) yield return (null, issue);
                    IEnumerable<KeyValuePair<string, FileAttributes?>> ordered = providerOrder ? children.OrderByDescending(c =>
                        c.Value?.HasFlag(FileAttributes.Directory) == true).ThenBy(c => Path.GetFileName(c.Key), StringComparer.CurrentCultureIgnoreCase) : children;
                    foreach (var child in ordered)
                    {
                        if (!FileTimeAvailable) { yield return (null, "file-time-budget"); yield break; }
                        if (child.Value is not FileAttributes attrs)
                        {
                            yield return (null, "file-tree-attributes");
                            if (predictedWrites.ContainsKey(child.Key) && matchesName?.Invoke(Path.GetFileName(child.Key)) != false)
                                yield return (new FileReference(child.Key), null);
                            continue;
                        }
                        if (!Matches(child.Key, attrs)) continue;
                        bool directoryEntry = (attrs & FileAttributes.Directory) != 0;
                        if (!directoryEntry || includeDirectories)
                            yield return (new FileReference(child.Key, directoryEntry ? PathKind.DirectoryInfo : PathKind.FileInfo), null);
                    }
                    if (issue is "file-count-budget" or "file-time-budget") yield break;
                    if (!recurse || depth >= maxDepth) continue;
                    if (!providerOrder && children.Values.Any(a => a.HasValue &&
                        a.Value.HasFlag(FileAttributes.Directory | FileAttributes.ReparsePoint)))
                        yield return (null, "directory-link-descendants-not-enumerated");
                    foreach (var child in children.Reverse())
                        if (child.Value is FileAttributes attrs && (attrs & FileAttributes.Directory) != 0 &&
                            (includeHidden || (attrs & FileAttributes.Hidden) == 0) && (followLinks || (attrs & FileAttributes.ReparsePoint) == 0) &&
                            (descend == null || descend(child.Key,attrs)))
                            pending.Push((child.Key, depth + 1));
                }
            }
        }
    }
}

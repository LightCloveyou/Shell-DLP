using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        static partial class Disk
        {
            internal static bool SafeStreamName(string? name) => !string.IsNullOrEmpty(name) && name!.Length <= 255 && name != "." && name != ".." &&
                name.IndexOfAny(Path.GetInvalidFileNameChars()) < 0 && name.IndexOfAny("[]".ToCharArray()) < 0 &&
                !name.EndsWith(".", StringComparison.Ordinal) && !name.EndsWith(" ", StringComparison.Ordinal);
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            struct StreamInfo
            {
                internal long Size;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)] internal string Name;
            }
            sealed class FindStreamHandle : SafeHandleZeroOrMinusOneIsInvalid
            {
                private FindStreamHandle() : base(true) { }
                protected override bool ReleaseHandle() => FindClose(handle);
            }
            [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
            static extern FindStreamHandle FindFirstStreamW(string path, int level, out StreamInfo data, uint flags);
            [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
            static extern bool FindNextStreamW(FindStreamHandle handle, out StreamInfo data);
            [DllImport("kernel32.dll", ExactSpelling = true)]
            static extern bool FindClose(IntPtr handle);
            internal static bool StreamList(string path, List<(string Name, long Size)> output, Func<bool> within)
            {
                if (!ClearAncestors(path) || !within()) return false;
                // Pin the base object. Enumerate stream headers only, not the contents of any fork.
                using var file = CreateFileW(path, 0x80, FileShare.Read | FileShare.Write, IntPtr.Zero, FileMode.Open, 0x02000000, IntPtr.Zero);
                if (file.IsInvalid) return false;
                var handle = file.DangerousGetHandle();
                var final = new StringBuilder(32768);
                uint len = GetFinalPathNameByHandleW(handle, final, (uint)final.Capacity, 0);
                if (len == 0 || len >= final.Capacity || !PathEq(final.ToString(), @"\\?\" + path) ||
                    !GetFileInformationByHandle(handle, out var before) || !within()) return false;
                using var cursor = FindFirstStreamW(path, 0, out var row, 0);
                if (cursor.IsInvalid) return Marshal.GetLastWin32Error() == 38; // EOF on a directory with no streams
                do
                {
                    if (!within() || output.Count >= Limits.MaxCollection || row.Name == null || row.Size < 0 ||
                        !row.Name.StartsWith(":") || !row.Name.EndsWith(":$DATA", StringComparison.OrdinalIgnoreCase)) return false;
                    var name = row.Name.Substring(1);
                    if (!name.Equals(":$DATA", StringComparison.OrdinalIgnoreCase))
                    {
                        if (name.Length <= 6 || !SafeStreamName(name = name.Substring(0, name.Length - 6))) return false;
                    }
                    output.Add((name, row.Size));
                } while (FindNextStreamW(cursor, out row));
                return Marshal.GetLastWin32Error() == 38 && GetFileInformationByHandle(handle, out var after) && Stamp(after) == Stamp(before);
            }
        }
        sealed partial class AdapterContext
        {
            Payload StreamEntries(Payload input, Args args)
            {
                var names = Value(args.Get("Stream"));
                var patterns = new List<Func<string, bool>>();
                foreach (var p in names.Elements ?? new[] { names })
                {
                    if (ExactString(p) is not string name || CompileWildcard(name) is not { } match) return Missing("stream-name-filter");
                    patterns.Add(match);
                }
                IEnumerable<Payload> Rows()
                {
                    foreach (var entry in SelectFilePaths(input, args, includeDirectories: true))
                    {
                        var basePath = Disk.Bind(entry.Text, cwd);
                        if (basePath == null || barrier || entry.InspectionPartial || plannedFiles.Contains(basePath) ||
                            PendingFiles.ContainsKey(basePath) || UncertainFileTree(Path.GetDirectoryName(basePath)) || !BeginFile() ||
                            Disk.ResolveLocalPath(basePath, () => FileTimeAvailable) is not string local)
                        { yield return Missing("stream-metadata-path"); continue; }
                        var list = new List<(string Name, long Size)>();
                        if (!Disk.StreamList(local, list, () => FileTimeAvailable)) { yield return Missing("stream-metadata-selection"); continue; }
                        foreach (var row in list.Where(s => patterns.Any(m => m(s.Name))))
                            yield return ReadObject("AlternateStreamData", ("Stream", Text(row.Name, "stream name")), ("Length", Number(row.Size)),
                                ("FileName", Text(basePath.Replace(row.Name, "").Trim(':'), "stream owner filename")));
                    }
                }
                return ReadOutput(Rows(), "Get-Item -Stream");
            }
            Payload ReadDataStream(string raw, string stream, out Disk.Sample? sample, bool binary, Encoding? encoding,
                bool unknownEncoding, Func<string, string>? slice)
            {
                sample = null;
                var path = Disk.Bind(raw, cwd);
                if (policy == null || path == null || !Disk.SafeStreamName(stream)) return Missing("alternate-stream-path");
                var origin = path + ":" + stream;
                var evidence = FilePathEvidence(path, "alternate-stream-content");
                if (barrier || UncertainFileTree(Path.GetDirectoryName(path)) || plannedFiles.Contains(path) ||
                    PendingFiles.ContainsKey(path) || !BeginFile() || Disk.ResolveLocalPath(path, () => FileTimeAvailable) is not string local)
                    return Partial(evidence, "alternate-stream-identity");
                if (!PathEq(local, path)) evidence.Tags = Merge(evidence.Tags.Concat(FilePathEvidence(local, "alternate-stream-content").Tags));
                long limit = policy.MaxFileBytes == 0 ? MaxContent : Math.Min(policy.MaxFileBytes, MaxContent);
                if (policy.MaxTotalFileBytes != 0) limit = Math.Min(limit, Math.Max(0, policy.MaxTotalFileBytes - fileBytesReserved));
                sample = Disk.TrySample(local, true, limit, dataStream: stream,
                    reader: policy.MaxTotalFileBytes == 0 ? null : s => new CountedFileStream(s, this, policy.MaxTotalFileBytes));
                if (sample?.Bytes == null || !FileTimeAvailable) { sample = null; return Partial(evidence, "alternate-stream-not-materialized"); }
                if (binary) return Bytes(sample.Bytes, origin, evidence.Tags);
                if (unknownEncoding) { sample = null; return Partial(evidence, "file-encoding"); }
                try
                {
                    if (encoding != null)
                    {
                        using var reader = new StreamReader(new MemoryStream(sample.Bytes, false), encoding, true);
                        sample.Text = reader.ReadToEnd();
                    }
                    if (slice != null && sample.Text != null) sample.Text = slice(sample.Text);
                    if (sample.Text == null) return Partial(evidence, "alternate-stream-decoding");
                    var result = Text(sample.Text, origin, evidence.Tags);
                    RecordSource(result, "file-stream");
                    return result;
                }
                catch (ArgumentException) { sample = null; return Partial(evidence, "file-encoding"); }
            }
        }
    }
}

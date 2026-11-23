using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using Microsoft.Win32.SafeHandles;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        static bool PathEq(string a, string b) => a.Equals(b, StringComparison.OrdinalIgnoreCase);
        static bool LoopbackHost(string host)
        {
            if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                host.Equals("localhost.", StringComparison.OrdinalIgnoreCase)) return true;
            if (!IPAddress.TryParse(host.Trim('[', ']'), out var address)) return false;
            return IPAddress.IsLoopback(address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address);
        }
        static bool LoopbackUri(string? endpoint) => endpoint != null &&
            Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) && LoopbackHost(uri.Host);
        static bool LoopbackSsh(string? endpoint)
        {
            if (endpoint == null) return false;
            if (LoopbackUri(endpoint)) return true;
            var match = Regex.Match(endpoint, @"^(?:[A-Za-z0-9._-]+@)?(?<host>[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\]):[^:]+$");
            return match.Success && LoopbackHost(match.Groups["host"].Value);
        }
        static int MaxContent => Limits.MaxMaterializedBytes;
        static int MaxEffects => Limits.MaxEffects;
        static readonly ConcurrentDictionary<string, int> PendingFiles = new ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        static readonly object WitnessGate = new object();
        static readonly Dictionary<string, (string Stamp, Mark[] Marks)> Witnesses =
            new Dictionary<string, (string, Mark[])>(StringComparer.OrdinalIgnoreCase);
        static string EnvKey(string scope, string name) => "env:" + scope + ":" + name;
        static bool HasWitness(string key) { lock (WitnessGate) return Witnesses.ContainsKey(key); }
        static Mark[] Witness(string key, string stamp)
        {
            lock (WitnessGate)
                return Witnesses.TryGetValue(key, out var entry) && entry.Stamp == stamp ? entry.Marks : Array.Empty<Mark>();
        }
        static void Remember(string key, string stamp, Mark[] marks)
        {
            lock (WitnessGate)
            {
                while (Witnesses.Count > Limits.MaxWitnesses || Witnesses.Count == Limits.MaxWitnesses && !Witnesses.ContainsKey(key))
                    Witnesses.Remove(Witnesses.Keys.First());
                Witnesses[key] = (stamp, marks);
            }
        }

        // A projected path string can be passed to a path parameter, but unlike
        // a FileInfo it is not a file upload when used as a multipart field.
        enum PathKind { FileInfo, DirectoryInfo, PathString }

        sealed class FileReference : IEquatable<FileReference>
        {
            internal readonly string Path;
            internal readonly PathKind Kind;
            internal FileReference(string path, PathKind kind = PathKind.FileInfo) { Path = path; Kind = kind; }
            public bool Equals(FileReference? other) => other != null && other.Kind == Kind && PathEq(other.Path, Path);
            public override bool Equals(object? obj) => obj is FileReference other && Equals(other);
            public override int GetHashCode() => (int)Kind ^ StringComparer.OrdinalIgnoreCase.GetHashCode(Path);
        }

        sealed class FileSetReference
        {
            // Membership is fixed when Get-ChildItem runs. A file's bytes are sampled at the send.
            internal readonly Payload[] Records;
            internal FileSetReference(Payload[] records) { Records = records; }
        }

        sealed class Payload
        {
            internal string? Text;
            internal string? ReadType;
            internal string? MemberDisplayType;
            internal DateTime? TimeValue;
            internal bool? ScalarTruth;
            internal string? NumericType;
            internal FileAttributes? PredictedAttributes;
            internal Payload? RecordRemainder;
            internal Payload? FileTaskResult;
            internal DeferredStreamRead? DeferredRead;
            internal (string Root, string Filter, PathKind? Kind, bool Recursive)? DeferredDirectory;
            internal string? LocalRecord;
            internal long? RecordCount;
            internal FileReference? FileObject;
            internal FileReference[]? PathAlternatives;
            internal int? FirstUncertainIndex;
            internal FileSetReference? Files;
            internal (int Start, Mark Tag)[]? TagPositions;
            internal string? PipeText;
            internal byte[]? Bytes;
            // Exact sequence of emitted Byte records. Not itself a PS byte[] object.
            internal byte[]? ByteRecordData;
            internal ModelValue? Model;
            internal HttpObject? HttpObject;
            internal Dictionary<string, Payload>? Map;
            internal Payload[]? Elements;
            internal bool InspectionPartial, UnmaterializedFileRecords;
            internal bool Complete, IsString, MayReadOriginal;
            internal string Issue = "";
            internal string SourceRef = "";
            internal Mark[] Tags = Array.Empty<Mark>();
            internal Payload Copy() => (Payload)MemberwiseClone();
            internal Payload Via(string step)
            {
                var next = Copy();
                next.SourceRef = step;
                next.Tags = Tags.Select(t => t.Via(step)).ToArray();
                next.TagPositions = TagPositions?.Select(p => (p.Start, p.Tag.Via(step))).ToArray();
                return next;
            }
        }
        static Payload Missing(string reason) => new Payload { Issue = reason };

        static partial class Disk
        {
            [StructLayout(LayoutKind.Sequential)]
            struct Id
            {
                internal uint attributes, creationLow, creationHigh, accessLow, accessHigh, writeLow, writeHigh,
                    volume, sizeHigh, sizeLow, links, fileHigh, fileLow;
            }
            [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
            static extern uint GetDriveTypeW(string root);
            [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
            static extern uint GetFinalPathNameByHandleW(IntPtr handle, StringBuilder path, uint size, uint flags);
            [DllImport("kernel32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool GetFileInformationByHandle(IntPtr handle, out Id id);

            internal sealed class Sample
            {
                internal string Path = "", Stamp = "";
                internal long Size;
                internal byte[]? Bytes;
                internal string? Text;
                internal byte[]? Probe;
                internal Mark[] StreamMarks = Array.Empty<Mark>();
                internal bool StreamChecked, LineSelectionApplied, ContentSkippedForPath;
                internal string StreamIssue = "";
            }
            internal static bool Local(string path) => path.Length >= 3 && path[1] == ':' && path[2] == '\\' &&
                GetDriveTypeW(path.Substring(0, 3)) == 3;
            internal static string? Bind(string? raw, string? directory)
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(raw) || raw!.IndexOfAny(new[] { '*', '?', '[', ']', '\0' }) >= 0 ||
                        raw.IndexOf(':', raw.Length > 1 && raw[1] == ':' ? 2 : 0) >= 0) return null;
                    bool driveAbsolute = raw.Length > 2 && raw[1] == ':' && (raw[2] == '\\' || raw[2] == '/');
                    if (Path.IsPathRooted(raw) && !driveAbsolute) return null;
                    if (!driveAbsolute && string.IsNullOrEmpty(directory)) return null;
                    var path = Path.GetFullPath(driveAbsolute ? raw : Path.Combine(directory!, raw));
                    return Local(path) ? path : null;
                }
                catch { return null; }
            }
            internal static string? ExternalRulePath(string? raw)
            {
                if (string.IsNullOrWhiteSpace(raw) || raw.IndexOfAny(new[] { '*', '?', '[', ']', '\0' }) >= 0) return null;
                try
                {
                    raw = raw.Replace('/', (char)92);
                    if (raw.StartsWith(@"\\", StringComparison.Ordinal))
                    {
                        var tail = raw.Substring(2).Split((char)92);
                        if (raw.IndexOf(':') >= 0 || tail.Length < 3 || tail[0].Length == 0 || tail[0] == "." ||
                            tail[1].Length == 0 || tail[1] == "." || tail[1] == ".." || tail[2].Length == 0) return null;
                        var full = Path.GetFullPath(raw);
                        return full.Length > Path.GetPathRoot(full)!.Length ? full : null;
                    }
                    if (raw.Length < 4 || raw[1] != ':' || raw[2] != (char)92 || raw.IndexOf(':', 2) >= 0 ||
                        GetDriveTypeW(raw.Substring(0, 3)) is not (2 or 4)) return null;
                    return Path.GetFullPath(raw);
                }
                catch { return null; }
            }
            static string Stamp(Id id) => string.Join(":", new uint[] { id.volume, id.fileHigh, id.fileLow,
                id.creationHigh, id.creationLow, id.writeHigh, id.writeLow, id.sizeHigh, id.sizeLow }.Select(x => x.ToString("x8", CultureInfo.InvariantCulture)));
            internal static string? TargetStamp(string path)
            {
                var file = TrySample(path, false);
                if (file != null) return file.Stamp;
                try { return !ClearAncestors(Path.GetDirectoryName(path)!) || File.Exists(path) || Directory.Exists(path) ? null : ""; }
                catch { return null; }
            }
            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            static extern SafeFileHandle CreateFileW(string path, uint access, FileShare sharing, IntPtr security,
                FileMode disposition, uint flags, IntPtr template);
            [DllImport("kernel32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool DeviceIoControl(SafeFileHandle handle, uint code, IntPtr input, int inputSize,
                [Out] byte[] output, int capacity, out int returned, IntPtr overlapped);

            static string? LinkTarget(string path)
            {
                const uint openReparsePoint = 0x00200000, backupSemantics = 0x02000000, getReparsePoint = 0x900a8;
                using var link = CreateFileW(path, 0, FileShare.ReadWrite | FileShare.Delete, IntPtr.Zero,
                    FileMode.Open, openReparsePoint | backupSemantics, IntPtr.Zero);
                if (link.IsInvalid) return null;
                var buffer = new byte[16 * 1024]; // MAXIMUM_REPARSE_DATA_BUFFER_SIZE from winnt.h
                if (!DeviceIoControl(link, getReparsePoint, IntPtr.Zero, 0, buffer, buffer.Length, out int count, IntPtr.Zero) ||
                    count < 16) return null;
                int header = BitConverter.ToUInt32(buffer, 0) switch
                {
                    0xa000000c => 20, // IO_REPARSE_TAG_SYMLINK
                    0xa0000003 => 16, // IO_REPARSE_TAG_MOUNT_POINT
                    _ => 0
                };
                int offset = header + BitConverter.ToUInt16(buffer, 8);
                int length = BitConverter.ToUInt16(buffer, 10);
                if (header == 0 || (offset & 1) != 0 || (length & 1) != 0 || length == 0 || offset > count - length) return null;
                string target = Encoding.Unicode.GetString(buffer, offset, length);
                if (header == 20 && BitConverter.ToUInt32(buffer, 16) == 1) return target;
                if (!target.StartsWith(@"\??\", StringComparison.Ordinal)) return null;
                string local = target.Substring(4);
                return Local(local) ? local : null;
            }

            // Inspect one link at a time. Never enumerate or open a remote target.
            internal static string? ResolveLocalPath(string path, Func<bool> withinBudget)
            {
                try
                {
                    var links = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    while (Local(path) && withinBudget())
                    {
                        string current = Path.GetPathRoot(path)!;
                        string[] parts = path.Substring(current.Length).Split(Path.DirectorySeparatorChar);
                        if (parts.Length > Limits.MaxPathDepth) return null;
                        bool redirected = false;
                        for (int i = 0; i < parts.Length; i++)
                        {
                            if (parts[i].Length == 0) continue;
                            current = Path.Combine(current, parts[i]);
                            var attr = File.GetAttributes(current);
                            if ((attr & FileAttributes.ReparsePoint) == 0) continue;
                            if (!links.Add(current) || !withinBudget()) return null;
                            var resolved = Bind(LinkTarget(current), Path.GetDirectoryName(current));
                            if (resolved == null) return null;
                            path = parts.Skip(i + 1).Aggregate(resolved, Path.Combine);
                            redirected = true;
                            break;
                        }
                        if (!redirected) return path;
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { }
                return null;
            }
            internal static bool ClearAncestors(string path)
            {
                if (!Local(path)) return false;
                var tree = new Stack<string>();
                for (string? p = path; p != null && tree.Count < Limits.MaxPathDepth; p = Path.GetDirectoryName(p)) tree.Push(p);
                try
                {
                    return tree.Count > 0 && Path.GetDirectoryName(tree.Peek()) == null && tree.All(p => (File.GetAttributes(p) & FileAttributes.ReparsePoint) == 0);
                }
                catch { return false; }
            }
            internal static Sample? TrySample(string path, bool content, long maxBytes = long.MaxValue,
                Action<Stream, long, Sample>? scanStream = null, Action<long>? reserve = null, bool streamOnly = false,
                Func<Stream, Stream>? reader = null, string? dataStream = null, Func<Sample, bool>? needsContent = null)
            {
                try
                {
                    if (!ClearAncestors(path) || dataStream != null && !SafeStreamName(dataStream)) return null;
                    string selected = dataStream == null ? path : path + ":" + dataStream;
                    using var opened = new FileStream(selected, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                        4096, FileOptions.SequentialScan);
                    var handle = opened.SafeFileHandle.DangerousGetHandle();
                    var name = new StringBuilder(512);
                    var length = GetFinalPathNameByHandleW(handle, name, (uint)name.Capacity, 0);
                    if (length >= name.Capacity && length < 32768)
                    {
                        name.EnsureCapacity((int)length + 1);
                        length = GetFinalPathNameByHandleW(handle, name, (uint)name.Capacity, 0);
                    }
                    if (length == 0 || length >= name.Capacity || !GetFileInformationByHandle(handle, out var id)) return null;
                    var final = name.ToString();
                    if (final.StartsWith(@"\\?\", StringComparison.Ordinal)) final = final.Substring(4);
                    if (!Local(final)) return null;
                    if (dataStream != null && !PathEq(final, selected) && !PathEq(final, selected + ":$DATA")) return null;
                    var stamp = Stamp(id);
                    var capture = new Sample { Path = final, Stamp = stamp, Size = ((long)id.sizeHigh << 32) | id.sizeLow };
                    // Let a caller decide from the verified handle identity before any
                    // content I/O. If bytes are needed, read from this same handle.
                    if (!content || (needsContent != null && !needsContent(capture))) return capture;
                    var stream = reader?.Invoke(opened) ?? opened;
                    long size = stream.Length;
                    reserve?.Invoke(size);
                    if (streamOnly || size > MaxContent || size > maxBytes)
                    {
                        if (scanStream == null) return capture;
                        scanStream(stream, size, capture);
                        if (!GetFileInformationByHandle(handle, out var checkedId) || Stamp(checkedId) != stamp) return null;
                        return capture;
                    }
                    var bytes = new byte[(int)size];
                    int cursor = 0;
                    while (cursor < bytes.Length)
                    {
                        int read = stream.Read(bytes, cursor, bytes.Length - cursor);
                        if (read == 0) return null;
                        cursor += read;
                    }
                    if (stream.ReadByte() != -1 || !GetFileInformationByHandle(handle, out var after) || Stamp(after) != stamp)
                        return null;
                    capture.Bytes = bytes;
                    capture.Text = Decode(bytes);
                    return capture;
                }
                catch { return null; }
            }
            internal static Encoding DetectEncoding(byte[] data, int count, Encoding fallback, out int start)
            {
                Encoding encoding = fallback;
                start = 0;
                if (count >= 4 && data[0] == 255 && data[1] == 254 && data[2] == 0 && data[3] == 0)
                { encoding = new UTF32Encoding(false, true, true); start = 4; }
                else if (count >= 4 && data[0] == 0 && data[1] == 0 && data[2] == 254 && data[3] == 255)
                { encoding = new UTF32Encoding(true, true, true); start = 4; }
                else if (count >= 2 && data[0] == 255 && data[1] == 254)
                { encoding = new UnicodeEncoding(false, true, true); start = 2; }
                else if (count >= 2 && data[0] == 254 && data[1] == 255)
                { encoding = new UnicodeEncoding(true, true, true); start = 2; }
                else if (count >= 3 && data[0] == 239 && data[1] == 187 && data[2] == 191) start = 3;
                return encoding;
            }
            internal static string? Decode(byte[] data)
            {
                try
                {
                    var encoding = DetectEncoding(data, data.Length, StrictUtf8, out int start);
                    var decoded = encoding.GetString(data, start, data.Length - start);
                    return decoded.IndexOf('\0') >= 0 ? null : decoded;
                }
                catch { return null; }
            }
        }

        static class DurableEnv
        {
            [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
            static extern int RegOpenKeyExW(IntPtr key, string subkey, uint options, uint access, out IntPtr handle);
            [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
            static extern int RegQueryInfoKeyW(IntPtr handle, IntPtr cls, IntPtr classLen, IntPtr reserved, IntPtr subkeys,
                IntPtr maxName, IntPtr maxClass, IntPtr values, IntPtr maxValueName, IntPtr maxValueLen, IntPtr security, out long lastWrite);
            [DllImport("advapi32.dll")]
            static extern int RegCloseKey(IntPtr handle);
            internal static string? Owner(string scope)
            {
                if (scope == "machine") return Environment.MachineName;
                try
                {
                    var type = Type.GetType("System.Security.Principal.WindowsIdentity, System.Security.Principal.Windows");
                    var identity = type?.GetMethod("GetCurrent", Type.EmptyTypes)?.Invoke(null, null);
                    using var dispose = identity as IDisposable;
                    return Prop(Prop(identity, "User"), "Value") as string;
                }
                catch { return null; }
            }
            internal static bool Read(string scope, string name, out string? value, out string stamp)
            {
                value = null; stamp = "";
                var host = scope == "user" ? new IntPtr(unchecked((int)0x80000001)) : new IntPtr(unchecked((int)0x80000002));
                string key = scope == "user" ? "Environment" : @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
                if (RegOpenKeyExW(host, key, 0, 1 | 0x100, out var handle) != 0) return false;
                try
                {
                    var n = IntPtr.Zero;
                    if (RegQueryInfoKeyW(handle, n, n, n, n, n, n, n, n, n, n, out var before) != 0) return false;
                    value = Environment.GetEnvironmentVariable(name, scope == "user" ? EnvironmentVariableTarget.User : EnvironmentVariableTarget.Machine);
                    if (RegQueryInfoKeyW(handle, n, n, n, n, n, n, n, n, n, n, out var after) != 0 || before != after) return false;
                    stamp = before.ToString("x", CultureInfo.InvariantCulture);
                    return true;
                }
                catch { return false; }
                finally { RegCloseKey(handle); }
            }
        }

        sealed class FileContentProof
        {
            internal readonly long PrefixLength;
            readonly byte[] digest;
            readonly string suffix;
            FileContentProof(long prefixLength, byte[] digest, string suffix)
            { PrefixLength = prefixLength; this.digest = digest; this.suffix = suffix; }

            internal FileContentProof? Append(string text) =>
                (long)suffix.Length + text.Length <= MaxContent / sizeof(char) ?
                    new FileContentProof(PrefixLength, digest, suffix + text) : null;

            static byte[]? Hash(Stream input, long count, Func<bool> withinTime)
            {
                using var hash = System.Security.Cryptography.IncrementalHash.CreateHash(System.Security.Cryptography.HashAlgorithmName.SHA256);
                var buffer = new byte[32768];
                while (count > 0)
                {
                    if (!withinTime()) return null;
                    int n = input.Read(buffer, 0, (int)Math.Min(count, buffer.Length));
                    if (n == 0) return null;
                    hash.AppendData(buffer, 0, n);
                    count -= n;
                }
                return hash.GetHashAndReset();
            }

            internal static FileContentProof? Capture(string path, string stamp, long limit, Func<bool> withinTime, Action<long> reserve)
            {
                FileContentProof? proof = null;
                var seen = Disk.TrySample(path, true, limit, (input, size, _) =>
                {
                    if (size <= limit && Hash(input, size, withinTime) is byte[] hash) proof = new FileContentProof(size, hash, "");
                }, reserve, streamOnly: true);
                return seen?.Stamp == stamp ? proof : null;
            }

            internal Disk.Sample? Confirm(string path)
            {
                var policy = Store.Current(out var issue);
                if (policy == null || issue != "") return null;
                var clock = Stopwatch.StartNew();
                bool valid = false;
                var after = Disk.TrySample(path, true, scanStream: (input, size, _) =>
                {
                    if (policy.MaxFileBytes != 0 && size > policy.MaxFileBytes ||
                        policy.MaxTotalFileBytes != 0 && size > policy.MaxTotalFileBytes ||
                        size < PrefixLength || size - PrefixLength > MaxContent) return;
                    if (Hash(input, PrefixLength, () => clock.ElapsedMilliseconds <= policy.FileScanBudgetMs) is not byte[] actual ||
                        !digest.SequenceEqual(actual)) return;
                    var tail = new byte[(int)(size - PrefixLength)];
                    for (int offset = 0; offset < tail.Length;)
                    {
                        int n = input.Read(tail, offset, tail.Length - offset);
                        if (n == 0) return;
                        offset += n;
                    }
                    valid = suffix.Length == 0 ? tail.Length == 0 :
                        new Encoding[] { StrictUtf8, Encoding.Unicode, Encoding.BigEndianUnicode, Encoding.UTF32,
                            new UTF32Encoding(true, false) }.Any(encoding => encoding.GetByteCount(suffix) == tail.Length &&
                                tail.SequenceEqual(encoding.GetBytes(suffix)));
                }, streamOnly: true);
                return valid ? after : null;
            }
        }

        sealed class PolicyWork
        {
            internal GitProof.JournalUpdate? Journal;
            internal string Target = "", Before = "", Name = "", Scope = "", From = "";
            internal byte[]? Bytes;
            internal Dictionary<string, byte[]>? Archive;
            internal string? Value;
            internal bool ExactText;
            internal FileContentProof? Proof;
            internal Mark[] Tags = Array.Empty<Mark>();
            internal bool File => Journal == null && Scope.Length == 0;
            string Key => File ? Target : EnvKey(Scope, Name);
            int registered;
            internal void Register()
            {
                if (Journal != null) return;
                PendingFiles.AddOrUpdate(Key, 1, (_, n) => n + 1);
                Interlocked.Exchange(ref registered, 1);
            }
            void Release()
            {
                if (Interlocked.Exchange(ref registered, 0) == 0) return;
                while (PendingFiles.TryGetValue(Key, out var n))
                {
                    if (n <= 1)
                    {
                        if (((ICollection<KeyValuePair<string, int>>)PendingFiles).Remove(new KeyValuePair<string, int>(Key, n))) break;
                    }
                    else if (PendingFiles.TryUpdate(Key, n - 1, n)) break;
                }
            }
            internal void Commit(bool success, State state)
            {
                if (Journal != null)
                {
                    if (success)
                    {
                        var status = Journal.Finish();
                        lock (state.Gate)
                        {
                            if (state.PolicyReports.Count >= MaxEffects) state.PolicyReports.RemoveAt(0);
                            state.PolicyReports.Add(Data("kind", "git-observation", "target", Target, "status", status));
                        }
                    }
                    return;
                }
                if (!success) { Release(); return; }
                Disk.Sample? after = null;
                string? owner = null, envStamp = null;
                try
                {
                    if (File)
                    {
                        after = Proof != null ? Proof.Confirm(Target) : Disk.TrySample(Target, true);
                        if (after == null || Before == after.Stamp || Proof == null && (after.Bytes == null ||
                            !(Archive != null ? AdapterContext.ConfirmsArchive(after.Bytes, Archive) :
                              Bytes != null ? Bytes.SequenceEqual(after.Bytes) :
                              Value != null && (after.Text == Value || (!ExactText && after.Text == Value + Environment.NewLine)))))
                        { Release(); return; }
                        Remember(after.Path, after.Stamp, Tags);
                    }
                    else
                    {
                        owner = DurableEnv.Owner(Scope);
                        if (owner == null || !DurableEnv.Read(Scope, Name, out var actual, out var stamp) ||
                            stamp == Before || actual != Value)
                        { Release(); return; }
                        envStamp = stamp;
                        Remember(Key, stamp, Tags);
                    }
                }
                catch { Release(); return; }
                // Commit the metadata before pipeline completion returns. Logging remains asynchronous.
                // Readers in other processes recheck the durable metadata generation.
                {
                    string outcome = "not-confirmed";
                    try
                    {
                        var eventId = Guid.NewGuid().ToString("N");
                        if (File && after != null && Disk.TargetStamp(Target) == after.Stamp)
                            outcome = Store.SaveCopies(after.Path, From, after.Stamp, Tags, eventId) ? "confirmed" : "state-write-failed";
                        else if (!File && owner != null && envStamp != null &&
                                 DurableEnv.Read(Scope, Name, out _, out var current) && current == envStamp)
                            outcome = Store.SavePersistent(Scope, owner, Name, envStamp, Tags, eventId) ? "confirmed" : "state-write-failed";
                    }
                    catch { outcome = "state-write-failed"; }
                    finally
                    {
                        lock (state.Gate)
                        {
                            if (state.PolicyReports.Count >= MaxEffects) state.PolicyReports.RemoveAt(0);
                            state.PolicyReports.Add(Data("kind", File ? "copy" : "persistent-variable", "target", File ? Target : Name,
                                "scope", Scope, "status", outcome));
                        }
                        Release();
                    }
                }
            }
        }

        sealed class RulePlan
        {
            internal readonly Dictionary<string, Payload> Assignments = new Dictionary<string, Payload>(StringComparer.OrdinalIgnoreCase);
            internal readonly List<PolicyWork> Work = new List<PolicyWork>();
            internal readonly List<object> Evidence = new List<object>();
            internal readonly List<object> Sources = new List<object>();
            readonly HashSet<(string Kind, string Source, int Stage, string Rule, string Origin)> sourceKeys =
                new HashSet<(string, string, int, string, string)>();
            internal int OmittedSources, OmittedEvidence;
            internal void Source(string kind, string source, int stage, IEnumerable<Mark> tags)
            {
                foreach (var mark in tags)
                {
                    var key = (kind, source, stage, mark.Id, mark.Origin);
                    if (sourceKeys.Count < Limits.MaxWitnesses && !sourceKeys.Add(key)) continue;
                    if (Sources.Count >= MaxEffects) { OmittedSources++; continue; }
                    Sources.Add(Data("kind", kind, "stage", stage, "source", source, "mark", mark.Report()));
                }
            }
            internal int Decision;
            internal object? PrimaryEvidence;
            internal string Reason = "uncovered:command-shape";
            internal string Configuration = "";
            internal void Result(int result, string reason, object evidence)
            {
                int Order(int n) => n == 1 ? 4 : n == 3 ? 3 : n == 5 ? 2 : n == 2 ? 1 : 0;
                bool primary = Order(result) > Order(Decision);
                if (Evidence.Count < MaxEffects) Evidence.Add(evidence);
                else
                {
                    OmittedEvidence++;
                    if (primary) Evidence[Evidence.Count - 1] = evidence;
                }
                if (primary) { Decision = result; Reason = reason; PrimaryEvidence = evidence; }
            }
        }
    }
}

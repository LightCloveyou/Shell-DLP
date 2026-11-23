using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            static bool SevenSignature(byte[] b) => b.Length >= 6 && b[0] == 55 && b[1] == 122 && b[2] == 188 && b[3] == 175 && b[4] == 39 && b[5] == 28;
            static readonly uint[] ArchiveCrcTable = Enumerable.Range(0, 256).Select(n => {
                uint v = (uint)n; for (int i = 0; i < 8; i++) v = (v >> 1) ^ ((v & 1) == 0 ? 0u : 0xedb88320u); return v;
            }).ToArray();
            static uint ArchiveCrc(byte[] data, int start, int size)
            {
                uint crc = uint.MaxValue; for (int i = start, end = checked(start + size); i < end; i++)
                    crc = (crc >> 8) ^ ArchiveCrcTable[(crc ^ data[i]) & 255]; return ~crc;
            }
            sealed class SevenInput
            {
                internal readonly byte[] B; internal int P; internal readonly int End;
                internal SevenInput(byte[] b, int p, int end) { ArchiveCheck(p >= 0 && end >= p && end <= b.Length); B = b; P = p; End = end; }
                internal byte Get() { ArchiveCheck(P < End); return B[P++]; }
                internal byte Peek() { ArchiveCheck(P < End); return B[P]; }
                internal void Need(int n) => ArchiveCheck(Get() == n);
                internal SevenInput Part(int n)
                { ArchiveCheck(n >= 0 && n <= End - P); int start = P; P += n; return new SevenInput(B, start, P); }
                internal uint Four() { int at = Part(4).P; return U32(B, at); }
                internal int Eight(int cap) { uint lo = Four(); ArchiveCheck(Four() == 0 && lo <= cap); return (int)lo; }
                internal int N(int cap)
                {
                    int first = Get(), mask = 128; ulong value = 0;
                    for (int i = 0; i < 8; i++, mask >>= 1)
                    {
                        if ((first & mask) == 0) { value |= (ulong)(first & (mask - 1)) << (8 * i); break; }
                        value |= (ulong)Get() << (8 * i);
                    }
                    ArchiveCheck(cap >= 0 && value <= (ulong)cap); return (int)value;
                }
                internal bool[] Bits(int n, bool defined = false)
                {
                    int all = defined ? Get() : 0;
                    ArchiveCheck(all is 0 or 1);
                    bool[] values = new bool[n]; int bits = 0;
                    for (int i = 0; i < n; i++)
                    {
                        if (all == 0 && i % 8 == 0) bits = Get();
                        values[i] = all != 0 || (bits & (128 >> (i % 8))) != 0;
                    }
                    return values;
                }
                internal uint?[] Crcs(int n)
                {
                    var defined = Bits(n, true);
                    return defined.Select(present => present ? (uint?)Four() : null).ToArray();
                }
            }
            sealed class SevenFolder
            {
                internal int Start, Packed, Size, Codec, Count = 1, Outputs = 1, Final;
                internal byte[] Props = Array.Empty<byte>();
                internal uint? PackedCheck, DecodedCheck;
                internal int[] Sizes = Array.Empty<int>(); internal uint?[] Checks = Array.Empty<uint?>();
                internal byte[]? Decoded;
                internal bool Attempted;
            }
            List<SevenFolder> SevenStreams(SevenInput r, int packLimit)
            {
                if (r.Peek() == 0) { r.Get(); return new List<SevenFolder>(); }
                r.Need(6);
                int start = checked(32 + r.N(packLimit - 32)), count = r.N(MaxPackedEntries);
                ArchiveCheck(count > 0);
                r.Need(9);
                var packed = new List<(int Start, int Length)>();
                for (int i = 0; i < count; i++)
                {
                    int length = r.N(packLimit - start);
                    packed.Add((start, length)); start += length;
                }
                var packedCrc = new uint?[count];
                if (r.Peek() == 10)
                { r.Get(); packedCrc = r.Crcs(count); }
                r.Need(0); r.Need(7); r.Need(11); int folderCount = r.N(count); r.Need(0);
                var folders = new List<SevenFolder>(); int nextPack = 0;
                for (int index = 0; index < folderCount; index++)
                {
                    int coders = r.N(16), ins = 0, outs = 0;
                    ArchiveCheck(coders > 0 && nextPack < count && Budget());
                    var f = new SevenFolder { Start = packed[nextPack].Start };
                    for (int c = 0; c < coders; c++)
                    {
                        int flags = r.Get(), idSize = flags & 15, codec = 0;
                        ArchiveCheck((flags & 192) == 0 && idSize >= 1 && idSize <= 8);
                        for (int j = 0; j < idSize; j++) codec = (codec << 8) | r.Get();
                        int ni = (flags & 16) != 0 ? r.N(16) : 1;
                        int no = (flags & 16) != 0 ? r.N(16) : 1;
                        ArchiveCheck(ni > 0 && no > 0);
                        ins += ni; outs += no;
                        f.Codec = coders == 1 && ni == 1 && no == 1 && idSize <= 4 ? codec : -1;
                        if ((flags & 32) != 0)
                        { var part = r.Part(r.N(128)); f.Props = part.B.AsSpan(part.P, part.End - part.P).ToArray(); }
                    }
                    // The header can still establish names and sizes for a coder chain whose
                    // contents we do not decode. Derive the final (unbound) output explicitly.
                    var boundIn = new HashSet<int>(); var boundOut = new HashSet<int>();
                    for (int j = 1; j < outs; j++) ArchiveCheck(boundIn.Add(r.N(ins - 1)) && boundOut.Add(r.N(outs - 1)));
                    int numPacked = ins - boundIn.Count;
                    ArchiveCheck(numPacked > 0 && numPacked <= count - nextPack);
                    if (numPacked > 1) for (int j = 0; j < numPacked; j++) ArchiveCheck(boundIn.Add(r.N(ins - 1)));
                    f.Final = Enumerable.Range(0, outs).Single(k => !boundOut.Contains(k)); f.Outputs = outs;
                    if (numPacked == 1) f.PackedCheck = packedCrc[nextPack];
                    for (int j = 0; j < numPacked; j++) f.Packed = checked(f.Packed + packed[nextPack++].Length);
                    folders.Add(f);
                }
                ArchiveCheck(nextPack == count);
                r.Need(12);
                foreach (var f in folders) for (int j = 0; j < f.Outputs; j++)
                { int n = r.N(int.MaxValue); if (j == f.Final) f.Size = n; }
                if (r.Peek() == 10) { r.Get(); var crc = r.Crcs(folderCount); for (int i = 0; i < folderCount; i++) folders[i].DecodedCheck = crc[i]; }
                r.Need(0);
                bool sub = r.Peek() == 8;
                if (sub) r.Get();
                if (sub && r.Peek() == 13)
                {
                    r.Get(); int left = MaxPackedEntries;
                    foreach (var f in folders) { f.Count = r.N(left); left -= f.Count; }
                }
                bool sizes = sub && r.Peek() == 9;
                if (sizes) r.Get();
                foreach (var f in folders)
                {
                    ArchiveCheck(f.Count < 2 || sizes);
                    f.Sizes = new int[f.Count]; f.Checks = new uint?[f.Count]; int remaining = f.Size;
                    for (int j = 0; j + 1 < f.Count; j++) { f.Sizes[j] = r.N(remaining); remaining -= f.Sizes[j]; }
                    if (f.Count > 0) f.Sizes[f.Count - 1] = remaining; else ArchiveCheck(remaining == 0);
                    if (f.Count == 1) f.Checks[0] = f.DecodedCheck;
                }
                if (sub && r.Peek() == 10)
                {
                    r.Get();
                    var unknown = folders.Where(f => f.Count != 1 || f.DecodedCheck == null).ToArray();
                    var crc = r.Crcs(unknown.Sum(f => f.Count)); int at = 0;
                    foreach (var f in unknown) for (int i = 0; i < f.Count; i++) f.Checks[i] = crc[at++];
                }
                if (sub) r.Need(0);
                r.Need(0);
                return folders;
            }
            byte[] SevenDecode(byte[] archive, SevenFolder f)
            {
                if (f.Decoded != null) return f.Decoded;
                ArchiveCheck(!f.Attempted && f.Codec is (0 or 0x030101 or 0x21) && Budget() && f.Size <= ExpansionRoom());
                f.Attempted = true;
                expandedReadBytes += f.Size;
                if (f.PackedCheck is uint inCrc) ArchiveCheck(ArchiveCrc(archive, f.Start, f.Packed) == inCrc);
                byte[] bytes;
                if (f.Codec == 0)
                {
                    ArchiveCheck(f.Props.Length == 0 && f.Packed == f.Size);
                    bytes = new byte[f.Size]; Buffer.BlockCopy(archive, f.Start, bytes, 0, bytes.Length);
                }
                else
                {
                    ArchiveCheck(f.Codec is 0x030101 or 0x21);
                    bytes = new ArchiveLz(f.Size, Budget).Decode(f.Codec == 0x21, archive, f.Start, f.Packed, f.Props);
                }
                ArchiveCheck(Budget() && (f.DecodedCheck == null || f.DecodedCheck == ArchiveCrc(bytes, 0, bytes.Length)));
                return f.Decoded = bytes;
            }
            List<ArchiveMember> SevenMembers(byte[] archive)
            {
                ArchiveCheck(archive.Length >= 32 && SevenSignature(archive) && archive[6] == 0 &&
                    U32(archive, 8) == ArchiveCrc(archive, 12, 20));
                var start = new SevenInput(archive, 12, 32);
                int packLimit = checked(32 + start.Eight(archive.Length - 32));
                int headerSize = start.Eight(archive.Length - packLimit);
                ArchiveCheck(packLimit + headerSize == archive.Length && start.Four() == ArchiveCrc(archive, packLimit, headerSize));
                var members = new List<ArchiveMember>();
                if (headerSize == 0) { ArchiveCheck(packLimit == 32); return members; }
                var r = new SevenInput(archive, packLimit, archive.Length);
                if (r.Peek() == 23)
                {
                    r.Get(); var wrapped = SevenStreams(r, packLimit);
                    ArchiveCheck(r.P == r.End && wrapped.Count == 1 && wrapped[0].Count == 1 && wrapped[0].Size <= MaxContent);
                    var decoded = SevenDecode(archive, wrapped[0]); packLimit = wrapped[0].Start;
                    r = new SevenInput(decoded, 0, decoded.Length);
                }
                r.Need(1);
                List<SevenFolder> folders = new List<SevenFolder>();
                if (r.Peek() == 4) { r.Get(); folders = SevenStreams(r, packLimit); }
                if (r.Peek() == 0) { r.Get(); ArchiveCheck(r.P == r.End && folders.Count == 0); return members; }
                r.Need(5); int count = r.N(MaxPackedEntries);
                var names = new string[count]; bool[] empty = new bool[count], files = Array.Empty<bool>(), anti = Array.Empty<bool>();
                uint[] attrs = new uint[count]; var seen = new HashSet<int>();
                while (r.Peek() != 0)
                {
                    int id = r.Get(); var prop = r.Part(r.N(r.End - r.P));
                    ArchiveCheck((id == 25 || seen.Add(id)) && Budget());
                    switch (id)
                    {
                        case 14: empty = prop.Bits(count); break;
                        case 15: files = prop.Bits(empty.Count(b => b)); break;
                        case 16: anti = prop.Bits(empty.Count(b => b)); break;
                        case 17:
                            prop.Need(0);
                            var utf16 = new UnicodeEncoding(false, false, true);
                            for (int i = 0; i < count; i++)
                            {
                                int from = prop.P;
                                while (prop.P + 2 <= prop.End && U16(prop.B, prop.P) != 0)
                                { prop.P += 2; ArchiveCheck(prop.P - from <= 2L * Limits.MaxArchivePath); }
                                ArchiveCheck(prop.P > from && prop.P + 2 <= prop.End);
                                names[i] = utf16.GetString(prop.B, from, prop.P - from); prop.P += 2;
                            }
                            break;
                        case 18: case 19: case 20: case 21:
                            var present = prop.Bits(count, true); prop.Need(0);
                            for (int i = 0; i < count; i++) if (present[i]) { if (id == 21) attrs[i] = prop.Four(); else prop.Part(8); }
                            break;
                        case 25: ArchiveCheck(ZeroBytes(prop.B, prop.P, prop.End)); prop.P = prop.End; break;
                        default: throw new InvalidDataException("7z property");
                    }
                    ArchiveCheck(prop.P == prop.End);
                }
                r.Need(0); r.Need(0);
                ArchiveCheck(r.P == r.End && (count == 0 || seen.Contains(17)) && empty.Count(b => !b) == folders.Sum(f => f.Count));
                var streams = new List<(SevenFolder F, int Offset, int Size, uint? Check)>();
                foreach (var f in folders)
                {
                    int pos = 0;
                    for (int j = 0; j < f.Count; j++) { streams.Add((f, pos, f.Sizes[j], f.Checks[j])); pos += f.Sizes[j]; }
                }
                int zero = 0, stream = 0;
                for (int i = 0; i < count; i++)
                {
                    int mode = (int)(attrs[i] >> 16) & 0xf000;
                    var m = new ArchiveMember { Name = names[i], Special = (attrs[i] & 0x400) != 0 || mode is not (0 or 0x4000 or 0x8000) };
                    if (empty[i])
                    {
                        m.Directory = files.Length == 0 || !files[zero]; m.Special |= anti.Length != 0 && anti[zero]; zero++;
                        m.Content = () => Array.Empty<byte>();
                    }
                    else
                    {
                        var unit = streams[stream++]; m.Size = unit.Size;
                        m.Content = () => {
                            ArchiveCheck(Budget() && unit.Size <= MaxContent);
                            var bytes = SevenDecode(archive, unit.F);
                            if (unit.Check is uint crc) ArchiveCheck(crc == ArchiveCrc(bytes, unit.Offset, unit.Size));
                            if (unit.Offset == 0 && unit.Size == bytes.Length) return bytes;
                            var result = new byte[unit.Size]; Buffer.BlockCopy(bytes, unit.Offset, result, 0, unit.Size); return result;
                        };
                    }
                    if (!m.Directory && ((attrs[i] & 16) != 0 || mode == 0x4000)) m.Special = true;
                    members.Add(m);
                }
                return members;
            }
        }
    }
}

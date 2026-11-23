using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            static long TarNumber(byte[] b, int pos, int len)
            {
                long v = 0;
                if ((b[pos] & 128) != 0)
                {
                    ArchiveCheck((b[pos] & 64) == 0);
                    v = b[pos++] & 63;
                    while (--len != 0) v = checked(v * 256 + b[pos++]);
                    return v;
                }
                int end = pos + len;
                while (pos < end && b[pos] == 32) pos++;
                while (pos < end && b[pos] is >= 48 and <= 55) v = checked(v * 8 + b[pos++] - 48);
                while (pos < end) ArchiveCheck(b[pos++] is 0 or 32);
                return v;
            }
            static string TarString(byte[] b, int p, int length)
            {
                int end = Array.IndexOf(b, (byte)0, p, length);
                return StrictUtf8.GetString(b, p, end < 0 ? length : end - p);
            }
            static bool ZeroBytes(byte[] data, int start, int end)
            {
                for (int i = start; i < end; i++) if (data[i] != 0) return false;
                return true;
            }
            void ReadPax(byte[] data, int offset, int size, Dictionary<string, string> fields, bool global)
            {
                int stop = offset + size;
                while (offset < stop)
                {
                    ArchiveCheck(fields.Count < Limits.MaxCollection && Budget());
                    int begin = offset, len = 0;
                    while (offset < stop && data[offset] is >= 48 and <= 57) len = checked(len * 10 + data[offset++] - 48);
                    ArchiveCheck(offset > begin && offset < stop && data[offset++] == 32 && len <= stop - begin && len > offset - begin + 2);
                    int end = begin + len, eq = Array.IndexOf(data, (byte)'=', offset, end - offset - 1);
                    ArchiveCheck(eq > offset && data[end - 1] == 10);
                    var key = StrictUtf8.GetString(data, offset, eq - offset);
                    var value = StrictUtf8.GetString(data, eq + 1, end - eq - 2);
                    // Unknown extensions can describe sparse data, alternate streams or a different path.
                    ArchiveCheck(key is "mtime" or "atime" or "ctime" or "gid" or "uid" or "gname" or "uname" or
                        "comment" or "LIBARCHIVE.creationtime" || !global && key is ("path" or "size" or "linkpath"));
                    fields[key] = value;
                    offset = end;
                }
            }
            List<ArchiveMember> TarMembers(byte[] data)
            {
                var list = new List<ArchiveMember>();
                var local = new Dictionary<string, string>(StringComparer.Ordinal);
                var global = new Dictionary<string, string>(StringComparer.Ordinal);
                int blocks = 0;
                for (int p = 0; p <= data.Length - 512;)
                {
                    ArchiveCheck(Budget() && ++blocks <= 4L * MaxPackedEntries + 2);
                    if (ZeroBytes(data, p, p + 512))
                    {
                        ArchiveCheck(local.Count == 0 && data.Length - p >= 1024 && ZeroBytes(data, p + 512, data.Length));
                        return list;
                    }
                    long headerCk = TarNumber(data, p + 148, 8);
                    int sum = 0, signedSum = 0;
                    for (int j = 0; j < 512; j++)
                    {
                        byte v = j >= 148 && j < 156 ? (byte)32 : data[p + j];
                        sum += v; signedSum += unchecked((sbyte)v);
                    }
                    ArchiveCheck(headerCk == sum || headerCk == signedSum);
                    string magic = TarString(data, p + 257, 6);
                    ArchiveCheck(magic is "ustar" or "ustar " or "");
                    string name = TarString(data, p, 100);
                    if (magic == "ustar")
                    {
                        var prefix = TarString(data, p + 345, 155);
                        if (prefix.Length > 0) name = prefix + "/" + name;
                    }
                    char kind = (char)data[p + 156];
                    bool extra = kind is 'x' or 'g' or 'L' or 'K';
                    long n = TarNumber(data, p + 124, 12);
                    if (!extra && local.TryGetValue("size", out var size))
                        ArchiveCheck(long.TryParse(size, NumberStyles.None, CultureInfo.InvariantCulture, out n) && n >= 0);
                    int start = p + 512;
                    ArchiveCheck(n <= data.Length - start);
                    int length = (int)n;
                    p = checked(start + (int)((n + 511) / 512 * 512));
                    ArchiveCheck(p <= data.Length);
                    if (extra)
                    {
                        if (kind is 'x' or 'g') ReadPax(data, start, length, kind == 'g' ? global : local, kind == 'g');
                        else
                        {
                            ArchiveCheck(length > 0 && length <= 4L * Limits.MaxArchivePath + 1);
                            local[kind == 'L' ? "path" : "linkpath"] = TarString(data, start, length);
                        }
                        continue;
                    }
                    if (local.TryGetValue("path", out var longer)) name = longer;
                    ArchiveCheck(list.Count < MaxPackedEntries && name.Length > 0 && name.Length <= Limits.MaxArchivePath && !name.Contains('\0'));
                    bool dir = kind == '5' || kind == '\0' && name.EndsWith("/", StringComparison.Ordinal);
                    bool regular = !dir && kind is ('0' or '\0' or '7');
                    ArchiveCheck(kind is ('0' or '\0' or '7' or '1' or '2' or '3' or '4' or '5' or '6'));
                    ArchiveCheck(regular || length == 0);
                    list.Add(new ArchiveMember { Name = name, Size = length, Directory = dir, Special = !dir && !regular,
                        Content = regular ? () => {
                            ArchiveCheck(length <= MaxContent && length <= ExpansionRoom() && Budget());
                            expandedReadBytes += length;
                            byte[] bytes = new byte[length]; Buffer.BlockCopy(data, start, bytes, 0, length); return bytes;
                        } : null });
                    local.Clear();
                }
                throw new InvalidDataException("tar end records");
            }
        }
    }
}

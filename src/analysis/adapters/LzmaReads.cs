using System;
using System.IO;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            // Read-only LZMA/LZMA2 for the bounded single-coder units in SevenZipReads.
            // The output array doubles as the dictionary. Never allocate the advertised dictionary size.
            sealed class ArchiveLz
            {
                readonly byte[] output;
                readonly Func<bool> within;
                uint dictionary, r0, r1, r2, r3;
                int at, history, state, lc, lp, pb;
                ushort[] literal = Array.Empty<ushort>();
                readonly ushort[] useMatch = new ushort[12 * 16], useRep = new ushort[12], repA = new ushort[12],
                    repB = new ushort[12], repC = new ushort[12], shortRep = new ushort[12 * 16],
                    slot = new ushort[4 * 64], special = new ushort[114], align = new ushort[16];
                readonly Lengths matchLen = new Lengths(), repLen = new Lengths();
                internal ArchiveLz(int size, Func<bool> within) { output = new byte[size]; this.within = within; }
                static void Init(ushort[] probabilities) => Array.Fill(probabilities, (ushort)1024);
                sealed class Range
                {
                    readonly SevenInput src;
                    uint range = uint.MaxValue, code;
                    internal Range(SevenInput src)
                    {
                        this.src = src; src.Need(0);
                        for (int i = 0; i < 4; i++) code = (code << 8) | src.Get();
                        ArchiveCheck(code < range);
                    }
                    internal bool Finished => code == 0 && src.P == src.End;
                    void Normalize()
                    { if (range < 1u << 24) { range <<= 8; code = (code << 8) | src.Get(); } }
                    internal int Bit(ushort[] model, int i)
                    {
                        ArchiveCheck((uint)i < model.Length);
                        int probability = model[i];
                        uint split = (range >> 11) * (uint)probability;
                        int bit;
                        if (code < split) { range = split; model[i] = (ushort)(probability + ((2048 - probability) >> 5)); bit = 0; }
                        else { range -= split; code -= split; model[i] = (ushort)(probability - (probability >> 5)); bit = 1; }
                        Normalize(); return bit;
                    }
                    internal uint Direct(int count)
                    {
                        uint result = 0;
                        while (count-- > 0)
                        {
                            range >>= 1; result <<= 1;
                            if (code >= range) { code -= range; result |= 1; }
                            ArchiveCheck(code < range); Normalize();
                        }
                        return result;
                    }
                    internal int Tree(ushort[] model, int start, int bits, bool reverse = false)
                    {
                        int node = 1, reversed = 0;
                        for (int i = 0; i < bits; i++) { int b = Bit(model, start + node); node = node * 2 + b; reversed |= b << i; }
                        return reverse ? reversed : node - (1 << bits);
                    }
                }
                sealed class Lengths
                {
                    readonly ushort[] choice = new ushort[2], low = new ushort[16 * 8], mid = new ushort[16 * 8], high = new ushort[256];
                    internal void Reset() { Init(choice); Init(low); Init(mid); Init(high); }
                    internal int Read(Range r, int pos) => r.Bit(choice, 0) == 0 ? r.Tree(low, pos * 8, 3) :
                        r.Bit(choice, 1) == 0 ? 8 + r.Tree(mid, pos * 8, 3) : 16 + r.Tree(high, 0, 8);
                }
                void Properties(int n)
                {
                    ArchiveCheck(n < 9 * 5 * 5);
                    lc = n % 9; n /= 9; lp = n % 5; pb = n / 5;
                    ArchiveCheck(lc + lp <= 4); // bounded common contexts; same requirement as LZMA2
                    int table = 0x300 << (lp + lc);
                    if (literal.Length != table) literal = new ushort[table];
                }
                void Reset()
                {
                    state = 0; r0 = r1 = r2 = r3 = 0;
                    Init(literal); Init(useMatch); Init(useRep); Init(repA); Init(repB); Init(repC);
                    Init(shortRep); Init(slot); Init(special); Init(align); matchLen.Reset(); repLen.Reset();
                }
                byte Back(uint distance)
                {
                    ArchiveCheck(distance < (uint)(at - history) && distance < dictionary);
                    return output[at - (int)distance - 1];
                }
                bool Symbol(Range r, int limit)
                {
                    int pos = (at - history) & ((1 << pb) - 1), sp = (state << 4) + pos;
                    if (r.Bit(useMatch, sp) == 0)
                    {
                        ArchiveCheck(at < limit);
                        int prev = at == history ? 0 : output[at - 1];
                        int ctx = ((((at - history) & ((1 << lp) - 1)) << lc) + (prev >> (8 - lc))) * 0x300;
                        int symbol = 1;
                        if (state >= 7)
                        {
                            int predicted = Back(r0);
                            while (symbol < 256)
                            {
                                int b = (predicted >> 7) & 1; predicted <<= 1;
                                int actual = r.Bit(literal, ctx + ((1 + b) << 8) + symbol);
                                symbol = symbol * 2 + actual; if (actual != b) break;
                            }
                        }
                        while (symbol < 256) symbol = symbol * 2 + r.Bit(literal, ctx + symbol);
                        output[at++] = (byte)symbol;
                        state = state < 4 ? 0 : state < 10 ? state - 3 : state - 6; return true;
                    }
                    int n;
                    if (r.Bit(useRep, state) == 0)
                    {
                        r3 = r2; r2 = r1; r1 = r0;
                        n = matchLen.Read(r, pos) + 2; state = state < 7 ? 7 : 10;
                        int s = r.Tree(slot, Math.Min(n - 2, 3) * 64, 6);
                        if (s < 4) r0 = (uint)s;
                        else
                        {
                            int bits = (s >> 1) - 1;
                            r0 = (uint)(2 | (s & 1)) << bits;
                            if (s < 14) r0 += (uint)r.Tree(special, (int)r0 - s - 1, bits, true);
                            else { r0 += r.Direct(bits - 4) << 4; r0 += (uint)r.Tree(align, 0, 4, true); }
                            if (r0 == uint.MaxValue) return false;
                        }
                    }
                    else
                    {
                        if (r.Bit(repA, state) == 0)
                        {
                            if (r.Bit(shortRep, sp) == 0)
                            {
                                ArchiveCheck(at < limit);
                                byte b = Back(r0); output[at++] = b; state = state < 7 ? 9 : 11; return true;
                            }
                        }
                        else
                        {
                            uint d;
                            if (r.Bit(repB, state) == 0) d = r1;
                            else { if (r.Bit(repC, state) == 0) d = r2; else { d = r3; r3 = r2; } r2 = r1; }
                            r1 = r0; r0 = d;
                        }
                        n = repLen.Read(r, pos) + 2; state = state < 7 ? 8 : 11;
                    }
                    ArchiveCheck(n <= limit - at && r0 < (uint)(at - history) && r0 < dictionary);
                    for (int i = 0; i < n; i++) { byte b = output[at - (int)r0 - 1]; output[at++] = b; }
                    return true;
                }
                void Block(SevenInput packed, int count, bool allowEndMarker)
                {
                    ArchiveCheck(count <= output.Length - at);
                    int end = at + count, ops = 0; var r = new Range(packed);
                    while (at < end)
                    {
                        if ((ops++ & 127) == 0) ArchiveCheck(within());
                        ArchiveCheck(Symbol(r, end));
                    }
                    if (allowEndMarker && !r.Finished) ArchiveCheck(!Symbol(r, end));
                    ArchiveCheck(r.Finished && within());
                }
                internal byte[] Decode(bool lzma2, byte[] archive, int start, int packedSize, byte[] props)
                {
                    var src = new SevenInput(archive, start, checked(start + packedSize));
                    if (!lzma2)
                    {
                        ArchiveCheck(props.Length == 5);
                        dictionary = Math.Max(4096u, U32(props, 1)); Properties(props[0]); Reset();
                        Block(src, output.Length, true); return output;
                    }
                    ArchiveCheck(props.Length == 1 && props[0] <= 40);
                    dictionary = props[0] == 40 ? uint.MaxValue : (uint)(2 | (props[0] & 1)) << ((props[0] >> 1) + 11);
                    bool needDictionary = true, needProperties = true;
                    for (;;)
                    {
                        ArchiveCheck(within()); int control = src.Get();
                        if (control == 0) { ArchiveCheck(at == output.Length && src.P == src.End); return output; }
                        if (control >= 224 || control == 1) { history = at; needDictionary = false; needProperties = true; }
                        ArchiveCheck(!needDictionary);
                        int n = ((src.Get() << 8) | src.Get()) + 1;
                        if (control < 128)
                        {
                            ArchiveCheck(control is 1 or 2 && n <= output.Length - at);
                            var raw = src.Part(n); Buffer.BlockCopy(raw.B, raw.P, output, at, n); at += n; continue;
                        }
                        n += (control & 31) << 16;
                        int compressed = ((src.Get() << 8) | src.Get()) + 1;
                        if (control >= 192) { Properties(src.Get()); needProperties = false; }
                        ArchiveCheck(!needProperties);
                        if (control >= 160) Reset();
                        Block(src.Part(compressed), n, false);
                    }
                }
            }
        }
    }
}

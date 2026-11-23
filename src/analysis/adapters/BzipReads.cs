using System;
using System.IO;
using System.Linq;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            sealed class BzBits
            {
                readonly byte[] input; int pos,used;
                internal BzBits(byte[] input){this.input=input;}
                internal bool End=>pos==input.Length && used==0;
                internal uint Bits(int n)
                {
                    uint v=0;
                    while(n>0){ArchiveCheck(pos<input.Length);int k=Math.Min(n,8-used);
                        v=(v<<k)|(uint)((input[pos]>>(8-used-k))&((1<<k)-1));used+=k;n-=k;
                        if(used==8){used=0;pos++;}}
                    return v;
                }
                internal void Align(){if(used>0)ArchiveCheck(Bits(8-used)==0);}
            }
            sealed class BzAlphabet
            {
                readonly int[] first=new int[21],count=new int[21],offset=new int[21],symbols;
                readonly int max;
                internal BzAlphabet(int[] lens)
                {
                    symbols=new int[lens.Length];max=lens.Max();
                    foreach(int len in lens)count[len]++;
                    int code=0,index=0;
                    for(int d=1;d<=max;d++)
                    {
                        first[d]=code;offset[d]=index;ArchiveCheck(code+count[d]<=1<<d);
                        for(int s=0;s<lens.Length;s++)if(lens[s]==d)symbols[index++]=s;
                        code=(code+count[d])<<1;
                    }
                }
                internal int Symbol(BzBits r)
                {
                    int code=0;
                    for(int d=1;d<=max;d++){code=(code<<1)|(int)r.Bits(1);int relative=code-first[d];
                        if(relative>=0 && relative<count[d])return symbols[offset[d]+relative];}
                    throw new InvalidDataException();
                }
            }
            static readonly uint[] BzCrcTable=Enumerable.Range(0,256).Select(i=>
            {uint v=(uint)i<<24;for(int j=0;j<8;j++)v=(v<<1)^((v&0x80000000)!=0?0x04c11db7u:0);return v;}).ToArray();
            byte[] BunzipBytes(byte[] input,int max)
            {
                var r=new BzBits(input);using var output=new MemoryStream();int blocks=0,streams=0;
                do
                {
                    ArchiveCheck(++streams<=MaxPackedEntries && Budget() && r.Bits(24)==0x425a68);
                    int level=(int)r.Bits(8)-48;ArchiveCheck(level is >=1 and <=9);uint combined=0;
                    while(true)
                    {
                        uint a=r.Bits(24),b=r.Bits(24);
                        if(a==0x177245 && b==0x385090){ArchiveCheck(combined==r.Bits(32));r.Align();break;}
                        ArchiveCheck(++blocks<=MaxPackedEntries && Budget() && a==0x314159 && b==0x265359);
                        uint expected=r.Bits(32);ArchiveCheck(r.Bits(1)==0); // legacy randomized blocks stay unobserved
                        int origin=(int)r.Bits(24), groupsUsed=(int)r.Bits(16);
                        var alphabet=new byte[256];int alphabetSize=0;
                        for(int i=0;i<16;i++)if((groupsUsed & (1<<(15-i)))!=0)
                        {uint bits=r.Bits(16);for(int j=0;j<16;j++)if((bits&(1u<<(15-j)))!=0)alphabet[alphabetSize++]=(byte)(16*i+j);}
                        int tableCount=(int)r.Bits(3),selectorCount=(int)r.Bits(15);
                        ArchiveCheck(alphabetSize>0 && tableCount is >=2 and <=6 && selectorCount is >=1 and <=18002);
                        var order=Enumerable.Range(0,tableCount).ToArray();var selectors=new byte[selectorCount];
                        for(int i=0;i<selectors.Length;i++)
                        {
                            if((i&255)==0)ArchiveCheck(Budget());
                            int k=0;while(r.Bits(1)!=0)ArchiveCheck(++k<tableCount);int t=order[k];
                            Array.Copy(order,0,order,1,k);order[0]=t;selectors[i]=(byte)t;
                        }
                        var tables=new BzAlphabet[tableCount];
                        for(int i=0;i<tableCount;i++)
                        {
                            int len=(int)r.Bits(5);var lens=new int[alphabetSize+2];
                            for(int j=0;j<lens.Length;j++)
                            {
                                ArchiveCheck(len is >=1 and <=20);
                                while(r.Bits(1)!=0){len+=r.Bits(1)==0?1:-1;ArchiveCheck(len is >=1 and <=20);}
                                lens[j]=len;
                            }
                            tables[i]=new BzAlphabet(lens);
                        }
                        // Four output bytes may occupy five bytes before inverse RLE. Bound scratch by both the
                        // advertised block ceiling and actual remaining expansion room, not by the input header alone.
                        int room=Math.Min(max-(int)output.Length,ExpansionRoom());ArchiveCheck(room>0);
                        int cap=(int)Math.Min(100000L*level,room*5L/4+5);
                        var last=new byte[cap];var freq=new int[256];int n=0,symbols=0;
                        int Next()
                        {
                            int idx=symbols++/50;ArchiveCheck(idx<selectorCount && ((symbols&255)!=0 || Budget()));
                            return tables[selectors[idx]].Symbol(r);
                        }
                        int sym=Next();
                        while(sym!=alphabetSize+1)
                        {
                            if(sym<2)
                            {
                                long run=0,weight=1;
                                do {run+=(sym+1)*weight;ArchiveCheck(run<=cap-n);weight*=2;sym=Next();}while(sym<2);
                                byte c=alphabet[0];Array.Fill(last,c,n,(int)run);n+=(int)run;freq[c]+=(int)run;
                            }
                            else
                            {
                                int rank=sym-1;ArchiveCheck(rank<alphabetSize && n<cap);byte c=alphabet[rank];
                                Array.Copy(alphabet,0,alphabet,1,rank);alphabet[0]=c;last[n++]=c;freq[c]++;sym=Next();
                            }
                        }
                        ArchiveCheck(origin<n);
                        var next=new int[n];int sum=0;
                        for(int i=0;i<256;i++){int f=freq[i];freq[i]=sum;sum+=f;}
                        for(int i=0;i<n;i++){if((i&2047)==0)ArchiveCheck(Budget());next[freq[last[i]]++]=i;}
                        uint crc=uint.MaxValue;int previous=-1,runLength=0,at=origin;
                        void Emit(byte value,int count)
                        {
                            ArchiveCheck(count<=max-output.Length && count<=ExpansionRoom());expandedReadBytes+=count;
                            for(int j=0;j<count;j++){output.WriteByte(value);crc=(crc<<8)^BzCrcTable[(byte)((crc>>24)^value)];}
                        }
                        for(int i=0;i<n;i++)
                        {
                            if((i&1023)==0)ArchiveCheck(Budget());
                            at=next[at];byte c=last[at];
                            if(runLength==4){Emit((byte)previous,c);previous=-1;runLength=0;}
                            else {Emit(c,1);runLength=previous==c?runLength+1:1;previous=c;}
                        }
                        ArchiveCheck(runLength!=4 && ~crc==expected);combined=((combined<<1)|(combined>>31))^expected;
                    }
                }while(!r.End);
                return output.ToArray();
            }
        }
    }
}

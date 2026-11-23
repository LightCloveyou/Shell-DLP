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
            // Raw DEFLATE can read ahead. Keep the member trailer and following member distinguishable.
            sealed class MemberInput : MemoryStream
            {
                readonly Func<bool> within;
                internal MemberInput(byte[] data,int offset,Func<bool> within):base(data,false){Position=offset;this.within=within;}
                int Limit(int count) {if((Position&255)==0)ArchiveCheck(within());return Math.Min(1,count);}
                public override int Read(byte[] b,int offset,int count)=>base.Read(b,offset,Limit(count));
                public override int Read(Span<byte> b)=>base.Read(b.Slice(0,Limit(b.Length)));
            }
            byte[] GunzipBytes(byte[] packed,int max)
            {
                using var output=new MemoryStream();int p=0,members=0;
                do
                {
                    int head=p;
                    ArchiveCheck(++members<=MaxPackedEntries && Budget() && packed.Length-p>=18 && packed[p]==31 && packed[p+1]==139 && packed[p+2]==8);
                    int flags=packed[p+3];p+=10;ArchiveCheck((flags&224)==0);
                    if((flags&4)!=0){ArchiveCheck(p+2<=packed.Length);int len=U16(packed,p);p+=2;ArchiveCheck(len<=packed.Length-p);p+=len;}
                    foreach(int flag in new[]{8,16})if((flags&flag)!=0){int nul=Array.IndexOf(packed,(byte)0,p);ArchiveCheck(nul>=p);p=nul+1;}
                    if((flags&2)!=0){ArchiveCheck(p+2<=packed.Length && (ArchiveCrc(packed,head,p-head)&65535)==U16(packed,p));p+=2;}
                    using var src=new MemberInput(packed,p,Budget);
                    using var ds=new DeflateStream(src,CompressionMode.Decompress,true);
                    byte[] bytes=ExpandStream(ds,null,max-(int)output.Length);p=(int)src.Position;
                    ArchiveCheck(packed.Length-p>=8 && U32(packed,p+4)==bytes.Length && ArchiveCrc(bytes,0,bytes.Length)==U32(packed,p));
                    output.Write(bytes,0,bytes.Length);p+=8;
                }while(p<packed.Length);
                return output.ToArray();
            }
            static readonly byte[] XzMagic={253,55,122,88,90,0};
            static readonly ulong[] XzCrcTable=Enumerable.Range(0,256).Select(v=>
            {ulong n=(uint)v;for(int j=0;j<8;j++)n=(n>>1)^((n&1)!=0?0xC96C5795D7870F42UL:0);return n;}).ToArray();
            static ulong XzCrc(byte[] b)
            {ulong crc=ulong.MaxValue;foreach(byte v in b)crc=XzCrcTable[(byte)(crc^v)]^(crc>>8);return ~crc;}
            static int XzVli(byte[] b,ref int p,int end)
            {
                long v=0;
                for(int i=0;i<5;i++)
                {
                    ArchiveCheck(p<end);int n=b[p++];v|=(long)(n&127)<<(7*i);
                    if((n&128)==0){ArchiveCheck((i==0 || n!=0) && v<=int.MaxValue);return (int)v;}
                }
                throw new InvalidDataException();
            }
            byte[] UnxzBytes(byte[] b,int max)
            {
                int end=b.Length,records=0;
                var streams=new Stack<(int Start,int Index,int Check,List<(int Packed,int Size)> Blocks)>();
                while(end>0)
                {
                    int pad=end;while(end>0 && b[end-1]==0)end--;
                    ArchiveCheck(Budget() && (pad-end)%4==0 && end>=24 && streams.Count<MaxPackedEntries);
                    int footer=end-12;
                    ArchiveCheck(b[end-2]==89 && b[end-1]==90 && U32(b,footer)==ArchiveCrc(b,footer+4,6));
                    long indexLen=((long)U32(b,footer+4)+1)*4;
                    ArchiveCheck(indexLen>=8 && indexLen<=footer-12);
                    int index=footer-(int)indexLen,p=index,limit=footer-4;
                    ArchiveCheck(b[p++]==0 && ArchiveCrc(b,index,limit-index)==U32(b,limit));
                    int count=XzVli(b,ref p,limit);ArchiveCheck(count<=MaxPackedEntries-records);records+=count;
                    var blocks=new List<(int,int)>();long area=0;
                    for(int i=0;i<count;i++)
                    {
                        int unpadded=XzVli(b,ref p,limit),size=XzVli(b,ref p,limit);
                        ArchiveCheck(unpadded>0 && Budget());area+=((long)unpadded+3)&~3L;blocks.Add((unpadded,size));
                    }
                    ArchiveCheck(limit-p<=3);while(p<limit)ArchiveCheck(b[p++]==0);
                    ArchiveCheck(area<=index-12);int start=index-(int)area-12;
                    ArchiveCheck(b.AsSpan(start,6).SequenceEqual(XzMagic) && b[start+6]==0 &&
                        b[footer+8]==0 && b[footer+9]==b[start+7] && ArchiveCrc(b,start+6,2)==U32(b,start+8));
                    int check=b[start+7];ArchiveCheck(check is 0 or 1 or 4);
                    streams.Push((start,index,check,blocks));end=start;
                }
                ArchiveCheck(streams.Count>0);using var output=new MemoryStream();
                foreach(var stream in streams)
                {
                    int p=stream.Start+12,checkSize=stream.Check==0?0:stream.Check==1?4:8;
                    foreach(var (unpadded,size) in stream.Blocks)
                    {
                        int from=p;
                        ArchiveCheck(Budget() && size<=max-output.Length && size<=ExpansionRoom() && p<stream.Index && b[p]!=0);
                        int header=(b[p++]+1)*4,headerEnd=from+header-4;
                        ArchiveCheck(headerEnd+4<=stream.Index && header+checkSize<unpadded && ArchiveCrc(b,from,header-4)==U32(b,headerEnd));
                        int flags=b[p++],compressed=unpadded-header-checkSize;ArchiveCheck((flags&63)==0);
                        if((flags&64)!=0)ArchiveCheck(XzVli(b,ref p,headerEnd)==compressed);
                        if((flags&128)!=0)ArchiveCheck(XzVli(b,ref p,headerEnd)==size);
                        ArchiveCheck(XzVli(b,ref p,headerEnd)==33 && XzVli(b,ref p,headerEnd)==1 && p<headerEnd);
                        byte prop=b[p++];ArchiveCheck(prop<=40);
                        while(p<headerEnd)ArchiveCheck(b[p++]==0);p=headerEnd+4;
                        ArchiveCheck(compressed<=stream.Index-p);expandedReadBytes+=size;
                        byte[] bytes=new ArchiveLz(size,Budget).Decode(true,b,p,compressed,new[]{prop});p+=compressed;
                        while((p-from)%4!=0){ArchiveCheck(p<stream.Index && b[p++]==0);}
                        ArchiveCheck(checkSize<=stream.Index-p);
                        if(stream.Check==1)ArchiveCheck(ArchiveCrc(bytes,0,size)==U32(b,p));
                        if(stream.Check==4)ArchiveCheck(XzCrc(bytes)==(U32(b,p)|((ulong)U32(b,p+4)<<32)));
                        p+=checkSize;output.Write(bytes,0,bytes.Length);
                    }
                    ArchiveCheck(p==stream.Index);
                }
                return output.ToArray();
            }
            static string? DecompressedName(string path,string format)
            {
                string lower=path.ToLowerInvariant();
                foreach(var s in format=="gzip"?new[]{".tgz",".gz"}:format=="xz"?new[]{".txz",".xz"}:new[]{".tbz2",".tbz",".bz2",".bz"})
                    if(lower.EndsWith(s,StringComparison.Ordinal) && Path.GetFileName(path).Length>s.Length)
                        return path.Substring(0,path.Length-s.Length)+(s.StartsWith(".t")?".tar":"");
                return null;
            }
            Payload CompressionRead(string tool,string[] args,Payload? pipe)
            {
                string format=tool is "gzip" or "gunzip" or "zcat"?"gzip":tool is "xz" or "unxz" or "xzcat"?"xz":"bzip2";
                bool decode=tool!=format,cat=tool.EndsWith("cat"),keep=false,end=false,check=false,list=false,force=false;
                var files=new List<string>();
                foreach(var a in args)
                {
                    if(!end && a=="--"){end=true;continue;}
                    if(end || a=="-" || !a.StartsWith("-")){files.Add(a);continue;}
                    var flags=a switch{"--decompress" or "--uncompress"=>"d","--stdout" or "--to-stdout"=>"c","--keep"=>"k",
                        "--test"=>"t","--force"=>"f","--quiet"=>"q","--list"=>"l",_=>a.Substring(1)};
                    foreach(char f in flags)
                    {
                        switch(f){case 'd':decode=true;break;case 'c':cat=true;break;case 'k':keep=true;break;case 'f':force=true;break;
                            case 'q':break;case 't':check=true;break;case 'l':list=true;break;
                            default:return Missing("compression-command-options");}
                    }
                }
                if(files.Count==0)files.Add("-");
                if(files.Count(p=>p=="-")>1)return Missing("compressed-stdin-reuse");
                if(check && !list)return Missing("no-expression-output"); // integrity diagnostics/exit status are not stdout content
                if(list)return Missing("compressed-list-metadata-not-materialized");
                using var stdout=new MemoryStream();var marks=new List<Mark>();bool partial=false;
                void Flush(){if(stdout.Length>0)marks.AddRange(Bytes(stdout.ToArray(),"decompressed stdout segment").Tags);stdout.SetLength(0);stdout.Position=0;}
                foreach(string path in files)
                {
                    bool writes=!cat && path!="-";string? full=path=="-"?null:Disk.Bind(path,cwd);
                    string? dest=full==null?null:decode?DecompressedName(full,format):full+(format=="gzip"?".gz":format=="xz"?".xz":".bz2");
                    if(!decode)
                    {
                        if(writes){UncertainWrite("compression-creation",dest);if(!keep && full!=null)MarkPossibleWrite(full,null);}
                        return Missing("compression-is-not-a-decoder");
                    }
                    Payload? part=null;string issue="compressed-file-format-or-budget";
                    if(Budget() && (!writes || dest!=null))
                    try
                    {
                        var packed=UtilityBytes(path,pipe,out var src);
                        if(packed!=null)
                        {
                            int room=Math.Min(MaxContent,ExpansionRoom());
                            byte[] body=format=="gzip"?GunzipBytes(packed,room):format=="xz"?UnxzBytes(packed,room):BunzipBytes(packed,room);
                            part=Bytes(body,src.SourceRef+"!"+format,body.Length==0?Array.Empty<Mark>():FileRecordMarks(src));
                        }
                    }
                    catch(Exception e) when(e is IOException or InvalidDataException or OverflowException or ArgumentException or NotSupportedException){ }
                    if(writes)
                    {
                        var dirs=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        if(dest==null || full==null || part==null || !ArchiveDestination(dest,false,out bool exists,dirs) || dirs.Count!=0)
                        {UncertainWrite(issue,dest,part);if(full!=null && !keep)MarkPossibleWrite(full,null);continue;}
                        if(exists && !force)MarkPossibleWrite(dest,part);
                        else {PlanWrite(dest,part,part.Bytes,false);if(predictedWrites.TryGetValue(dest,out var fact))fact.MayReadOriginal|=exists;}
                        if(!keep)MarkPossibleWrite(full,null); // permissions/links can prevent deletion; retain old-content alternative.
                        continue;
                    }
                    if(part?.Bytes is not byte[] bytes){Flush();partial=true;continue;}
                    marks.AddRange(part.Tags);
                    if(bytes.Length>MaxContent-stdout.Length){Flush();partial=true;}
                    stdout.Write(bytes,0,bytes.Length);
                }
                if(!cat && !files.Contains("-"))return Missing("no-expression-output");
                if(partial){Flush();return new Payload{InspectionPartial=true,Issue="decompressed-stdout-incomplete",Tags=Merge(marks)};}
                var result=Bytes(stdout.ToArray(),"decompressed stdout",Merge(marks));result.PipeText=Disk.Decode(result.Bytes!);return result;
            }
        }
    }
}

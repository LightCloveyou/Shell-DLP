using System;
using System.Globalization;
using System.IO;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            sealed class FsMetadata
            {
                internal FileAttributes Attributes;
                internal long? Length;
                internal DateTime? Created, Modified, Accessed;
            }
            // Metadata only: do not use the content sampler. Reject remote paths, reparse chains,
            // pending observations and conflicting predicted writes before opening a metadata object.
            FsMetadata? InspectMetadata(string path)
            {
                if (policy==null || barrier || !Budget() || !Disk.Local(path) ||
                    PendingFiles.ContainsKey(path) || UncertainFileTree(Path.GetDirectoryName(path))) return null;
                if (plannedFiles.Contains(path))
                {
                    if (!predictedWrites.TryGetValue(path,out var p) || p.MayReadOriginal || p.InspectionPartial ||
                        p.Issue=="file-moved" || p.PredictedAttributes is not FileAttributes flags) return null;
                    return new FsMetadata { Attributes=flags, Length=p.Bytes?.LongLength };
                }
                if (!BeginFile() || !Disk.ClearAncestors(path)) return null;
                try
                {
                    var attrs=System.IO.File.GetAttributes(path);
                    if (attrs.HasFlag(FileAttributes.ReparsePoint)) return null;
                    FileSystemInfo fs=attrs.HasFlag(FileAttributes.Directory) ? new DirectoryInfo(path) : new FileInfo(path);
                    fs.Refresh();
                    if (!fs.Exists || fs.Attributes!=attrs || !FileTimeAvailable) return null;
                    return new FsMetadata { Attributes=attrs, Length=(fs as FileInfo)?.Length, Created=fs.CreationTimeUtc,
                        Modified=fs.LastWriteTimeUtc, Accessed=fs.LastAccessTimeUtc };
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or System.Security.SecurityException) { return null; }
            }
            static bool FsProperty(string name) => name is "fullname" or "name" or "psiscontainer" or "extension" or
                "basename" or "directoryname" or "directory" or "parent" or "root" or "length" or "attributes" or
                "creationtime" or "creationtimeutc" or "lastwritetime" or "lastwritetimeutc" or "lastaccesstime" or "lastaccesstimeutc";
            static Payload Timestamp(DateTime time) => new Payload { Complete=true, TimeValue=time, ReadType="System.DateTime",
                SourceRef="filesystem timestamp" }; // No guessed localized string representation.
            Payload TimestampProperty(DateTime t,string property) => property switch {
                "year"=>Number(t.Year),"month"=>Number(t.Month),"day"=>Number(t.Day),"dayofyear"=>Number(t.DayOfYear),
                "hour"=>Number(t.Hour),"minute"=>Number(t.Minute),"second"=>Number(t.Second),"millisecond"=>Number(t.Millisecond),
                "ticks"=>Number(t.Ticks),"date"=>Timestamp(t.Date),_=>Missing("timestamp-member") };
            Payload FsStatField(FsMetadata data,string property)
            {
                if(property=="length")return data.Length is long n ? Number(n) : Missing("file-length");
                if(property=="attributes")return new Payload{Text=data.Attributes.ToString(),ReadType="System.IO.FileAttributes",
                    Complete=true,SourceRef="file attributes",ScalarTruth=data.Attributes!=0};
                DateTime? time=property.StartsWith("creation")?data.Created:property.StartsWith("lastaccess")?data.Accessed:
                    property.StartsWith("lastwrite")?data.Modified:null;
                return time.HasValue?Timestamp(property.EndsWith("utc")?time.Value:time.Value.ToLocalTime()):Missing("filesystem-timestamp");
            }
            Payload DotNetFsField(Payload input,string property)
            {
                var raw=ExactString(input);
                if(raw==null || !Path.IsPathFullyQualified(raw) || Disk.Bind(raw,null) is not string full)
                    return Missing("filesystem-metadata-path");
                return InspectMetadata(full) is FsMetadata data?FsStatField(data,property):Missing("filesystem-metadata-unobserved");
            }
            Payload FsField(FileReference item,string property)
            {
                bool dir=item.Kind==PathKind.DirectoryInfo;var path=item.Path;
                if(item.Kind==PathKind.PathString) return Missing("not-filesystem-object");
                if(property=="extension")return Text(Path.GetExtension(path),"file extension");
                if(property=="basename")return Text(dir?new DirectoryInfo(path).Name:Path.GetFileNameWithoutExtension(path),"filesystem basename");
                if(property=="directoryname" && !dir)return Text(Path.GetDirectoryName(path),"containing directory path");
                if(property=="directory" && !dir || dir && property is ("root" or "parent"))
                {
                    var selected=property=="root"?Path.GetPathRoot(path):Path.GetDirectoryName(path);
                    return selected==null?Missing("no-parent-directory"):new Payload{Complete=true,SourceRef=selected,
                        FileObject=new FileReference(selected,PathKind.DirectoryInfo)};
                }
                if(property is "directoryname" or "root" or "directory" or "parent" || dir && property=="length")
                    return Missing("filesystem-member-type");
                // FileSystemInfo metadata may have been cached before a modeled mutation.
                return !plannedFiles.Contains(path) && InspectMetadata(path) is FsMetadata data?FsStatField(data,property):
                    Missing("filesystem-metadata-unobserved");
            }
        }
    }
}

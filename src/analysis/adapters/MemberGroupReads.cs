using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            sealed class ReadGroup
            {
                internal Payload[] Keys=Array.Empty<Payload>();
                internal readonly List<Payload> Items=new List<Payload>();
            }
            static string? GroupKeyType(Payload v)=>!v.Complete||v.InspectionPartial?null:v.IsString && v.Text!=null?"string":
                v.TimeValue.HasValue?"time":v.NumericType is ("Int32" or "Int64" or "Int16" or "Byte" or "UInt32" or "UInt64" or "UInt16" or "SByte") &&
                decimal.TryParse(v.Text,NumberStyles.Integer,CultureInfo.InvariantCulture,out _)?"integer":
                v.NumericType==null && v.ScalarTruth.HasValue && v.ReadType==null && v.Text is ("True" or "False")?"bool":null;
            Payload GroupRead(object command,Payload? pipe)
            {
                using var args=new Args(this,command,new[]{"Property","InputObject","Culture"},new[]{"CaseSensitive","AsHashTable","AsString","NoElement"});
                var node=args.Get("InputObject");var prop=args.Get("Property")??args.Plain.FirstOrDefault();
                if(!args.Valid || (node==null)==(pipe==null) || args.Plain.Count!=(prop!=null && !args.Has("Property")?1:0) ||
                    args.Has("AsString")&&!args.Has("AsHashTable"))return Missing("group-binding");
                var keys=prop==null?Array.Empty<string>():LocalNames(Value(prop));
                if(keys==null || keys.Length>Limits.MaxArguments)return Missing("group-property-expression");
                var culture=CultureInfo.CurrentCulture;
                if(args.Has("Culture"))
                {
                    var locale=ExactString(Value(args.Get("Culture")));if(locale==null)return Missing("group-culture");
                    try{culture=CultureInfo.GetCultureInfo(locale);}catch(CultureNotFoundException){return Missing("group-culture");}
                }
                var comparer=StringComparer.Create(culture,!args.Has("CaseSensitive"));
                var input=pipe??Value(node);
                var items=node!=null?new[]{input}:IterationItems(input)??new[]{input};
                string[]? kinds=null;
                bool partial=input.InspectionPartial || input.RecordRemainder!=null;
                int Compare(Payload[] a,Payload[] b)
                {
                    for(int i=0;i<a.Length;i++)
                    {
                        int cmp=kinds![i] switch{
                            "string"=>comparer.Compare(a[i].Text,b[i].Text),
                            "integer"=>decimal.Compare(decimal.Parse(a[i].Text!,CultureInfo.InvariantCulture),decimal.Parse(b[i].Text!,CultureInfo.InvariantCulture)),
                            "time"=>DateTime.Compare(a[i].TimeValue!.Value,b[i].TimeValue!.Value),
                            _=>a[i].ScalarTruth!.Value.CompareTo(b[i].ScalarTruth!.Value)};
                        if(cmp!=0)return cmp;
                    }
                    return 0;
                }
                var groups=new SortedDictionary<Payload[],ReadGroup>(Comparer<Payload[]>.Create(Compare));
                var uncertainKeys=new List<Payload>();
                var uncertainMembers=new List<Payload>();
                foreach(var item in items)
                {
                    if(!Budget()){partial=true;break;}
                    var vals=keys.Length==0?new[]{item}:keys.Select(k=>ReadProjection(item,k)).ToArray();
                    var types=vals.Select(GroupKeyType).ToArray();
                    if(types.Any(t=>t==null))
                    {
                        partial=true;
                        if(uncertainMembers.Count>=Limits.MaxCollection || uncertainKeys.Count+vals.Length>Limits.MaxCollection)break;
                        uncertainKeys.AddRange(vals.Where(v=>v.HttpObject==null && v.FileObject==null && v.Map==null && v.Elements==null));
                        uncertainMembers.Add(item);continue;
                    }
                    if(kinds==null)kinds=types.Select(t=>t!).ToArray();
                    if(!types.SequenceEqual(kinds))return Missing("group-mixed-key-types");
                    if(!groups.TryGetValue(vals,out var group))
                    {
                        if(groups.Count>=Limits.MaxCollection){partial=true;break;}
                        group=new ReadGroup{Keys=vals};groups.Add(vals,group);
                    }
                    group.Items.Add(item);
                }
                var records=new List<Payload>();bool noItems=args.Has("NoElement"),table=args.Has("AsHashTable");
                var map=new Dictionary<string,Payload>(comparer);
                var tableKeys=new List<Payload>();
                foreach(var g in groups.Values)
                {
                    if(!Budget()){partial=true;break;}
                    string label=string.Join(", ",g.Keys.Select((k,i)=>kinds![i]=="time"?k.TimeValue!.Value.ToString(CultureInfo.CurrentCulture):k.Text));
                    var title=Text(label,"group key",Merge(KnownMarks(g.Keys)));
                    var members=CollectElements(noItems?Array.Empty<Payload>():g.Items.ToArray());
                    if(partial && !noItems){members=Partial(members,"group-members-incomplete");members.RecordRemainder=Missing("group-member");}
                    if(table)
                    {
                        var key=args.Has("AsString")?label:GroupKeyType(g.Keys[0])=="string"?g.Keys[0].Text:null;
                        if(key==null || map.ContainsKey(key))return Missing("group-hashtable-key");
                        map.Add(key,members);tableKeys.Add(args.Has("AsString")?title:g.Keys[0]);continue;
                    }
                    var record=ReadObject("group",("Name",title),("Values",CollectElements(g.Keys)),("Group",members),
                        ("Count",partial?Missing("group-count-incomplete"):Number(g.Items.Count)));
                    record.ReadType="Microsoft.PowerShell.Commands."+(noItems?"GroupInfoNoElement":"GroupInfo");
                    records.Add(record);
                }
                if(table && (groups.Count!=0 || partial))return new Payload{Map=map,ReadType="System.Collections.Hashtable",Complete=!partial,
                    InspectionPartial=partial,Issue=partial?"group-table-incomplete":"",Tags=Merge(KnownMarks(map.Values.Concat(tableKeys)
                        .Concat(uncertainKeys).Concat(noItems?Array.Empty<Payload>():uncertainMembers.ToArray()))),SourceRef="group table"};
                if(partial)
                {
                    if(uncertainMembers.Count>0)
                    {
                        var key=UnknownValue("group-key-not-observed",uncertainKeys.ToArray());
                        records.Add(ReadObject("possible group",("Name",key),("Values",key),("Count",Missing("group-count-incomplete")),
                            ("Group",noItems?CollectElements(Array.Empty<Payload>()):UnknownValue("group-members-incomplete",uncertainMembers.ToArray()))));
                    }
                    records.Add(Missing("group-key-remainder"));
                }
                return MetadataRows(records,"Group-Object");
            }

            Payload MetadataRows(IEnumerable<Payload> records,string name)
            {
                var result=CollectElements(records);
                var rows=result.Elements??Array.Empty<Payload>();
                bool gap=result.InspectionPartial||rows.Any(p=>p.Map==null && !p.Complete);
                if(!gap && rows.Length==1)return rows[0];
                result.SourceRef=name;result.Tags=Merge(result.Tags.Concat(KnownMarks(rows)));
                if(gap)
                {
                    result.InspectionPartial=true;result.Complete=false;result.FirstUncertainIndex=0;
                    result.Issue=name+"-unobserved-records";result.RecordRemainder=Missing(result.Issue);
                }
                return result;
            }

            static string? ReadObjectType(Payload item)
            {
                if(item.ReadType!=null)return item.ReadType;
                if(item.FileObject is FileReference file)return file.Kind==PathKind.DirectoryInfo?"System.IO.DirectoryInfo":"System.IO.FileInfo";
                if(item.IsString)return "System.String";
                if(item.NumericType!=null)return "System."+item.NumericType;
                if(item.ScalarTruth.HasValue)return "System.Boolean";
                if(item.Bytes!=null)return "System.Byte[]";
                if(item.Elements!=null && item.Complete)return "System.Object[]";
                return null;
            }
            static Type? MemberClrType(string name)=>name switch{
                "System.IO.FileInfo"=>typeof(FileInfo),"System.IO.DirectoryInfo"=>typeof(DirectoryInfo),"System.String"=>typeof(string),
                "System.Int16"=>typeof(short),"System.Int32"=>typeof(int),"System.Int64"=>typeof(long),"System.Boolean"=>typeof(bool),
                "System.Byte"=>typeof(byte),"System.Double"=>typeof(double),"System.Decimal"=>typeof(decimal),"System.Byte[]"=>typeof(byte[]),
                "System.Object[]"=>typeof(object[]),"System.DateTime"=>typeof(DateTime),"System.IO.FileAttributes"=>typeof(FileAttributes),
                "System.Collections.Hashtable"=>typeof(System.Collections.Hashtable),_=>null};
            static string? FriendlyType(Type t)=>t==typeof(string)?"string":t==typeof(int)?"int":t==typeof(long)?"long":
                t==typeof(bool)?"bool":t==typeof(byte)?"byte":t==typeof(short)?"short":t==typeof(double)?"double":
                t==typeof(decimal)?"decimal":t==typeof(DateTime)?"datetime":t==typeof(object)?"System.Object":t.FullName;
            Payload MemberRead(object command,Payload? pipe)
            {
                using var args=new Args(this,command,new[]{"InputObject","Name","MemberType","View"},new[]{"Force","Static"});
                var node=args.Get("InputObject");var n=args.Get("Name")??args.Plain.FirstOrDefault();
                if(!args.Valid || (node==null)==(pipe==null) || args.Plain.Count!=(n!=null&&!args.Has("Name")?1:0) || args.Has("Force"))
                    return Missing("get-member-binding-or-hidden-members");
                var names=n==null?new[]{"*"}:MemberTerms(Value(n));
                var matcher=names?.Select(CompileWildcard).ToArray();
                if(matcher==null || matcher.Any(m=>m==null))return Missing("get-member-name-pattern");
                var types=args.Has("MemberType")?MemberTerms(Value(args.Get("MemberType"))) : new[]{"All"};
                if(types==null)return Missing("get-member-kind");
                var filters=new HashSet<string>(types.SelectMany(t=>t.Split(',')).Select(t=>t.Trim()),StringComparer.OrdinalIgnoreCase);
                bool KindIncluded(string k)=>filters.Contains("All") || filters.Contains(k) ||
                    (k.EndsWith("Property") || k=="Property") && filters.Contains("Properties") || k.EndsWith("Method") && filters.Contains("Methods");
                string? view=args.Has("View")?ExactString(Value(args.Get("View")))?.ToLowerInvariant():"all";
                if(view is not ("all" or "base" or "adapted" or "extended"))return Missing("get-member-view");
                bool staticOnly=args.Has("Static");
                var input=pipe??Value(node);
                var items=node!=null?new[]{input}:IterationItems(input)??new[]{input};
                var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                IEnumerable<Payload> Definitions()
                {
                    foreach(var item in items)
                    {
                        if(!Budget()){yield return Missing("get-member-budget");yield break;}
                        string? type=ReadObjectType(item);
                        if(type==null){yield return Missing("get-member-input-type");continue;}
                        string? display=staticOnly?type:item.MemberDisplayType??(type=="Selected.Object"?null:type);
                        if(display==null){yield return Missing("get-member-owner-type");continue;}
                        if(!seen.Add(display))continue; // Get-Member reports once per effective type, not once per input row.
                        bool custom=type=="System.Management.Automation.PSCustomObject" || type.StartsWith("Selected.",StringComparison.Ordinal);
                        var fields=new Dictionary<string,(string Kind,Payload Definition)>(StringComparer.OrdinalIgnoreCase);
                        bool partial=false;
                        void Add(string key,string kind,Func<Payload> definition)
                        {
                            if(KindIncluded(kind) && matcher.Any(m=>m!(key)) && !fields.ContainsKey(key))
                                fields.Add(key,(kind,definition()));
                        }
                        if(!staticOnly && custom && view is ("all" or "extended") && item.Map!=null)
                            foreach(var kv in item.Map) Add(kv.Key,"NoteProperty",()=>NoteDefinition(kv.Key,kv.Value));
                        if(!staticOnly && (type=="Microsoft.PowerShell.Commands.GroupInfo" || type=="Microsoft.PowerShell.Commands.GroupInfoNoElement" ||
                            type=="Microsoft.PowerShell.Commands.MemberDefinition") && view!="extended" && item.Map!=null)
                            foreach(var key in item.Map.Keys)Add(key,"Property",()=>Missing("member-signature-rendering"));
                        var clr=MemberClrType(type);
                        if(clr!=null && view!="extended")
                        {
                            var flags=BindingFlags.Public | (staticOnly?BindingFlags.Static|BindingFlags.FlattenHierarchy:BindingFlags.Instance);
                            foreach(var m in clr.GetMembers(flags))
                            {
                                if(!Budget()){partial=true;break;}
                                if(m is PropertyInfo p)
                                    Add(p.Name,"Property",()=>p.GetIndexParameters().Length==0 && FriendlyType(p.PropertyType) is string pt?
                                        Text(pt+" "+p.Name+" {"+(p.GetMethod?.IsPublic==true?"get;":"")+(p.SetMethod?.IsPublic==true?"set;":"")+"}","property signature"):
                                        Missing("member-indexer-definition"));
                                else if(m is MethodInfo fn && !fn.IsSpecialName)Add(fn.Name,"Method",()=>Missing("member-overload-signatures"));
                                else if(m is EventInfo ev)Add(ev.Name,"Event",()=>Missing("member-event-signature"));
                                else if(m is FieldInfo fld)Add(fld.Name,"Property",()=>Missing("member-field-signature"));
                            }
                        }
                        // Type data/extensions may add members; never call arbitrary getters, adapters, methods or ToString().
                        if(view is "all" or "extended" && !staticOnly || clr==null)
                        {
                            if(!custom && item.FileObject!=null && !staticOnly && view is ("all" or "extended"))
                            { Add("BaseName","ScriptProperty",()=>Missing("member-script-definition")); }
                            bool exactNames=names!.All(k=>k.IndexOfAny("*?[".ToCharArray())<0&&fields.ContainsKey(k));
                            if(!exactNames && !(custom && !staticOnly && filters.SetEquals(new[]{"NoteProperty"}) && !item.InspectionPartial))
                                partial=true;
                        }
                        foreach(var pair in fields.OrderBy(p=>p.Value.Kind,StringComparer.OrdinalIgnoreCase).ThenBy(p=>p.Key,StringComparer.OrdinalIgnoreCase))
                        {
                            var row=ReadObject("member metadata",("Name",Text(pair.Key,"member name")),("TypeName",Text(display,"member owner type")),
                                ("MemberType",Text(pair.Value.Kind,"member kind")),("Definition",pair.Value.Definition));
                            row.ReadType="Microsoft.PowerShell.Commands.MemberDefinition";yield return row;
                        }
                        if(partial)yield return Missing("get-member-additional-metadata");
                    }
                    if(input.InspectionPartial && node==null)yield return Missing("get-member-input-remainder");
                }
                return MetadataRows(Definitions(),"Get-Member");
            }
            string[]? MemberTerms(Payload input)
            {
                var entries=input.Elements??new[]{input};
                if(!input.Complete || input.InspectionPartial || entries.Length>Limits.MaxArguments || entries.Length==0 ||
                    entries.Any(e=>ExactString(e) is not string s || s.Length==0 || s.Length>Limits.MaxFilter))return null;
                return entries.Select(e=>e.Text!).ToArray();
            }
            Payload NoteDefinition(string name,Payload value)
            {
                // PSNoteProperty's Definition renders the actual scalar value, unlike its Name and MemberType.
                if(value.Complete && !value.InspectionPartial && value.Text is string s && ReadObjectType(value) is string type &&
                    MemberClrType(type) is Type clr && FriendlyType(clr) is string display && (value.IsString||value.NumericType!=null||value.ScalarTruth.HasValue))
                    return Text(display+" "+name+"="+s,"note property definition",FileRecordMarks(value));
                return value.IsString ? new Payload {InspectionPartial=true,Issue="note-property-value-rendering",
                    Tags=FileRecordMarks(value)} : Missing("note-property-value-rendering");
            }
        }
    }
}

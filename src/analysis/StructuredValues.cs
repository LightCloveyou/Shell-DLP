using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Globalization;
using System.IO;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            Payload? StructuredValue(object? node, int depth)
            {
                switch (Kind(node))
                {
                    case "HashtableAst":
                        var pairs = MapAst(node).ToArray();
                        if (pairs.Length > Limits.MaxCollection) return Missing("hashtable-size");
                        var map = new Dictionary<string, Payload>(StringComparer.OrdinalIgnoreCase);
                        foreach (var (key, value) in pairs)
                        {
                            var p = Value(key, depth + 1);
                            if (p.Text == null || !p.Complete || map.ContainsKey(p.Text)) return Missing("hashtable-key");
                            var expression = Prop(SingleElement(value), "Expression");
                            map.Add(p.Text, expression != null ? Value(expression, depth + 1) :
                                Pipeline(value, depth + 1) ?? Missing("hashtable-entry"));
                        }
                        return new Payload { Map = map, Complete = true, SourceRef = "hashtable", ReadType = "System.Collections.Hashtable" };
                    case "ArrayLiteralAst":
                    case "ArrayExpressionAst":
                        if (Kind(node) == "ArrayExpressionAst")
                        {
                            var block = Prop(node, "SubExpression");
                            if (Items(Prop(block, "Traps")).Any()) return Missing("array-traps");
                            var statements = Items(Prop(block, "Statements")).ToArray();
                            if (statements.Length == 1 && Kind(SingleElement(statements[0])) == "CommandAst")
                            {
                                var emitted = Pipeline(statements[0], depth + 1);
                                if (emitted?.Files != null || emitted?.Elements != null) return emitted;
                                return new Payload { Elements = emitted == null ? Array.Empty<Payload>() : new[] { emitted },
                                    Complete = emitted?.Complete ?? true, SourceRef = "array output" };
                            }
                            if (statements.Length != 1 || Kind(Prop(SingleElement(statements[0]), "Expression")) != "ArrayLiteralAst")
                            {
                                var emitted = new List<Payload>();
                                AnalyzeStatements(statements, depth + 1, emitted);
                                return CollectElements(emitted.SelectMany(v => v.Files?.Records ?? v.Elements ?? new[] { v }));
                            }
                            node = Prop(SingleElement(statements[0]), "Expression");
                        }
                        return CollectElements(Items(Prop(node, "Elements")).Select(n => Value(n, depth + 1)));
                    case "ExpandableStringExpressionAst":
                        return Expand(node, depth);
                    case "IndexExpressionAst":
                        var container = MaterializeDirectory(Value(Prop(node, "Target"), depth + 1));
                        var index = Value(Prop(node, "Index"), depth + 1);
                        if (index.Complete && index.Text is string keyText)
                        {
                            if (container.Map?.TryGetValue(keyText, out var entry) == true) return entry;
                            var elements = container.Files?.Records ?? container.Elements;
                            if (!int.TryParse(keyText, NumberStyles.Integer, CultureInfo.InvariantCulture, out int i)) return Missing("index-value");
                            if (container.FileObject != null && i is 0 or -1) return container;
                            if (elements != null)
                            {
                                int gap = container.FirstUncertainIndex ?? (container.Files == null ? -1 :
                                    Array.FindIndex(elements, record => record.FileObject == null));
                                if (gap >= 0 && (i < 0 || i >= gap))
                                {
                                    var candidates = elements.Skip(i < 0 ? 0 : gap).Append(container.RecordRemainder).OfType<Payload>().ToArray();
                                    var unknown = UnknownValue("partial-file-index", candidates);
                                    if (container.FirstUncertainIndex.HasValue)
                                    {
                                        var paths = candidates.Where(v => v.IsString && v.Text != null)
                                            .Select(v => new FileReference(v.Text!, PathKind.PathString))
                                            .Concat(unknown.PathAlternatives ?? Array.Empty<FileReference>()).Distinct().ToArray();
                                        if (paths.Length != 0) unknown.PathAlternatives = paths;
                                    }
                                    return unknown;
                                }
                                long? count = container.RecordCount ?? (container.RecordRemainder == null && !container.InspectionPartial ? (long?)elements.Length : null);
                                long? position = i < 0 ? count + i : i;
                                if (position >= 0 && position < elements.Length) return elements[(int)position.Value];
                                if (position is long known && (known < 0 || known >= count)) return Missing("index-value");
                                if (container.RecordRemainder != null)
                                    return position.HasValue ? container.RecordRemainder :
                                        UnknownValue("partial-index", elements.Append(container.RecordRemainder).ToArray());
                            }
                        }
                        return Missing("index-value");
                    case "MemberExpressionAst":
                        if (Equals(Prop(node,"Static"),true) &&
                            HttpType(TypeName(Prop(node,"Expression"))) is string enumType &&
                            enumType is ("io.compression.compressionmode" or "io.compression.compressionlevel") &&
                            Literal(Prop(node,"Member")) is string enumName)
                            return new Payload { Text=enumName, ReadType=enumType, Complete=true, SourceRef="compression enum" };
                        if (Equals(Prop(node, "Static"), true) && TypeName(Prop(node, "Expression")) == "microsoft.win32.registry" &&
                            Literal(Prop(node, "Member")) is string hive) return RegistryRoot(hive);
                        if (!Equals(Prop(node, "Static"), false) || Literal(Prop(node, "Member")) is not string member)
                            return null;
                        var receiver = Value(Prop(node, "Expression"), depth + 1);
                        if (CurrentHttp(receiver.HttpObject) is { Kind: HttpObjectKind.XmlDocument } xml)
                            return xml.Body?.Map?.TryGetValue(member, out var component) == true ? component : Missing("xml-document-member");
                        if (member.Equals("Entries", StringComparison.OrdinalIgnoreCase) &&
                            CurrentHttp(receiver.HttpObject) is { Kind: HttpObjectKind.ZipArchive } zip) return ZipSelection(zip, null, find: false);
                        if (CurrentHttp(receiver.HttpObject) is HttpObject readHandle && IsReadHandle(readHandle))
                            return ReaderProperty(readHandle, member.ToLowerInvariant());
                        if (CurrentHttp(receiver.HttpObject) is HttpObject cursor && cursor.Kind==HttpObjectKind.AsyncLineCursor &&
                            member.Equals("Current",StringComparison.OrdinalIgnoreCase))
                            return ReaderOpen(cursor) && Slot(cursor,"readPending")==null ? Slot(cursor,"current") ?? Missing("async-enumerator-position") :
                                Missing("async-enumerator-pending-or-closed");
                        if (CurrentHttp(receiver.HttpObject) is HttpObject httpOwner &&
                            (member.Equals("DefaultRequestHeaders", StringComparison.OrdinalIgnoreCase) && httpOwner.Kind == HttpObjectKind.Client ||
                             member.Equals("Headers", StringComparison.OrdinalIgnoreCase) && httpOwner.Kind is
                                (HttpObjectKind.Message or HttpObjectKind.Content or HttpObjectKind.Multipart or HttpObjectKind.Request or HttpObjectKind.WebClient)))
                            return HttpObjectValue(new HttpObject(HttpObjectKind.Headers, owner: httpOwner));
                        if (member.Equals("Length", StringComparison.OrdinalIgnoreCase) && receiver.Bytes != null)
                            return new Payload { Text = receiver.Bytes.Length.ToString(CultureInfo.InvariantCulture), Complete = true, NumericType = "Int32" };
                        if (member.Equals("Result", StringComparison.OrdinalIgnoreCase) && receiver.Issue == "dotnet-http-response")
                            return receiver;
                        if (member.Equals("Result", StringComparison.OrdinalIgnoreCase) && receiver.Issue is ("file-read-task" or "file-read-valuetask"))
                            return FinishRead(receiver);
                        // Hashtable keys take precedence, including names such as Count.
                        if (receiver.Map?.TryGetValue(member, out var item) == true) return item;
                        if (receiver.Issue == "environment-map") return EnvironmentMapMembers(receiver, member.ToLowerInvariant());
                        if (receiver.HttpObject?.Kind == HttpObjectKind.RegistryKey && member.Equals("Name", StringComparison.OrdinalIgnoreCase))
                            return Text(receiver.HttpObject.Address?.Text?.Substring(9), "registry key name");
                        if (receiver.LocalRecord != null || receiver.Issue is "local-source-records-not-observed" or "local-source-alternatives")
                            return LocalField(receiver, member);
                        var property = member.ToLowerInvariant();
                        if (receiver.TimeValue is DateTime timestamp) return TimestampProperty(timestamp,property);
                        if(property!="length" && FsProperty(property) && (receiver.Files!=null ||
                            receiver.Elements?.Any(e=>e.FileObject!=null || e.PathAlternatives!=null)==true))
                            return FileSystemMember(receiver,property,member);
                        if (receiver.Elements is { } entries && entries.Any(e => e.Map != null || e.LocalRecord != null))
                        {
                            if (property is "count" or "length" or "longlength")
                                return receiver.Complete && !receiver.InspectionPartial && receiver.FirstUncertainIndex == null ?
                                    Number(entries.Length) : Missing("collection-count");
                            if (property is not ("rank" or "isfixedsize" or "isreadonly" or "issynchronized" or "syncroot"))
                            {
                                IEnumerable<Payload> Fields()
                                {
                                    foreach (var record in entries)
                                    {
                                        if (record.Map != null)
                                        {
                                            if (record.Map.TryGetValue(member, out var field)) yield return field;
                                            else if (record.LocalRecord != null) yield return LocalField(record, member);
                                        }
                                        else if (record.LocalRecord != null) yield return LocalField(record, member);
                                        else if (record.FileObject != null && FsProperty(property))
                                            yield return FileSystemMember(record, property) ?? Missing("filesystem-member");
                                        else if (!record.Complete) yield return Missing("collection-member");
                                    }
                                    if (receiver.InspectionPartial) yield return Missing("collection-member-remainder");
                                }
                                return ReadOutput(Fields(), "collection." + member);
                            }
                        }
                        if (property is ("count" or "length" or "longlength") && (receiver.Files!=null || receiver.Elements!=null))
                            return receiver.RecordCount is long known ? Number(known) :
                                receiver.Complete && !receiver.InspectionPartial && receiver.RecordRemainder==null && receiver.FirstUncertainIndex==null ?
                                Number((receiver.Files?.Records ?? receiver.Elements!).Length) : Missing("collection-count");
                        return FsProperty(property) ? FileSystemMember(receiver, property) : null;
                    case "SubExpressionAst":
                        return EvaluateSubExpression(node, depth + 1);
                    case "BinaryExpressionAst":
                        var binary = Str(Prop(node, "Operator"));
                        if (ComparisonOperator(binary))
                            return CompareScalars(binary, Value(Prop(node, "Left"), depth + 1), Value(Prop(node, "Right"), depth + 1));
                        if (binary == "DotDot")
                            return IntegerRange(Value(Prop(node, "Left"), depth + 1), Value(Prop(node, "Right"), depth + 1));
                        if (binary != "Join")
                        {
                            if (ConditionMutates(node) && binary is not ("And" or "Or" or "QuestionQuestion"))
                            {
                                _ = Value(Prop(node, "Left"), depth + 1);
                                _ = Value(Prop(node, "Right"), depth + 1);
                            }
                            else if (ConditionMutates(node)) InvalidateSessionFacts();
                            return null;
                        }
                        return JoinArray(Value(Prop(node, "Left"), depth + 1), Value(Prop(node, "Right"), depth + 1));
                    case "UnaryExpressionAst":
                        var op = Str(Prop(node, "TokenKind"));
                        if (IsIncrement(op)) return ApplyIncrement(node, op);
                        if (op != "Join") return null;
                        return JoinArray(Value(Prop(node, "Child"), depth + 1), Text("", "join delimiter"));
                    case "InvokeMemberExpressionAst":
                        if (Equals(Prop(node, "Static"), true) || Literal(Prop(node, "Member"))?.ToLowerInvariant() != "replace")
                            return null;
                        var args = Items(Prop(node, "Arguments")).Take(3).ToArray();
                        if (args.Length != 2) return null;
                        return ReplaceString(Value(Prop(node, "Expression"), depth + 1),
                            Value(args[0], depth + 1), Value(args[1], depth + 1));
                    case "ConstantExpressionAst":
                        var scalar = Scalar(Prop(node, "Value"), "literal");
                        if (!scalar.Known || scalar.Text == null) return null;
                        var literal = Text(scalar.Text, "literal");
                        literal.IsString = scalar.Type == "String";
                        literal.ScalarTruth = ScalarTruth(scalar.Type, scalar.Text);
                        if (NumericScalar(scalar.Type)) literal.NumericType = scalar.Type;
                        return literal;
                    default:
                        return null;
                }
            }

            Payload? FileSystemMember(Payload receiver, string property, string? mapKey=null)
            {
                string MemberText(FileReference item) => property == "fullname" ? item.Path :
                    item.Kind == PathKind.DirectoryInfo ? new DirectoryInfo(item.Path).Name : Path.GetFileName(item.Path);

                Payload? Member(Payload record)
                {
                    if (record.Map?.TryGetValue(mapKey??property, out var field) == true) return field;
                    if (record.LocalRecord!=null) return LocalField(record,mapKey??property);
                    if (record.FileObject is FileReference item)
                    {
                        bool directory = item.Kind == PathKind.DirectoryInfo;
                        var origin = item.Kind + "." + property;
                        var result = property == "psiscontainer"
                            ? new Payload { Text = directory ? "True" : "False", ScalarTruth = directory, Complete = true, SourceRef = origin }
                            : property is "fullname" or "name" ? Text(MemberText(item), origin) : FsField(item,property);
                        return record.InspectionPartial ? Partial(result, "conditional-file-selection") : result;
                    }
                    if (record.PathAlternatives is { } alternatives)
                    {
                        var result = Missing("conditional-filesystem-member");
                        if (property is "fullname" or "name")
                        {
                            var paths = alternatives.Where(p => p.Kind != PathKind.PathString)
                                .Select(p => new FileReference(MemberText(p), PathKind.PathString)).Distinct().ToArray();
                            if (paths.Length != 0) result.PathAlternatives = paths;
                        }
                        result.InspectionPartial = true;
                        return result;
                    }
                    // A known scalar without the property emits nothing. An unknown
                    // record keeps its place; it is not an empty path or a clean file.
                    return record.Complete && (record.IsString || record.NumericType != null || record.ScalarTruth.HasValue ||
                        record.Map != null) ? null : Missing(record.Issue.Length == 0 ? "filesystem-member" : record.Issue);
                }

                var records = receiver.Files?.Records ?? receiver.Elements;
                if (records == null) return receiver.FileObject != null || receiver.PathAlternatives != null ? Member(receiver) : null;
                var values = new List<Payload>(records.Length);
                int? gap = null;
                bool timedOut = false;
                for (int i = 0; i < records.Length; i++)
                {
                    if (!Budget()) { timedOut = true; break; }
                    if (receiver.FirstUncertainIndex == i || !records[i].Complete || records[i].InspectionPartial ||
                        receiver.Files != null && records[i].FileObject == null)
                        gap ??= values.Count; // An enumeration diagnostic can stand for many missing siblings.
                    if (Member(records[i]) is Payload value) values.Add(value);
                }
                var rest = timedOut ? Missing("file-time-budget") : receiver.RecordRemainder == null ? null :
                    Member(receiver.RecordRemainder) ?? Missing("filesystem-member-remainder");
                return new Payload { Elements = values.ToArray(), FirstUncertainIndex = gap, RecordRemainder = rest,
                    RecordCount = !timedOut && gap == null && values.Count == records.Length ? receiver.RecordCount : null,
                    Complete = receiver.Complete && !timedOut && gap==null, InspectionPartial = receiver.InspectionPartial || timedOut || gap!=null,
                    Tags = Merge(KnownMarks(values)), Issue = timedOut ? "file-time-budget" : gap!=null ? "filesystem-member-uncertain-position" : receiver.Issue,
                    SourceRef = "filesystem collection." + property };
            }

            Payload CollectElements(IEnumerable<Payload> items)
            {
                var records = new List<Payload>();
                var tags = new Dictionary<(string, string), Mark>();
                var tailTags = new Dictionary<(string, string), Mark>();
                var tailPaths = new HashSet<FileReference>();
                bool truncated = false, stringTail = true;
                foreach (var item in items)
                {
                    bool overflow = records.Count >= Limits.MaxCollection;
                    if (!overflow) records.Add(item);
                    else
                    {
                        truncated = true;
                        stringTail &= item.IsString;
                        tailPaths.UnionWith(FilePathCandidates(item));
                    }
                    foreach (var mark in KnownMarks(new[] { item }))
                    {
                        tags[(mark.Id, mark.Origin)] = mark;
                        if (overflow) tailTags[(mark.Id, mark.Origin)] = mark;
                    }
                    if (!Budget()) { truncated = true; stringTail = false; break; }
                }
                return new Payload { Elements = records.ToArray(), Complete = !truncated,
                    FirstUncertainIndex = truncated ? records.Count : (int?)null,
                    RecordRemainder = truncated ? new Payload { InspectionPartial = true, IsString = stringTail,
                        Tags = Merge(tailTags.Values), PathAlternatives = tailPaths.Count == 0 ? null : tailPaths.ToArray(),
                        Issue = "array-materialization-limit" } : null,
                    InspectionPartial = truncated, Tags = truncated ? Merge(tags.Values) : Array.Empty<Mark>(),
                    SourceRef = "array", Issue = truncated ? "array-materialization-limit" : "" };
            }

            Payload IntegerRange(Payload first, Payload last)
            {
                if (!first.Complete || !last.Complete || first.NumericType is not ("Int32" or "Int64") ||
                    last.NumericType is not ("Int32" or "Int64") ||
                    !int.TryParse(first.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var start) ||
                    !int.TryParse(last.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var end))
                    return Missing("range-endpoints");
                long count = Math.Abs((long)end - start) + 1;
                if (count > Limits.MaxCollection) return Missing("range-limit");
                var items = new Payload[(int)count];
                int step = start <= end ? 1 : -1;
                for (int i = 0; i < items.Length; i++)
                {
                    var number = start + i * step;
                    var item = Text(number.ToString(CultureInfo.InvariantCulture), "range item");
                    item.IsString = false;
                    item.NumericType = "Int32";
                    item.ScalarTruth = number != 0;
                    items[i] = item;
                }
                return new Payload { Elements = items, Complete = true, SourceRef = "integer range" };
            }

            static bool ComparisonOperator(string op) => op is "Ieq" or "Ceq" or "Ine" or "Cne" or
                "Ilt" or "Clt" or "Ile" or "Cle" or "Igt" or "Cgt" or "Ige" or "Cge";
            Payload CompareScalars(string op, Payload left, Payload right)
            {
                if (!left.Complete || !right.Complete || left.Text == null || right.Text == null)
                    return Missing("comparison-value");
                int order;
                if (left.NumericType is ("Int32" or "Int64") && right.NumericType is ("Int32" or "Int64") &&
                    long.TryParse(left.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out long a) &&
                    long.TryParse(right.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out long b))
                    order = a.CompareTo(b);
                else if (left.IsString && right.IsString)
                    order = CultureInfo.InvariantCulture.CompareInfo.Compare(left.Text, right.Text,
                        op[0] == 'I' ? CompareOptions.IgnoreCase : CompareOptions.None);
                else return Missing("comparison-type");
                bool truth = op.Substring(1) switch
                {
                    "eq" => order == 0, "ne" => order != 0, "lt" => order < 0,
                    "le" => order <= 0, "gt" => order > 0, _ => order >= 0
                };
                return new Payload { Text = truth ? "True" : "False", Complete = true, ScalarTruth = truth,
                    SourceRef = "comparison" };
            }

            bool UpdateTrackedMap(object assignment)
            {
                if (Str(Prop(assignment, "Operator")) != "Equals") return false;
                var left = Prop(assignment, "Left");
                var kind = Kind(left);
                var variable = kind == "IndexExpressionAst" ? VarName(Prop(left, "Target")) :
                    kind == "MemberExpressionAst" && Equals(Prop(left, "Static"), false) ? VarName(Prop(left, "Expression")) : "";
                if (!SafeName(variable)) return false;
                var container = Variable(variable);
                if (container.Map == null) return false;
                var key = kind == "IndexExpressionAst" ? Value(Prop(left, "Index")).Text : Literal(Prop(left, "Member"));
                if (key == null || (!container.Map.ContainsKey(key) && container.Map.Count >= Limits.MaxCollection)) return false;
                var expression = Prop(SingleElement(Prop(assignment, "Right")), "Expression");
                var added = expression == null ? Pipeline(Prop(assignment, "Right")) ?? Missing("map-value") : Value(expression);
                // Copy on write keeps earlier branch snapshots intact. All aliases
                // reachable from the current scope see the same replacement table.
                var original = container.Map;
                var rewritten = new Dictionary<Payload, Payload>();
                var tables = new Dictionary<Dictionary<string, Payload>, Dictionary<string, Payload>>();
                Payload Rewrite(Payload value, int depth)
                {
                    if (rewritten.TryGetValue(value, out var prior)) return prior;
                    if (value.Map == null && value.Elements == null) return value;
                    if (!StackAvailable || depth > MaxExpressionDepth) return UnknownValue("map-depth", value);
                    var copy = value.Copy();
                    rewritten.Add(value, copy);
                    if (value.Elements != null) copy.Elements = value.Elements.Select(v => Rewrite(v, depth + 1)).ToArray();
                    if (value.Map != null)
                    {
                        if (!tables.TryGetValue(value.Map, out var map))
                        {
                            map = new Dictionary<string, Payload>(value.Map.Comparer);
                            tables.Add(value.Map, map);
                            foreach (var pair in value.Map) map[pair.Key] = Rewrite(pair.Value, depth + 1);
                            if (ReferenceEquals(value.Map, original)) map[key] = Rewrite(added, depth + 1);
                        }
                        copy.Map = map;
                    }
                    return copy;
                }
                foreach (var name in values.Keys.ToArray()) values[name] = Rewrite(values[name], 0);
                foreach (var name in plan.Assignments.Keys.ToArray()) plan.Assignments[name] = Rewrite(plan.Assignments[name], 0);
                values[Key(variable)] = Rewrite(container, 0);
                return true;
            }

            Payload PartialString(string reason, IEnumerable<Payload> pieces) => new Payload {
                IsString = true, InspectionPartial = true, Issue = reason,
                // Interpolation/Join do not serialize arbitrary object properties or read files.
                Tags = Merge(pieces.Where(v => v.IsString || v.NumericType != null ||
                    v.ScalarTruth.HasValue && v.Text != null && v.Map == null && v.Elements == null)
                    .SelectMany(v => v.Tags))
            };

            Payload ComposedText(string value, string step, IEnumerable<Mark> inherited, IEnumerable<(int Start, Mark Tag)> positions)
            {
                var result = Text(value, step);
                result.Tags = Merge(result.Tags.Concat(inherited.Select(m => m.Via(step))));
                // Include matches that first appear across a boundary, not just the offsets
                // copied from the inputs. Do not give every inherited mark offset zero.
                result.TagPositions = (result.TagPositions ?? Array.Empty<(int Start, Mark Tag)>()).Concat(positions)
                    .GroupBy(p => (p.Start, p.Tag.Id, p.Tag.Origin)).Select(g => g.First()).Take(Limits.MaxPositions).ToArray();
                return result;
            }

            Payload? JoinArray(Payload input, Payload separator)
            {
                if (input.Elements == null) return null;
                Payload Incomplete(string why)
                {
                    var pieces = input.Elements.AsEnumerable();
                    if (input.RecordRemainder is Payload rest) pieces = pieces.Append(rest);
                    if (input.Elements.Length > 1) pieces = pieces.Append(separator);
                    return PartialString(why, pieces);
                }
                if (!input.Complete || input.InspectionPartial || input.RecordRemainder != null ||
                    input.FirstUncertainIndex != null || !separator.Complete || separator.InspectionPartial ||
                    separator.Text == null || input.Elements.Any(p => !p.Complete || p.InspectionPartial || p.Text == null))
                    return Incomplete("join-input");
                long length = input.Elements.Sum(p => (long)p.Text!.Length) +
                    (long)Math.Max(0, input.Elements.Length - 1) * separator.Text.Length;
                if (length > MaxContent) return Incomplete("join-limit");
                return Text(string.Join(separator.Text, input.Elements.Select(p => p.Text)), "join array",
                    Merge(input.Elements.SelectMany(p => p.Tags).Concat(input.Elements.Length > 1 ? separator.Tags : Array.Empty<Mark>())));
            }
            Payload ReplaceString(Payload input, Payload oldValue, Payload newValue)
            {
                if (!input.Complete || !input.IsString || input.Text == null ||
                    !oldValue.Complete || !oldValue.IsString || string.IsNullOrEmpty(oldValue.Text) ||
                    !newValue.Complete || !newValue.IsString || newValue.Text == null)
                    return Missing("string-replace-input");
                int index = input.Text.IndexOf(oldValue.Text, StringComparison.Ordinal);
                if (index < 0) return input;
                var retained = Merge(FileRecordMarks(input).Concat(newValue.Tags));
                long length = input.Text.Length;
                if (newValue.Text.Length > oldValue.Text.Length)
                {
                    for (; index >= 0; index = input.Text.IndexOf(oldValue.Text, index + oldValue.Text.Length, StringComparison.Ordinal))
                    {
                        length += newValue.Text.Length - oldValue.Text.Length;
                        if (length * sizeof(char) > MaxContent || !Budget())
                            return new Payload { IsString = true, InspectionPartial = true, Tags = retained, Issue = "string-replace-limit" };
                    }
                }
                var output = input.Text.Replace(oldValue.Text, newValue.Text);
                // Content-based matches are recomputed; preserve sensitive origins such as configured files.
                return Text(output, "string replace", Merge(retained.Select(m => m.Via("string replace"))));
            }
            Payload EvaluateSubExpression(object? node, int depth)
            {
                var block = Prop(node, "SubExpression");
                if (Items(Prop(block, "Traps")).Any()) return Missing("subexpression-traps");
                var statements = Items(Prop(block, "Statements")).Take(ProbeCount(MaxStatements)).ToArray();
                if (statements.Length == 1)
                {
                    var expression = Prop(SingleElement(statements[0]), "Expression");
                    if (expression != null) return Value(expression, depth + 1);
                    if (Kind(statements[0]) is "PipelineAst" or "PipelineChainAst")
                        return Pipeline(statements[0], depth + 1) ?? Missing("subexpression-output");
                }
                AnalyzeStatements(statements, depth + 1);
                return Missing("subexpression-output");
            }

            static object? SubExpression(object? node)
            {
                var block = Prop(node, "SubExpression");
                if (Items(Prop(block, "Traps")).Any()) return null;
                var statements = Items(Prop(block, "Statements")).Take(2).ToArray();
                return statements.Length == 1 ? Prop(SingleElement(statements[0]), "Expression") : null;
            }
            Payload Expand(object? node, int depth)
            {
                // The host parser has already handled quoting, escapes and here-strings.
                // We only substitute analysed scalar expressions into its format template.
                if (InternalProp(node, "FormatExpression") is not string template || template.Length > MaxContent)
                    return Missing("string-expansion-shape");
                var expansions = Items(Prop(node, "NestedExpressions")).Take(ProbeCount(Limits.MaxCollection)).ToArray();
                if (expansions.Length > Limits.MaxCollection) return Missing("string-expansion-limit");
                var chars = new StringBuilder();
                var marks = new List<Mark>();
                var positions = new List<(int Start, Mark Tag)>();
                var values = new Payload[expansions.Length];
                for (int i = 0; i < expansions.Length; i++) values[i] = Value(expansions[i], depth + 1);
                Payload IncompleteExpansion(string why)
                {
                    var partial = PartialString(why, values);
                    var known = new StringBuilder();
                    var confirmed = new List<Mark>();
                    void Flush()
                    {
                        if (known.Length == 0) return;
                        confirmed.AddRange(Text(known.ToString(), "string expansion").Tags);
                        known.Clear();
                    }
                    // Known runs are independent of substitutions on either side. Never
                    // construct a new literal match across an unknown substitution.
                    for (int i = 0; i < template.Length && Budget(); i++)
                    {
                        char c = template[i];
                        if (c != '{' && c != '}') known.Append(c);
                        else if (i + 1 < template.Length && template[i+1] == c) { known.Append(c); i++; }
                        else
                        {
                            int end = c == '{' ? template.IndexOf('}', i+1) : -1;
                            if (end < 0 || end - i > 11 || !int.TryParse(template.Substring(i+1, end-i-1),
                                NumberStyles.None, CultureInfo.InvariantCulture, out var index) || index >= values.Length) break;
                            var p = values[index];
                            if (!p.Complete || p.InspectionPartial || p.Text == null) Flush();
                            else if ((long)known.Length + p.Text.Length <= MaxContent / sizeof(char)) known.Append(p.Text);
                            else { Flush(); if (p.Text.Length <= MaxContent / sizeof(char)) known.Append(p.Text); }
                            i = end;
                        }
                        if (known.Length >= MaxContent / sizeof(char)) Flush();
                    }
                    Flush();
                    partial.Tags = Merge(partial.Tags.Concat(confirmed));
                    return partial;
                }
                if (values.Any(p => !p.Complete || p.InspectionPartial || p.Text == null))
                    return IncompleteExpansion("string-expansion-value");
                for (int o = 0; o < template.Length; o++)
                {
                    char c = template[o];
                    if (c != '{' && c != '}') chars.Append(c);
                    else if (o + 1 < template.Length && template[o + 1] == c)
                    { chars.Append(c); o++; }
                    else if (c == '{')
                    {
                        int end = template.IndexOf('}', o + 1);
                        if (end < 0 || end - o > 11 ||
                            !int.TryParse(template.Substring(o + 1, end - o - 1), NumberStyles.None, CultureInfo.InvariantCulture, out int i) ||
                            i < 0 || i >= values.Length) return Missing("string-expansion-template");
                        var p = values[i];
                        if (chars.Length + (long)p.Text!.Length > MaxContent) return IncompleteExpansion("string-expansion-limit");
                        positions.AddRange(Positions(p, chars.Length, "string expansion"));
                        chars.Append(p.Text);
                        marks.AddRange(p.Tags);
                        o = end;
                    }
                    else return Missing("string-expansion-template");
                    if (chars.Length > MaxContent || marks.Count > Limits.MaxPositions) return IncompleteExpansion("string-expansion-limit");
                }
                return ComposedText(chars.ToString(), "string expansion", marks, positions);
            }
            Payload SnapshotPayload(object value, string origin, int depth = 0)
            {
                if (!StackAvailable || depth >= Limits.MaxExpressionDepth) return Missing("runtime-value-depth");
                if (value is byte[] bytes) return Bytes(bytes, origin);
                if (value is FileReference file)
                    return new Payload { FileObject = file, Complete = true, SourceRef = origin };
                if (value is Dictionary<string, object> map)
                    return new Payload { Map = map.ToDictionary(p => p.Key, p => SnapshotPayload(p.Value, origin, depth + 1),
                        StringComparer.OrdinalIgnoreCase), Complete = true, SourceRef = origin };
                if (value is SnapshotRecords captured)
                {
                    var records = captured.Items.Select(v => SnapshotPayload(v, origin, depth + 1)).ToArray();
                    return new Payload { Elements = records, Complete = !captured.Truncated, InspectionPartial = captured.Truncated,
                        Tags = captured.Truncated ? Merge(KnownMarks(records)) : Array.Empty<Mark>(), SourceRef = origin,
                        Issue = captured.Truncated ? "runtime-collection-limit" : "" };
                }
                if (value is object[] items)
                    return new Payload { Elements = items.Select(x => SnapshotPayload(x, origin, depth + 1)).ToArray(),
                        Complete = true, SourceRef = origin };
                if (value is string text) return Text(text, origin);
                if (value is Observed scalar)
                {
                    if (!scalar.Known || scalar.Text == null) return Missing(scalar.Source);
                    var typed = Text(scalar.Text, origin, scalar.Marks);
                    typed.IsString = scalar.Type is "String" or "Char";
                    typed.ScalarTruth = ScalarTruth(scalar.Type, scalar.Text);
                    if (NumericScalar(scalar.Type)) typed.NumericType = scalar.Type;
                    return typed;
                }
                return Missing("runtime-value-shape");
            }
        }

        sealed class SnapshotRecords
        {
            internal readonly object[] Items;
            internal readonly bool Truncated;
            internal SnapshotRecords(object[] items, bool truncated) { Items = items; Truncated = truncated; }
        }

        static object? Snapshot(object? value, int depth, ref int budget)
        {
            if (!StackAvailable || depth > Limits.MaxExpressionDepth || budget-- <= 0) return null;
            value = UnwrapHostValue(value);
            if (value == null) return null;
            if (value is byte[] bytes) return bytes.Length <= MaxContent ? bytes.ToArray() : null;
            if (value is FileSystemInfo fsItem && (fsItem.GetType() == typeof(FileInfo) || fsItem.GetType() == typeof(DirectoryInfo)))
            {
                var path = fsItem.FullName;
                return path.Length <= Limits.MaxRuntimeChars ?
                    new FileReference(path, fsItem is DirectoryInfo ? PathKind.DirectoryInfo : PathKind.FileInfo) : null;
            }
            if (value is IDictionary table &&
                (value.GetType() == typeof(Hashtable) || value.GetType() == typeof(System.Collections.Specialized.OrderedDictionary) ||
                 (value.GetType().FullName == "System.Management.Automation.DefaultParameterDictionary" &&
                  value.GetType().Assembly.GetName().Name == "System.Management.Automation")))
            {
                if (table.Count > Limits.MaxCollection) return null;
                var map = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                foreach (DictionaryEntry entry in table)
                {
                    if (entry.Key is not string key || key.Length > Limits.MaxRuntimeChars || map.ContainsKey(key)) return null;
                    // Preserve other independently known entries if one value is unsupported.
                    map.Add(key, Snapshot(entry.Value, depth + 1, ref budget) ?? Unknown("runtime-map-entry"));
                }
                return map;
            }
            if (value is IList items && (value is Array array && array.Rank == 1 && array.GetLowerBound(0) == 0 ||
                value.GetType() == typeof(ArrayList) || value.GetType() == typeof(List<System.IO.FileInfo>) ||
                value.GetType() == typeof(System.Collections.ObjectModel.Collection<System.IO.FileInfo>) ||
                value.GetType() == typeof(List<DirectoryInfo>) || value.GetType() == typeof(System.Collections.ObjectModel.Collection<DirectoryInfo>) ||
                value.GetType() == typeof(List<FileSystemInfo>) || value.GetType() == typeof(System.Collections.ObjectModel.Collection<FileSystemInfo>)))
            {
                int count = Math.Min(items.Count, Math.Max(0, Math.Min(Limits.MaxCollection, budget)));
                var copy = new object[count];
                for (int i = 0; i < count; i++)
                    copy[i] = Snapshot(items[i], depth + 1, ref budget) ?? Unknown("runtime-array-entry");
                return count == items.Count ? (object)copy : new SnapshotRecords(copy, true);
            }
            if (value is string s && s.Length <= Limits.MaxRuntimeChars) return s;

            if (value is bool or byte or sbyte or short or ushort or int or uint or long or ulong or float or double or decimal or char)
                return Scalar(value, "runtime");
            return null;
        }
    }
}

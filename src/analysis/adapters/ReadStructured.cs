using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.XPath;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            Payload ReadStructured(object command, string name, Payload? pipe)
            {
                bool json = name == "convertfrom-json", select = name == "select-xml";
                var parameters = json ? new[] { "InputObject" } : select ? Paths.Concat(new[] { "XPath", "Content", "Namespace" }).ToArray() : Paths;
                using var args = new Args(this, command, parameters, json ? new[] { "AsHashtable", "NoEnumerate" } : Empty);
                int pos = 0;
                var xpath = select ? args.Get("XPath") ?? args.Plain.ElementAtOrDefault(pos++) : null;
                var node = json ? args.Get("InputObject") : select ? args.Get("Content") : null;
                bool inline = json || node != null;
                var pathNode = args.Get("Path") ?? args.Get("LiteralPath");
                if (node == null && pathNode == null && pos < args.Plain.Count)
                { if (json) node = args.Plain[pos++]; else pathNode = args.Plain[pos++]; }
                if (!args.Valid || args.Plain.Count != pos || args.Has("Path") && args.Has("LiteralPath") ||
                    (node != null ? 1 : 0) + (pathNode != null ? 1 : 0) + (pipe != null ? 1 : 0) != 1 ||
                    select && xpath == null) return Missing("structured-read-binding");
                var query = select ? ExactString(Value(xpath)) : null;
                var namespaces = args.Has("Namespace") ? Value(args.Get("Namespace")) : null;
                var input = pipe ?? Value(pathNode ?? node);
                if (json && pipe != null) return ReadJsonPipeline(input, args.Has("AsHashtable"), args.Has("NoEnumerate"));
                IEnumerable<Payload> Rows()
                {
                    var sources = inline ? input.Elements ?? new[] { input } : SelectFilePaths(input, args);
                    foreach (var item in sources)
                    {
                        if (!Budget()) { yield return Missing("structured-read-budget"); yield break; }
                        var src = inline ? item : ReadFileArgument(item, true);
                        if (!src.Complete || src.InspectionPartial || item.InspectionPartial || src.Text == null)
                        { yield return Missing("structured-read-content"); continue; }
                        var result = name == "import-powershelldatafile" ? ReadDataLiteral(command, src) :
                            ParseReadDocument(name, src, query, namespaces, args.Has("AsHashtable"));
                        if (args.Has("NoEnumerate") || result.Elements == null) yield return result;
                        else
                        {
                            foreach (var value in result.Elements) yield return value;
                            if (result.InspectionPartial) yield return Missing("structured-read-remainder");
                        }
                    }
                    if (input.InspectionPartial) yield return Missing("structured-read-input");
                }
                return ReadOutput(Rows(), name);
            }

            Payload ReadJsonPipeline(Payload input, bool hashtable, bool noEnumerate)
            {
                IEnumerable<Payload> Inputs()
                {
                    if (input.Elements != null)
                    {
                        foreach (var item in input.Elements) yield return item;
                    }
                    else if (input.Text == null && input.PipeText is string wire && input.Complete && !input.InspectionPartial)
                    {
                        var marks = FileRecordMarks(input);
                        using var reader = new StringReader(wire);
                        while (reader.ReadLine() is string line)
                        {
                            if (!Budget()) { yield return Missing("json-input-budget"); yield break; }
                            yield return Text(line, input.SourceRef, marks);
                        }
                    }
                    else yield return input;
                }
                var rows = Inputs().Take(Limits.MaxLines + 1).ToArray();
                bool complete = input.Complete && !input.InspectionPartial && input.RecordRemainder == null &&
                    input.FirstUncertainIndex == null && rows.Length <= Limits.MaxLines;
                bool Materialized(Payload p) => p.Complete && !p.InspectionPartial && p.Text != null && p.Map == null &&
                    p.Elements == null && (p.IsString || p.PipeText != null) && p.Text.Length <= MaxContent / sizeof(char);
                Payload Parse(Payload src) => ParseReadDocument("convertfrom-json", src, null, null, hashtable);
                IEnumerable<Payload> Expand(Payload result)
                {
                    if (noEnumerate || result.Elements == null) yield return result;
                    else
                    {
                        foreach (var item in result.Elements) yield return item;
                        if (result.InspectionPartial) yield return Missing("json-array-remainder");
                    }
                }
                IEnumerable<Payload> Documents()
                {
                    if (rows.Length == 0) { if (!complete) yield return Missing("json-input-incomplete"); yield break; }
                    if (input.FirstUncertainIndex == 0) { yield return Missing("json-first-record-order"); yield break; }
                    if (!Materialized(rows[0]) || !Budget()) { yield return Missing("json-first-record"); yield break; }
                    var first = Parse(rows[0]);
                    if (rows.Length > 1 && first.Issue is ("structured-document-invalid" or "json-null"))
                    {
                        if (!complete || rows.Any(p => !Materialized(p)) ||
                            rows.Sum(p => (long)p.Text!.Length + Environment.NewLine.Length) > MaxContent / sizeof(char))
                        { yield return Missing("json-fragments-incomplete"); yield break; }
                        var inherited = FileRecordMarks(rows[0]);
                        var origins = inherited.Select(m => (m.Id, m.Origin)).ToHashSet();
                        if (rows.Skip(1).Any(p => !Budget() || !origins.SetEquals(FileRecordMarks(p).Select(m => (m.Id, m.Origin)))))
                        { yield return Missing("json-fragment-field-origins"); yield break; }
                        var origin = rows.All(p => p.SourceRef == rows[0].SourceRef) ? rows[0].SourceRef : "JSON pipeline";
                        var joined = Text(string.Join(Environment.NewLine, rows.Select(p => p.Text)), origin, inherited);
                        foreach (var item in Expand(Parse(joined))) yield return item;
                        yield break;
                    }
                    for (int i = 0; i < Math.Min(rows.Length, Limits.MaxLines); i++)
                    {
                        if (input.FirstUncertainIndex is int gap && i >= gap) { yield return Missing("json-record-order"); yield break; }
                        if (!Budget() || !Materialized(rows[i])) { yield return Missing("json-record-incomplete"); yield break; }
                        var result = i == 0 ? first : Parse(rows[i]);
                        foreach (var item in Expand(result)) yield return item;
                        if (!result.Complete || result.InspectionPartial) yield break;
                    }
                    if (!complete) yield return Missing("json-record-remainder");
                }
                return ReadOutput(Documents(), "ConvertFrom-Json");
            }

            Payload StringDataRecord(Payload src, char separator)
            {
                if (!src.Complete || src.Text == null || src.InspectionPartial) return UnknownValue("stringdata-input", src);
                var fields = new Dictionary<string, Payload>(StringComparer.OrdinalIgnoreCase);
                var marks = FileRecordMarks(src);
                foreach (string raw in src.Text.Split('\n'))
                {
                    if (!Budget() || fields.Count >= Limits.MaxCollection) return Missing("stringdata-budget");
                    string line = raw.Trim();
                    if (line.Length == 0 || line[0] == '#') continue;
                    int eq = line.IndexOf(separator);
                    if (eq < 1) return Missing("stringdata-line");
                    var key = line.Substring(0, eq).Trim();
                    if (fields.ContainsKey(key)) return Missing("stringdata-duplicate");
                    try { fields[key] = Text(Regex.Unescape(line.Substring(eq + 1).Trim()), src.SourceRef, marks); }
                    catch (ArgumentException) { return Missing("stringdata-escape"); }
                }
                return new Payload { Map = fields, Complete = true, SourceRef = src.SourceRef, Tags = marks };
            }
            Payload ReadStringData(object command, Payload? pipe)
            {
                using var args = new Args(this, command, new[] { "StringData", "Delimiter" }, Empty);
                var node = args.Get("StringData") ?? args.Plain.FirstOrDefault();
                if (!args.Valid || args.Plain.Count != (node == null || args.Has("StringData") ? 0 : 1) || (node == null) == (pipe == null))
                    return Missing("stringdata-binding");
                var sep = args.Has("Delimiter") ? ExactString(Value(args.Get("Delimiter"))) : "=";
                if (sep?.Length != 1) return Missing("stringdata-delimiter");
                var input = pipe ?? Value(node);
                var items = pipe != null ? IterationItems(input) ?? new[] { input } : new[] { input };
                return ReadOutput(items.Select(p => StringDataRecord(p, sep[0])), "ConvertFrom-StringData");
            }
            Payload ReadLocalizedData(object command, Payload? pipe)
            {
                using var args = new Args(this, command, new[] { "BindingVariable", "UICulture", "BaseDirectory", "FileName", "SupportedCommand" }, Empty);
                var binding = args.Get("BindingVariable") ?? args.Plain.FirstOrDefault();
                if (!args.Valid || pipe != null || args.Has("SupportedCommand") || args.Plain.Count != (args.Has("BindingVariable") || binding == null ? 0 : 1))
                    return Missing("localized-data-binding");
                var variable = binding == null ? null : ExactString(Value(binding));
                if (binding != null && (variable == null || !BareVariable(variable))) return Missing("localized-data-variable");
                Payload Finish(Payload v)
                {
                    if (variable == null) return v;
                    values[Key(variable)] = plan.Assignments[Key(variable)] = v.Via("$" + variable);
                    return Missing("no-expression-output");
                }
                var script = Prop(Prop(command, "Extent"), "File") as string;
                var filename = args.Has("FileName") ? ExactString(Value(args.Get("FileName"))) : Path.GetFileName(script);
                var dir = args.Has("BaseDirectory") ? ExactString(Value(args.Get("BaseDirectory"))) :
                    string.IsNullOrEmpty(script) ? cwd : Path.GetDirectoryName(script);
                var baseDir = Disk.Bind(dir, cwd);
                var cultureName = args.Has("UICulture") ? ExactString(Value(args.Get("UICulture"))) : CultureInfo.CurrentUICulture.Name;
                if (barrier || filename == null || !ArchivePart(filename) || baseDir == null || cultureName == null) return Finish(Missing("localized-data-path"));
                CultureInfo culture;
                try { culture = CultureInfo.GetCultureInfo(cultureName); }
                catch (CultureNotFoundException) { return Finish(Missing("localized-data-culture")); }
                var cultures = new List<CultureInfo> { culture };
                if (!args.Has("UICulture") && !culture.Name.Equals("en-US", StringComparison.OrdinalIgnoreCase)) cultures.Add(CultureInfo.GetCultureInfo("en-US"));
                var folders = new List<string>();
                foreach (var first in cultures)
                    for (var c = first; c.Name.Length > 0 && folders.Count < Limits.MaxPathDepth; c = c.Parent)
                        folders.Add(c.Name);
                foreach (var folder in folders.Append("").Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    var path = Path.Combine(baseDir, folder, Path.GetFileNameWithoutExtension(filename) + ".psd1");
                    if (!ArchiveDestination(path, false, out bool exists, new HashSet<string>(StringComparer.OrdinalIgnoreCase)))
                        return Finish(Missing("localized-data-location"));
                    if (!exists) continue;
                    var input = File(path, true, out _);
                    if (!input.Complete || input.InspectionPartial || input.Text == null) return Finish(UnknownValue("localized-data-content", input));
                    return Finish(ReadDataLiteral(command, input, localized: true));
                }
                return Finish(Missing("localized-data-not-found"));
            }
            Payload ReadDataLiteral(object command, Payload src, bool localized = false)
            {
                var text = src.Text!;
                // Never invoke a ScriptBlock, resolve an imported module, or evaluate a data-file expression.
                if (text.IndexOf("using", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    text.IndexOf("#requires", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    text.IndexOf("class", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    text.IndexOf("enum", StringComparison.OrdinalIgnoreCase) >= 0) return Missing("data-file-directive");
                var parser = command.GetType().Assembly.GetType("System.Management.Automation.Language.Parser");
                var parse = parser?.GetMethods().SingleOrDefault(m => m.Name == "ParseInput" && m.GetParameters().Length == 3);
                if (parse == null) return Missing("data-file-parser");
                var argv = new object?[] { text, null, null };
                object? root;
                try { root = parse.Invoke(null, argv); }
                catch (TargetInvocationException) { return Missing("data-file-parser"); }
                var statements = Items(Prop(Prop(root, "EndBlock"), "Statements")).Take(2).ToArray();
                var element = statements.Length == 1 ? SingleElement(statements[0]) : null;
                var expression = Prop(element, "Expression");
                if (Items(argv[2]).Any() || element == null ||
                    new[] { "BeginBlock", "ProcessBlock", "CleanBlock", "ParamBlock" }.Any(k => Prop(root, k) != null))
                    return Missing("data-file-shape");
                if (localized && Kind(element) == "CommandAst" && Name(element) == "convertfrom-stringdata" &&
                    !flow.IsShadowed("convertfrom-stringdata") && Str(Prop(element, "InvocationOperator")) == "Unknown")
                {
                    var parts = Items(Prop(element, "CommandElements")).ToArray();
                    return parts.Length == 2 && Literal(parts[1]) is string literal ? StringDataRecord(Text(literal, src.SourceRef, FileRecordMarks(src)), '=') :
                        Missing("localized-data-command");
                }
                if (Kind(expression) != "HashtableAst") return Missing("data-file-shape");
                var marks = FileRecordMarks(src);
                int count = 0;
                Payload Visit(object? ast, int depth)
                {
                    if (++count > Limits.MaxJsonElements || !Budget() || depth > MaxExpressionDepth || !StackAvailable)
                        return Missing("data-file-limit");
                    if (Literal(ast) is string s) return Text(s, src.SourceRef, marks);
                    if (Kind(ast) == "ConstantExpressionAst" && Prop(ast, "Value") is object scalar)
                    {
                        var observed = Scalar(scalar, src.SourceRef);
                        if (!observed.Known || observed.Text == null) return Missing("data-file-scalar");
                        var p = Text(observed.Text, src.SourceRef, marks);
                        p.IsString = observed.Type is "String" or "Char";
                        p.ScalarTruth = ScalarTruth(observed.Type, observed.Text);
                        if (NumericScalar(observed.Type)) p.NumericType = observed.Type;
                        return p;
                    }
                    var v = VarName(ast).ToLowerInvariant();
                    if (v is "true" or "false") return new Payload { Text = v == "true" ? "True" : "False",
                        ScalarTruth = v == "true", Complete = true, Tags = marks };
                    if (Kind(ast) == "ArrayLiteralAst") return CollectElements(Items(Prop(ast, "Elements")).Select(n => Visit(n, depth + 1)));
                    if (Kind(ast) == "ArrayExpressionAst")
                    {
                        var block = Prop(ast, "SubExpression");
                        if (Items(Prop(block, "Traps")).Any()) return Missing("data-file-array");
                        return CollectElements(Items(Prop(block, "Statements")).Select(n => Visit(Prop(SingleElement(n), "Expression"), depth + 1))
                            .SelectMany(p => p.Elements ?? new[] { p }));
                    }
                    if (Kind(ast) != "HashtableAst") return Missing("data-file-nonliteral");
                    var map = new Dictionary<string, Payload>(StringComparer.OrdinalIgnoreCase);
                    foreach (var (key, val) in MapAst(ast))
                    {
                        if (map.Count >= Limits.MaxCollection || Literal(key) is not string k || map.ContainsKey(k))
                            return Missing("data-file-key");
                        map[k] = Visit(Prop(SingleElement(val), "Expression"), depth + 1);
                    }
                    return new Payload { Complete = true, Map = map, SourceRef = src.SourceRef };
                }
                return Visit(expression, 0);
            }

            Payload LoadXmlSource(Payload input, string kind, bool fileOrStream, bool whitespace)
            {
                var src = input;
                if (fileOrStream)
                {
                    if (CurrentHttp(input.HttpObject) is { Kind: HttpObjectKind.FileStream } stream) src = RemainingStream(stream, true);
                    else
                    {
                        var path = input.FileObject?.Kind == PathKind.FileInfo ? input.FileObject.Path : ExactString(input);
                        if (Disk.Bind(path, cwd) == null) return Missing("xml-local-file");
                        var read = File(path, false, out var sample, forceBytes: true, inspectArchive: false);
                        var bytes = sample?.Bytes ?? read.Bytes;
                        if (bytes == null || read.InspectionPartial) return UnknownValue("xml-file-content", read);
                        src = Bytes(bytes, read.SourceRef, FileRecordMarks(read));
                    }
                }
                else if (input.Elements != null)
                {
                    if (input.InspectionPartial || input.Elements.Any(v => !v.Complete || !v.IsString || v.Text == null) ||
                        input.Elements.Sum(p => (long)p.Text!.Length + 1) > MaxContent / 2)
                        return Missing("xml-input-lines");
                    // LanguagePrimitives.ConvertToXml supplies an explicit LF separator; it doesn't use $OFS.
                    src = Text(string.Join("\n", input.Elements.Select(v => v.Text)), input.SourceRef,
                        Merge(input.Elements.SelectMany(FileRecordMarks)));
                }
                else if (input.Complete && input.Text == null && input.PipeText is string records && !input.InspectionPartial)
                {
                    using var reader = new StringReader(records);
                    var lines = new List<string>(); string? line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (lines.Count >= Limits.MaxLines || !Budget()) return Missing("xml-input-lines");
                        lines.Add(line);
                    }
                    src = Text(string.Join("\n", lines), input.SourceRef, FileRecordMarks(input));
                }
                if (src.Bytes == null && (!src.Complete || src.Text == null) || src.InspectionPartial) return Missing("xml-input");
                return ParseReadDocument(kind, src, null, null, false, whitespace);
            }
            Payload XmlTree(XmlDocument doc, Payload src, bool linq)
            {
                var marks = FileRecordMarks(src);
                int nodes = 0; long remaining = MaxContent;
                Payload Data(string s)
                {
                    remaining -= (long)s.Length * 2;
                    return remaining >= 0 ? Text(s, src.SourceRef, marks) : Missing("xml-materialization-budget");
                }
                Payload Node(XmlElement element, int depth)
                {
                    if (!StackAvailable || depth > MaxExpressionDepth || ++nodes > Limits.MaxJsonElements || remaining < 0 || !Budget())
                        return Missing("xml-node-budget");
                    var innerText = Data(element.InnerText);
                    if (linq) return ReadObject("XElement", ("Value", innerText), ("Name", ReadObject("XName",
                        ("LocalName", Text(element.LocalName, "XML name")), ("NamespaceName", Text(element.NamespaceURI, "XML namespace")))));
                    var fields = new Dictionary<string, Payload>(StringComparer.OrdinalIgnoreCase) {
                        ["InnerText"] = innerText, ["InnerXml"] = Data(element.InnerXml), ["OuterXml"] = Data(element.OuterXml),
                        ["Name"] = Text(element.Name, "XML element name"), ["LocalName"] = Text(element.LocalName, "XML local name"),
                        ["NamespaceURI"] = Text(element.NamespaceURI, "XML namespace") };
                    var adapted = new Dictionary<string, List<Payload>>(StringComparer.OrdinalIgnoreCase);
                    void Add(string key, Payload val)
                    {
                        if (!adapted.TryGetValue(key, out var list)) adapted[key] = list = new List<Payload>();
                        list.Add(val);
                    }
                    foreach (XmlAttribute attr in element.Attributes) Add(attr.LocalName, Data(attr.Value));
                    foreach (var child in element.ChildNodes.OfType<XmlElement>())
                    {
                        if (!Budget() || adapted.Count > Limits.MaxCollection) return Missing("xml-node-budget");
                        var simple = child.Attributes.Count == 0 && (child.ChildNodes.Count == 0 || child.ChildNodes.Count == 1 &&
                            child.FirstChild?.NodeType is (XmlNodeType.Text or XmlNodeType.CDATA));
                        Add(child.LocalName, simple ? Data(child.InnerText) : Node(child, depth + 1));
                    }
                    foreach (var pair in adapted) fields[pair.Key] = pair.Value.Count == 1 ? pair.Value[0] : CollectElements(pair.Value);
                    return new Payload { Map = fields, Complete = remaining >= 0, InspectionPartial = remaining < 0, Tags = marks, SourceRef = src.SourceRef };
                }
                var root = doc.DocumentElement!;
                var node = Node(root, 0);
                if (linq) return ReadObject("XDocument", ("Root", node));
                var tree = ReadObject("XmlDocument", ("DocumentElement", node), ("InnerText", Data(doc.InnerText)), ("OuterXml", Data(doc.OuterXml)));
                tree.Map![root.LocalName] = root.Attributes.Count == 0 && (root.ChildNodes.Count == 0 || root.ChildNodes.Count == 1 &&
                    root.FirstChild?.NodeType is (XmlNodeType.Text or XmlNodeType.CDATA)) ? Data(root.InnerText) : node;
                tree.Tags = Merge(marks.Concat(tree.Map["InnerText"].Tags));
                return tree;
            }
            Payload ParseReadDocument(string name, Payload src, string? query, Payload? namespaces, bool hashtable, bool whitespace = true)
            {
                var marks = FileRecordMarks(src);
                Payload Field(string s) => Text(s, src.SourceRef, marks);
                bool json = name is "convertfrom-json" or "jq";
                XmlReader Open()
                {
                    if (json) return JsonReaderWriterFactory.CreateJsonReader(StrictUtf8.GetBytes(src.Text!),
                        new XmlDictionaryReaderQuotas { MaxDepth = MaxExpressionDepth, MaxStringContentLength = MaxContent,
                            MaxArrayLength = Limits.MaxCollection, MaxNameTableCharCount = Limits.MaxJsonNames });
                    var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, IgnoreWhitespace = !whitespace,
                        XmlResolver = null, MaxCharactersInDocument = MaxContent, MaxCharactersFromEntities = MaxContent, CloseInput = true };
                    return src.Bytes != null && name is ("dom-xml" or "linq-xml") ? XmlReader.Create(new MemoryStream(src.Bytes, false), settings) :
                        XmlReader.Create(new StringReader(src.Text!), settings);
                }
                try
                {
                    // Bound both depth and node count before DOM operations such as InnerText.
                    using (var check = Open())
                    {
                        int n = 0;
                        while (check.Read()) if ((n += 1 + check.AttributeCount) > Limits.MaxJsonElements ||
                            check.Depth > MaxExpressionDepth || !Budget()) return Missing("structured-document-limit");
                    }
                    var doc = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
                    using (var reader = Open()) doc.Load(reader);
                    if (doc.DocumentElement is not XmlElement root) return Missing("structured-document");
                    if (name is "dom-xml" or "linq-xml") return XmlTree(doc, src, name == "linq-xml");
                    if (name == "select-xml")
                    {
                        // Only a bounded location path, not arbitrary XPath functions/axes.
                        if (query == null || query.Length > Limits.MaxFilter ||
                            !Regex.IsMatch(query, @"^\.?/{0,2}(?:[\w.:-]+|\*)(?:/(?:[\w.:-]+|\*))*?(?:/@[\w.:-]+|/text\(\))?$",
                                RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(30)) || query.Contains("::") || query.Contains(".."))
                            return Missing("select-xml-xpath");
                        var ns = new XmlNamespaceManager(doc.NameTable);
                        if (namespaces != null)
                        {
                            if (namespaces.Map == null || !namespaces.Complete) return Missing("select-xml-namespace");
                            foreach (var kv in namespaces.Map)
                            { if (ExactString(kv.Value) is not string uri) return Missing("select-xml-namespace"); ns.AddNamespace(kv.Key, uri); }
                        }
                        var nodes = doc.SelectNodes(query, ns);
                        if (nodes == null) return Missing("select-xml-result");
                        IEnumerable<Payload> Project()
                        {
                            long size = 0;
                            foreach (XmlNode n in nodes)
                            {
                                if (!Budget()) { yield return Missing("select-xml-budget"); yield break; }
                                var outer = n.OuterXml;
                                if ((size += outer.Length) * 2 > MaxContent) { yield return Missing("select-xml-output-limit"); yield break; }
                                var value = ReadObject("XmlNode", ("InnerText", Field(n.InnerText)), ("OuterXml", Field(outer)),
                                    ("InnerXml", Field(n.InnerXml)), ("Name", Field(n.Name)));
                                if (n.Value != null) value.Map!["Value"] = Field(n.Value);
                                yield return ReadObject("SelectXmlInfo", ("Node", value), ("Path", Text(Path.IsPathRooted(src.SourceRef) ? src.SourceRef : "InputStream", "xml input")));
                            }
                        }
                        return CollectElements(Project());
                    }
                    int visited = 0;
                    var refs = new Dictionary<string, Payload>();
                    Payload Decode(XmlElement el, int depth)
                    {
                        if (!StackAvailable || depth > MaxExpressionDepth || ++visited > Limits.MaxJsonElements || !Budget()) return Missing("structured-field-limit");
                        var type = json ? el.GetAttribute("type") : el.LocalName;
                        var children = el.ChildNodes.OfType<XmlElement>();
                        if (type == "null" && json) return new Payload { Complete = true, Issue = "json-null", SourceRef = src.SourceRef, Tags = marks };
                        if (type is "array" or "LST" or "QUE" or "STK") return CollectElements(children.Select(c => Decode(c, depth + 1)));
                        if (type == "Ref") return refs.TryGetValue(el.GetAttribute("RefId"), out var found) ? found : Missing("clixml-reference");
                        if (type is "object" or "Obj")
                        {
                            var map = new Dictionary<string, Payload>(hashtable ? StringComparer.Ordinal : StringComparer.OrdinalIgnoreCase);
                            var result = new Payload { Map = map, Complete = true, SourceRef = src.SourceRef,
                                ReadType = json ? hashtable ? "System.Management.Automation.OrderedHashtable" : "System.Management.Automation.PSCustomObject" : null };
                            var sequence = json ? null : children.FirstOrDefault(c => c.LocalName is "LST" or "QUE" or "STK");
                            if (sequence != null) result = Decode(sequence, depth + 1);
                            else
                            {
                                foreach (var c in json ? children : children.Where(e => e.LocalName is "Props" or "MS").SelectMany(e => e.ChildNodes.OfType<XmlElement>()))
                                {
                                    var k = json ? c.GetAttributeNode("item")?.Value ?? c.LocalName : XmlConvert.DecodeName(c.GetAttribute("N"));
                                    if (map.Count >= Limits.MaxCollection || map.ContainsKey(k)) return Missing("structured-field-key");
                                    map[k] = Decode(c, depth + 1);
                                }
                                if (!json && map.Count == 0) return Missing("clixml-object-shape");
                            }
                            if (!json && el.HasAttribute("RefId")) refs[el.GetAttribute("RefId")] = result;
                            return result;
                        }
                        if (type is "string" or "S") return Field(json ? el.InnerText : XmlConvert.DecodeName(el.InnerText));
                        if (type is "number" or "I32" or "I64") { var p = Field(el.InnerText); p.IsString = false;
                            p.NumericType = long.TryParse(p.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out _) ? "Int64" : "Double"; return p; }
                        if (type is "boolean" or "B" && bool.TryParse(el.InnerText, out var flag))
                            return new Payload { Text = flag ? "True" : "False", ScalarTruth = flag, Complete = true, Tags = marks };
                        return Missing("structured-field-" + (json ? "json" : "clixml"));
                    }
                    if (json) return Decode(root, 0);
                    if (root.LocalName != "Objs" || root.NamespaceURI != "http://schemas.microsoft.com/powershell/2004/04")
                        return Missing("clixml-document");
                    return CollectElements(root.ChildNodes.OfType<XmlElement>().Select(c => Decode(c, 0)));
                }
                catch (Exception e) when (e is XmlException or XPathException or ArgumentException or InvalidOperationException or
                    RegexMatchTimeoutException or FormatException or System.Runtime.Serialization.SerializationException)
                { return Missing("structured-document-invalid"); }
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            // The normal pipeline and policy stay shared. Only this table selects the native CLI dialect.
            static readonly Dictionary<string, Action<AdapterContext, object, Payload?>> NativeTransfers =
                new Dictionary<string, Action<AdapterContext, object, Payload?>>(StringComparer.Ordinal)
                {
                    ["curl"] = (ctx, cmd, pipe) => ctx.Curl(cmd, pipe),
                    ["wget"] = (ctx, cmd, pipe) => ctx.Wget(cmd, pipe),
                    ["scp"] = (ctx, cmd, pipe) => ctx.Scp(cmd),
                    ["sftp"] = (ctx, cmd, pipe) => ctx.Sftp(cmd, pipe),
                    ["robocopy"] = (ctx, cmd, pipe) => ctx.WindowsCopyTool("robocopy", cmd),
                    ["xcopy"] = (ctx, cmd, pipe) => ctx.WindowsCopyTool("xcopy", cmd),
                    ["ncat"] = (ctx, cmd, pipe) => ctx.Ncat(cmd, pipe)
                };

            sealed class NativeOption
            {
                internal readonly string Name;
                internal readonly bool TakesValue;
                internal NativeOption(string name, bool takesValue) { Name = name; TakesValue = takesValue; }
            }
            static Dictionary<string, NativeOption> NativeOptions(params string[] groups)
            {
                var result = new Dictionary<string, NativeOption>(StringComparer.Ordinal);
                foreach (var group in groups)
                {
                    var spellings = group.Split(' ');
                    bool value = spellings[0][0] == '+';
                    if (value) spellings[0] = spellings[0].Substring(1);
                    var option = new NativeOption(spellings[0], value);
                    foreach (var alias in spellings) result.Add(alias, option);
                }
                return result;
            }

            sealed class NativeArgument
            {
                internal readonly string? Text;
                internal readonly Payload? Value;
                internal NativeArgument(string? text, Payload? value) { Text = text; Value = value; }
            }
            sealed class NativeCall
            {
                internal readonly List<(string Name, NativeArgument Arg)> Options =
                    new List<(string, NativeArgument)>();
                internal readonly List<NativeArgument> Position = new List<NativeArgument>();
                internal string? Error;
                internal bool UncertainOperandOrder;
                internal bool Has(string name) => Options.Any(o => o.Name == name);
            }

            NativeCall ReadNative(object command, Dictionary<string, NativeOption> options, bool longEquals, bool exactShort = false,
                Dictionary<string, bool>? otherArity = null, Func<NativeCall, string, NativeArgument, NativeCall>? handleOption = null)
            {
                var flat = FlattenNative(command, out var bound);
                var call = new NativeCall();
                void Add(string name, NativeArgument value)
                {
                    if (handleOption == null) call.Options.Add((name, value));
                    else call = handleOption(call, name, value);
                }
                if (flat.Length > Limits.MaxArguments) call.Error = "argument-limit";
                bool positional = false;
                for (int i = 0; i < Math.Min(flat.Length, Limits.MaxArguments); i++)
                {
                    var arg = flat[i];
                    if (arg == null)
                    {
                        call.UncertainOperandOrder = true;
                        call.Error ??= "dynamic-argument";
                        call.Position.Add(new NativeArgument(null, bound[i]));
                        continue;
                    }
                    if (!positional && arg == "--") { positional = true; continue; }
                    if (positional || arg.Length < 2 || arg[0] != '-')
                    { call.Position.Add(new NativeArgument(arg, bound[i])); continue; }

                    bool isLong = arg.StartsWith("--", StringComparison.Ordinal);
                    if (exactShort && !isLong && options.TryGetValue(arg, out var exact) && !exact.TakesValue)
                    { Add(exact.Name, new NativeArgument(null, null)); continue; }
                    for (int j = 1; j < arg.Length; j++)
                    {
                        int equals = isLong && longEquals ? arg.IndexOf('=') : -1;
                        string name = isLong ? (equals < 0 ? arg : arg.Substring(0, equals)) : "-" + arg[j];
                        bool takesValue = false;
                        if (!options.TryGetValue(name, out var spec))
                        {
                            bool knownArity = otherArity != null && (otherArity.TryGetValue(name, out takesValue) ||
                                (name.StartsWith("--no-", StringComparison.Ordinal) &&
                                    otherArity.TryGetValue("--" + name.Substring(5), out var negated) && !negated));
                            if (!knownArity)
                            {
                                call.UncertainOperandOrder = true;
                                call.Error ??= "unsupported-option";
                                // Arity is unknown. The adjacent token may belong to this
                                // option. Resume at independently recognizable arguments.
                                if (equals < 0 && i + 1 < flat.Length && flat[i + 1]?.StartsWith("-", StringComparison.Ordinal) == false)
                                    i++;
                                break;
                            }
                            call.Error ??= "unmodeled-option";
                        }
                        if (!(spec?.TakesValue ?? takesValue))
                        {
                            if (equals >= 0) { call.Error ??= "flag-with-value"; break; }
                            if (spec != null) Add(spec.Name, new NativeArgument(null, null));
                            if (isLong) break;
                            continue;
                        }
                        string? inline = isLong ? (equals < 0 ? null : arg.Substring(equals + 1)) :
                            (j + 1 == arg.Length ? null : arg.Substring(j + 1));
                        if (inline != null)
                        {
                            if (spec != null) Add(spec.Name, new NativeArgument(inline, bound[i]));
                        }
                        else
                        {
                            if (++i == flat.Length) { call.Error = "missing-option-value"; return call; }
                            var value = new NativeArgument(flat[i], bound[i]);
                            if (spec != null) Add(spec.Name, value);
                            if (value.Text == null)
                            {
                                call.Error ??= "dynamic-option-value";
                                // An unresolved splat has no known width and can shift subsequent options.
                                if (value.Value == null)
                                { call.Error = "dynamic-argument-list"; call.UncertainOperandOrder = true; }
                            }
                        }
                        break;
                    }
                }
                return call;
            }

            // Start-Process joins ArgumentList with spaces before the target executable parses it.
            Payload? StartProcess(object command)
            {
                using var args = new Args(this, command, new[] { "FilePath", "ArgumentList", "WorkingDirectory", "RedirectStandardInput",
                    "RedirectStandardOutput", "RedirectStandardError", "WindowStyle", "Credential", "Verb", "Environment" },
                    new[] { "Wait", "NoNewWindow", "PassThru", "WhatIf", "Confirm", "UseNewEnvironment", "LoadUserProfile" });
                var fileNode = args.Get("FilePath") ?? args.Plain.FirstOrDefault();
                var executable = Value(fileNode);
                var tool = Tool(executable.Text?.ToLowerInvariant() ?? "");
                if (tool != "git" && !NativeTransfers.ContainsKey(tool))
                {
                    return args.Has("PassThru") ? Missing("process-output") : null;
                }
                int pos = args.Has("FilePath") ? 0 : 1;
                var listNode = args.Get("ArgumentList") ?? args.Plain.ElementAtOrDefault(pos);
                bool shellConflict = args.Has("Verb") && new[] { "Credential", "NoNewWindow", "LoadUserProfile", "UseNewEnvironment",
                    "RedirectStandardInput", "RedirectStandardOutput", "RedirectStandardError" }.Any(p => args.Has(p) || args.Disabled.Contains(p));
                if ((!args.Valid && !args.Uncertain) || args.Plain.Count > pos + (args.Has("ArgumentList") ? 0 : 1) ||
                    shellConflict || args.Has("WindowStyle") && args.Has("NoNewWindow"))
                { Send(tool, null, Array.Empty<Payload>(), "start-process-arguments"); return Missing("process-output"); }
                if (args.Has("WhatIf")) return null;
                var value = listNode == null ? null : Value(listNode);
                var list = value?.Elements ?? (value == null ? Array.Empty<Payload>() : new[] { value });
                bool incomplete = value?.InspectionPartial == true || list.Any(p => !p.Complete || p.Text == null) ||
                    list.Sum(p => (long)(p.Text?.Length ?? 0) + 1) > MaxContent;
                var argv = new List<Payload>();
                if (incomplete)
                {
                    // Keep opaque arguments at their original positions so the native
                    // adapter can still identify bodies, file operands and local options.
                    var run = new List<Payload>();
                    foreach (var item in list)
                    {
                        if (item.Complete && item.Text != null) { run.Add(item); continue; }
                        argv.AddRange(SplitProcessArguments(run));
                        run.Clear();
                        argv.Add(UnknownValue("start-process-argument", item));
                    }
                    argv.AddRange(SplitProcessArguments(run));
                    ReportMissing("start-process-argument-list");
                }
                else argv.AddRange(SplitProcessArguments(list));

                bool previousContext = uncertainProcessContext;
                bool changedContext = args.Uncertain || args.Has("Environment") || args.Has("UseNewEnvironment") ||
                    args.Has("Credential") || args.Has("LoadUserProfile") || args.Has("Verb");
                var parentDirectory = cwd;
                var stdin = args.Has("RedirectStandardInput") ? ReadFileArgument(Value(args.Get("RedirectStandardInput")), true) : null;
                foreach (var parameter in new[] { "RedirectStandardOutput", "RedirectStandardError" })
                    if (args.Has(parameter)) InvalidateOutputFile(Value(args.Get(parameter)));
                try
                {
                    uncertainProcessContext |= changedContext;
                    if (changedContext) ReportMissing("start-process-child-context");
                    if (args.Has("WorkingDirectory")) cwd = Disk.Bind(Value(args.Get("WorkingDirectory")).Text, parentDirectory);
                    if (tool == "git" && changedContext) ReportMissing("git-child-environment");
                    else if (tool == "git") Git(argv.ToArray());
                    else NativeTransfers[tool](this, argv.ToArray(), stdin);
                }
                finally { cwd = parentDirectory; uncertainProcessContext = previousContext; }
                return args.Has("PassThru") ? Missing("process-output") : null;
            }

            List<Payload> SplitProcessArguments(IReadOnlyList<Payload> list)
            {
                if (list.Sum(p => (long)p.Text!.Length + 1) > MaxContent) return list.ToList();
                var line = string.Join(" ", list.Select(p => p.Text));
                var argv = new List<Payload>();
                int cursor = 0, piece = 0, pieceStart = 0;
                while (cursor < line.Length)
                {
                    while (cursor < line.Length && (line[cursor] == ' ' || line[cursor] == '\t')) cursor++;
                    if (cursor == line.Length) break;
                    int start = cursor;
                    var word = new System.Text.StringBuilder();
                    bool quoted = false;
                    while (cursor < line.Length && (quoted || (line[cursor] != ' ' && line[cursor] != '\t')))
                    {
                        int slashes = 0;
                        while (cursor < line.Length && line[cursor] == (char)92) { slashes++; cursor++; }
                        if (cursor < line.Length && line[cursor] == '"')
                        {
                            word.Append((char)92, slashes / 2);
                            cursor++;
                            if ((slashes & 1) != 0) word.Append('"');
                            else if (quoted && cursor < line.Length && line[cursor] == '"') { word.Append('"'); cursor++; }
                            else quoted = !quoted;
                        }
                        else
                        {
                            word.Append((char)92, slashes);
                            if (cursor < line.Length && (quoted || (line[cursor] != ' ' && line[cursor] != '\t')))
                                word.Append(line[cursor++]);
                        }
                    }
                    while (piece < list.Count && pieceStart + list[piece].Text!.Length < start)
                        pieceStart += list[piece++].Text!.Length + 1;
                    var marks = new List<Mark>();
                    for (int i = piece, offset = pieceStart; i < list.Count && offset < cursor; i++)
                    {
                        // A literal match is checked on the actual child argument. File origins
                        // survive quoting and splitting of the original PowerShell string.
                        if (start <= offset && offset + list[i].Text!.Length <= cursor)
                            marks.AddRange(list[i].Tags);
                        else marks.AddRange(FileRecordMarks(list[i]));
                        offset += list[i].Text!.Length + 1;
                    }
                    argv.Add(Text(word.ToString(), "Start-Process argument", Merge(marks)));
                }
                return argv;
            }

            // A control stream can contain several PowerShell string records. Preserve
            // per-record origins and report any opaque record in place, never execute it.
            IEnumerable<Payload> TransferLines(Payload? source, string role)
            {
                if (source == null) { yield return Missing(role); yield break; }
                var records = source.Elements ?? new[] { source };
                int count = 0; long chars = 0;
                foreach (var record in records)
                {
                    if (!Budget() || ++count > Limits.MaxLines) { yield return Missing(role + "-limit"); yield break; }
                    var text = record.PipeText ?? record.Text;
                    if (!record.Complete || record.InspectionPartial || text == null ||
                        (source.Elements != null && !record.IsString && record.PipeText == null))
                    { yield return Missing(role + "-record"); continue; }
                    if ((chars += text.Length) > MaxContent) { yield return Missing(role + "-limit"); yield break; }
                    using var lines = new System.IO.StringReader(text);
                    int n = 0;
                    while (lines.ReadLine() is string line)
                    {
                        if (!Budget() || (n++ != 0 && ++count > Limits.MaxLines)) { yield return Missing(role + "-limit"); yield break; }
                        yield return Text(line, role, FileRecordMarks(record));
                    }
                }
                if (source.RecordRemainder != null || source.Elements != null && (!source.Complete || source.InspectionPartial))
                    yield return Missing(role + "-partial");
            }

            Payload NativeText(NativeArgument arg, string role) => arg.Text == null
                ? arg.Value == null ? Missing(role + "-value") : UnknownValue(role + "-value", arg.Value)
                : arg.Value?.Text == arg.Text ? arg.Value.Via(role) : Text(arg.Text, role, arg.Value?.Tags).Via(role);

            Payload NativeFile(string? path, string role, Payload? pipe = null, bool stdin = false)
            {
                if (string.IsNullOrWhiteSpace(path)) return Missing(role + "-path");
                if (stdin && path == "-") return pipe?.Bytes != null
                    ? new Payload { Tags = pipe.Bytes.Length == 0 ? Array.Empty<Mark>() : FileRecordMarks(pipe),
                        InspectionPartial = true, Issue = "stdin-byte-serialization" } : pipe ?? Missing("stdin-unresolved");
                if (path == "-") return Missing(role + "-path");
                return File(path, false, out _).Via(role);
            }
            void NativeSend(string tool, string? endpoint, List<Payload> parts, string? problem,
                Dictionary<Payload, Payload>? inspected = null, int? targetOrdinal = null)
            {
                if (problem == null && !barrier && TrustLoopback && LoopbackUri(endpoint))
                {
                    if (parts.Count != 0) SkipLoopback(tool, endpoint, targetOrdinal);
                    return;
                }
                if (problem != null || parts.Count != 0) Send(tool, endpoint, parts, problem, inspected, targetOrdinal);
            }
        }
    }
}

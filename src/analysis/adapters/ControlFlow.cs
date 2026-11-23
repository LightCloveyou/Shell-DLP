using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace PowerShell7Guard
{
    public static partial class AstBridge
    {
        sealed partial class AdapterContext
        {
            StatementExit AnalyzeLoop(object node, int depth, List<Payload>? output)
            {
                var kind = Kind(node);
                var condition = Prop(node, "Condition");
                var iterator = Prop(node, "Iterator");
                var body = Prop(node, "Body");
                var statements = Items(Prop(body, "Statements")).ToArray();
                var exits = new List<(StatementState State, StatementExit Exit)>();
                bool post = kind is "DoWhileStatementAst" or "DoUntilStatementAst";
                var init = Prop(node, "Initializer");
                if (init != null) AnalyzeStatements(new[] { init }, depth + 1);
                var iterations = new StatementState(this);
                bool? Test()
                {
                    if (condition == null) return true;
                    var value = Truth(Pipeline(condition, depth + 1) ?? Missing("loop-condition"));
                    return kind == "DoUntilStatementAst" ? !value : value;
                }
                for (int i = 0; ; i++)
                {
                    if (!post || i != 0)
                    {
                        var again = Test();
                        if (again != true) exits.Add((new StatementState(this), StatementExit.None));
                        if (again == false) { if (i == 0) SkipBranch(body); break; }
                    }
                    if (i >= MaxLoopIterations || !Budget())
                    {
                        iterations.Join(new StatementState(this));
                        exits.Add((iterations, StatementExit.None));
                        ReportMissing("loop-iteration-limit");
                        break;
                    }
                    ReachBranch(body);
                    var branches = new List<(StatementState State, StatementExit Exit)>();
                    var outcome = AnalyzeBlock(statements, depth + 1, branches, output);
                    branches.Add((new StatementState(this), outcome));
                    StatementState? next = null;
                    foreach (var (state, exit) in branches)
                    {
                        if (exit is StatementExit.None or StatementExit.Continue)
                        { if (next == null) next = state; else next.Join(state); }
                        else exits.Add((state, exit == StatementExit.Break ? StatementExit.None : exit));
                    }
                    if (next == null) break;
                    RestoreStatementState(next);
                    if (iterator != null) AnalyzeStatements(new[] { iterator }, depth + 1);
                    iterations.Join(new StatementState(this));
                }
                return MergeStatementPaths(exits);
            }

            StatementExit AnalyzeSwitch(object node, int depth, List<Payload>? output)
            {
                var flags = Str(Prop(node, "Flags"));
                var sequence = Pipeline(Prop(node, "Condition"), depth + 1);
                if (flags.Contains("File") && sequence != null)
                {
                    var contents = ReadFileArgument(sequence, true);
                    if (contents.Complete && contents.Text is string text)
                        sequence = new Payload { PipeText = text, Tags = contents.Tags, SourceRef = contents.SourceRef, Complete = true };
                    else sequence = UnknownValue("switch-file-records", contents);
                }
                var items = IterationItems(sequence);
                var exits = new List<(StatementState State, StatementExit Exit)>();
                var clauses = Items(Prop(node, "Clauses")).ToArray();
                var otherwise = Prop(node, "Default");
                bool caseSensitive = flags.Contains("CaseSensitive");
                var previous = Variable("_");
                if (items == null) exits.Add((new StatementState(this), StatementExit.None));
                var records = items ?? new[] { UnknownValue("switch-input", sequence) };
                var selected = records.Take(MaxForEachIterations).ToList();
                if (records.Length > selected.Count)
                { selected.Add(UnknownValue("switch-item-limit", records.Skip(selected.Count).ToArray())); ReportMissing("switch-item-limit"); }
                bool? Match(object? pattern, Payload item)
                {
                    if (Kind(pattern) == "ScriptBlockExpressionAst")
                    {
                        var statements = Items(Prop(Prop(Prop(pattern, "ScriptBlock"), "EndBlock"), "Statements")).ToArray();
                        if (statements.Length == 1 && Kind(statements[0]) == "PipelineAst")
                            return Truth(Pipeline(statements[0], depth + 1) ?? Missing("switch-predicate"));
                        AnalyzeStatements(statements, depth + 1, output);
                        return null;
                    }
                    var value = Value(pattern, depth + 1);
                    if (!value.Complete || !item.Complete || item.Text == null || value.Text == null) return null;
                    if (flags.Contains("Regex"))
                    {
                        try { return Regex.IsMatch(item.Text, value.Text, caseSensitive ? RegexOptions.None : RegexOptions.IgnoreCase,
                            TimeSpan.FromMilliseconds(Math.Max(1, policy!.FileScanBudgetMs - clock.ElapsedMilliseconds))); }
                        catch (ArgumentException) { return null; }
                        catch (RegexMatchTimeoutException) { return null; }
                    }
                    if (flags.Contains("Wildcard"))
                    {
                        // Use the host's PowerShell wildcard syntax and comparison flags.
                        var type = node.GetType().Assembly.GetType("System.Management.Automation.WildcardPattern", true)!;
                        var options = node.GetType().Assembly.GetType("System.Management.Automation.WildcardOptions", true)!;
                        var matcher = Activator.CreateInstance(type, value.Text, Enum.Parse(options, caseSensitive ? "None" : "IgnoreCase"));
                        try { return (bool?)type.GetMethod("IsMatch", new[] { typeof(string) })!.Invoke(matcher, new object[] { item.Text }); }
                        catch (System.Reflection.TargetInvocationException) { return null; }
                    }
                    return string.Equals(item.Text, value.Text, caseSensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase);
                }
                bool running = true;
                foreach (var item in selected)
                {
                    values[Key("_")] = values[Key("PSItem")] = item;
                    bool definite = false, possible = false;
                    var nextItem = new List<(StatementState State, StatementExit Exit)>();
                    void Body(object? block, bool optional)
                    {
                        var skipped = optional ? new StatementState(this) : null;
                        var paths = new List<(StatementState State, StatementExit Exit)>();
                        var exit = AnalyzeBlock(Items(Prop(block, "Statements")), depth + 1, paths, output);
                        paths.Add((new StatementState(this), exit));
                        foreach (var path in paths)
                        {
                            if (path.Exit == StatementExit.None)
                            { if (skipped == null) skipped = path.State; else skipped.Join(path.State); }
                            else if (path.Exit == StatementExit.Continue) nextItem.Add((path.State, StatementExit.None));
                            else exits.Add((path.State, path.Exit == StatementExit.Break ? StatementExit.None : path.Exit));
                        }
                        running = skipped != null;
                        if (skipped != null) RestoreStatementState(skipped);
                    }
                    foreach (var clause in clauses)
                    {
                        if (!running) break;
                        var body = Prop(clause, "Item2");
                        var match = Match(Prop(clause, "Item1"), item);
                        if (match == false) { SkipBranch(body); continue; }
                        definite |= match == true;
                        possible = true;
                        ReachBranch(body);
                        Body(body, match == null);
                    }
                    if (otherwise != null && running && !definite) { ReachBranch(otherwise); Body(otherwise, possible); }
                    else if (otherwise != null) SkipBranch(otherwise);
                    if (running) nextItem.Add((new StatementState(this), StatementExit.None));
                    running = nextItem.Count != 0;
                    if (!running) break;
                    MergeStatementPaths(nextItem);
                }
                if (running) exits.Add((new StatementState(this), StatementExit.None));
                var result = MergeStatementPaths(exits);
                values[Key("_")] = values[Key("PSItem")] = previous;
                return result;
            }

            Payload? ForEachObject(object command, Payload? input, int depth, bool hasUpstream)
            {
                using var args = new Args(this, command, new[] { "Begin", "Process", "End", "InputObject", "OutVariable", "Parallel", "ThrottleLimit", "TimeoutSeconds", "RemainingScripts", "MemberName", "ArgumentList" },
                    new[] { "WhatIf", "Confirm", "AsJob", "UseNewRunspace" });
                if (!args.Valid)
                { ReportMissing("foreach-object-arguments"); return Missing("foreach-object-arguments"); }
                if (args.Has("MemberName") || args.Has("ArgumentList") || args.Plain.Count == 1 && Kind(args.Plain[0]) == "StringConstantExpressionAst")
                {
                    var memberNode = args.Get("MemberName") ?? args.Plain.FirstOrDefault();
                    if (memberNode == null || args.Plain.Count != (args.Has("MemberName") ? 0 : 1) ||
                        args.Has("ArgumentList") || args.Has("Begin") || args.Has("Process") || args.Has("End") ||
                        args.Has("Parallel") || args.Has("RemainingScripts") || args.Has("Confirm") ||
                        (input != null) == args.Has("InputObject")) return Missing("foreach-object-member");
                    var member = ExactString(Value(memberNode, depth + 1));
                    if (!ExactSelector(member)) return Missing("foreach-object-member-selection");
                    if (args.Has("WhatIf")) return Missing("no-expression-output");
                    var receiver = input ?? Value(args.Get("InputObject"), depth + 1);
                    var members = input == null ? new[] { receiver } : IterationItems(receiver) ?? new[] { receiver };
                    IEnumerable<Payload> Project()
                    {
                        foreach (var item in members)
                        {
                            var v = ReadProjection(item, member!);
                            foreach (var field in v.Elements ?? new[] { v }) yield return field;
                            if (v.Elements != null && v.InspectionPartial) yield return v.RecordRemainder ?? Missing("member-remainder");
                        }
                        if (receiver.InspectionPartial && receiver.RecordRemainder == null) yield return Missing("member-input-remainder");
                    }
                    return ReadOutput(Project(), "ForEach-Object -MemberName");
                }
                var blocks = new List<object>();
                if (args.Has("Process")) blocks.AddRange(ListItems(args.Get("Process"), Limits.MaxArguments));
                foreach (var block in args.Plain) blocks.AddRange(ListItems(block, Limits.MaxArguments));
                bool parallel = args.Has("Parallel");
                if (parallel)
                {
                    if (blocks.Count != 0 || args.Has("Begin") || args.Has("End") || args.Has("RemainingScripts"))
                        return Missing("foreach-object-parameter-set");
                    blocks.Add(args.Get("Parallel")!);
                }
                if (args.Get("RemainingScripts") is object rest)
                    blocks.AddRange(ListItems(rest, Limits.MaxArguments));
                object? begin = args.Get("Begin"), end = args.Get("End");
                if (begin == null && blocks.Count > 1) { begin = blocks[0]; blocks.RemoveAt(0); }
                if (end == null && blocks.Count > 1) { end = blocks.Last(); blocks.RemoveAt(blocks.Count - 1); }
                if (blocks.Concat(new[] { begin, end }.OfType<object>()).Any(b => Kind(b) != "ScriptBlockExpressionAst"))
                { ReportMissing("foreach-object-block"); return Missing("foreach-object-block"); }
                if (blocks.Count == 0 || args.Has("Confirm") || args.Has("WhatIf") || !parallel &&
                    (args.Has("AsJob") || args.Has("UseNewRunspace") || args.Has("ThrottleLimit") || args.Has("TimeoutSeconds")))
                {
                    foreach (var block in blocks) SkipBranch(block);
                    SkipBranch(begin);
                    SkipBranch(end);
                    return Missing("foreach-object-parameter-set");
                }
                var previous = Variable("_");
                var result = new List<Payload>();
                void Run(object? block)
                {
                    if (block == null) return;
                    ReachBranch(block);
                    var body = Prop(Prop(block, "ScriptBlock"), "EndBlock");
                    AnalyzeStatements(Items(Prop(body, "Statements")), depth + 1, result);
                }
                Run(begin);
                var records = args.Has("InputObject") ? new[] { Value(args.Get("InputObject")) } : IterationItems(input);
                bool unknown = records == null && input != null;
                var items = records ?? (unknown ? new[] { UnknownValue("foreach-object-item", input) } : hasUpstream ? Array.Empty<Payload>() : new[] { new Payload { Complete = true, ScalarTruth = false, SourceRef = "no pipeline object" } });
                if (items.Length == 0) foreach (var block in blocks) SkipBranch(block);
                var entry = unknown ? new StatementState(this) : null;
                var parent = parallel ? new StatementState(this, preserveMutableValues: true) : null;
                void RunItem(Payload item)
                {
                    var captures = usingValues;
                    try
                    {
                        if (parent != null)
                        {
                            usingValues = parent.Values;
                            InvalidateSessionFacts();
                        }
                        values[Key("_")] = values[Key("PSItem")] = item;
                        foreach (var block in blocks) Run(block);
                    }
                    finally
                    {
                        usingValues = captures;
                        if (parent != null) RestoreStatementState(parent);
                    }
                }
                foreach (var item in items.Take(MaxForEachIterations)) RunItem(item);
                if (items.Length > MaxForEachIterations)
                {
                    RunItem(UnknownValue("foreach-object-item", items.Skip(MaxForEachIterations).ToArray()));
                    ReportMissing("foreach-iteration");
                }
                if (entry != null) { entry.Join(new StatementState(this)); RestoreStatementState(entry); }
                values[Key("_")] = values[Key("PSItem")] = previous;
                Run(end);
                if (parallel && items.Length != 0)
                { InvalidateFileFacts(); ReportMissing("parallel-order"); }
                if (args.Has("AsJob")) return Missing("foreach-job-output");
                var output = new Payload { Elements = result.ToArray(), Tags = Merge(KnownMarks(result)), SourceRef = "ForEach-Object",
                    Complete = !unknown && items.Length <= MaxForEachIterations, Issue = "foreach-object-output" };
                return output;
            }
        }
    }
}

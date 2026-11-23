#Requires -Version 7.0
[CmdletBinding()]
param([string]$Build = (Join-Path $PSScriptRoot '..\build\Release'))
$ErrorActionPreference = 'Stop'
$dir = Join-Path (Split-Path -Parent $PSScriptRoot) 'logs'
$log = Join-Path $dir 'events.jsonl'
if (Test-Path -LiteralPath $log) { throw 'Fixture requires a user session with no existing Guard journal.' }
$dirExists = Test-Path -LiteralPath $dir
$buildPath = (Resolve-Path -LiteralPath $Build).Path
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class GuardLogFixture {
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
    private delegate int RunFixture([MarshalAs(UnmanagedType.LPWStr)] string provider);
    public static int Run(string loader, string provider) {
        var module = NativeLibrary.Load(loader);
        try { return Marshal.GetDelegateForFunctionPointer<RunFixture>(NativeLibrary.GetExport(module, "RunGuardFixture"))(provider); }
        finally { NativeLibrary.Free(module); }
    }
}
'@
try {
    $old = [Environment]::CurrentDirectory
    try {
        [Environment]::CurrentDirectory = $buildPath
        $code = [GuardLogFixture]::Run((Join-Path $buildPath 'GuardFixture.dll'), (Join-Path $buildPath 'PowerShell7Guard.dll'))
    } finally { [Environment]::CurrentDirectory = $old }
    if ($code -ne 0) { throw "Synthetic Scan checks failed: $code" }
    if (-not (Test-Path -LiteralPath $log)) { throw 'No journal was written.' }
    $events = @(Get-Content -LiteralPath $log | ConvertFrom-Json)
    if ($events.Count -ne 3 -or @($events | Where-Object { $_.process.pid -ne $PID -or $_.ast.status -ne 'parsed' }).Count) {
        throw 'Expected three parsed events from this fixture process.'
    }
    $main = $events | Where-Object { $_.amsi.scanSequence -eq 1 }
    $warning = $events | Where-Object severity -eq Warning
    $blocked = $events | Where-Object decision -eq Block
    if ($main.amsi.contentName -ne 'C:\fixture.ps1' -or $main.amsi.session -ne 1 -or -not $main.process.cwd -or
        $main.ast.commands.name -notcontains 'Invoke-RestMethod' -or $main.ast.filePaths -notcontains 'C:\fixture.txt' -or
        $main.ast.ipAddresses -notcontains '127.0.0.1' -or $main.ast.urls -notcontains 'https://example.invalid/upload' -or
        $main.ast.encodingCalls -notcontains 'FromBase64String' -or $warning.message -ne 'Information missing' -or
        $warning.result -ne 1 -or $blocked.result -ne 0x4000) { throw 'Unexpected journal content.' }
    $exe = Join-Path $buildPath 'guard-log.exe'
    $short = (& $exe --once) -join [char]10
    if ($LASTEXITCODE -ne 0 -or $short -notmatch 'Information missing' -or $short -match '脚本源码') {
        throw 'Compact Rust output did not match expectation.'
    }
    $debug = (& $exe --file $log --debug --all --once) -join [char]10
    if ($LASTEXITCODE -ne 0 -or $debug -notmatch '脚本源码' -or $debug -notmatch '编码调用') { throw 'Debug Rust output did not match expectation.' }
    'PASS: actual pwsh in-process AST, queued file output, warning and blocking, Rust compact/debug.'
} finally {
    if (Test-Path -LiteralPath $log) {
        # Only remove a journal made solely by this fixture; never touch an existing user journal.
        $entries = @(Get-Content -LiteralPath $log | ConvertFrom-Json -ErrorAction SilentlyContinue)
        if ($entries.Count -and -not @($entries | Where-Object { $_.process.pid -ne $PID }).Count) {
            [IO.File]::Delete($log)
        }
    }
    if (-not $dirExists -and (Test-Path -LiteralPath $dir) -and
        -not (Get-ChildItem -LiteralPath $dir -Force | Select-Object -First 1)) {
        [IO.Directory]::Delete($dir, $false)
    }
}

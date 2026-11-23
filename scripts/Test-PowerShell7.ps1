#Requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][uri]$Target, [switch]$Live,
    [string]$Journal = (Join-Path $PSScriptRoot '..\logs\events.jsonl'))
$ErrorActionPreference = 'Stop'
if (-not $Target.IsAbsoluteUri -or $Target.Scheme -notin 'http','https' -or $Target.IsLoopback -or $Target.UserInfo) {
    throw 'Specify the HTTP(S) address of your external test server.'
}
. (Join-Path $PSScriptRoot 'Registration.ps1')
$registration = Get-GuardRegistration (Get-GuardContext) -Discover
"Guard registration: $registration"
$pwsh = [Environment]::ProcessPath
if ([IO.Path]::GetFileName($pwsh) -ine 'pwsh.exe') { throw 'Run this test from pwsh.exe.' }
$PSNativeCommandUseErrorActionPreference = $false
$clean = & $pwsh -NoProfile -NonInteractive -Command "Write-Output 'guard-clean-ok'"
if ($LASTEXITCODE -ne 0 -or $clean -cne 'guard-clean-ok') { throw 'Benign child script failed.' }
# Default: compile only. -Live invokes the actual command and lets AMSI decide
# before a request can be sent. The HTTP response is not used for acceptance.
$url = $Target.AbsoluteUri.Replace("'", "''")
$tag = 'PS7GUARD_AMSI_' + [guid]::NewGuid().ToString('N')
$probe = "Invoke-WebRequest -Method Post -Uri '$url' -Body 'PS7GUARD_TEST_SECRET $tag' -TimeoutSec 5"
$wrapper = @'
$ErrorActionPreference = 'Stop'
"ProbePid=$PID"
$code = 0
try {
    $script = [scriptblock]::Create($env:PS7GUARD_SMOKE_INPUT)
    if ($env:PS7GUARD_SMOKE_LIVE -eq '1') {
        & $script | Out-Null
        'Live command completed without an AMSI block.'
    } else {
        $compile = [scriptblock].GetMethod('Compile', [Reflection.BindingFlags]'NonPublic,Instance', $null,
            [type[]]@([bool]), $null)
        if (-not $compile) { throw 'PowerShell ScriptBlock.Compile was not found.' }
        $null = $compile.Invoke($script, [object[]]@($false))
        'Compile finished without an AMSI block. Script was not invoked.'
    }
} catch {
    $code = 1
    "ErrorId=$($_.FullyQualifiedErrorId)"
    for ($e = $_.Exception; $null -ne $e; $e = $e.InnerException) {
        "Exception=$($e.GetType().FullName): $($e.Message)"
        if ($e -is [System.Management.Automation.ParseException]) {
            foreach ($parseError in $e.Errors) {
                "ParseErrorId=$($parseError.ErrorId)"
                if ($parseError.ErrorId -eq 'ScriptHasAdminBlockedContent') { $code = 42 }
            }
        }
    }
}
# Let the child process's asynchronous Guard writer flush before it exits.
Start-Sleep -Milliseconds 350
exit $code
'@
$oldProbe = $env:PS7GUARD_SMOKE_INPUT
$oldLive = $env:PS7GUARD_SMOKE_LIVE
$oldNoProxy = $env:NO_PROXY
try {
    $env:PS7GUARD_SMOKE_INPUT = $probe
    $env:PS7GUARD_SMOKE_LIVE = if ($Live) { '1' } else { '0' }
    if ($Live) { $env:NO_PROXY = $Target.IdnHost }
    $output = & $pwsh -NoProfile -NonInteractive -Command $wrapper 2>&1 | Out-String
    $code = $LASTEXITCODE
} finally {
    $env:PS7GUARD_SMOKE_INPUT = $oldProbe
    $env:PS7GUARD_SMOKE_LIVE = $oldLive
    $env:NO_PROXY = $oldNoProxy
}
Write-Host $output.TrimEnd()
$match = [regex]::Match($output, '(?m)^ProbePid=(\d+)\r?$')
$event = $null
if ($match.Success) {
    $childId = [int]$match.Groups[1].Value
    foreach ($attempt in 1..8) {
        $event = Select-String -LiteralPath $Journal -SimpleMatch $tag -ErrorAction SilentlyContinue |
            ForEach-Object { ConvertFrom-Json -InputObject $_.Line -AsHashtable -ErrorAction SilentlyContinue } |
            Where-Object { $_.process.pid -eq $childId -and $_.amsi.appName -and $_.amsi.content -like "*$tag*" } |
            Select-Object -Last 1
        if ($event) { break }
        Start-Sleep -Milliseconds 150
    }
}
if ($event) { "Guard AMSI: scan=$($event.amsi.scanSequence), decision=$($event.decision), reason=$($event.reason)" }
else { 'Guard AMSI: no matching event.' }
if ($code -ne 42 -or $output -notmatch '(?m)^ParseErrorId=ScriptHasAdminBlockedContent\r?$') {
    throw "No AMSI administrative block in the command's errors; exit=$code."
}
if ($output -notmatch '\bAMSI_RESULT_BLOCKED_BY_ADMIN_BEGIN\b') {
    throw 'The command did not print AMSI_RESULT_BLOCKED_BY_ADMIN_BEGIN.'
}
if (-not $event -or $event.result -ne 0x4000) {
    throw 'AMSI blocked the command, but no matching Guard block event attributed it to this provider.'
}
'PASS: AMSI_RESULT_BLOCKED_BY_ADMIN_BEGIN and the matching Guard block event.'

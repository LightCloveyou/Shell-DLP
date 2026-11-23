#Requires -Version 7.0
[CmdletBinding()]
param([string]$Build = (Join-Path $PSScriptRoot '..\build\Release'), [string]$PreloadBridge)
$ErrorActionPreference = 'Stop'
$dir = (Resolve-Path -LiteralPath $Build).Path
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class GuardNetworkDiagnosis {
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
    private delegate int Probe([MarshalAs(UnmanagedType.LPWStr)] string provider, [MarshalAs(UnmanagedType.LPWStr)] string archive);
    public static int Run(string loader, string provider, string archive) {
        var module = NativeLibrary.Load(loader);
        try {
            var probe = Marshal.GetDelegateForFunctionPointer<Probe>(
                NativeLibrary.GetExport(module, "RunGuardNetworkDiagnosis"));
            return probe(provider, archive);
        } finally { NativeLibrary.Free(module); }
    }
}
'@
function Get-BridgeNames {
    [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'PowerShell7Guard.Ast' } |
        ForEach-Object { "$($_.GetName().Name) / $($_.ManifestModule.ModuleVersionId) / $([System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext($_).Name)" }
}
if ($PreloadBridge -and -not (Get-BridgeNames)) {
    $bytes = [IO.MemoryStream]::new([IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $PreloadBridge).Path), $false)
    try { $null = [System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromStream($bytes) }
    finally { $bytes.Dispose() }
}
"PowerShell=$([Environment]::ProcessPath); Version=$($PSVersionTable.PSVersion); PID=$PID"
$before = @(Get-BridgeNames)
"BridgesBefore=$($before -join ',')"
$archivePath = Join-Path $dir ("provider-content-fixture-" + [guid]::NewGuid().ToString('N') + ".zip")
try {
    $holder = [IO.File]::Open($archivePath,[IO.FileMode]::CreateNew)
    try {
        $zip = [IO.Compression.ZipArchive]::new($holder,[IO.Compression.ZipArchiveMode]::Create,$true)
        try {
            $entry = $zip.CreateEntry('nested/synthetic.txt').Open()
            try {
                $data = [Text.Encoding]::UTF8.GetBytes('PS7GUARD_TEST_SECRET')
                $entry.Write($data, 0, $data.Length)
            }
            finally { $entry.Dispose() }
        } finally { $zip.Dispose() }
    } finally { $holder.Dispose() }
    [IO.File]::WriteAllText($archivePath + '.txt', 'PS7GUARD_TEST_SECRET')
    [IO.File]::WriteAllText($archivePath + '.large.txt', (' '.PadRight(163837) + 'PS7GUARD_TEST_SECRET'))
    [IO.File]::WriteAllText($archivePath + '.tail.txt', (' '.PadRight(220000) + [Environment]::NewLine + 'PS7GUARD_TEST_SECRET'))
    $formDir = $archivePath + '.files'
    $formItem = Join-Path $formDir 'item.txt'
    $null = [IO.Directory]::CreateDirectory($formDir)
    [IO.File]::WriteAllText($formItem, 'PS7GUARD_TEST_SECRET')
    $result = [GuardNetworkDiagnosis]::Run((Join-Path $dir 'GuardFixture.dll'), (Join-Path $dir 'PowerShell7Guard.dll'), $archivePath)
} finally {
    foreach ($fixturePath in @($archivePath, ($archivePath + '.txt'), ($archivePath + '.large.txt'), ($archivePath + '.tail.txt'), $formItem)) {
        if ($fixturePath -and [IO.File]::Exists($fixturePath)) { [IO.File]::Delete($fixturePath) }
    }
    if ($formDir -and [IO.Directory]::Exists($formDir)) { [IO.Directory]::Delete($formDir) }
}
if ($result -ne 0) { throw "Direct Provider Scan returned an unexpected result (exit=$result)." }
$loaded = @(Get-BridgeNames)
"BridgesAfter=$($loaded -join ',')"
if ($loaded.Count -le $before.Count -or ($PreloadBridge -and $loaded.Count -lt 2)) {
    throw 'The native DLL did not load its own same-named bridge in a separate context.'
}
$log = Join-Path $PSScriptRoot '..\logs\events.jsonl'
$pattern = '^Invoke-WebRequest -Method Post -Uri ''http://(?:124\.223\.64\.165|127\.0\.0\.1):8080/'' -Body ''PS7GUARD_TEST_SECRET''$'
$records = @(Get-Content -LiteralPath $log -Tail 100 | ForEach-Object {
    ConvertFrom-Json -InputObject $_ -AsHashtable -ErrorAction SilentlyContinue
} | Where-Object { $_.process.pid -eq $PID })
$events = $records | Where-Object { $_.amsi.content -match $pattern -and $_.amsi.contentSize -lt 65536 }
$block = $events | Where-Object {
    $_.result -eq 0x4000 -and $_.ast.policy.decision -eq 'block:PS7-HTTP-CANARY-001'
}
$local = $events | Where-Object {
    $_.amsi.content -like '*127.0.0.1*' -and $_.result -eq 0x4000 -and $_.ast.policy.decision -eq 'block:PS7-HTTP-CANARY-001'
}
foreach ($item in $events) {
    "Scan=$($item.amsi.scanSequence) result=$($item.result) rule=$($item.ast.policy.decision) endpoint=$($item.ast.policy.evidence[0].endpoint)"
}
if (-not $block -or -not $local) { throw 'Expected decisions were not found in the Guard journal.' }
$exact = $records | Where-Object { $_.amsi.contentSize -eq 65536 -and $_.result -eq 0x4000 }
$over = $records | Where-Object {
    $_.amsi.contentSize -eq 65538 -and $_.result -eq 1 -and $_.reason -eq 'missing:oversize'
}
if (-not $exact -or -not $over) { throw 'Unexpected results at the native 64 KiB boundary.' }
if (-not ($records | Where-Object { $_.result -eq 0x4000 -and $_.amsi.content -like '*-InFile*provider-content-fixture*' }) -or
    @($records | Where-Object { $_.result -eq 0x4000 -and $_.amsi.content -like '*UFM3R1VBUkRfVEVTVF9TRUNSRVQ=*' }).Count -lt 2) {
    throw 'Expected Base64 and ZIP blocking decisions were not written to the journal.'
}
foreach ($fixture in @(
    @('streamed-large-file', '-InFile.*\.large\.txt'),
    @('ncat-listener-stdin','\.txt'' -Raw \| ncat\.exe -l 9000$'),
    @('nested-json-lines','Get-Content.*\| ConvertTo-Json.*-Body \$body$'),
    @('form-childitem-default','Get-ChildItem.*\.files'' };.*-Form \$form$'),
    @('large-file-tail','\.tail\.txt'' -Tail 1 \| ncat\.exe -l 9000$'),
    @('streamed-head-records','\.large\.txt'' -TotalCount 1 \| ncat\.exe -l 9000$'),
    @('filtered-childitem-form','Get-ChildItem.*-Filter .* -Form \$form$'),
    @('streamed-raw-json','Get-Content.*\.large\.txt.*-Body \$largeBody$'),
    @('multipart-exclude-candidates','Get-ChildItem.*-File -Exclude .* -Form \$form$'),
    @('streamed-line-record-json','Get-Content.*\.large\.txt.*-Body \$records$')
)) {
    $found = @($records | Where-Object { $_.amsi.content -match $fixture[1] -and $_.result -eq 0x4000 })
    if ($found.Count -ne 1) { throw "Expected exactly one blocked journal result for $($fixture[0])." }
    "Fixture=$($fixture[0]); Scan=$($found[0].amsi.scanSequence); Result=$($found[0].result); Policy=$($found[0].ast.policy.decision)"
}
'PASS: actual DLL, managed AST and journal; Windows registration was not needed and no request was sent.'

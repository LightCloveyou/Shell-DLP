# Dot-sourced by Test-SensitiveRules.ps1 inside its isolated Runspace/fixture.
$counts = [ordered]@{}
function Case([string]$group, [int]$expected, [string]$command, [string]$label, [switch]$Local) {
    if ($Local -and $expected -ne 0) { throw 'Only local file-producing commands may be executed in this matrix.' }
    $answer = Scan $command -ExecuteLocal:$Local
    Is $expected $answer "$group / $label"
    if (-not $counts.Contains($group)) { $counts[$group] = 0 }
    $counts[$group]++
    return $answer
}
function Put([string]$name, [string]$text, [Text.Encoding]$encoding = [Text.UTF8Encoding]::new($false)) {
    [IO.File]::WriteAllText((Join-Path $files $name), $text, $encoding)
}
function Zip([string]$filename, $contents) {
    $stream = [IO.File]::Open((Join-Path $files $filename), 'Create')
    try {
        $zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($item in $contents) {
                $entry = $zip.CreateEntry([string]$item.Name)
                $data = if ($item.Data -is [byte[]]) { $item.Data } else { [Text.Encoding]::UTF8.GetBytes([string]$item.Data) }
                $writer = $entry.Open()
                try { $writer.Write([byte[]]$data, 0, $data.Length) } finally { $writer.Dispose() }
            }
        } finally { $zip.Dispose() }
    } finally { $stream.Dispose() }
}
function GZip([string]$filename,[string]$text) {
    $stream = [IO.File]::Open((Join-Path $files $filename), 'Create')
    try {
        $gzip = [IO.Compression.GZipStream]::new($stream, [IO.Compression.CompressionMode]::Compress, $true)
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes($text)
            $gzip.Write($bytes,0,$bytes.Length)
        } finally { $gzip.Dispose() }
    } finally { $stream.Dispose() }
}
function Upload([string]$method,[string]$path) {
    switch ($method) {
        'http' { "Invoke-WebRequest -Method Post -Uri '$endpoint' -InFile '$path'" }
        'curl' { "curl.exe --data-binary '@$path' '$endpoint'" }
        'scp' { "scp.exe '$path' '$remote'" }
    }
}
$encodings = @(
    [Text.UTF8Encoding]::new($false),[Text.UTF8Encoding]::new($true),
    [Text.UnicodeEncoding]::new($false,$true),[Text.UnicodeEncoding]::new($true,$true),
    [Text.UTF32Encoding]::new($false,$true),[Text.UTF32Encoding]::new($true,$true)
)
foreach ($i in 0..($encodings.Count-1)) {
    foreach ($protectedContent in $false,$true) {
        $name = "encoding-$i-$protectedContent.dat"
        $value = if ($protectedContent) { '测试-雪 fixture-sensitive-xyz' } else { '测试-雪 normal content' }
        Put $name $value $encodings[$i]
        foreach ($adapter in 'http','curl','scp') {
            $null = Case file $(if ($protectedContent) { 1 } else { 2 }) (Upload $adapter $name) "$adapter encoding $i sensitive=$protectedContent"
        }
    }
}
Put 'empty.dat' ''
Put 'edge-max.txt' (('x' * (128KB - 'fixture-sensitive-xyz'.Length)) + 'fixture-sensitive-xyz')
Put 'edge-over.txt' (('x' * (128KB - 'fixture-sensitive-xyz'.Length + 1)) + 'fixture-sensitive-xyz')
[IO.File]::WriteAllBytes((Join-Path $files 'opaque.dat'),[byte[]]@(0,255,40,1,128))
foreach ($adapter in 'http','curl','scp') {
    foreach ($case in @(
            @{Path='empty.dat';Expected=2}, @{Path='edge-max.txt';Expected=1},
            @{Path='edge-over.txt';Expected=1}, @{Path='opaque.dat';Expected=3},
            @{Path='no-such-file.txt';Expected=3}, @{Path='private.txt';Expected=1},
            @{Path='.\PRIVATE.txt';Expected=1}, @{Path=(Join-Path $files 'private.txt');Expected=1}
        )) {
        $null = Case file $case.Expected (Upload $adapter $case.Path) "$adapter $($case.Path)"
    }
}
$sub = Join-Path $folder 'deep\further'
[IO.Directory]::CreateDirectory($sub) | Out-Null
Put 'protected\deep\further\空 格.txt' 'same innocent bytes'
Put 'protected-old\空 格.txt' 'same innocent bytes'
Put 'protected-old\rule-text.txt' 'fixture-sensitive-xyz'
foreach ($adapter in 'http','curl','scp') {
    foreach ($case in @(
        @{Path='protected\deep\further\空 格.txt';Expected=1},
        @{Path='protected-old\空 格.txt';Expected=2},
        @{Path='protected-old\rule-text.txt';Expected=1},
        @{Path='protected\..\protected-old\空 格.txt';Expected=2},
        @{Path='protected\*.txt';Expected=3},
        @{Path='protected';Expected=3}
    )) { $null = Case folder $case.Expected (Upload $adapter $case.Path) "$adapter $($case.Path)" }
}
Put 'pipe-source.txt' ("ordinary line" + [Environment]::NewLine + 'fixture-sensitive-xyz')
Put 'pipe-clean.txt' ("ordinary" + [Environment]::NewLine + 'another line')
$curlStdin = "curl.exe --data-binary '@-' '$endpoint'"
foreach ($case in @(
    @{E=1;P="Get-Content -Raw -LiteralPath 'pipe-source.txt'"},
    @{E=1;P="Get-Content -LiteralPath 'pipe-source.txt'"},
    @{E=1;P="Get-Content -LiteralPath 'pipe-source.txt' | Write-Output"},
    @{E=2;P="Get-Content -Raw -LiteralPath 'pipe-clean.txt'"},
    @{E=2;P="Write-Output -InputObject 'ordinary'"},
    @{E=1;P="Write-Output -InputObject 'fixture-sensitive-xyz' -NoEnumerate"},
    @{E=3;P="Get-Content -LiteralPath 'missing-source.txt'"},
    @{E=3;P="Get-Content -Raw -AsByteStream -LiteralPath 'pipe-source.txt'"},
    @{E=3;P="Get-Content -LiteralPath 'pipe-source.txt' | Where-Object { `$_ }"}
)) { $null = Case pipeline $case.E ($case.P + ' | ' + $curlStdin) $case.P }
foreach ($case in @(
    @{Name='pipeline-set.txt';Tail="Set-Content -LiteralPath 'pipeline-set.txt'"},
    @{Name='pipeline-out.txt';Tail="Out-File -FilePath 'pipeline-out.txt'"},
    @{Name='pipeline-redir.txt';Tail=$null}
)) {
    $localWrite = if ($case.Tail) { "Get-Content -Raw -LiteralPath 'private.txt' | $($case.Tail)" } else {
        "Get-Content -Raw -LiteralPath 'private.txt' > '$($case.Name)'"
    }
    $null = Case pipeline 0 $localWrite "local write $($case.Name)" -Local
    Await-Config $case.Name
    $taint = Case pipeline 1 (Upload 'http' $case.Name) "confirmed write $($case.Name)"
    if ($taint.report.policy.evidence[0].flow[0].route -notmatch 'private\.txt') { throw 'Lost original file provenance' }
}
$null = Case pipeline 0 "`$b = Get-Content -AsByteStream -Raw -LiteralPath 'private.txt'; Set-Content -AsByteStream -LiteralPath 'binary-copy.dat' -Value `$b" 'verified byte copy' -Local
Await-Config 'binary-copy.dat'
$null = Case pipeline 1 (Upload 'scp' 'binary-copy.dat') 'byte copy retains sensitivity'

$sensitive64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('fixture-sensitive-xyz'))
$other64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('ordinary payload'))
$file64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($inputFile))
foreach ($item in @(@{Value=$sensitive64;E=1},@{Value=$other64;E=2},@{Value=$file64;E=2})) {
    $null = Case base64 $item.E (Post "'$($item.Value)'") 'plain canonical body'
    $null = Case base64 $item.E ("Write-Output '$($item.Value)' | " + $curlStdin) 'canonical stdin'
}
$null = Case base64 1 (Post "([Convert]::FromBase64String('$sensitive64'))") 'explicit Base64 decode to HTTP bytes'
$null = Case base64 1 (Post "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$sensitive64')))") 'explicit decode to text'
$null = Case base64 1 (Post "([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('fixture-sensitive-xyz')))") 'explicit encode'
$null = Case base64 2 (Post "([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('ordinary payload')))") 'clean explicit encode'
$null = Case base64 3 (Post "([Convert]::FromBase64String('%%%invalid%%%'))") 'invalid explicit decode'
$null = Case base64 3 (Post '([Convert]::FromBase64String($unknownFixtureEncoding))') 'unknown decode input'
$null = Case base64 1 ("Get-Content -Raw -LiteralPath 'private.txt' | Write-Output > 'encoded-source.txt'; " +
    "curl.exe --data-binary '@encoded-source.txt' '$endpoint'") 'direct chained source and known local write'
$localEncoding = "`$global:fixtureEncoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Content -Raw -LiteralPath 'private.txt')))"
$null = Case base64 0 $localEncoding 'encode path-only sensitive source' -Local
$null = Case base64 1 (Post '$global:fixtureEncoded') 'path-only provenance across blocks survives encoding'

Zip 'plain.zip' @(@{Name='normal/file.txt';Data='ordinary payload'})
Zip 'sensitive.zip' @(@{Name='x/y/deep.txt';Data='fixture-sensitive-xyz'})
Zip 'encoding.zip' @(@{Name='opaque.b64';Data=$sensitive64})
Zip 'outer.zip' @(@{Name='nested.zip';Data=[IO.File]::ReadAllBytes((Join-Path $files 'sensitive.zip'))})
Zip 'over-depth.zip' @(@{Name='top.zip';Data=[IO.File]::ReadAllBytes((Join-Path $files 'outer.zip'))})
Zip 'too-large.zip' @(@{Name='large.txt';Data=('A' * (128KB + 5))})
Zip 'too-many.zip' @(1..65 | ForEach-Object {@{Name="f$_.txt";Data='small'}})
Zip 'duplicate.zip' @(@{Name='a.txt';Data='first'},@{Name='A.TXT';Data='second'})
Zip 'traversal.zip' @(@{Name='../outside.txt';Data='ordinary'})
Zip 'mixed.zip' @(@{Name='file.txt';Data='fixture-sensitive-xyz'},@{Name='opaque.data';Data=[byte[]]@(0,255,40)})
Zip 'empty.zip' @()
[IO.File]::WriteAllBytes((Join-Path $files 'corrupted.zip'),[byte[]]@(0x50,0x4b,3,4,0,2,0))
[IO.File]::Copy((Join-Path $files 'sensitive.zip'), (Join-Path $files 'renamed.data'))
GZip 'normal.txt.gz' 'ordinary'
GZip 'sensitive.txt.gz' 'fixture-sensitive-xyz'
GZip 'expanded.txt.gz' ('a' * (256KB+1))
Put 'not-supported.rar' 'ordinary'
Put 'zip-raw-marker.txt' 'fixture-sensitive-xyz'
Compress-Archive -LiteralPath (Join-Path $files 'zip-raw-marker.txt') -DestinationPath (Join-Path $files 'stock.zip')
foreach ($adapter in 'http','curl','scp') {
    foreach ($item in @(
        @{F='plain.zip';E=2},@{F='sensitive.zip';E=1},@{F='encoding.zip';E=1},@{F='outer.zip';E=1},
        @{F='over-depth.zip';E=3},@{F='too-large.zip';E=3},@{F='too-many.zip';E=3},@{F='duplicate.zip';E=3},
        @{F='traversal.zip';E=3},@{F='corrupted.zip';E=3},@{F='mixed.zip';E=1},@{F='empty.zip';E=2},
        @{F='normal.txt.gz';E=2},@{F='sensitive.txt.gz';E=1},@{F='expanded.txt.gz';E=3},@{F='renamed.data';E=1},
        @{F='not-supported.rar';E=3},@{F='stock.zip';E=1}
    )) { $null = Case archive $item.E (Upload $adapter $item.F) "$adapter $($item.F)" }
}
$zip64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $files 'sensitive.zip')))
$null = Case archive 1 (Post "'$zip64'") 'ZIP wrapped in Base64 body'
$null = Case archive 1 (Post "([Convert]::FromBase64String('$zip64'))") 'explicit decode emits ZIP bytes'
$broken64 = [Convert]::ToBase64String([byte[]]@(0x50,0x4b,3,4,4,1,7,19,19,12))
$null = Case archive 3 (Post "'$broken64'") 'corrupted ZIP wrapped in Base64 warns'
$import = [powershell]::Create()
try {
    $import.Runspace = $runspace
    $null = $import.AddCommand('Import-Module').AddParameter('Name','Microsoft.PowerShell.Archive').Invoke()
    if ($import.HadErrors) { throw ($import.Streams.Error -join ', ') }
} finally { $import.Dispose() }
$privateArchive = "Compress-Archive -LiteralPath 'private.txt' -DestinationPath 'path-only.zip' -CompressionLevel Fastest"
$folderArchive = "Compress-Archive -LiteralPath 'protected' -DestinationPath 'protected-folder.zip'"
$null = Case archive 1 ("Compress-Archive -LiteralPath 'private.txt' -DestinationPath 'unexecuted-plan.zip'; " +
    (Upload 'http' 'unexecuted-plan.zip')) 'same-block archive provenance without creating the file'
if (Test-Path -LiteralPath (Join-Path $files 'unexecuted-plan.zip')) { throw 'Blocked archive was created' }
$null = Case archive 0 $privateArchive 'real stock Compress-Archive restricted file' -Local
Await-Config 'path-only.zip'
$null = Case archive 1 (Upload 'curl' 'path-only.zip') 'verified copied archive inherits source path'
$null = Case archive 0 $folderArchive 'real stock Compress-Archive restricted nested directory' -Local
Await-Config 'protected-folder.zip'
$forFolder = Case archive 1 (Upload 'scp' 'protected-folder.zip') 'verified archive inherits protected folder provenance'
if ($forFolder.report.policy.evidence[0].flow[0].origin -notmatch 'protected') { throw 'Archive folder provenance was lost' }
$null = Case archive 3 ("Compress-Archive -Path 'protected\*' -DestinationPath 'indeterminate.zip'; " +
    (Upload 'http' 'indeterminate.zip')) 'unbound archive wildcard only warns'
$sum = ($counts.Values | Measure-Object -Sum).Sum
"PASS: $sum additional cases - $(($counts.Keys | ForEach-Object { "$_=$($counts[$_])" }) -join ', ')."

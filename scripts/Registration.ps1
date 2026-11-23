function Get-GuardContext {
    if (-not $IsWindows -or [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64') {
        throw 'Run these scripts in Windows PowerShell 7 x64 (pwsh.exe).'
    }
    $id = '{B19A3622-9E37-46C6-9A76-D48332292DC7}'
    $directory = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'PowerShell7Guard'
    [pscustomobject]@{
        Directory = $directory
        Dll = Join-Path $directory 'PowerShell7Guard.dll'
        Regsvr = Join-Path $env:SystemRoot 'System32\regsvr32.exe'
        Com = "SOFTWARE\Classes\CLSID\$id"
        Amsi = "SOFTWARE\Microsoft\AMSI\Providers\$id"
    }
}

function Assert-GuardImage {
    param([Parameter(Mandatory)][string]$Path)
    $file = [IO.File]::OpenRead($Path)
    try {
        $reader = [IO.BinaryReader]::new($file)
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw 'Invalid DOS header.' }
        $file.Position = 0x3C
        $file.Position = $reader.ReadUInt32()
        if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) {
            throw 'Expected an x64 PE image.'
        }
    } finally { $file.Dispose() }
}

function Assert-ProtectedGuardPath {
    param([Parameter(Mandatory)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Deployment path is a reparse point: $Path"
    }
    $acl = Get-Acl -LiteralPath $Path
    $sidType = [Security.Principal.SecurityIdentifier]
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    if ($acl.GetOwner($sidType).Value -notin $trusted) {
        throw "Deployment path is not owned by a system administrator: $Path"
    }
    # Write, delete, delete-child, change permissions, take ownership, generic-all/write.
    $mutatingRights = 0x500D0156
    foreach ($rule in $acl.GetAccessRules($true, $true, $sidType)) {
        $sid = $rule.IdentityReference.Value
        if ($rule.AccessControlType -ne 'Allow' -or $sid -in $trusted) { continue }
        # Newly created children inherit CREATOR OWNER for the trusted creator only.
        if ($sid -eq 'S-1-3-0' -and ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        if ([int]$rule.FileSystemRights -band $mutatingRights) {
            throw "Deployment path grants write access to a non-administrative principal: $Path"
        }
    }
}

function Initialize-GuardDirectory {
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -LiteralPath $Path) { return }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    $permissions = @{
        'S-1-5-32-544' = 'FullControl'
        'S-1-5-18' = 'FullControl'
        'S-1-5-11' = 'ReadAndExecute'
    }
    foreach ($grant in $permissions.GetEnumerator()) {
        $sid = [Security.Principal.SecurityIdentifier]::new($grant.Key)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]$grant.Value, $inherit, 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    $null = [IO.FileSystemAclExtensions]::CreateDirectory($acl, $Path)
}

function Test-GuardDeploymentPath {
    param($Context, [string]$Path)
    if (-not $Path) { return $false }
    $name = [IO.Path]::GetFileName($Path)
    return $name -match '^PowerShell7Guard(?:-[0-9A-F]{32})?\.dll$' -and
        $Path -ieq (Join-Path $Context.Directory $name)
}

function Get-GuardDeploymentFiles {
    param($Context)
    if (-not (Test-Path -LiteralPath $Context.Directory -PathType Container)) { return }
    Get-ChildItem -LiteralPath $Context.Directory -Filter 'PowerShell7Guard*.dll' -File -Force |
        Where-Object { Test-GuardDeploymentPath $Context $_.FullName }
}

function Set-GuardDeploymentFile {
    param([Parameter(Mandatory)][string]$Staged, [Parameter(Mandatory)][string]$Destination)
    try {
        if (Test-Path -LiteralPath $Destination) {
            # Atomic replacement at the fixed path; [NullString] means no backup file.
            [IO.File]::Replace($Staged, $Destination, [NullString]::Value)
        } else {
            [IO.File]::Move($Staged, $Destination)
        }
    } catch {
        $cause = $_.Exception.GetBaseException()
        if ($cause -is [IO.IOException] -or $cause -is [UnauthorizedAccessException]) {
            throw "固定路径替换失败 ${Destination}：$($cause.Message) 若旧 DLL 正被 PowerShell 占用，关闭对应窗口后重试，不必先卸载。"
        }
        throw
    }
}

function Remove-StaleGuardFiles {
    param($Context, [string]$Keep)
    foreach ($file in (Get-GuardDeploymentFiles $Context)) {
        if ($file.FullName -ieq $Keep) { continue }
        try {
            Assert-ProtectedGuardPath $file.FullName
            Assert-GuardImage $file.FullName
            [IO.File]::Delete($file.FullName)
        } catch {
            Write-Warning "旧部署文件暂未清理：$($file.FullName)。$($_.Exception.Message)"
        }
    }
}

function Get-GuardRegistration {
    param($Context, [switch]$Discover)
    $root = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
    $com = $server = $amsi = $null
    try {
        $com = $root.OpenSubKey($Context.Com)
        $server = $root.OpenSubKey("$($Context.Com)\InProcServer32")
        $amsi = $root.OpenSubKey($Context.Amsi)
        if (-not $com -and -not $amsi) { return 'Absent' }
        $registeredPath = if ($server) { $server.GetValue('') }
        if (-not $com -or -not (Test-GuardDeploymentPath $Context $registeredPath) -or
            (-not $Discover -and $registeredPath -ine $Context.Dll)) {
            throw 'Guard CLSID exists but ownership does not match this DLL path; leaving it untouched.'
        }
        if ($amsi -and $amsi.GetValue('') -ne 'PowerShell7Guard') {
            throw 'Unexpected AMSI registration value; leaving it untouched.'
        }
        if ($Discover) { $Context.Dll = $registeredPath }
        if (-not $amsi -or $server.GetValue('ThreadingModel') -ne 'Both') { return 'Partial' }
        'Registered'
    } finally {
        foreach ($key in $amsi,$server,$com,$root) { if ($key) { $key.Dispose() } }
    }
}

function Assert-GuardElevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $p = [Security.Principal.WindowsPrincipal]::new($id)
        if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Start PowerShell 7 x64 as administrator in the test VM.'
        }
    } finally { $id.Dispose() }
}

function Invoke-GuardRegsvr {
    param($Context, [switch]$Unregister)
    $arguments = @('/s')
    if ($Unregister) { $arguments += '/u' }
    # Start-Process joins ArgumentList with spaces; quote the Program Files path.
    $arguments += ('"{0}"' -f $Context.Dll)
    $process = Start-Process -FilePath $Context.Regsvr -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
    try { return $process.ExitCode } finally { $process.Dispose() }
}

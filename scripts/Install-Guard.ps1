#Requires -Version 7.0
[CmdletBinding(SupportsShouldProcess)]
param([string]$Dll = (Join-Path $PSScriptRoot '..\build\Release\PowerShell7Guard.dll'))

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Registration.ps1')
$guard = Get-GuardContext
$destination = $guard.Dll
$state = Get-GuardRegistration $guard -Discover
$needsRegistration = $state -ne 'Registered' -or $guard.Dll -ine $destination
$guard.Dll = $destination
$source = (Get-Item -LiteralPath $Dll).FullName
Assert-GuardImage $source
$hash = (Get-FileHash -LiteralPath $source).Hash

if (-not $PSCmdlet.ShouldProcess($guard.Dll, 'Deploy and register the AMSI provider')) { return }

Assert-GuardElevated
Initialize-GuardDirectory $guard.Directory
Assert-ProtectedGuardPath $guard.Directory
if (Test-Path -LiteralPath $guard.Dll) { Assert-ProtectedGuardPath $guard.Dll }
if (-not (Test-Path -LiteralPath $guard.Dll) -or (Get-FileHash -LiteralPath $guard.Dll).Hash -ne $hash) {
    $staged = Join-Path $guard.Directory ("guard-" + [guid]::NewGuid().ToString('N') + ".tmp")
    try {
        [IO.File]::Copy($source, $staged, $false)
        Assert-ProtectedGuardPath $staged
        if ((Get-FileHash -LiteralPath $staged).Hash -ne $hash) { throw '构建文件在部署时发生变化，请重试。' }
        Set-GuardDeploymentFile -Staged $staged -Destination $guard.Dll
    } finally {
        if (Test-Path -LiteralPath $staged) { [IO.File]::Delete($staged) }
    }
}
Assert-ProtectedGuardPath $guard.Dll
if ((Get-FileHash -LiteralPath $guard.Dll).Hash -ne $hash) { throw "部署副本的哈希不匹配：$($guard.Dll)" }
if ($needsRegistration) {
    if ((Get-AuthenticodeSignature -LiteralPath $guard.Dll).Status -ne 'Valid') {
        Write-Warning 'The DLL is not validly signed; Windows may decline to load it.'
    }
    $regCode = Invoke-GuardRegsvr $guard
    $state = Get-GuardRegistration $guard
    if ($state -ne 'Registered') {
        throw "注册未完成：regsvr32 退出码=$regCode，注册状态=$state。"
    }
}
Remove-StaleGuardFiles $guard -Keep $guard.Dll
"Registered: $($guard.Dll). Open a new PowerShell 7 window to load this version."

#Requires -Version 7.0
[CmdletBinding(SupportsShouldProcess)]
param([switch]$CheckOnly)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Registration.ps1')
$guard = Get-GuardContext
$state = Get-GuardRegistration $guard -Discover
$filePresent = Test-Path -LiteralPath $guard.Dll
$deployed = @(Get-GuardDeploymentFiles $guard)
if ($CheckOnly) { "Rollback preflight: $state; deployed DLLs: $($deployed.Count); no changes."; return }
if ($state -eq 'Absent' -and -not $deployed.Count) { 'Already uninstalled.'; return }
if (-not $PSCmdlet.ShouldProcess($guard.Directory, 'Unregister the provider and remove its deployed DLLs')) { return }

Assert-GuardElevated
Assert-ProtectedGuardPath $guard.Directory
if ($state -ne 'Absent') {
    if (-not $filePresent) { throw 'Registration still exists, but the deployed DLL is missing.' }
    Assert-ProtectedGuardPath $guard.Dll
    Assert-GuardImage $guard.Dll
    $regCode = Invoke-GuardRegsvr $guard -Unregister
    $state = Get-GuardRegistration $guard
    if ($state -ne 'Absent') {
        throw "注销未完成：regsvr32 退出码=$regCode，注册状态=$state。部署副本已保留。"
    }
}
Remove-StaleGuardFiles $guard
if (Get-GuardDeploymentFiles $guard) { throw '已注销；仍有 DLL 未清理。关闭加载它的旧 PowerShell 窗口后重跑卸载。' }
if (-not (Get-ChildItem -LiteralPath $guard.Directory -Force | Select-Object -First 1)) {
    [IO.Directory]::Delete($guard.Directory, $false)
}
'Uninstalled. The workspace build was kept.'

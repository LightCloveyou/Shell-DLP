#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$Remote = '',
    [string[]]$Refspec = @(),
    [switch]$All,
    [switch]$Tags,
    [switch]$FollowTags,
    [ValidateNotNullOrEmpty()][string]$Repository = (Get-Location).ProviderPath,
    [ValidateNotNullOrEmpty()][string]$Bridge = (Join-Path $PSScriptRoot '..\build\ast\PowerShell7Guard.Ast.dll')
)
$ErrorActionPreference = 'Stop'
if ($Remote.Length -eq 0 -and $Refspec.Count -ne 0) {
    throw 'Specify -Remote when supplying one or more refspecs.'
}
$repo = Get-Item -LiteralPath $Repository -Force
if ($repo -isnot [IO.DirectoryInfo]) { throw '-Repository must refer to a filesystem directory.' }
$dll = Get-Item -LiteralPath $Bridge -Force
if ($dll -isnot [IO.FileInfo]) { throw '-Bridge must refer to a DLL file.' }
$git = (Get-Command git.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$context = [System.Runtime.Loader.AssemblyLoadContext]::new('PowerShell7Guard.GitPreflight', $true)
$bytes = [IO.MemoryStream]::new([IO.File]::ReadAllBytes($dll.FullName), $false)
try {
    $entry = $context.LoadFromStream($bytes).GetType('PowerShell7Guard.AstBridge', $true).GetMethod('PrepareGitPush')
    $arguments = [object[]]::new(4)
    $arguments[0] = $git
    $arguments[1] = $repo.FullName
    $arguments[2] = $Remote
    $selection = @(
        if ($All) { '--all' }
        if ($Tags) { '--tags' }
        if ($FollowTags) { '--follow-tags' }
    )
    $arguments[3] = [string[]]($selection + $Refspec)
    $entry.Invoke($null, $arguments)
}
finally {
    $bytes.Dispose()
    $context.Unload()
}

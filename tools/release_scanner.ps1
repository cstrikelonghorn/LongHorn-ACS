<#
.SYNOPSIS
    Cuts a numbered ACS scanner release from committed code.

.DESCRIPTION
    Players should only ever receive numbered builds, and the same file for as long as possible:
    SmartScreen reputation belongs to the exact file, so every ad-hoc rebuild starts from zero.

    Steps: refuse uncommitted scanner changes and non-increasing versions, set the version in
    ACPScanner.csproj, publish, check the exe carries that version and an upload token, write
    windows/release/version.txt and ACPScanner.exe.sha256, then commit and tag vX.Y.Z.
    Nothing is pushed or uploaded.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools/release_scanner.ps1 -Version 1.0.1
#>
param(
    [Parameter(Mandatory = $true)]
    [string] $Version
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$csproj = Join-Path $root 'windows\ACPScanner.csproj'
$releaseDir = Join-Path $root 'windows\release'
$exe = Join-Path $releaseDir 'ACPScanner.exe'

function Invoke-Git {
    $output = & git -C $root @args 2>&1
    if ($LASTEXITCODE -ne 0) { throw "git $($args -join ' ') failed:`n$output" }
    return $output
}

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "Version must be three numbers, for example 1.0.1 (got '$Version')."
}

# A release must be reproducible from git, otherwise nobody can say what a given exe contains.
$dirty = Invoke-Git status --porcelain -- windows
if ($dirty) {
    throw "Commit the scanner changes under windows/ first:`n$($dirty -join "`n")"
}

$project = [IO.File]::ReadAllText($csproj)
$current = [regex]::Match($project, '<Version>\s*([^<\s]+)\s*</Version>').Groups[1].Value
if (-not $current) { throw "No <Version> found in $csproj." }
if ([version]$Version -le [version]$current) {
    throw "Version $Version must be higher than the current $current."
}
if (Invoke-Git tag --list "v$Version") {
    throw "Tag v$Version already exists."
}

Write-Host "Releasing ACS scanner $current -> $Version"
$project = $project -replace '<Version>[^<]*</Version>', "<Version>$Version</Version>"
$project = $project -replace '<AssemblyVersion>[^<]*</AssemblyVersion>', "<AssemblyVersion>$Version.0</AssemblyVersion>"
[IO.File]::WriteAllText($csproj, $project, (New-Object Text.UTF8Encoding $false))

& dotnet publish $csproj -c Release --nologo
if ($LASTEXITCODE -ne 0) {
    Invoke-Git checkout -- windows/ACPScanner.csproj | Out-Null
    throw 'dotnet publish failed; the version change was reverted.'
}

$fileVersion = (Get-Item $exe).VersionInfo.FileVersion
if ($fileVersion -ne "$Version.0") {
    throw "The published exe reports version '$fileVersion', expected '$Version.0'."
}
# Without an embedded token every player's upload is refused; a plain build must never ship.
$bytes = [IO.File]::ReadAllBytes($exe)
if (-not [Text.Encoding]::ASCII.GetString($bytes).Contains('AcsApiToken')) {
    throw 'The published exe has no embedded upload token (AcsApiToken). Not releasing it.'
}

$hash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
[IO.File]::WriteAllText((Join-Path $releaseDir 'version.txt'), $Version)
[IO.File]::WriteAllText((Join-Path $releaseDir 'ACPScanner.exe.sha256'), "$hash  ACS-Scanner-$Version-windows.exe`n")

Invoke-Git add -- windows/ACPScanner.csproj | Out-Null
Invoke-Git commit -m "Release scanner $Version" | Out-Null
Invoke-Git tag -a "v$Version" -m "ACS Scanner $Version (sha256 $hash)" | Out-Null

Write-Host ""
Write-Host "Released $Version"
Write-Host "  exe     : $exe"
Write-Host "  sha256  : $hash"
Write-Host "  git     : commit 'Release scanner $Version', tag v$Version (not pushed)"
Write-Host ""
Write-Host "Next: add the release to CHANGELOG.md, then upload ACPScanner.exe and version.txt together."

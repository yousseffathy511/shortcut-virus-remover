<#
.SYNOPSIS
    Builds the one-click Windows executable for GitHub Releases.

.DESCRIPTION
    Compiles ShortcutVirusRemover.ps1 into dist\ShortcutVirusRemover.exe
    using the ps2exe module. The generated executable requests
    Administrator rights through its manifest, so users only need to
    double-click it and accept the Windows UAC prompt.
#>

[CmdletBinding()]
param(
    [string]$Version = '1.0.0',
    [string]$OutputDir,
    [switch]$SkipModuleInstall
)

$ErrorActionPreference = 'Stop'

$scriptDir = if ($PSScriptRoot) {
    $PSScriptRoot
} elseif ($MyInvocation.MyCommand.Path) {
    Split-Path -Parent $MyInvocation.MyCommand.Path
} else {
    (Get-Location).Path
}

if (-not $OutputDir) {
    $OutputDir = Join-Path $scriptDir 'dist'
}

$source = Join-Path $scriptDir 'ShortcutVirusRemover.ps1'
$output = Join-Path $OutputDir 'ShortcutVirusRemover.exe'
$checksumOutput = "$output.sha256"

if (-not (Test-Path -LiteralPath $source)) {
    throw "Source file not found: $source"
}

if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

if (-not (Get-Command Invoke-ps2exe -ErrorAction SilentlyContinue)) {
    if ($SkipModuleInstall) {
        throw 'Invoke-ps2exe was not found. Install the ps2exe module or remove -SkipModuleInstall.'
    }

    Write-Host 'Installing ps2exe from PowerShell Gallery...' -ForegroundColor Cyan
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-Module -Name ps2exe -Scope CurrentUser -Force -AllowClobber
}

Import-Module ps2exe -ErrorAction Stop

Write-Host "Building $output ..." -ForegroundColor Cyan

Invoke-ps2exe `
    -inputFile $source `
    -outputFile $output `
    -requireAdmin `
    -title 'Shortcut Virus Remover' `
    -description 'One-click remover for the Windows shortcut virus / Runner malware family.' `
    -company 'Widescreen' `
    -product 'Shortcut Virus Remover' `
    -copyright 'Copyright (c) 2026 Youssef Fathy / Widescreen. MIT License.' `
    -version $Version

if (-not (Test-Path -LiteralPath $output)) {
    throw "Build failed: $output was not created."
}

$item = Get-Item -LiteralPath $output
$hash = Get-FileHash -LiteralPath $output -Algorithm SHA256
# GNU-style line: "<hex>  <basename>\n" with Unix LF — avoids CRLF issues for release uploads
$hashLine = ('{0}  {1}' -f $hash.Hash.ToLowerInvariant(), $item.Name)
[System.IO.File]::WriteAllText(
    $checksumOutput,
    $hashLine + "`n",
    [System.Text.UTF8Encoding]::new($false)
)

Write-Host ("Built {0} ({1:N0} bytes)" -f $item.FullName, $item.Length) -ForegroundColor Green
Write-Host "SHA-256: $($hash.Hash)" -ForegroundColor Green

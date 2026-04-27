<#
.SYNOPSIS
    Safely recovers user files from a USB drive infected by the shortcut virus,
    while skipping every shortcut/script/executable payload.

.DESCRIPTION
    The shortcut virus hides your real folder on a USB drive and drops:
        <Volume>.lnk         <-- fake shortcut, do NOT click
        sysvolume\u<n>.vbs   <-- elevation script
        sysvolume\u<n>.bat   <-- payload installer
        sysvolume\u<n>.dat   <-- DLL written to System32

    Your real files are still on the drive in a hidden+system folder.
    This script copies them to a clean folder on your local disk and skips
    any of the malware artifacts listed above.

.PARAMETER Drive
    Drive letter to recover from. Default: E:

.PARAMETER Destination
    Where to put the recovered files. Default: Desktop\USB-Recovered-<timestamp>

.EXAMPLE
    PS> .\Recover-UsbFiles.ps1 -Drive E:
#>

[CmdletBinding()]
param(
    [string]$Drive = 'E:',
    [string]$Destination
)

$ErrorActionPreference = 'Stop'

if (-not $Destination) {
    $stamp       = Get-Date -Format 'yyyyMMdd-HHmmss'
    $Destination = Join-Path ([Environment]::GetFolderPath('Desktop')) "USB-Recovered-$stamp"
}

$Drive = $Drive.TrimEnd('\') + '\'
if (-not (Test-Path $Drive)) {
    Write-Error "Drive $Drive is not accessible."
    exit 1
}

New-Item -ItemType Directory -Path $Destination -Force | Out-Null
Write-Host "Source     : $Drive"           -ForegroundColor Cyan
Write-Host "Destination: $Destination"     -ForegroundColor Cyan
Write-Host ""
Write-Host "Copying real user files (skipping shortcuts and scripts)..." -ForegroundColor Yellow

# Excluded extensions (payloads, shortcuts, executables)
$excludedFiles = @(
    '*.lnk', '*.vbs', '*.vbe', '*.bat', '*.cmd',
    '*.js',  '*.jse', '*.wsf', '*.scr', '*.exe',
    '*.dll', '*.dat', '*.bin', '*.hta'
)

# Excluded folders that are known payload containers
$excludedDirs = @('sysvolume', 'sysvolume.x86', 'systemvolume', 'System Volume Information', '$RECYCLE.BIN')

$args = @(
    "$Drive", "$Destination",
    '/E',          # subfolders, including empty
    '/COPY:DAT',   # data, attributes, timestamps (no NTFS perms)
    '/R:1',        # 1 retry on errors
    '/W:1',        # 1 second wait between retries
    '/XF'
)
$args += $excludedFiles
$args += '/XD'
$args += $excludedDirs

& robocopy.exe @args
$rc = $LASTEXITCODE

# robocopy exit codes 0-7 are success-ish; 8+ indicate real errors
if ($rc -lt 8) {
    Write-Host ""
    Write-Host "Recovery complete." -ForegroundColor Green
    Write-Host "Your files are at: $Destination" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "robocopy reported errors (exit code $rc)." -ForegroundColor Red
}
exit 0

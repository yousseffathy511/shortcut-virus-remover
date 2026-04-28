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
    any of the malware artifacts listed above. After the copy, it walks
    the destination tree and writes a recovery-manifest.json with the
    SHA-256, size, and last-write-time of every recovered file so you can
    later verify nothing was tampered with.

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

$excludedFiles = @(
    '*.lnk', '*.vbs', '*.vbe', '*.bat', '*.cmd',
    '*.js',  '*.jse', '*.wsf', '*.scr', '*.exe',
    '*.dll', '*.dat', '*.bin', '*.hta'
)

$excludedDirs = @('sysvolume', 'sysvolume.x86', 'systemvolume', 'System Volume Information', '$RECYCLE.BIN')

$roboArgs = @(
    "$Drive", "$Destination",
    '/E',          # subfolders, including empty
    '/COPY:DAT',   # data, attributes, timestamps (no NTFS perms)
    '/R:1',        # 1 retry on errors
    '/W:1',        # 1 second wait between retries
    '/XF'
)
$roboArgs += $excludedFiles
$roboArgs += '/XD'
$roboArgs += $excludedDirs

& robocopy.exe @roboArgs
$rc = $LASTEXITCODE

# robocopy exit codes 0-7 are success-ish; 8+ indicate real errors
if ($rc -ge 8) {
    Write-Host ""
    Write-Host "robocopy reported errors (exit code $rc). Skipping manifest." -ForegroundColor Red
    exit 0
}

Write-Host ""
Write-Host "Recovery complete." -ForegroundColor Green
Write-Host "Your files are at: $Destination" -ForegroundColor Green

Write-Host ""
Write-Host "Computing SHA-256 manifest..." -ForegroundColor Yellow

$destinationFull = (Resolve-Path -LiteralPath $Destination).Path
$manifestPath    = Join-Path $destinationFull 'recovery-manifest.json'

$entries = New-Object System.Collections.Generic.List[object]
Get-ChildItem -LiteralPath $destinationFull -File -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -ne $manifestPath } |
    ForEach-Object {
        $relative = $_.FullName.Substring($destinationFull.Length).TrimStart('\','/')
        $sha256   = $null
        try { $sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch {
            Write-Host "  Could not hash $($_.FullName): $_" -ForegroundColor Yellow
        }
        $relativePosix = ($relative -replace '\\', '/')
        $entries.Add([pscustomobject]@{
            path          = $relativePosix
            sha256        = $sha256
            size          = $_.Length
            lastWriteTime = $_.LastWriteTime.ToString('o')
        }) | Out-Null
    }

$manifest = [ordered]@{
    schema       = 'https://github.com/yousseffathy511/shortcut-virus-remover#recovery-manifest-v1'
    sourceDrive  = $Drive
    destination  = $destinationFull
    generatedAt  = (Get-Date).ToString('o')
    fileCount    = $entries.Count
    files        = $entries
}

try {
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    Write-Host "Manifest: $manifestPath" -ForegroundColor Green
} catch {
    Write-Host "Could not write manifest: $_" -ForegroundColor Red
}

exit 0

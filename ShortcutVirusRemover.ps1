<#
.SYNOPSIS
    One-click installer wrapper for the Shortcut Virus Remover.

.DESCRIPTION
    This is a SELF-CONTAINED wrapper designed to be compiled to a single
    Windows .exe with ps2exe and the -RequireAdmin manifest flag, so a
    non-technical user can:

      1. Download ShortcutVirusRemover.exe
      2. Double-click it
      3. Click "Yes" on the Windows UAC prompt
      4. Wait for the cleanup to finish

    The wrapper inlines the same logic as Remove-ShortcutVirus.ps1 so the
    compiled exe does not depend on any other file being present next to it.

    Cleanup performed (always with -Harden):
      * Stop running malware processes (rundll32 ...IdllEntry, sysvolume scripts).
      * Stop and delete the u<digits> Windows service + its registry key.
      * Delete u<digits>.dll from C:\Windows\System32 (delete-on-reboot fallback).
      * Remove Defender exclusions added by the malware.
      * Clean every connected removable drive: delete shortcuts and the
        sysvolume payload folder, unhide the user's real folders.
      * Disable AutoRun, show hidden files, enable Defender ASR rules.
      * Trigger a Defender Quick Scan in the background.

.NOTES
    Author : Cursor / Community
    License: MIT
#>

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# -------------------------------------------------------------------
# Resolve a base directory that works under powershell.exe AND ps2exe
# -------------------------------------------------------------------
function Get-RunBaseDirectory {
    if ($PSScriptRoot -and (Test-Path $PSScriptRoot)) { return $PSScriptRoot }
    try {
        $exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        if ($exe) { return (Split-Path -Parent $exe) }
    } catch { }
    try {
        $base = [System.AppDomain]::CurrentDomain.BaseDirectory
        if ($base) { return $base.TrimEnd('\') }
    } catch { }
    return (Get-Location).Path
}

$BaseDir = Get-RunBaseDirectory
$LogPath = Join-Path $env:TEMP 'shortcut-virus-remover.log'

# -------------------------------------------------------------------
# Logging helpers
# -------------------------------------------------------------------
function Write-Log {
    param(
        [Parameter(Mandatory)] [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','OK','STEP')] [string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line      = "[$timestamp] [$Level] $Message"
    $color     = switch ($Level) {
        'INFO'  { 'Gray' }
        'STEP'  { 'Cyan' }
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
    }
    Write-Host $line -ForegroundColor $color
    try { Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8 } catch { }
}

function Write-FriendlyBanner {
    $banner = @'

  +------------------------------------------------------------+
  |                                                            |
  |              SHORTCUT VIRUS REMOVER  v1.0.0                |
  |                                                            |
  |   Removes the "Shortcut / Runner" malware from your PC     |
  |   and cleans every connected USB flash drive.              |
  |                                                            |
  +------------------------------------------------------------+

  What this tool will do automatically:

    [1] Stop the malware processes that are running right now.
    [2] Delete the malware Windows service (u<digits>).
    [3] Delete the malware DLL from C:\Windows\System32.
    [4] Remove the Defender exclusions the malware added.
    [5] Clean every USB drive: delete fake shortcuts, remove
        the hidden "sysvolume" payload, and unhide your real
        folders so you can see your files again.
    [6] Disable AutoRun on USB drives so this cannot happen
        again.
    [7] Start a Microsoft Defender Quick Scan in the background.

  No personal files on the C: drive are touched.
  A log of everything that was done will be written to:
    %TEMP%\shortcut-virus-remover.log

'@
    Write-Host $banner -ForegroundColor Cyan
}

# -------------------------------------------------------------------
# Admin check (ps2exe -RequireAdmin already triggers UAC, this is a
# safety net for when the .ps1 is run directly without elevation)
# -------------------------------------------------------------------
function Test-IsAdministrator {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    return ([System.Security.Principal.WindowsPrincipal]$id).IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Wait-ForUserExit {
    param([int]$ExitCode = 0)
    Write-Host ""
    Write-Host "  Press any key to close this window..." -ForegroundColor Gray
    try {
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    } catch {
        # Some hosts don't support ReadKey; fall back to Read-Host.
        Read-Host "Press ENTER to exit" | Out-Null
    }
    exit $ExitCode
}

# -------------------------------------------------------------------
# Win32: schedule delete-on-reboot for files in use
# -------------------------------------------------------------------
function Register-DeleteOnReboot {
    param([Parameter(Mandatory)] [string]$Path)
    try {
        if (-not ('Win32.NativeMethods' -as [type])) {
            Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@
        }
        # MOVEFILE_DELAY_UNTIL_REBOOT = 0x4
        [void][Win32.NativeMethods]::MoveFileEx($Path, $null, 4)
        Write-Log "Scheduled for delete-on-reboot: $Path" -Level WARN
    } catch {
        Write-Log "Could not schedule delete-on-reboot for $Path : $_" -Level ERROR
    }
}

# -------------------------------------------------------------------
# IOC patterns (match the same family as Remove-ShortcutVirus.ps1)
# -------------------------------------------------------------------
$IocNamePattern    = '^u\d{4,}$'
$IocDllPattern     = '^u\d{4,}\.dll$'
$IocScriptPattern  = '^u\d{4,}\.(vbs|bat|cmd|js|jse|wsf|dat|bin)$'
$IocPayloadFolders = @('sysvolume', 'sysvolume.x86', 'systemvolume')
$SuspiciousExtsRoot = @('.lnk', '.vbs', '.vbe', '.bat', '.cmd',
                        '.js',  '.jse', '.wsf', '.scr', '.exe', '.hta')

# -------------------------------------------------------------------
# Step 1: Kill running malware processes
# -------------------------------------------------------------------
function Stop-MaliciousProcesses {
    Write-Log "Looking for live malware processes..." -Level STEP

    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
             Where-Object {
                $_.CommandLine -match 'u\d{4,}\.(dll|vbs|bat|dat)' -or
                $_.CommandLine -match 'sysvolume'                  -or
                $_.CommandLine -match 'IdllEntry'                  -or
                ($_.Name -eq 'rundll32.exe' -and
                 $_.CommandLine -match 'C:\\Windows\\System32\\u\d{4,}\.dll')
             }

    if (-not $procs) {
        Write-Log "No suspicious processes running." -Level OK
        return
    }

    foreach ($p in $procs) {
        Write-Log ("Killing PID {0} ({1}): {2}" -f $p.ProcessId, $p.Name, $p.CommandLine) -Level WARN
        try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop }
        catch { Write-Log "Stop-Process failed for PID $($p.ProcessId): $_" -Level WARN }
    }
}

# -------------------------------------------------------------------
# Step 2: Remove malicious services
# -------------------------------------------------------------------
function Remove-MaliciousServices {
    Write-Log "Scanning Windows services for malware pattern '$IocNamePattern'..." -Level STEP

    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match $IocNamePattern }

    if (-not $services) {
        Write-Log "No malicious services found." -Level OK
        return
    }

    foreach ($svc in $services) {
        Write-Log ("Found service: name={0} state={1} startmode={2} path={3}" -f `
            $svc.Name, $svc.State, $svc.StartMode, $svc.PathName) -Level WARN

        try { Stop-Service -Name $svc.Name -Force -ErrorAction Stop }
        catch { Write-Log "Stop-Service failed for $($svc.Name): $_" -Level WARN }

        $sc = Start-Process -FilePath 'sc.exe' `
                            -ArgumentList "delete `"$($svc.Name)`"" `
                            -PassThru -Wait -WindowStyle Hidden
        if ($sc.ExitCode -eq 0) {
            Write-Log "Deleted service: $($svc.Name)" -Level OK
        } else {
            Write-Log "sc.exe delete returned $($sc.ExitCode) for $($svc.Name)" -Level WARN
        }

        $regKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
        if (Test-Path $regKey) {
            Remove-Item -LiteralPath $regKey -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Removed registry key: $regKey" -Level OK
        }
    }
}

# -------------------------------------------------------------------
# Step 3: Remove malicious DLLs in System32
# -------------------------------------------------------------------
function Remove-MaliciousDlls {
    Write-Log "Scanning C:\Windows\System32 for malicious DLLs..." -Level STEP

    $dlls = Get-ChildItem -LiteralPath 'C:\Windows\System32' -Filter 'u*.dll' -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $IocDllPattern }

    if (-not $dlls) {
        Write-Log "No malicious DLLs found in System32." -Level OK
        return
    }

    foreach ($dll in $dlls) {
        Write-Log ("Found DLL: {0} ({1:N0} bytes, {2})" -f $dll.FullName, $dll.Length, $dll.LastWriteTime) -Level WARN
        try {
            attrib.exe -h -s -r $dll.FullName 2>$null
            Remove-Item -LiteralPath $dll.FullName -Force -ErrorAction Stop
            Write-Log "Deleted: $($dll.FullName)" -Level OK
        } catch {
            Write-Log "Direct delete failed (file in use): $_" -Level WARN
            Register-DeleteOnReboot -Path $dll.FullName
        }
    }
}

# -------------------------------------------------------------------
# Step 4: Remove Defender exclusions added by malware
# -------------------------------------------------------------------
function Clear-MalwareDefenderExclusions {
    Write-Log "Removing Defender exclusion paths added by malware..." -Level STEP

    $candidates = @(
        'C:\Windows\System32',
        'C:\Windows\System32\'
    )

    Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' -ErrorAction SilentlyContinue |
        ForEach-Object {
            $candidates += $_.DeviceID + '\'
            $candidates += $_.DeviceID + '\sysvolume'
            $candidates += $_.DeviceID + '\sysvolume\'
        }

    foreach ($p in ($candidates | Sort-Object -Unique)) {
        try { Remove-MpPreference -ExclusionPath $p -ErrorAction SilentlyContinue } catch { }
    }
    Write-Log "Defender exclusion cleanup attempted for removable drives + System32." -Level OK
}

# -------------------------------------------------------------------
# Step 5: Clean removable drives
# -------------------------------------------------------------------
function Clear-RemovableDrive {
    param([Parameter(Mandatory)] [string]$DriveRoot)

    Write-Log "Cleaning drive: $DriveRoot" -Level STEP

    if (-not (Test-Path $DriveRoot)) {
        Write-Log "Drive $DriveRoot not accessible. Skipping." -Level WARN
        return
    }

    $rootItems = Get-ChildItem -LiteralPath $DriveRoot -Force -ErrorAction SilentlyContinue

    $rootSuspicious = $rootItems | Where-Object {
        -not $_.PSIsContainer -and
        ($SuspiciousExtsRoot -contains $_.Extension.ToLower())
    }
    foreach ($item in $rootSuspicious) {
        Write-Log "Removing root payload: $($item.FullName)" -Level WARN
        try {
            attrib.exe -h -s -r $item.FullName 2>$null
            Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
        } catch { Write-Log "Delete failed: $_" -Level ERROR }
    }

    foreach ($folder in $rootItems | Where-Object { $_.PSIsContainer -and ($IocPayloadFolders -contains $_.Name.ToLower()) }) {
        Write-Log "Removing payload folder: $($folder.FullName)" -Level WARN
        try {
            attrib.exe -h -s -r $folder.FullName /S /D 2>$null
            Remove-Item -LiteralPath $folder.FullName -Recurse -Force -ErrorAction Stop
        } catch { Write-Log "Delete failed: $_" -Level ERROR }
    }

    foreach ($protectedFolderName in @('System Volume Information', '$RECYCLE.BIN')) {
        $protectedFolder = Join-Path $DriveRoot $protectedFolderName
        if (Test-Path -LiteralPath $protectedFolder) {
            attrib.exe +h +s $protectedFolder 2>$null
            Write-Log "Kept Windows system folder in place and hidden: $protectedFolder" -Level INFO
        }
    }

    $hiddenFolders = Get-ChildItem -LiteralPath $DriveRoot -Directory -Force -ErrorAction SilentlyContinue |
                     Where-Object {
                        ($_.Attributes -band [IO.FileAttributes]::Hidden) -and
                        ($_.Attributes -band [IO.FileAttributes]::System) -and
                        ($IocPayloadFolders -notcontains $_.Name.ToLower())
                     }
    foreach ($f in $hiddenFolders) {
        Write-Log "Unhiding folder: $($f.FullName)" -Level OK
        attrib.exe -h -s $f.FullName /S /D 2>$null
    }

    $deepSuspicious = Get-ChildItem -LiteralPath $DriveRoot -Recurse -File -Force -ErrorAction SilentlyContinue |
                      Where-Object {
                          $_.Name -match $IocScriptPattern -or
                          ($_.Extension -ieq '.lnk' -and $_.DirectoryName -ne $DriveRoot.TrimEnd('\'))
                      }
    foreach ($s in $deepSuspicious) {
        Write-Log "Removing nested payload: $($s.FullName)" -Level WARN
        try {
            attrib.exe -h -s -r $s.FullName 2>$null
            Remove-Item -LiteralPath $s.FullName -Force -ErrorAction Stop
        } catch { Write-Log "Delete failed: $_" -Level ERROR }
    }
}

function Clear-AllRemovableDrives {
    Write-Log "Enumerating removable drives..." -Level STEP
    $drives = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' -ErrorAction SilentlyContinue
    if (-not $drives) {
        Write-Log "No removable drives detected." -Level OK
        return
    }
    foreach ($d in $drives) {
        Clear-RemovableDrive -DriveRoot ($d.DeviceID + '\')
    }
}

# -------------------------------------------------------------------
# Step 6: Hardening
# -------------------------------------------------------------------
function Invoke-Hardening {
    Write-Log "Applying hardening settings..." -Level STEP

    $explorerKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    if (-not (Test-Path $explorerKey)) { New-Item -Path $explorerKey -Force | Out-Null }
    Set-ItemProperty -Path $explorerKey -Name 'NoDriveTypeAutoRun' -Type DWord -Value 0xFF -Force
    Set-ItemProperty -Path $explorerKey -Name 'NoAutorun'          -Type DWord -Value 1     -Force
    Write-Log "AutoRun disabled for all drives." -Level OK

    $advKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    if (Test-Path $advKey) {
        Set-ItemProperty -Path $advKey -Name 'Hidden'          -Type DWord -Value 1 -Force
        Set-ItemProperty -Path $advKey -Name 'ShowSuperHidden' -Type DWord -Value 0 -Force
        Set-ItemProperty -Path $advKey -Name 'HideFileExt'    -Type DWord -Value 0 -Force
        Write-Log "Explorer set to show hidden files and extensions, while keeping protected Windows files hidden." -Level OK
    }

    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids   'D3E037E1-3EB8-44C8-A917-57927947596D' `
                        -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
        Add-MpPreference -AttackSurfaceReductionRules_Ids   'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' `
                        -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
        Write-Log "Defender Attack Surface Reduction rules enabled." -Level OK
    } catch {
        Write-Log "Could not enable ASR rules: $_" -Level WARN
    }
}

# -------------------------------------------------------------------
# Main flow
# -------------------------------------------------------------------
Clear-Host
Write-FriendlyBanner

if (-not (Test-IsAdministrator)) {
    Write-Host ""
    Write-Host "  ERROR: This tool must be run as Administrator." -ForegroundColor Red
    Write-Host "  Right-click ShortcutVirusRemover.exe and choose 'Run as administrator'." -ForegroundColor Red
    Wait-ForUserExit -ExitCode 1
}

Write-Host "  Starting in 3 seconds..." -ForegroundColor Yellow
Start-Sleep -Seconds 3
Write-Host ""

"--- Run started $(Get-Date -Format s) (one-click installer) ---" |
    Add-Content -LiteralPath $LogPath -ErrorAction SilentlyContinue
Write-Log "Log file: $LogPath" -Level INFO
Write-Log "Base directory: $BaseDir" -Level INFO

$summary = [ordered]@{
    HostCleaned       = $false
    UsbCleaned        = $false
    HardeningApplied  = $false
    DefenderScanQueued = $false
}

try {
    Stop-MaliciousProcesses
    Remove-MaliciousServices
    Remove-MaliciousDlls
    Clear-MalwareDefenderExclusions
    $summary.HostCleaned = $true
} catch {
    Write-Log "Host cleanup error: $_" -Level ERROR
}

try {
    Clear-AllRemovableDrives
    $summary.UsbCleaned = $true
} catch {
    Write-Log "USB cleanup error: $_" -Level ERROR
}

try {
    Invoke-Hardening
    $summary.HardeningApplied = $true
} catch {
    Write-Log "Hardening error: $_" -Level ERROR
}

Write-Log "Triggering Defender Quick Scan in the background..." -Level STEP
try {
    Start-Job -ScriptBlock { Start-MpScan -ScanType QuickScan } | Out-Null
    $summary.DefenderScanQueued = $true
    Write-Log "Defender Quick Scan started in background." -Level OK
} catch {
    Write-Log "Could not start Defender Quick Scan: $_" -Level WARN
}

Write-Host ""
Write-Host "  +--------------------------------------------------------+" -ForegroundColor Green
Write-Host "  |                  CLEANUP COMPLETE                      |" -ForegroundColor Green
Write-Host "  +--------------------------------------------------------+" -ForegroundColor Green
Write-Host ""
Write-Host ("    Host disinfection .... {0}" -f ($(if ($summary.HostCleaned)       { 'OK' } else { 'FAILED' }))) -ForegroundColor White
Write-Host ("    USB drive cleanup .... {0}" -f ($(if ($summary.UsbCleaned)        { 'OK' } else { 'FAILED' }))) -ForegroundColor White
Write-Host ("    Hardening applied .... {0}" -f ($(if ($summary.HardeningApplied)  { 'OK' } else { 'FAILED' }))) -ForegroundColor White
Write-Host ("    Defender quick scan .. {0}" -f ($(if ($summary.DefenderScanQueued){ 'queued' } else { 'skipped' }))) -ForegroundColor White
Write-Host ""
Write-Host "  Recommended next steps:" -ForegroundColor Yellow
Write-Host "    1. Reboot the PC if any DLL was scheduled for delete-on-reboot." -ForegroundColor Yellow
Write-Host "    2. Run a full Microsoft Defender Offline Scan for extra safety." -ForegroundColor Yellow
Write-Host "    3. After copying your files off the USB, format the USB drive." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Detailed log: $LogPath" -ForegroundColor Gray

Wait-ForUserExit -ExitCode 0

<#
.SYNOPSIS
    Removes the "Shortcut Virus" family (Trojan:PowerShell/Runner.PGRA!MTB,
    Trojan:BAT/Runner.PGRD!MTB, and similar variants) from Windows
    and from any connected removable drives.

.DESCRIPTION
    This malware family:
      * Hides the real top-level folder on a USB drive (sets +h +s on it).
      * Replaces it with a .lnk shortcut that has the same name as the
        volume label so the user thinks it's still their data folder.
      * The shortcut launches wscript.exe on a .vbs file in a hidden folder
        on the USB (commonly named "sysvolume").
      * The .vbs re-launches itself via UAC ("runas") and then runs a .bat.
      * The .bat:
          - Adds Microsoft Defender exclusions for the USB and System32.
          - Copies u<digits>.dat from the USB to C:\Windows\System32\u<digits>.dll.
          - Runs the DLL with: rundll32.exe ...,IdllEntry 1
      * On the host PC the DLL is registered as a Windows service
        named u<digits>, hosted by "svchost.exe -k DcomLaunch", with
        a ServiceDll registry entry. The service watches USB inserts
        and re-infects every drive that is plugged in.

    This script:
      1. Auto-elevates to Administrator.
      2. Detects and stops malicious services matching the pattern.
      3. Deletes the malicious DLL in C:\Windows\System32 (with a
         delete-on-reboot fallback if the file is locked).
      4. Removes Defender exclusion paths added by the malware.
      5. Cleans every removable drive: deletes shortcuts, removes the
         sysvolume payload folder, and unhides the real user folder.
      6. Optionally hardens the system to prevent re-infection
         (disables AutoRun on removable media and shows hidden files).

.PARAMETER WhatIf
    Show what would be removed without actually changing anything.

.PARAMETER SkipUsb
    Skip cleaning removable drives. Use this if you only want to
    disinfect the host PC.

.PARAMETER SkipHost
    Skip cleaning the host PC. Use this if you only want to clean
    a removable drive.

.PARAMETER Harden
    After cleanup, apply prevention settings:
      * Disable AutoRun for all drives.
      * Show hidden files and known file extensions in Explorer.

.PARAMETER LogPath
    Path to write the log file.
    Default: $env:TEMP\shortcut-virus-remover.log

.EXAMPLE
    PS> .\Remove-ShortcutVirus.ps1
    Full disinfection of host + USB drives. Will auto-elevate.

.EXAMPLE
    PS> .\Remove-ShortcutVirus.ps1 -Harden
    Disinfect and apply hardening settings.

.EXAMPLE
    PS> .\Remove-ShortcutVirus.ps1 -WhatIf
    Dry run. Reports what would be removed without changing anything.

.NOTES
    Author : Cursor / Community
    License: MIT
    Tested on Windows 10 and Windows 11.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$SkipUsb,
    [switch]$SkipHost,
    [switch]$Harden,
    [string]$LogPath = (Join-Path $env:TEMP 'shortcut-virus-remover.log')
)

$ErrorActionPreference = 'Continue'

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

function Write-Banner {
    $banner = @'
+-----------------------------------------------------------+
|        Shortcut Virus Remover (Windows)                   |
|        Removes Trojan:*/Runner family + USB cleanup       |
+-----------------------------------------------------------+
'@
    Write-Host $banner -ForegroundColor Cyan
}

# -------------------------------------------------------------------
# Self-elevation: relaunch as Administrator if needed
# -------------------------------------------------------------------
function Test-IsAdministrator {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    return ([System.Security.Principal.WindowsPrincipal]$id).IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-SelfElevate {
    if (Test-IsAdministrator) { return }
    Write-Host "Administrator rights required. Re-launching with UAC..." -ForegroundColor Yellow

    $argList = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', "`"$($MyInvocation.PSCommandPath)`""
    )
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [switch]) {
            if ($v.IsPresent) { $argList += "-$k" }
        } else {
            $argList += @("-$k", "`"$v`"")
        }
    }

    Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs
    exit
}

# -------------------------------------------------------------------
# Win32 API: schedule delete-on-reboot for files in use
# -------------------------------------------------------------------
function Register-DeleteOnReboot {
    param([Parameter(Mandatory)] [string]$Path)
    try {
        if (-not ('NativeMethods' -as [type])) {
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
# Patterns / IOCs
#   The malware uses random-looking names like "u123456".
#   Service / DLL / dropper file names match: ^u\d{4,}$ (digits only).
# -------------------------------------------------------------------
$IocNamePattern    = '^u\d{4,}$'
$IocDllPattern     = '^u\d{4,}\.dll$'
$IocScriptPattern  = '^u\d{4,}\.(vbs|bat|cmd|js|jse|wsf|dat|bin)$'
$IocPayloadFolders = @('sysvolume', 'sysvolume.x86', 'systemvolume')
$ProtectedWindowsFolders = @('system volume information', '$recycle.bin')
$SuspiciousExtsRoot = @('.lnk', '.vbs', '.vbe', '.bat', '.cmd',
                        '.js',  '.jse', '.wsf', '.scr', '.exe', '.hta')

# -------------------------------------------------------------------
# Step 1: Remove malicious services
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

        if ($PSCmdlet.ShouldProcess($svc.Name, "Stop and delete service")) {
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
}

# -------------------------------------------------------------------
# Step 2: Kill running malware processes
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
        if ($PSCmdlet.ShouldProcess("PID $($p.ProcessId)", "Stop-Process")) {
            try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop }
            catch { Write-Log "Stop-Process failed for PID $($p.ProcessId): $_" -Level WARN }
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

        if (-not $PSCmdlet.ShouldProcess($dll.FullName, "Delete malicious DLL")) { continue }

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

    # The malware whitelists removable drives + System32. Remove those
    # specific paths if present. We don't blanket-clear all exclusions
    # the user may have added on purpose.
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
        try {
            if ($PSCmdlet.ShouldProcess($p, "Remove Defender exclusion")) {
                Remove-MpPreference -ExclusionPath $p -ErrorAction SilentlyContinue
            }
        } catch { }
    }
    Write-Log "Defender exclusion cleanup attempted for removable drives + System32." -Level OK
}

# -------------------------------------------------------------------
# Step 5: Clean a single removable drive
# -------------------------------------------------------------------
function Clear-RemovableDrive {
    param([Parameter(Mandatory)] [string]$DriveRoot)  # e.g. 'E:\'

    Write-Log "Cleaning drive: $DriveRoot" -Level STEP

    if (-not (Test-Path $DriveRoot)) {
        Write-Log "Drive $DriveRoot not accessible. Skipping." -Level WARN
        return
    }

    $rootItems = Get-ChildItem -LiteralPath $DriveRoot -Force -ErrorAction SilentlyContinue

    # 5a. Delete suspicious script / shortcut files at the root
    $rootSuspicious = $rootItems | Where-Object {
        -not $_.PSIsContainer -and
        ($SuspiciousExtsRoot -contains $_.Extension.ToLower())
    }
    foreach ($item in $rootSuspicious) {
        Write-Log "Removing root payload: $($item.FullName)" -Level WARN
        if ($PSCmdlet.ShouldProcess($item.FullName, "Delete suspicious file")) {
            try {
                attrib.exe -h -s -r $item.FullName 2>$null
                Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
            } catch { Write-Log "Delete failed: $_" -Level ERROR }
        }
    }

    # 5b. Delete known payload folders (sysvolume, etc.)
    foreach ($folder in $rootItems | Where-Object { $_.PSIsContainer -and ($IocPayloadFolders -contains $_.Name.ToLower()) }) {
        Write-Log "Removing payload folder: $($folder.FullName)" -Level WARN
        if ($PSCmdlet.ShouldProcess($folder.FullName, "Delete payload folder")) {
            try {
                attrib.exe -h -s -r $folder.FullName /S /D 2>$null
                Remove-Item -LiteralPath $folder.FullName -Recurse -Force -ErrorAction Stop
            } catch { Write-Log "Delete failed: $_" -Level ERROR }
        }
    }

    foreach ($protectedFolderName in @('System Volume Information', '$RECYCLE.BIN')) {
        $protectedFolder = Join-Path $DriveRoot $protectedFolderName
        if (Test-Path -LiteralPath $protectedFolder) {
            if ($PSCmdlet.ShouldProcess($protectedFolder, "Keep Windows system folder hidden")) {
                attrib.exe +h +s $protectedFolder 2>$null
                Write-Log "Kept Windows system folder in place and hidden: $protectedFolder" -Level INFO
            }
        }
    }

    # 5c. Unhide every hidden+system top-level folder so the user can see their data
    $hiddenFolders = Get-ChildItem -LiteralPath $DriveRoot -Directory -Force -ErrorAction SilentlyContinue |
                     Where-Object {
                        ($_.Attributes -band [IO.FileAttributes]::Hidden) -and
                        ($_.Attributes -band [IO.FileAttributes]::System) -and
                        ($IocPayloadFolders -notcontains $_.Name.ToLower()) -and
                        ($ProtectedWindowsFolders -notcontains $_.Name.ToLower())
                     }
    foreach ($f in $hiddenFolders) {
        Write-Log "Unhiding folder: $($f.FullName)" -Level OK
        if ($PSCmdlet.ShouldProcess($f.FullName, "Clear +h +s attributes")) {
            attrib.exe -h -s $f.FullName /S /D 2>$null
        }
    }

    foreach ($protectedFolderName in @('System Volume Information', '$RECYCLE.BIN')) {
        $protectedFolder = Join-Path $DriveRoot $protectedFolderName
        if (Test-Path -LiteralPath $protectedFolder) {
            if ($PSCmdlet.ShouldProcess($protectedFolder, "Keep Windows system folder hidden")) {
                attrib.exe +h +s $protectedFolder 2>$null
            }
        }
    }

    # 5d. Recurse: also strip any nested .lnk / script files
    $deepSuspicious = Get-ChildItem -LiteralPath $DriveRoot -Recurse -File -Force -ErrorAction SilentlyContinue |
                      Where-Object {
                          $_.Name -match $IocScriptPattern -or
                          ($_.Extension -ieq '.lnk' -and $_.DirectoryName -ne $DriveRoot.TrimEnd('\'))
                      }
    foreach ($s in $deepSuspicious) {
        Write-Log "Removing nested payload: $($s.FullName)" -Level WARN
        if ($PSCmdlet.ShouldProcess($s.FullName, "Delete nested suspicious file")) {
            try {
                attrib.exe -h -s -r $s.FullName 2>$null
                Remove-Item -LiteralPath $s.FullName -Force -ErrorAction Stop
            } catch { Write-Log "Delete failed: $_" -Level ERROR }
        }
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
# Step 6: Hardening (optional)
# -------------------------------------------------------------------
function Invoke-Hardening {
    Write-Log "Applying hardening settings..." -Level STEP

    # Disable AutoRun for all drive types
    $explorerKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    if (-not (Test-Path $explorerKey)) {
        New-Item -Path $explorerKey -Force | Out-Null
    }
    Set-ItemProperty -Path $explorerKey -Name 'NoDriveTypeAutoRun' -Type DWord -Value 0xFF -Force
    Set-ItemProperty -Path $explorerKey -Name 'NoAutorun'          -Type DWord -Value 1     -Force
    Write-Log "AutoRun disabled for all drives." -Level OK

    # Show normal hidden files + extensions, but keep protected Windows files hidden.
    $advKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    if (Test-Path $advKey) {
        Set-ItemProperty -Path $advKey -Name 'Hidden'      -Type DWord -Value 1 -Force # show hidden
        Set-ItemProperty -Path $advKey -Name 'ShowSuperHidden' -Type DWord -Value 0 -Force # hide protected OS files
        Set-ItemProperty -Path $advKey -Name 'HideFileExt' -Type DWord -Value 0 -Force # show extensions
        Write-Log "Explorer set to show hidden files and extensions, while keeping protected Windows files hidden." -Level OK
    }

    # Defender ASR rule: block JavaScript/VBScript launching downloaded executable content
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids   'D3E037E1-3EB8-44C8-A917-57927947596D' `
                        -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
        # Block Office child processes (often paired with shortcut viruses)
        Add-MpPreference -AttackSurfaceReductionRules_Ids   'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' `
                        -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
        Write-Log "Defender Attack Surface Reduction rules enabled." -Level OK
    } catch {
        Write-Log "Could not enable ASR rules: $_" -Level WARN
    }
}

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
Write-Banner
Invoke-SelfElevate
"--- Run started $(Get-Date -Format s) ---" | Add-Content -LiteralPath $LogPath
Write-Log "Log file: $LogPath" -Level INFO
Write-Log "Mode: WhatIf=$($WhatIfPreference) SkipUsb=$SkipUsb SkipHost=$SkipHost Harden=$Harden" -Level INFO

if (-not $SkipHost) {
    Stop-MaliciousProcesses
    Remove-MaliciousServices
    Remove-MaliciousDlls
    Clear-MalwareDefenderExclusions
} else {
    Write-Log "Skipping host disinfection (-SkipHost)." -Level INFO
}

if (-not $SkipUsb) {
    Clear-AllRemovableDrives
} else {
    Write-Log "Skipping USB cleanup (-SkipUsb)." -Level INFO
}

if ($Harden) {
    Invoke-Hardening
}

Write-Log "Triggering Defender Quick Scan in the background..." -Level STEP
try {
    Start-Job -ScriptBlock { Start-MpScan -ScanType QuickScan } | Out-Null
    Write-Log "Defender Quick Scan started in background." -Level OK
} catch {
    Write-Log "Could not start Defender Quick Scan: $_" -Level WARN
}

Write-Host ""
Write-Log "All done. Recommended next steps:" -Level OK
Write-Host "  1. Reboot the PC if any DLL was scheduled for delete-on-reboot." -ForegroundColor Yellow
Write-Host "  2. Run a full Microsoft Defender Offline Scan for extra safety." -ForegroundColor Yellow
Write-Host "  3. Format the USB drive after recovering your files." -ForegroundColor Yellow
Write-Host ""
Write-Host "Press any key to close..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

<#
.SYNOPSIS
    Removes the "Shortcut Virus" family (Trojan:PowerShell/Runner.PGRA!MTB,
    Trojan:BAT/Runner.PGRD!MTB, and similar variants) from Windows and from
    any connected removable drives, with quarantine, restore-point, and
    consolidated-confirmation safety nets.

.DESCRIPTION
    This malware family:
      * Hides the real top-level folder on a USB drive (sets +h +s on it).
      * Replaces it with a .lnk shortcut whose name matches the volume
        label, so the user thinks it is still their data folder.
      * The shortcut launches wscript.exe on a .vbs file in a hidden
        folder on the USB (commonly named "sysvolume").
      * The .vbs re-launches itself via UAC ("runas") and then runs a .bat.
      * The .bat:
          - Adds Microsoft Defender exclusions for the USB and System32.
          - Copies u<digits>.dat from the USB to C:\Windows\System32\u<digits>.dll.
          - Runs the DLL with: rundll32.exe ...,IdllEntry 1
      * On the host PC the DLL is registered as a Windows service named
        u<digits>, hosted by "svchost.exe -k DcomLaunch", with a ServiceDll
        registry entry. The service watches USB inserts and re-infects
        every drive that is plugged in.

    This script:
      1. Auto-elevates to Administrator.
      2. Creates a System Restore checkpoint (best-effort).
      3. Detects malicious services and DLLs and shows a single
         consolidated confirmation prompt with a 10 second auto-Yes timeout.
      4. Stops malicious processes.
      5. Stops and removes malicious services + their registry keys.
      6. Quarantines malicious DLLs in System32 to
         %ProgramData%\ShortcutVirusRemover\Quarantine\<timestamp>\
         (delete-on-reboot fallback if the file is locked) with a manifest.
      7. Removes Defender exclusion paths added by the malware.
      8. Cleans every removable drive: deletes shortcuts, removes the
         sysvolume payload folder, and unhides the real user folder.
      9. Optionally hardens the system (-Harden).

.PARAMETER WhatIf
    Show what would be removed without actually changing anything. Skips
    the confirmation prompt.

.PARAMETER SkipUsb
    Skip cleaning removable drives. Use this if you only want to disinfect
    the host PC.

.PARAMETER SkipHost
    Skip cleaning the host PC. Use this if you only want to clean a
    removable drive.

.PARAMETER Harden
    After cleanup, apply prevention settings:
      * Disable AutoRun for all drives.
      * Show hidden files and known file extensions in Explorer.
      * Enable two Defender Attack Surface Reduction rules (only if
        Microsoft Defender is alive on this machine).

.PARAMETER Force
    Skip the consolidated confirmation prompt. Useful for unattended runs.
    The -Force switch does NOT change what gets removed - it only
    suppresses the prompt.

.PARAMETER LogPath
    Path to write the log file. Default:
        %ProgramData%\ShortcutVirusRemover\Logs\shortcut-virus-remover-<yyyyMMdd-HHmmss>.log

.EXAMPLE
    PS> .\Remove-ShortcutVirus.ps1
    Full disinfection of host + USB drives. Will auto-elevate and prompt
    once if any host threats are detected.

.EXAMPLE
    PS> .\Remove-ShortcutVirus.ps1 -Harden -Force
    Disinfect, apply hardening, and never prompt.

.EXAMPLE
    PS> .\Remove-ShortcutVirus.ps1 -WhatIf
    Dry run. Reports what would be removed without changing anything.

.NOTES
    Author : Youssef Fathy
    Company: Widescreen
    License: MIT
    Tested on Windows 10 and Windows 11.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$SkipUsb,
    [switch]$SkipHost,
    [switch]$Harden,
    [switch]$Force,
    [string]$LogPath
)

$ErrorActionPreference = 'Continue'

# -------------------------------------------------------------------
# Constants / IOC patterns
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
# Resolve log + quarantine roots under %ProgramData%
# -------------------------------------------------------------------
function Initialize-RuntimePaths {
    [CmdletBinding()]
    param(
        [string]$ExplicitLogPath
    )

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $programData = $env:ProgramData
    if (-not $programData) { $programData = 'C:\ProgramData' }

    $appRoot       = Join-Path $programData 'ShortcutVirusRemover'
    $logsDir       = Join-Path $appRoot 'Logs'
    $quarantineDir = Join-Path (Join-Path $appRoot 'Quarantine') $stamp

    foreach ($d in @($appRoot, $logsDir)) {
        if (-not (Test-Path -LiteralPath $d)) {
            try { New-Item -ItemType Directory -Path $d -Force | Out-Null } catch { }
        }
    }

    if ($ExplicitLogPath) {
        $logFile = $ExplicitLogPath
        $parent  = Split-Path -Parent $logFile
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            try { New-Item -ItemType Directory -Path $parent -Force | Out-Null } catch { }
        }
    } else {
        $logFile = Join-Path $logsDir ("shortcut-virus-remover-$stamp.log")
    }

    [pscustomobject]@{
        Stamp         = $stamp
        AppRoot       = $appRoot
        LogsDir       = $logsDir
        LogFile       = $logFile
        QuarantineDir = $quarantineDir
    }
}

# -------------------------------------------------------------------
# Logging helpers
# -------------------------------------------------------------------
function Write-Log {
    [CmdletBinding()]
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
    if ($script:LogPathResolved) {
        try { Add-Content -LiteralPath $script:LogPathResolved -Value $line -Encoding UTF8 } catch { }
    }
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
    [CmdletBinding()]
    param([hashtable]$BoundParameters, [string]$ScriptPath)
    if (Test-IsAdministrator) { return }
    Write-Host "Administrator rights required. Re-launching with UAC..." -ForegroundColor Yellow

    $argList = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', "`"$ScriptPath`""
    )
    foreach ($k in $BoundParameters.Keys) {
        $v = $BoundParameters[$k]
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
    [CmdletBinding()]
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
# Defender liveness check
# -------------------------------------------------------------------
function Test-DefenderAlive {
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        return [bool]$status
    } catch {
        Write-Log "Microsoft Defender does not appear to be available: $_" -Level WARN
        return $false
    }
}

# -------------------------------------------------------------------
# System Restore checkpoint (best effort, never fails the run)
# -------------------------------------------------------------------
function Invoke-RestoreCheckpoint {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Write-Log "Creating System Restore checkpoint (best effort)..." -Level STEP
    if (-not $PSCmdlet.ShouldProcess('System Restore', 'Create restore point')) { return }
    try {
        Checkpoint-Computer -Description 'Before Shortcut Virus Remover' `
                            -RestorePointType MODIFY_SETTINGS `
                            -ErrorAction Stop
        Write-Log "Restore point created." -Level OK
    } catch {
        # Windows throttles restore points to one per 24h by default.
        # That is fine - log it and continue.
        Write-Log "Restore point not created (Windows throttles to 1/24h or System Protection is off): $_" -Level WARN
    }
}

# -------------------------------------------------------------------
# Detection: malicious services and DLLs (read-only)
# -------------------------------------------------------------------
function Get-MaliciousServices {
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $IocNamePattern }
}

function Get-MaliciousDlls {
    Get-ChildItem -LiteralPath 'C:\Windows\System32' -Filter 'u*.dll' -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $IocDllPattern }
}

# -------------------------------------------------------------------
# Consolidated confirmation prompt with a 10 second auto-Yes timeout
# -------------------------------------------------------------------
function Confirm-Cleanup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string[]]$Findings,
        [int]$TimeoutSeconds = 10,
        [switch]$Force
    )

    if ($WhatIfPreference) { return $true }
    if ($Force.IsPresent)  { return $true }
    if (-not $Findings -or $Findings.Count -eq 0) { return $true }

    Write-Host ""
    Write-Host ("  The tool found {0} threat(s) on this PC:" -f $Findings.Count) -ForegroundColor Yellow
    foreach ($f in $Findings) {
        Write-Host ("    - {0}" -f $f) -ForegroundColor Yellow
    }
    Write-Host ("  Continue? [Y/n] (auto-Yes in $TimeoutSeconds seconds): ") -ForegroundColor Cyan -NoNewline

    $start = Get-Date
    $line  = ''
    $canPoll = $true
    try { $null = [Console]::KeyAvailable } catch { $canPoll = $false }

    if (-not $canPoll) {
        Write-Host ""
        Write-Log "Non-interactive host - auto-accepting cleanup." -Level INFO
        return $true
    }

    while ($true) {
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            if ($key.Key -eq 'Enter') {
                Write-Host ""
                break
            } elseif ($key.Key -eq 'Backspace') {
                if ($line.Length -gt 0) {
                    $line = $line.Substring(0, $line.Length - 1)
                    Write-Host "`b `b" -NoNewline
                }
            } else {
                $line += $key.KeyChar
                Write-Host $key.KeyChar -NoNewline
            }
        }
        if (((Get-Date) - $start).TotalSeconds -ge $TimeoutSeconds) {
            Write-Host ""
            Write-Log "No response in $TimeoutSeconds seconds - auto-accepting cleanup." -Level INFO
            return $true
        }
        Start-Sleep -Milliseconds 75
    }

    $answer = $line.Trim().ToLowerInvariant()
    if ($answer -eq '' -or $answer -eq 'y' -or $answer -eq 'yes') {
        return $true
    }
    Write-Log "User declined cleanup. Aborting." -Level WARN
    return $false
}

# -------------------------------------------------------------------
# Step: kill running malware processes
# -------------------------------------------------------------------
function Stop-MaliciousProcesses {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
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
# Step: remove malicious services
# -------------------------------------------------------------------
function Remove-MaliciousServices {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([object[]]$Services)

    if (-not $Services -or $Services.Count -eq 0) {
        Write-Log "No malicious services to remove." -Level OK
        return
    }

    foreach ($svc in $Services) {
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
# Step: quarantine malicious DLLs (instead of straight deletion)
# -------------------------------------------------------------------
function Quarantine-MaliciousDlls {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [object[]]$Dlls,
        [Parameter(Mandatory)] [string]$QuarantineRoot
    )

    if (-not $Dlls -or $Dlls.Count -eq 0) {
        Write-Log "No malicious DLLs to quarantine." -Level OK
        return
    }

    if (-not (Test-Path -LiteralPath $QuarantineRoot)) {
        try { New-Item -ItemType Directory -Path $QuarantineRoot -Force | Out-Null } catch {
            Write-Log "Could not create quarantine folder $QuarantineRoot : $_" -Level ERROR
            return
        }
    }

    $manifest = New-Object System.Collections.Generic.List[object]

    foreach ($dll in $Dlls) {
        Write-Log ("Found DLL: {0} ({1:N0} bytes, {2})" -f $dll.FullName, $dll.Length, $dll.LastWriteTime) -Level WARN

        if (-not $PSCmdlet.ShouldProcess($dll.FullName, "Quarantine malicious DLL")) { continue }

        try { attrib.exe -h -s -r $dll.FullName 2>$null } catch { }

        $sha256 = $null
        try { $sha256 = (Get-FileHash -LiteralPath $dll.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch {
            Write-Log "Could not hash $($dll.FullName): $_" -Level WARN
        }

        $entry = [ordered]@{
            originalPath  = $dll.FullName
            name          = $dll.Name
            sha256        = $sha256
            size          = $dll.Length
            lastWriteTime = $dll.LastWriteTime.ToString('o')
            attributes    = "$($dll.Attributes)"
            reason        = 'matches IOC ^u\d{6}\.dll$'
            timestamp     = (Get-Date).ToString('o')
            quarantinePath = $null
            method        = $null
        }

        $destination = Join-Path $QuarantineRoot $dll.Name
        try {
            Move-Item -LiteralPath $dll.FullName -Destination $destination -Force -ErrorAction Stop
            try {
                $info = Get-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue
                if ($info -and $dll.LastWriteTime) {
                    $info.LastWriteTime = $dll.LastWriteTime
                    $info.CreationTime  = $dll.CreationTime
                }
            } catch { }
            try {
                & icacls.exe $destination '/inheritance:r' '/grant' 'Administrators:F' '/grant' 'SYSTEM:F' 2>$null | Out-Null
            } catch { }
            $entry.quarantinePath = $destination
            $entry.method = 'moved'
            Write-Log "Quarantined: $($dll.FullName) -> $destination" -Level OK
        } catch {
            Write-Log "Direct move failed (file in use): $_" -Level WARN
            try {
                $renameTarget = "$($dll.FullName).malware_to_delete"
                if (Test-Path -LiteralPath $renameTarget) {
                    Remove-Item -LiteralPath $renameTarget -Force -ErrorAction SilentlyContinue
                }
                Rename-Item -LiteralPath $dll.FullName -NewName (Split-Path -Leaf $renameTarget) -Force -ErrorAction Stop
                Register-DeleteOnReboot -Path $renameTarget
                $entry.quarantinePath = $renameTarget
                $entry.method = 'rename-and-delete-on-reboot'
                Write-Log "Renamed to $renameTarget and scheduled for delete-on-reboot." -Level WARN
            } catch {
                Write-Log "Rename fallback also failed: $_" -Level ERROR
                Register-DeleteOnReboot -Path $dll.FullName
                $entry.method = 'delete-on-reboot-only'
            }
        }

        $manifest.Add([pscustomobject]$entry) | Out-Null
    }

    if ($manifest.Count -gt 0) {
        $manifestPath = Join-Path $QuarantineRoot 'quarantine-manifest.json'
        try {
            $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
            Write-Log "Wrote quarantine manifest: $manifestPath" -Level OK
        } catch {
            Write-Log "Could not write manifest $manifestPath : $_" -Level ERROR
        }
    }
}

# -------------------------------------------------------------------
# Step: remove Defender exclusions added by malware
# -------------------------------------------------------------------
function Clear-MalwareDefenderExclusions {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([bool]$DefenderAlive = $true)

    Write-Log "Removing Defender exclusion paths added by malware..." -Level STEP

    if (-not $DefenderAlive) {
        Write-Log "Defender not available - skipping exclusion cleanup." -Level WARN
        return
    }

    # The malware whitelists removable drives + System32. Remove only those
    # specific paths if present. We do NOT blanket-clear all exclusions
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
# Step: clean a single removable drive
# -------------------------------------------------------------------
function Clear-RemovableDrive {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)] [string]$DriveRoot)  # e.g. 'E:\'

    Write-Log "Cleaning drive: $DriveRoot" -Level STEP

    if (-not (Test-Path $DriveRoot)) {
        Write-Log "Drive $DriveRoot not accessible. Skipping." -Level WARN
        return
    }

    $rootItems = Get-ChildItem -LiteralPath $DriveRoot -Force -ErrorAction SilentlyContinue

    # Delete suspicious script / shortcut files at the root
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

    # Delete known payload folders (sysvolume, etc.)
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

    # Unhide every hidden+system top-level folder so the user can see their data
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

    # Recurse: also strip any nested .lnk / script files
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
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
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
# Step: hardening (optional)
# -------------------------------------------------------------------
function Invoke-Hardening {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([bool]$DefenderAlive = $true)

    Write-Log "Applying hardening settings..." -Level STEP

    $explorerKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    if (-not (Test-Path $explorerKey)) {
        New-Item -Path $explorerKey -Force | Out-Null
    }
    Set-ItemProperty -Path $explorerKey -Name 'NoDriveTypeAutoRun' -Type DWord -Value 0xFF -Force
    Set-ItemProperty -Path $explorerKey -Name 'NoAutorun'          -Type DWord -Value 1     -Force
    Write-Log "AutoRun disabled for all drives." -Level OK

    $advKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    if (Test-Path $advKey) {
        Set-ItemProperty -Path $advKey -Name 'Hidden'          -Type DWord -Value 1 -Force
        Set-ItemProperty -Path $advKey -Name 'ShowSuperHidden' -Type DWord -Value 0 -Force
        Set-ItemProperty -Path $advKey -Name 'HideFileExt'     -Type DWord -Value 0 -Force
        Write-Log "Explorer set to show hidden files and extensions, while keeping protected Windows files hidden." -Level OK
    }

    if (-not $DefenderAlive) {
        Write-Log "Defender not available - skipping ASR rule activation." -Level WARN
        return
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
# Main entry point - wrapped in a function so the script can be
# dot-sourced for testing without running anything.
# -------------------------------------------------------------------
function Invoke-ShortcutVirusRemover {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$SkipUsb,
        [switch]$SkipHost,
        [switch]$Harden,
        [switch]$Force,
        [string]$LogPath,
        [hashtable]$BoundParameters,
        [string]$ScriptPath
    )

    Write-Banner
    Invoke-SelfElevate -BoundParameters $BoundParameters -ScriptPath $ScriptPath

    $paths = Initialize-RuntimePaths -ExplicitLogPath $LogPath
    $script:LogPathResolved = $paths.LogFile

    "--- Run started $(Get-Date -Format s) ---" | Add-Content -LiteralPath $paths.LogFile -ErrorAction SilentlyContinue
    Write-Log "Log file: $($paths.LogFile)" -Level INFO
    Write-Log "Quarantine root: $($paths.QuarantineDir)" -Level INFO
    Write-Log "Mode: WhatIf=$($WhatIfPreference) SkipUsb=$SkipUsb SkipHost=$SkipHost Harden=$Harden Force=$Force" -Level INFO

    $defenderAlive = Test-DefenderAlive
    Write-Log "Microsoft Defender alive: $defenderAlive" -Level INFO

    Invoke-RestoreCheckpoint

    $quarantinePath = $null

    if (-not $SkipHost) {
        Write-Log "Detecting host threats..." -Level STEP
        $services = @(Get-MaliciousServices)
        $dlls     = @(Get-MaliciousDlls)

        $findings = @()
        foreach ($s in $services) { $findings += "Service: $($s.Name) (will be stopped and removed)" }
        foreach ($d in $dlls)     { $findings += "DLL: $($d.FullName) (will be quarantined)" }

        if (-not (Confirm-Cleanup -Findings $findings -Force:$Force)) {
            Write-Log "Aborting host cleanup at user's request." -Level WARN
        } else {
            Stop-MaliciousProcesses
            Remove-MaliciousServices -Services $services
            if ($dlls.Count -gt 0) {
                Quarantine-MaliciousDlls -Dlls $dlls -QuarantineRoot $paths.QuarantineDir
                $quarantinePath = $paths.QuarantineDir
            }
            Clear-MalwareDefenderExclusions -DefenderAlive $defenderAlive
        }
    } else {
        Write-Log "Skipping host disinfection (-SkipHost)." -Level INFO
    }

    if (-not $SkipUsb) {
        Clear-AllRemovableDrives
    } else {
        Write-Log "Skipping USB cleanup (-SkipUsb)." -Level INFO
    }

    if ($Harden) {
        Invoke-Hardening -DefenderAlive $defenderAlive
    }

    if ($defenderAlive -and -not $WhatIfPreference) {
        Write-Log "Triggering Defender Quick Scan in the background..." -Level STEP
        try {
            Start-Job -ScriptBlock { Start-MpScan -ScanType QuickScan } | Out-Null
            Write-Log "Defender Quick Scan started in background." -Level OK
        } catch {
            Write-Log "Could not start Defender Quick Scan: $_" -Level WARN
        }
    } else {
        Write-Log "Skipping Defender Quick Scan (Defender unavailable or -WhatIf)." -Level INFO
    }

    Write-Host ""
    Write-Log "All done. Recommended next steps:" -Level OK
    Write-Host "  1. Reboot the PC if any DLL was scheduled for delete-on-reboot." -ForegroundColor Yellow
    Write-Host "  2. Run a full Microsoft Defender Offline Scan for extra safety." -ForegroundColor Yellow
    Write-Host "  3. Format the USB drive after recovering your files." -ForegroundColor Yellow
    if ($quarantinePath) {
        Write-Host ""
        Write-Host ("  Quarantined items (recoverable): {0}" -f $quarantinePath) -ForegroundColor Cyan
    }
    Write-Host ""
    Write-Host "  Detailed log: $($paths.LogFile)" -ForegroundColor Gray
}

# -------------------------------------------------------------------
# Run only if invoked as a script (not when dot-sourced for tests)
# -------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-ShortcutVirusRemover `
        -SkipUsb:$SkipUsb `
        -SkipHost:$SkipHost `
        -Harden:$Harden `
        -Force:$Force `
        -LogPath $LogPath `
        -BoundParameters $PSBoundParameters `
        -ScriptPath $MyInvocation.MyCommand.Path

    if ($MyInvocation.MyCommand.Path) {
        Write-Host ""
        Write-Host "Press any key to close..." -ForegroundColor Gray
        try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { }
    }
}

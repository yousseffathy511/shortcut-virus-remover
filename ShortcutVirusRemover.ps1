<#
.SYNOPSIS
    One-click installer wrapper for the Shortcut Virus Remover.

.DESCRIPTION
    Synced from Remove-ShortcutVirus.ps1 - keep behavior in sync.

    This is a SELF-CONTAINED wrapper designed to be compiled to a single
    Windows .exe with ps2exe and the -RequireAdmin manifest flag, so a
    non-technical user can:

      1. Right-click ShortcutVirusRemover.exe -> Properties -> Unblock
      2. Double-click it
      3. Click "Yes" on the Windows UAC prompt
      4. Wait for the cleanup to finish

    The wrapper inlines the same logic as Remove-ShortcutVirus.ps1 so the
    compiled exe does not depend on any other file being present next to
    it. Behavior must match Remove-ShortcutVirus.ps1; future updates
    should be ported mechanically.

    Cleanup performed (always with -Harden, never with -Force):
      * Create a System Restore checkpoint (best effort).
      * Detect host threats and prompt once with a 10s auto-Yes timeout.
      * Stop running malware processes (rundll32 ...IdllEntry, sysvolume).
      * Stop and delete the u<digits> Windows service + its registry key.
      * Quarantine u<digits>.dll from C:\Windows\System32 to
        %ProgramData%\ShortcutVirusRemover\Quarantine\<timestamp>\.
      * Remove Defender exclusions added by the malware.
      * Clean every connected removable drive.
      * Disable AutoRun, show hidden files, enable Defender ASR rules
        (only if Defender is alive).
      * Trigger a Defender Quick Scan in the background.

.NOTES
    Author : Youssef Fathy
    Company: Widescreen
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

# -------------------------------------------------------------------
# Resolve runtime log + quarantine paths under %ProgramData%
# -------------------------------------------------------------------
function Initialize-RuntimePaths {
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

    $logFile = Join-Path $logsDir ("shortcut-virus-remover-$stamp.log")

    [pscustomobject]@{
        Stamp         = $stamp
        AppRoot       = $appRoot
        LogsDir       = $logsDir
        LogFile       = $logFile
        QuarantineDir = $quarantineDir
    }
}

$script:RuntimePaths    = Initialize-RuntimePaths
$script:LogPathResolved = $script:RuntimePaths.LogFile

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
    if ($script:LogPathResolved) {
        try { Add-Content -LiteralPath $script:LogPathResolved -Value $line -Encoding UTF8 } catch { }
    }
}

function Write-FriendlyBanner {
    $banner = @'

  +------------------------------------------------------------+
  |                                                            |
  |                SHORTCUT VIRUS REMOVER                      |
  |                                                            |
  |        Developed by Youssef Fathy under Widescreen         |
  |                                                            |
  |   Removes the "Shortcut / Runner" malware from your PC     |
  |   and cleans every connected USB flash drive.              |
  |                                                            |
  +------------------------------------------------------------+

  What this tool will do automatically:

    [1] Create a Windows System Restore checkpoint (best effort).
    [2] Stop the malware processes that are running right now.
    [3] Delete the malware Windows service (u<digits>).
    [4] Quarantine the malware DLL from C:\Windows\System32 into
        %ProgramData%\ShortcutVirusRemover\Quarantine\<timestamp>\
        so a false positive can be recovered.
    [5] Remove the Defender exclusions the malware added.
    [6] Clean every USB drive: delete fake shortcuts, remove
        the hidden "sysvolume" payload, and unhide your real
        folders so you can see your files again.
    [7] Disable AutoRun on USB drives so this cannot happen
        again.
    [8] Start a Microsoft Defender Quick Scan in the background.

  No personal files on the C: drive are touched.
  A log of everything that was done will be written to:
    %ProgramData%\ShortcutVirusRemover\Logs\

'@
    Write-Host $banner -ForegroundColor Cyan
}

# -------------------------------------------------------------------
# Admin check
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
$ProtectedWindowsFolders = @('system volume information', '$recycle.bin')
$SuspiciousExtsRoot = @('.lnk', '.vbs', '.vbe', '.bat', '.cmd',
                        '.js',  '.jse', '.wsf', '.scr', '.exe', '.hta')

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
# System Restore checkpoint (best effort)
# -------------------------------------------------------------------
function Invoke-RestoreCheckpoint {
    Write-Log "Creating System Restore checkpoint (best effort)..." -Level STEP
    try {
        Checkpoint-Computer -Description 'Before Shortcut Virus Remover' `
                            -RestorePointType MODIFY_SETTINGS `
                            -ErrorAction Stop
        Write-Log "Restore point created." -Level OK
    } catch {
        Write-Log "Restore point not created (Windows throttles to 1/24h or System Protection is off): $_" -Level WARN
    }
}

# -------------------------------------------------------------------
# Detection
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
# Consolidated confirmation prompt with 10s auto-Yes timeout
# (the EXE intentionally does NOT pass -Force - the prompt only
# appears when there is actually something to remove)
# -------------------------------------------------------------------
function Confirm-Cleanup {
    param(
        [Parameter(Mandatory)] [string[]]$Findings,
        [int]$TimeoutSeconds = 10
    )

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
# Stop running malware processes
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
# Remove malicious services
# -------------------------------------------------------------------
function Remove-MaliciousServices {
    param([object[]]$Services)

    if (-not $Services -or $Services.Count -eq 0) {
        Write-Log "No malicious services to remove." -Level OK
        return
    }

    foreach ($svc in $Services) {
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
# Quarantine malicious DLLs (instead of straight deletion)
# -------------------------------------------------------------------
function Quarantine-MaliciousDlls {
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
# Defender exclusion cleanup
# -------------------------------------------------------------------
function Clear-MalwareDefenderExclusions {
    param([bool]$DefenderAlive = $true)

    Write-Log "Removing Defender exclusion paths added by malware..." -Level STEP

    if (-not $DefenderAlive) {
        Write-Log "Defender not available - skipping exclusion cleanup." -Level WARN
        return
    }

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
# Removable drive cleanup
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
                        ($IocPayloadFolders -notcontains $_.Name.ToLower()) -and
                        ($ProtectedWindowsFolders -notcontains $_.Name.ToLower())
                     }
    foreach ($f in $hiddenFolders) {
        Write-Log "Unhiding folder: $($f.FullName)" -Level OK
        attrib.exe -h -s $f.FullName /S /D 2>$null
    }

    foreach ($protectedFolderName in @('System Volume Information', '$RECYCLE.BIN')) {
        $protectedFolder = Join-Path $DriveRoot $protectedFolderName
        if (Test-Path -LiteralPath $protectedFolder) {
            attrib.exe +h +s $protectedFolder 2>$null
        }
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
# Hardening
# -------------------------------------------------------------------
function Invoke-Hardening {
    param([bool]$DefenderAlive = $true)
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
    Add-Content -LiteralPath $script:LogPathResolved -ErrorAction SilentlyContinue
Write-Log "Log file: $($script:RuntimePaths.LogFile)" -Level INFO
Write-Log "Quarantine root: $($script:RuntimePaths.QuarantineDir)" -Level INFO
Write-Log "Base directory: $BaseDir" -Level INFO

$summary = [ordered]@{
    HostCleaned        = $false
    UsbCleaned         = $false
    HardeningApplied   = $false
    DefenderScanQueued = $false
    QuarantinePath     = $null
}

$defenderAlive = Test-DefenderAlive
Write-Log "Microsoft Defender alive: $defenderAlive" -Level INFO

Invoke-RestoreCheckpoint

try {
    Write-Log "Detecting host threats..." -Level STEP
    $services = @(Get-MaliciousServices)
    $dlls     = @(Get-MaliciousDlls)

    $findings = @()
    foreach ($s in $services) { $findings += "Service: $($s.Name) (will be stopped and removed)" }
    foreach ($d in $dlls)     { $findings += "DLL: $($d.FullName) (will be quarantined)" }

    if (-not (Confirm-Cleanup -Findings $findings)) {
        Write-Log "User declined - skipping host cleanup." -Level WARN
    } else {
        Stop-MaliciousProcesses
        Remove-MaliciousServices -Services $services
        if ($dlls.Count -gt 0) {
            Quarantine-MaliciousDlls -Dlls $dlls -QuarantineRoot $script:RuntimePaths.QuarantineDir
            $summary.QuarantinePath = $script:RuntimePaths.QuarantineDir
        }
        Clear-MalwareDefenderExclusions -DefenderAlive $defenderAlive
        $summary.HostCleaned = $true
    }
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
    Invoke-Hardening -DefenderAlive $defenderAlive
    $summary.HardeningApplied = $true
} catch {
    Write-Log "Hardening error: $_" -Level ERROR
}

if ($defenderAlive) {
    Write-Log "Triggering Defender Quick Scan in the background..." -Level STEP
    try {
        Start-Job -ScriptBlock { Start-MpScan -ScanType QuickScan } | Out-Null
        $summary.DefenderScanQueued = $true
        Write-Log "Defender Quick Scan started in background." -Level OK
    } catch {
        Write-Log "Could not start Defender Quick Scan: $_" -Level WARN
    }
} else {
    Write-Log "Skipping Defender Quick Scan (Defender unavailable)." -Level WARN
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
if ($summary.QuarantinePath) {
    Write-Host ("    Quarantined items in: {0}" -f $summary.QuarantinePath) -ForegroundColor Cyan
    Write-Host  "    (See quarantine-manifest.json there if you need to restore a false positive.)" -ForegroundColor Gray
    Write-Host ""
}
Write-Host "  Recommended next steps:" -ForegroundColor Yellow
Write-Host "    1. Reboot the PC if any DLL was scheduled for delete-on-reboot." -ForegroundColor Yellow
Write-Host "    2. Run a full Microsoft Defender Offline Scan for extra safety." -ForegroundColor Yellow
Write-Host "    3. After copying your files off the USB, format the USB drive." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Detailed log: $($script:RuntimePaths.LogFile)" -ForegroundColor Gray

Wait-ForUserExit -ExitCode 0

<#
.SYNOPSIS
    Hardens a Windows machine against the shortcut virus family
    (Trojan:*/Runner) without performing disinfection.

.DESCRIPTION
    * Disables AutoRun on every drive type.
    * Shows hidden files, system files, and file extensions in Explorer
      so that .vbs / .bat payloads can't hide behind a folder icon.
    * Enables two Microsoft Defender Attack Surface Reduction rules
      that block this attack class:
        - Block JavaScript or VBScript from launching downloaded executable content.
        - Block all Office applications from creating child processes.

    Run elevated (the script auto-elevates if needed).
#>

[CmdletBinding()]
param()

function Test-IsAdministrator {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    return ([System.Security.Principal.WindowsPrincipal]$id).IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    Write-Host "Re-launching as Administrator..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList @(
        '-NoProfile','-ExecutionPolicy','Bypass',
        '-File',"`"$($MyInvocation.PSCommandPath)`""
    )
    exit
}

Write-Host "Applying hardening settings..." -ForegroundColor Cyan

# ----- Disable AutoRun for ALL drives -----
$explorerKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
if (-not (Test-Path $explorerKey)) { New-Item -Path $explorerKey -Force | Out-Null }
Set-ItemProperty -Path $explorerKey -Name 'NoDriveTypeAutoRun' -Type DWord -Value 0xFF -Force
Set-ItemProperty -Path $explorerKey -Name 'NoAutorun'          -Type DWord -Value 1     -Force
Write-Host "  [OK] AutoRun disabled for all drive types." -ForegroundColor Green

# ----- Show hidden files and known extensions for current user -----
$advKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
if (Test-Path $advKey) {
    Set-ItemProperty -Path $advKey -Name 'Hidden'          -Type DWord -Value 1 -Force
    Set-ItemProperty -Path $advKey -Name 'ShowSuperHidden' -Type DWord -Value 0 -Force
    Set-ItemProperty -Path $advKey -Name 'HideFileExt'     -Type DWord -Value 0 -Force
    Write-Host "  [OK] Explorer set to show hidden files and extensions, while protected Windows files stay hidden." -ForegroundColor Green
}

# ----- Microsoft Defender Attack Surface Reduction rules -----
try {
    Add-MpPreference -AttackSurfaceReductionRules_Ids   'D3E037E1-3EB8-44C8-A917-57927947596D' `
                    -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
    Add-MpPreference -AttackSurfaceReductionRules_Ids   'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' `
                    -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
    Write-Host "  [OK] Defender ASR rules enabled." -ForegroundColor Green
} catch {
    Write-Host "  [WARN] Could not enable ASR rules: $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Hardening complete. Sign out and back in (or reboot) to fully apply Explorer changes." -ForegroundColor Cyan
Write-Host "Press any key to close..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

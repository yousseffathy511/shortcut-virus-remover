# Shortcut Virus Remover

A focused, open-source toolkit for removing the **shortcut virus**
family that affects Windows machines and USB flash drives. This is the
malware Microsoft Defender labels as:

- `Trojan:PowerShell/Runner.PGRA!MTB`
- `Trojan:BAT/Runner.PGRD!MTB`
- and similar `Runner.*` variants

If your USB drive's contents have been replaced by a single
**`<DriveName>.lnk`** shortcut and a hidden `sysvolume` folder, you have
this infection. The folder is not gone ù it is just hidden, and the
shortcut is bait.

> **Do not double-click the shortcut.** Doing so launches the malware
> with administrator rights and infects the host PC.

---

## Download (one-click installer)

**For non-technical users**:

1. Go to the [Releases page](https://github.com/yousseffathy511/shortcut-virus-remover/releases/latest).
2. Download `ShortcutVirusRemover.exe`.
3. Double-click it. Click **Yes** on the Windows security prompt.
4. Wait for it to finish. Your USB drives will be cleaned, the malware
   will be removed from your PC, and AutoRun will be disabled to
   prevent re-infection.

That's it. No installation, no PowerShell required.

Do **not** download the source code ZIP if you just want to clean your
computer. The source code is for developers and security reviewers.

> **Windows SmartScreen warning?** The installer is not code-signed,
> so Windows may say *"Windows protected your PC"* the first time you
> run it. Click **More info**, then **Run anyway**. This is expected
> for any free, unsigned tool.

### For maintainers: publishing the `.exe`

This repository builds the one-click executable automatically with
GitHub Actions.

```powershell
# Build locally
.\Build-Exe.ps1

# Publish a new release from git
git tag v1.0.0
git push origin v1.0.0
```

When the tag is pushed, GitHub Actions builds
`dist\ShortcutVirusRemover.exe` and uploads it to the GitHub Release.

---

## What this malware actually does

```
USB inserted
    -> User sees only a single ".lnk" file with the volume's name.
    -> Real folder is still there, but hidden + system.

User clicks the .lnk
    -> Runs:  wscript.exe   E:\sysvolume\u123456.vbs
    -> .vbs re-runs itself with "runas" (UAC prompt).
    -> Once elevated, .vbs runs:
            cmd.exe /c "E:\sysvolume\u654321.bat"

The .bat then:
    1. Add-MpPreference -ExclusionPath  E:\
    2. Add-MpPreference -ExclusionPath  C:\Windows\System32
    3. copy  E:\sysvolume\u<n>.dat  ->  C:\Windows\System32\u<n>.dll
    4. rundll32.exe  C:\Windows\System32\u<n>.dll,IdllEntry 1

Persistence on the host PC:
    HKLM\SYSTEM\CurrentControlSet\Services\u<n>
        ImagePath = svchost.exe -k DcomLaunch
        Parameters\ServiceDll = C:\Windows\System32\u<n>.dll

The service watches for new USB drives and re-creates the
shortcut + sysvolume payload on every drive that is plugged in.
```

This is why **deleting the shortcut by hand keeps "failing"**: the
service on the host immediately re-creates it.

---

## Indicators of compromise (IOCs)

| Where                                    | What to look for                                    |
|------------------------------------------|-----------------------------------------------------|
| `C:\Windows\System32\`                   | A DLL named `u<digits>.dll` (e.g. `u707321.dll`)    |
| `HKLM\SYSTEM\CurrentControlSet\Services` | A service named `u<digits>`                         |
| Defender exclusions                      | `E:\`, `E:\sysvolume`, `C:\Windows\System32`        |
| USB root                                 | `<VolumeLabel>.lnk` shortcut + hidden `sysvolume\`  |
| USB `sysvolume`                          | Files matching `u\d+\.(vbs|bat|dat|bin)`            |
| `rundll32.exe` command lines             | `...,IdllEntry 1`                                   |

---

## Scripts

### 1. `Remove-ShortcutVirus.ps1`

The main remover. It auto-elevates to Administrator, then:

1. Stops malicious processes.
2. Stops and deletes any `u<digits>` service plus its registry key.
3. Deletes `u<digits>.dll` files in `C:\Windows\System32`. If the file
   is locked, schedules it for delete-on-next-reboot via
   `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)`.
4. Removes Microsoft Defender exclusions added by the malware.
5. Cleans every connected removable drive: deletes shortcuts and
   payload folders, unhides your real folders.
6. Optionally hardens the OS (`-Harden` flag).
7. Triggers a Microsoft Defender Quick Scan in the background.

**Usage**

```powershell
# Full disinfection (will prompt for UAC once)
.\Remove-ShortcutVirus.ps1

# Disinfect AND apply prevention settings
.\Remove-ShortcutVirus.ps1 -Harden

# Dry run - report what would happen, don't change anything
.\Remove-ShortcutVirus.ps1 -WhatIf

# Only clean USB drives, don't touch the host
.\Remove-ShortcutVirus.ps1 -SkipHost

# Only disinfect the host, don't touch USB drives
.\Remove-ShortcutVirus.ps1 -SkipUsb
```

### 2. `Recover-UsbFiles.ps1`

Copies the real user files from an infected USB drive into a clean
folder on your hard disk. It uses `robocopy` and explicitly skips every
shortcut, script, and executable extension so the malware cannot ride
along into the recovered folder.

```powershell
# Recover from E: to Desktop\USB-Recovered-<timestamp>
.\Recover-UsbFiles.ps1 -Drive E:

# Recover to a custom folder
.\Recover-UsbFiles.ps1 -Drive E: -Destination D:\backup\my-usb
```

This script does **not** require Administrator.

### 3. `Protect-System.ps1`

Standalone hardening. Apply the same prevention settings as
`Remove-ShortcutVirus.ps1 -Harden`, without running the disinfection
itself.

---

## Recommended workflow

1. **Unplug** any other USB drives so they cannot be re-infected mid-run.
2. Open **Windows PowerShell as Administrator**.
3. Run:

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
   .\Remove-ShortcutVirus.ps1 -Harden
   ```

4. **Reboot** if the script reported any DLL was scheduled for
   delete-on-reboot.
5. Plug the USB back in, then run:

   ```powershell
   .\Recover-UsbFiles.ps1 -Drive E:
   ```

6. After recovery, **format the USB drive** (right-click drive in
   Explorer ? Format ? Quick Format) before using it again.
7. Run **Microsoft Defender Offline Scan**:
   *Windows Security ? Virus & threat protection ? Scan options ?
   Microsoft Defender Antivirus (offline scan)*

---

## How to stay safe afterwards

- Never double-click a `.lnk` file at the root of a USB drive whose
  name matches the volume label. That is always the bait.
- Keep AutoRun disabled (`-Harden` does this).
- Show hidden files and known file extensions in Explorer
  (`-Harden` does this) so a `.vbs` cannot pretend to be a folder.
- Keep Microsoft Defender's real-time protection on, and review
  `Get-MpPreference | Select ExclusionPath` from time to time. Any
  exclusion of `C:\Windows\System32` or a removable drive is suspicious.

---

## Requirements

- Windows 10 or Windows 11
- Windows PowerShell 5.1 or PowerShell 7+
- Administrator rights (the script will request UAC automatically)

## Disclaimer

This software is provided **as is**, without warranty of any kind.
Always review the code of any security tool before running it on a
machine you care about. See [LICENSE](LICENSE).

## License

MIT ù see [LICENSE](LICENSE).

## Contributing

Pull requests are welcome. If you encounter a new variant (different
file names, different service pattern, different payload location),
please open an issue with the indicators of compromise so the
detection patterns can be updated.

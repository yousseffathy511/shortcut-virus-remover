# Contributing to Shortcut Virus Remover

Thanks for considering a contribution! This is a small security tool
that runs as Administrator on user PCs, so the bar for changes is high
and intentionally conservative.

## Ground rules

1. **All changes must be reproducible from public commits.** No binary
   blobs, no opaque dependencies, no copy-pasted code from a private
   tool. Anything in `dist/` is a build artifact and is `.gitignore`d.
2. **Every script must syntax-parse cleanly.** Run the parser check
   below before pushing.
3. **Sign off your commits** (`git commit -s`) so the
   [Developer Certificate of Origin](https://developercertificate.org)
   is recorded.
4. **GitHub Actions are pinned to commit SHAs**, never to floating tags
   like `@v4`. See "Pinning third-party actions" below.

## Cloning the repo

```powershell
git clone https://github.com/yousseffathy511/shortcut-virus-remover.git
cd shortcut-virus-remover
```

## Running the scripts safely

Because this is a malware-removal tool, you should always do a dry run
first when you are testing changes:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\Remove-ShortcutVirus.ps1 -WhatIf -Harden
```

`-WhatIf` reports every action without changing anything, including the
quarantine and Defender exclusion paths.

## Validating that scripts parse

Before committing, make sure all PowerShell scripts parse cleanly:

```powershell
$scripts = Get-ChildItem -Filter '*.ps1' -File
$failed  = $false
foreach ($s in $scripts) {
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $s.FullName, [ref]$null, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        $failed = $true
        Write-Host "FAIL: $($s.Name)" -ForegroundColor Red
        $errors | ForEach-Object {
            Write-Host ("  {0} (line {1})" -f $_.Message, $_.Extent.StartLineNumber) -ForegroundColor Red
        }
    } else {
        Write-Host "OK:   $($s.Name)" -ForegroundColor Green
    }
}
if ($failed) { exit 1 }
```

Save that as `scripts/Test-Parse.ps1` if you find yourself running it
often. CI will run an equivalent check on push.

## Filing an issue

Please include:

- The OS version (`Get-ComputerInfo OsName, OsVersion`).
- A copy of the relevant cleanup log:
  `%ProgramData%\ShortcutVirusRemover\Logs\shortcut-virus-remover-<timestamp>.log`.
- For false positives, the matching `quarantine-manifest.json` entry
  from `%ProgramData%\ShortcutVirusRemover\Quarantine\<timestamp>\`.
- Whether the issue is on host cleanup, USB cleanup, hardening, or the
  EXE wrapper.

For security issues, **do not** open a public issue. Use
[private vulnerability reporting](https://github.com/yousseffathy511/shortcut-virus-remover/security/advisories/new)
instead.

## Proposing a new IOC pattern

The malware family iterates: every couple of months a new variant
appears with a slightly different file name pattern, payload folder
name, or service name. To add a new IOC:

1. Open an issue first with a small evidence packet:
   - The matching file name(s) on the USB / in System32.
   - The Windows service name (if any) and its `ServiceDll` value.
   - Defender exclusion paths added by the variant.
   - The `rundll32` / `wscript` command lines from
     `Get-CimInstance Win32_Process` (redact PII).
2. Once the IOC is acknowledged, send a PR that:
   - Adds the new pattern in `Remove-ShortcutVirus.ps1` next to the
     existing `$Ioc*Pattern` constants.
   - **Mirrors the change in `ShortcutVirusRemover.ps1`** so the
     compiled EXE matches. The wrapper inlines the same logic on
     purpose; the two files must stay behaviorally identical.
   - Updates the IOC table in `README.md`.
   - Includes a regex anchored on both ends (`^...$`) and is as narrow
     as possible to avoid false positives.

## Testing the EXE build locally

```powershell
# Builds dist\ShortcutVirusRemover.exe + the .sha256 file.
.\Build-Exe.ps1 -Version 1.0.7-dev

# Compute the hash and compare.
Get-FileHash .\dist\ShortcutVirusRemover.exe -Algorithm SHA256
Get-Content .\dist\ShortcutVirusRemover.exe.sha256
```

`Build-Exe.ps1` will install the `ps2exe` PowerShell module from the
PSGallery on first run. Pass `-SkipModuleInstall` if your environment
forbids that.

**Do not run the EXE on a machine you care about** while testing
changes. Test on a VM with a deliberately-infected USB, or pass
`-SkipHost` and `-SkipUsb` switches in a script-mode dry run.

## Signing off your commits

```powershell
git commit -s -m "feat: tighten USB cleanup IOC for variant X"
```

`-s` adds a `Signed-off-by:` trailer that records your agreement to the
[Developer Certificate of Origin](https://developercertificate.org). PRs
without sign-off will be asked to add it.

## Pinning third-party actions

Every `uses:` line in `.github/workflows/*` MUST reference a commit SHA,
not a floating version tag:

```yaml
# Correct:
- uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4

# Incorrect:
- uses: actions/checkout@v4
```

The trailing `# v4` (or whatever the human-readable tag was at the time)
is required. To resolve a SHA from a tag:

```powershell
gh api repos/<owner>/<repo>/git/refs/tags/<tag> --jq '.object.sha'
```

When updating an action, look up the new SHA the same way and update
both the SHA and the trailing comment in the same commit.
[Dependabot](.github/dependabot.yml) opens PRs for these updates weekly.

## Conventional commits

This project uses [Conventional Commits](https://www.conventionalcommits.org).
Common prefixes:

| Prefix      | Use for                                                 |
|-------------|---------------------------------------------------------|
| `feat:`     | A new behavior of the cleanup tool or a new flag.       |
| `fix:`      | A bug fix in detection / cleanup / hardening / EXE.     |
| `docs:`     | Documentation-only change.                              |
| `chore:`    | Tooling, repo hygiene, build script tweaks.             |
| `ci:`       | Workflow / GitHub Actions / release pipeline change.    |
| `refactor:` | Internal restructuring with no behavior change.         |
| `test:`     | Adding or fixing tests.                                 |

## Releasing

Releases are cut by tagging:

```powershell
git tag -a v1.0.x -m "v1.0.x: <one-line summary>"
git push origin v1.0.x
```

The release workflow rebuilds the EXE, computes its SHA-256, generates
a build-provenance attestation, optionally uploads to VirusTotal, and
publishes the GitHub Release using
[`.github/release-notes-template.md`](.github/release-notes-template.md).

# Changelog

All notable changes to Shortcut Virus Remover are documented here.

## v1.0.7

- Host remediation now creates a **System Restore checkpoint** (best effort)
  before making changes.
- Malicious **`u<digits>.dll`** files found in **`C:\\Windows\\System32`**
  are **quarantined** under **`%ProgramData%\\ShortcutVirusRemover\\Quarantine`** with a
  **`quarantine-manifest.json`** instead of being blindly deleted outright.
  A delete-on-next-reboot fallback is still used when a file cannot be moved.
- A consolidated **confirmation prompt with a ~10 auto-accept timeout**
  appears when host-side threats are discovered (skipped with `-Force` — not
  used by the one-click exe — and suppressed with `-WhatIf`).
- Cleanup logs moved from **`%TEMP%`** to **`%ProgramData%\\ShortcutVirusRemover\\Logs`**.
- USB recovery (**`Recover-UsbFiles.ps1`**) emits **`recovery-manifest.json`**
  with SHA-256 for every recovered file (`$args`/`$roboArgs` shadowing bug fixed).
- GitHub Actions: **pinned Actions to commit SHAs**, added **Sigstore-style attestations**
  on tagged releases (**`actions/attest-build-provenance`**), richer auto-generated release
  notes / checksums / commit pointers, optional **crazy-max/ghaction-virustotal** upload
  when **`VT_API_KEY`** is configured as a repo secret, plus **weekly OpenSSF Scorecard**
  workflow and Dependabot scans for **`github-actions`**.
- README overhauled: verify-first flow, clearer SmartScreen/Unblock guidance.

## v1.0.6

- Restored the stronger USB root payload cleanup behavior from the
  earlier remover versions.
- The tool again removes common shortcut-virus payload types from the USB
  root, including fake shortcuts, scripts, suspicious executables, and
  HTML application payloads used by this malware family.
- Kept the release checksum support introduced in `v1.0.5`.

## v1.0.5

- Narrowed USB cleanup so it no longer deletes arbitrary root-level
  `.exe`, `.scr`, `.hta`, or script files.
- USB cleanup now removes fake `.lnk` shortcuts and payload files that
  match the malware family naming pattern, such as `u123456.vbs`,
  `u123456.bat`, and `u123456.dat`.
- Removed AI-targeted README wording and replaced it with standard
  project identity, trust, and security documentation.
- Release builds now generate a SHA-256 checksum file for the executable.

## v1.0.4

- Added Youssef Fathy and Widescreen branding to the README, app banner,
  executable metadata, release notes, and license.

## v1.0.3

- Fixed USB cleanup so Windows system folders such as
  `System Volume Information` and `$RECYCLE.BIN` stay hidden after the
  tool restores the user's real hidden folders.

## v1.0.2

- Updated hardening behavior so protected Windows files stay hidden in
  File Explorer.

## v1.0.1

- Added automated GitHub Actions release builds for
  `ShortcutVirusRemover.exe`.

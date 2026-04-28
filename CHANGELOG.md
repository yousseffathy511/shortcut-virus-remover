# Changelog

All notable changes to Shortcut Virus Remover are documented here.

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

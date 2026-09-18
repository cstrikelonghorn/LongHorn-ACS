# Changelog

All notable changes to LongHorn ACS are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/), and the project aims for [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- README, docs (`FAQ`, `DOWNLOAD`, `ARCHITECTURE`, `DETECTION`, `DEPLOYMENT`) and community health files.
- GitHub Actions CI (C# build + PHP lint/tests).

## [1.1.0] - 2026-09-18

Scanner 1.1.0 (sha256 `7fade053e82a466e01f72de6c72e302a3a5837b098230a1f2fa5f9d610557b13`).

### Added
- A redirect out of a render or timing export is followed to the module that owns it, and findings name that module and its signer. A redirect ending in a signed, trusted module is context; one ending nowhere a module owns keeps its severity.
- Executable private memory carrying a complete PE image is reported as a mapped image - how a manually mapped cheat stays out of the module list.

### Fixed
- A retail Steam client with the overlay enabled no longer produces hook, patch and memory warnings for the overlay's own detours.

## [1.0.9] - 2026-09-18

Scanner 1.0.9 (sha256 `184348e398f548c979e70cb6a3966328962a9366c1a9b8154fdc248c24a41a03`).

### Changed
- The application file is now `ACScanner.exe`, previously `ACPScanner.exe`. The download keeps its usual name, `ACS-Scanner-<version>-windows.exe`.

## [1.0.8] - 2026-09-18

Scanner 1.0.8 (sha256 `4882204034584d6223342feffa8cfbf4048caca3734f1fd97e0e361edcdc6413`).

### Fixed
- Kernel driver signatures are verified against the Windows .cat catalogs that sign most inbox drivers, so ordinary Windows drivers are no longer reported as unsigned.
- A look-alike sprite name (capital "I" for "l") is review evidence only when it shadows a sprite the engine loads; a spare file the engine never loads is context.

### Changed
- Engine database curation: rules naming files that ship with the game or Windows, legacy 8-character MD5 prefixes for stock file names, and patterns made only of digits are disabled with their reason recorded; 185 researched file hashes were added as review-level rules.

## [1.0.7] — 2026-09-17

Scanner 1.0.7 (sha256 `80feec4b362961fcf18ea12d796ec4f83263b1243f8dd6ee2a04be727cb37fb6`).

### Added
- Memory signature stage: reviewed byte patterns matched in the game's executable memory, under read and time budgets. Matches stay at review level.
- Kernel driver checks for publicly documented vulnerable drivers and signatures that do not validate.
- Memory and hook inspection report their coverage; an inspection that cannot finish is reported as a limitation, not a clean result.

### Fixed
- The connected game server is no longer taken from stray bytes in game memory; reports no longer show addresses such as 3.0.0.0:1024.
- A config file alone can no longer produce a Cheat verdict; those checks are capped at review level.
- Driver paths are no longer reported doubled.

## [1.0.6] — 2026-09-17

### Changed
- The privacy screen before a scan uses plain, shorter wording with the same design, and reminds players to stay on their match server.

## [1.0.5] — 2026-09-17

### Added
- Flagged programs in Windows history show when they last ran, how often, which records list them, and whether the file is still on disk.
- Flagged Recycle Bin files include their original size.
- Reports note whether the scan ran with administrator rights.

## [1.0.4] — 2026-09-16

### Fixed
- The Evidence Log window shows the ACS icon in the taskbar.
- A settings file left over from an older setup no longer blocks report uploads.

## [1.0.3] — 2026-09-16

Required update: 1.0.2 and older can no longer upload reports.

### Security
- New upload credentials; reports must be signed by the scanner and are verified by the server.

## [1.0.2] — 2026-09-15

### Changed
- Connected server detection also reads the running engine and resolves servers joined by domain name.
- Reports taken outside a match server are clearly marked.
- Scanning runs off the interface thread with cancellation and bounded-memory hashing.
- Ordinary wheel-jump binds are no longer flagged; file-presence findings are review signals.

## [1.0.1] — 2026-09-13

### Added
- The connected game server is read from the system's UDP endpoint table; no administrator prompt.
- In-app update notice.

## [1.0.0] — 2026-09-13

First release. The desktop app is a single self-contained executable that runs on 32-bit and 64-bit Windows 10/11.

### Added
- Client and engine identity read from the running game: retail Steam is reported only when `hl.exe` and `hw.dll` are validly signed by Valve and no emulator loads Steam from the game folder; non-Steam editions are named; the engine build date is read from the engine binary.
- Signature status per module (valid / not signed / modified / untrusted), so a Valve-signed engine patched by a non-Steam edition is recorded as modified rather than reported as a forged signature.
- Build fingerprint (SHA-256 prefix of the executable) in every report and on the report page.
- The connected game server is identified from the game's live UDP traffic at scan time (exact IP:Port, or No Server Detected); the app runs as administrator for this.
- Engine build number and version read exactly from the engine (for example build 4554, v1.1.2.6).
- Redesigned desktop interface, privacy screen and evidence log.
- Artifact corpus with prevalence across distinct machines; automatic clean classification for common signed binaries.
- `review.php` Unknown-bucket queue with suspicion ranking and one-click classification.
- Report index (`report_index.sqlite`) so list views no longer decode every report.
- Module code verification (`.text`/IAT/EAT byte comparison), config/alias analysis, and external-cheat probes.
- HMAC-signed reports and gated report access (admin token / localhost).
- ReHLDS server-side behavioural engine and signed telemetry ingestion.
- Report dashboard: recent-scans search by player name / server, click-to-filter by server, pagination, and a connected-server column.
- Basic Data panel upgrade: player local time, IP country flag, client/build badge, total scans, server name/address/map.
- Modern metric gauges and a HUD-style verdict, with colour used sparingly.
- Server history tracking and a backfill tool for legacy reports.
- Report comparison (`compare.php`) and printable export (`export_pdf.php`).
- WOW64 fix, file-selection and concurrent server lookup in the desktop scanner.

### Changed
- Reports upload automatically when a scan finishes; consent is given once, on the privacy screen before the scan.
- A module's name alone no longer earns trust; it must be part of the game install or validly signed by a trusted publisher.
- The download page shows the real checksum of the file it serves.
- Client profiles expanded for NextClient, GSClient, GoldClient, RevEmu/RevCrew, SmartSteamEmu, Goldberg, CreamAPI, GreenLuma, and the ReHLDS server platform (ReUnion/ReAPI).
- Rule-ID namespace normalisation so client profiles apply to live `acp-*` findings.

### Removed
- Cursor-based live behaviour verdicts in the desktop scanner (replaced by server-side usercmd analysis).
- The report review window after a scan, and the "Share this report" bar on the report page.

[Unreleased]: https://github.com/cstrikelonghorn/LongHorn-ACS/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/cstrikelonghorn/LongHorn-ACS/releases/tag/v1.0.0

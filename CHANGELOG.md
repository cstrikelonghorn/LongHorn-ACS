# Changelog

All notable changes to LongHorn ACS are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/), and the project aims for [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- README, docs (`FAQ`, `DOWNLOAD`, `ARCHITECTURE`, `DETECTION`, `DEPLOYMENT`) and community health files.
- GitHub Actions CI (C# build + PHP lint/tests).

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

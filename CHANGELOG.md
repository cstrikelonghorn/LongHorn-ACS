# Changelog

All notable changes to LongHorn ACS are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/), and the project aims for [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- README, docs (`FAQ`, `DOWNLOAD`, `ARCHITECTURE`, `DETECTION`, `DEPLOYMENT`) and community health files.
- GitHub Actions CI (C# build + PHP lint/tests).

## [3.3.0] — 2026

### Added
- Report dashboard: recent-scans search by player name / server, click-to-filter by server, pagination, and a connected-server column.
- Basic Data panel upgrade: player local time, IP country flag, client/build badge, total scans, server name/address/map.
- Modern metric gauges and a HUD-style verdict, with colour used sparingly.
- Server history tracking and a backfill tool for legacy reports.
- Report comparison (`compare.php`) and printable export (`export_pdf.php`).
- WOW64 fix, file-selection and concurrent server lookup in the desktop scanner.

### Changed
- Client profiles expanded for NextClient, GSClient, GoldClient, RevEmu/RevCrew, SmartSteamEmu, Goldberg, CreamAPI, GreenLuma, and the ReHLDS server platform (ReUnion/ReAPI).
- Rule-ID namespace normalisation so client profiles apply to live `acp-*` findings.

## [3.2.0]

### Added
- Artifact corpus with prevalence across distinct machines; automatic clean classification for common signed binaries.
- `review.php` Unknown-bucket queue with suspicion ranking and one-click classification.
- Report index (`report_index.sqlite`) so list views no longer decode every report.

### Removed
- Cursor-based live behaviour verdicts in the desktop scanner (replaced by server-side usercmd analysis).

## [3.0.0]

### Added
- Module code verification (`.text`/IAT/EAT byte comparison), config/alias analysis, and external-cheat probes.
- HMAC-signed reports and gated report access (admin token / share link / localhost).
- ReHLDS server-side behavioural engine and signed telemetry ingestion.

[Unreleased]: https://github.com/cstrikelonghorn/LongHorn-ACS/compare/v3.3.0...HEAD
[3.3.0]: https://github.com/cstrikelonghorn/LongHorn-ACS/releases/tag/v3.3.0

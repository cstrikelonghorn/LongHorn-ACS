# Developer validation — 3.3.1-beta.1

Performed locally on Windows x64, 2026-09-12 (2026-09-13 UTC). These are maintainer-run checks, not an independent audit or malware certification.

| Check | Result |
| --- | --- |
| Self-contained Windows x64 Release publish | Succeeded; 0 errors, 131 compiler warnings |
| Desktop regression checks and ready-screen rendering | 19 passed |
| Backend regression suites | 7 suites passed; 103 assertions |
| Signature-feed validation | 5 tests passed |
| Modified PHP download/reputation code syntax | Passed |

Desktop checks cover ordinary binds versus recursive scripts, disguised executable configs, informational severity, verified file hashes versus hash-looking filenames, HTTPS requirements, cancellation, file-budget coverage, and upload consent. No callback or a declined decision prevents upload through the consent gate. Approval receives the report JSON.

Backend checks cover identity/risk handling, compatibility-profile boundaries, signed report ingestion and server-side recomputation, report access controls, indexing, and honest release reputation. Feed tests cover hash-only rules, changed payloads, invalid dates, empty feeds, and invalid hash input.

Compiler warnings remain, chiefly nullable reference analysis and native structure fields. They need review before a stable release. The app's own executable and assembly are unsigned; signatures on bundled Microsoft files do not sign ACS.

## Limits

No live player scan or real report upload was used for these checks. This release has no demonstrated real-world detection-rate, false-positive-rate, or scan-speed benchmark across the claimed client families. Passing synthetic compatibility tests is not a certification for every client build. No claim of superiority to VAC, WarGods, or other products is established.

The public package has no configured report API. GitHub hosts downloads and documentation, not the report backend. An operator must deploy and configure that separately before players can scan.

Private source and test fixtures remain outside this repository. This summary describes developer-run results; public readers cannot independently reproduce those source-level tests from this distribution repository alone. An independent reviewer would need confidential access to the relevant source, build process and exact release.

# ACS 3.3.1-beta.1 — transparency beta

Windows x64 portable build, bundled .NET runtime. Requires a running compatible Counter-Strike 1.6/GoldSrc client and an operator-provided report API configuration. No production endpoint or secret is bundled.

- Added a per-scan privacy disclosure showing the actual report destination.
- Added complete JSON report review before upload. Declining or closing the preview prevents report upload.
- Changed missing upload approval to fail closed.
- Added an explicit message when no server is configured.
- Preserved the desktop gaming interface and the existing web dashboard styles.
- Corrected the local download page's reputation logic: missing analysis is unverified; suspicious results count as flags; invented vendor/sandbox results and safety claims were removed.

Client profiles include Steam/non-Steam distributions, NextClient, GoldClient, GSClient, RevEmu and server-platform components. Profile recognition is not a compatibility certification for every build. The desktop scans on demand. Continuous gameplay behavior analysis requires the separately deployed server plugin, which is not included in this public package.

Known limitations: unsigned application binaries; no independent audit; no verified antivirus report for this exact release; compiler warnings remain; no measured real-world false-positive/recall benchmark; operator-managed data retention. This release does not claim superiority to VAC, WarGods or ECD, detection of every cheat, or immunity to bypass.

See `VALIDATION.md`, `PRIVACY.md`, and `VERIFY.md` for evidence and limitations.

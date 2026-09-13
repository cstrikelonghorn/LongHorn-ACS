# LongHorn ACS

Counter-Strike 1.6 / GoldSrc anti-cheat evidence scanner for Windows.

**Public distribution and transparency repository.** Scanner source, detection databases, server code, credentials and player reports are not published here. This repository is not an open-source release of the scanner.

## Release

Version **1.0.0** — one portable Windows executable for 32-bit and 64-bit Windows 10/11. The app is **unsigned** and **not independently audited**. No verified antivirus analysis for this exact build is claimed. A GitHub download or matching checksum is not a guarantee of safety.

[Download 1.0.0](https://github.com/cstrikelonghorn/LongHorn-ACS/releases/tag/v1.0.0) · [Verification](VERIFY.md) · [Data access and privacy](PRIVACY.md) · [Security reporting](SECURITY.md) · [Release notes](RELEASE_NOTES.md)

## Start

1. Download `ACS-Scanner-1.0.0-windows.exe` from the tagged release and compare its SHA-256 with `CHECKSUMS.sha256`.
2. Get `acp-settings.json` from your trusted server operator. Place it next to the executable, or in `%APPDATA%\LongHorn ACS\`. The executable itself contains no server address.
3. Start Counter-Strike, then run the executable.
4. Read the screen shown before scanning. It names the report destination and what is collected. **The report uploads automatically when the scan finishes** — choose **Cancel** there if you do not want it sent.

Review `PRIVACY.md` for the data collected and operator-controlled retention.

## What the evidence means

ACS inventories game artifacts and reviews code changes, signatures, scripts and suspicious signals. Warnings require interpretation. A scan with no findings does not prove that a device or player is cheat-free. The app is not affiliated with or endorsed by Valve, GitHub, or Microsoft.

## What is public

The website, documentation, per-release checksums, file manifest, dependency inventory, and the release executable with its runtime license notices. The optional server plugin and driver scaffold are not bundled. Only sanitized synthetic examples belong in public issues.

## Website

Static HTML is in `docs/`. GitHub Pages can publish `main:/docs`. It contains no PHP API or report collection endpoint.

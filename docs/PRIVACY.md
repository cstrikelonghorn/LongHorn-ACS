# ACS privacy and data access

Applies to desktop beta 3.3.1-beta.1. Updated 2026-09-12.

ACS is an on-demand anti-cheat evidence scanner. Before each scan, the app displays the configured report destination and a disclosure. Before upload, it shows the complete report and asks you to choose Upload or Do not upload. Closing the preview declines upload. No report is uploaded without that decision through the official desktop interface.

## Data inspected and included

The scanner inspects the running Counter-Strike/GoldSrc process, loaded modules and code integrity, executable memory, drivers, other running processes, game/config files, aliases, suspicious external handles/windows/threads, execution and download traces, and recent filesystem deletion traces. It briefly samples cursor and game-button state during scanning; it is not a general text-entry recorder.

Report fields can include player and Steam identifiers, machine name, a volume serial and device fingerprint, OS/time-zone information, process/module/driver names and paths, file hashes, game and server details, memory strings, findings, scan timing, and inspection notes. Review the actual JSON preview for the exact fields in your scan. The scanner does not need your GitHub or Steam password.

## Network and upload

The app downloads detection rules from your configured server before report review. That request exposes your IP address to that server even if you later decline report upload. Remote API endpoints must use HTTPS; localhost HTTP is allowed for development. If you approve upload, the report goes to the displayed operator. The receiving server can record your IP address and correlate reports. A report link may open in your browser after upload.

The public release contains no report destination or API secret. Obtain settings from a trusted operator. Never put a report-signing, admin, or server-telemetry secret into a public issue or repository.

## Access, retention and deletion

Each operator controls their report service and access settings. Report storage has no automatic expiry guarantee in this release; data can remain until the operator removes it. Correlation databases, logs, backups and artifact metadata may retain information separately. The client cannot delete data already received by a server. Ask your operator about access and retention before scanning, and contact that operator for access or deletion requests. Do not assume reports are private because their URLs are hard to guess.

## Your choices

Cancel before scanning, cancel an active scan at its next checkpoint, decline report upload, or close the portable app. The public package installs no service or kernel driver. Removing the extracted directory removes the package; this does not remove server-side records. The complete local preview is held in memory and is not automatically saved by the preview feature.

## Public website

The included static website contains no analytics scripts, tracking pixels, cookies, third-party fonts, or scan/report submission forms. GitHub operates GitHub Pages and repository hosting and may process hosting/access information under its own policies. Links to GitHub and Microsoft are external destinations.

This document describes implementation behavior, not an independent privacy certification. Deployment policies must be provided by the operator of the report server.

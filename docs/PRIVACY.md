# ACS privacy and data access

Applies to ACS 1.0.7. Updated 2026-09-14.

ACS is an on-demand anti-cheat evidence scanner. Before each scan, the app shows the configured report destination and what the scan collects, and states that the report is uploaded automatically when the scan finishes. Choosing **Cancel** on that screen means nothing is scanned or sent. There is no second confirmation after the scan.

## Data inspected and included

The scanner inspects the running Counter-Strike/GoldSrc process, loaded modules and their code integrity and signatures, executable memory, drivers, other running processes, game/config files, aliases, suspicious external handles/windows/threads, execution and download traces, and recent filesystem deletion traces. It briefly samples cursor and game-button state during scanning; it is not a general text-entry recorder.

For about two and a half seconds it also watches the game's own UDP traffic to identify the server the game is joined to. Only packet addresses, ports and counts are read; packet contents are neither inspected nor kept. Reading another program's live traffic requires administrator rights, so ACS asks for them when it starts.

Report fields can include player and Steam identifiers, machine name, a volume serial and device fingerprint, OS/time-zone information, process/module/driver names and paths, file hashes, digital-signature status, game client and server details, memory strings, findings, scan timing, the scanner's own build fingerprint, and inspection notes. The scanner does not need your GitHub or Steam password.

## Network and upload

The app downloads detection rules from the configured server when the scan starts, which exposes your IP address to that server. When the scan finishes, the report is uploaded to the destination shown before scanning, and a report link may open in your browser. The receiving server can record your IP address and correlate reports. Remote API endpoints must use HTTPS; localhost HTTP is allowed for development.

This operator build contains its report destination and a scoped upload-access token so it works after download. Desktop users can extract that token, so it grants no administrative authority and is not device attestation. A separate `acp-settings.json` can override the destination. Never put an admin or server-telemetry secret into a public issue or repository.

## Access, retention and deletion

Each operator controls their report service and access settings. Report storage has no automatic expiry guarantee in this release; data can remain until the operator removes it. Correlation databases, logs, backups and artifact metadata may retain information separately. The client cannot delete data already received by a server. Ask your operator about access and retention before scanning, and contact that operator for access or deletion requests. Do not assume reports are private because their URLs are hard to guess.

## Your choices

Cancel before scanning, cancel an active scan at its next checkpoint (nothing is uploaded from a cancelled scan), or close the app. ACS is a single portable executable: it installs no service or kernel driver, and deleting the file removes it. This does not remove server-side records.

## Public website

The included static website contains no analytics scripts, tracking pixels, cookies, third-party fonts, or scan/report submission forms. GitHub operates GitHub Pages and repository hosting and may process hosting/access information under its own policies. Links to GitHub and Microsoft are external destinations.

This document describes implementation behavior, not an independent privacy certification. Deployment policies must be provided by the operator of the report server.

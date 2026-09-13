# Frequently Asked Questions

ACS (Anti-Cheat Scanner) is an anti-cheat **evidence** suite for Counter-Strike 1.6: a Windows scanner you run on your PC, a web dashboard that stores and explains the results, and an optional server plugin that watches players in-game. Everything below explains what it does, how to use it, and how your data is handled.

- [Overview](#overview)
- [How it works](#how-it-works)
- [What it scans](#what-it-scans)
- [What's included](#whats-included)
- [Using the desktop app](#using-the-desktop-app)
- [Using the web dashboard](#using-the-web-dashboard)
- [How safe is it?](#how-safe-is-it)
- [Tutorials](#tutorials)
- [Questions](#questions)

---

## Overview

| Part | Role |
|---|---|
| **Desktop scanner** | A Windows app that attaches to a running `hl.exe`, inventories the game, checks it against a signature database and uploads a signed report. |
| **Web dashboard** | A PHP dashboard that stores reports, shows what was found, ranks review items, and lets admins compare scans or export a PDF. |
| **Server engine** | An optional ReHLDS plugin that analyses how a player actually moves, aims and fires — without needing any client cooperation. |

**Who is it for?** Server owners and their staff who want evidence-backed decisions instead of guesswork, and honest players who want a way to prove their game is clean.

## How it works

1. **Scan.** With Counter-Strike running, the desktop app reads the live game process: loaded modules, memory regions, hooks, files, drivers and configuration.
2. **Upload.** The findings are packed into a report with an HMAC-SHA256 integrity check. This detects a changed payload but is not device attestation; the player controls their own client.
3. **Review.** The dashboard stores the report, classifies each artifact, and presents a clear verdict with confirmed detections separated from lower-confidence review items.

> **Evidence, not a verdict.** A report is a set of observations. Bans are always a human decision made by the server operator.

## What it scans

- **Running processes** — compared against a known cheat/tool list, with paths and hashes recorded.
- **Drivers** — loaded kernel drivers with MD5/SHA256, publisher and signature state.
- **Game modules** — every DLL mapped into `hl.exe`, its path, signer and trust state.
- **Memory regions** — private executable memory that backs no file on disk (a manual-map indicator).
- **Inline hooks & patches** — engine code compared byte-for-byte against the file on disk.
- **External readers** — other processes holding read/write handles on the game, foreign threads, overlay windows.
- **Scripts & config** — alias graphs and control-flow shapes that reveal bunny-hop, rapid-fire and no-recoil scripts regardless of naming.
- **Game files** — the live `cstrike` folder with hashes, so altered sprites and dropped DLLs are visible.
- **Game build & client** — Steam, non-Steam, NextClient, GSClient, RevEmu and other emulators are identified so they are not mistaken for cheats.

## What's included

- **Unified signature database** — hundreds of curated signatures plus a live artifact corpus that learns prevalence across machines.
- **Corpus & prevalence** — every hash ever seen, classified clean / cheat / unknown, so rare files stand out and common ones stop being false positives.
- **Client profiles** — known-legitimate CS 1.6 clients and Steam emulators recognised by name and hash.
- **Player risk view** — server behaviour and client scan results combined into one explainable score per SteamID.
- **Compare & export** — side-by-side report comparison and a printable PDF export.
- **ReChecker feed** — the signature set can be rendered into a ReChecker `resources.ini` for server-side enforcement.

## Using the desktop app

1. **Configure.** Set `apiUrl` to your deployed `api.php` and `apiToken` to the server's upload token.
2. **Launch Counter-Strike.** The scanner only runs while `hl.exe` / `cstrike.exe` is already open.
3. **Start the scan** from the app.
4. **Play normally** while the live-behaviour stage captures a short sample window.
5. **Upload.** The signed report is sent to your dashboard automatically when the scan finishes.

> **Tip.** Run the scanner as administrator for the deepest evidence — some memory and process reads are limited otherwise.

## Using the web dashboard

1. **Dashboard.** Newest scans are listed with name, IP, server, status and time. Use the search box to filter by player or server.
2. **Report.** Open a scan to see the verdict, the Basic Data panel, confirmed detections and review evidence.
3. **Evidence.** Each detection opens a forensic drawer with the engine rule, hook target, disassembly/byte difference and timestamp.
4. **History.** Previous scans for the same player and their server connection history are shown on the report.
5. **Share.** Players copy their report link from the app's **View Evidence** window and send it to an admin, who opens it with their own access.
6. **Compare / Export.** Compare two reports side by side, or export a clean PDF for records.

## How safe is it?

- **The scanner is an evidence tool** — it collects and explains; it does not ban, punish or modify your game.
- **No account password needed** — it reads the SteamID the game already exposes and a hardware fingerprint, never your Steam password.
- **Reports are tamper-evident** — HMAC-SHA256 signed; edited reports are rejected when the server enforces signatures.
- **Your IP is masked** — displayed with the last octet hidden (e.g. `109.187.61.***`).
- **Access is gated** — reports are stored outside direct web access; viewing requires an admin token, a single-report share key, or localhost.
- **False-positive resistant** — known clients/emulators are recognised, and common files are learned as clean from the corpus.

Full details: [Privacy Policy](../privacy.php) and [Terms of Use](../terms.php).

## Tutorials

<details>
<summary><b>Run your first scan</b></summary>

1. Put an `acp-settings.json` with `apiUrl` and `apiToken` next to `ACPScanner.exe`, or in `%APPDATA%\LongHorn ACS\`.
2. Start Counter-Strike 1.6 and join any server (or the main menu).
3. Launch the scanner and press Scan. Keep the game focused while the live-behaviour stage runs.
4. When it finishes, the report uploads automatically and the link opens.
</details>

<details>
<summary><b>Read a report correctly</b></summary>

1. Start with the verdict and the metric circles — they summarise confirmed detections.
2. Check **Basic Data** for identity, build and server at scan time.
3. Read **Confirmed Detections** as strong evidence; read **Review Evidence** as "worth a look", not a verdict.
4. Open a row's _Forensics_ drawer to see the exact rule and byte difference.
</details>

<details>
<summary><b>Share a clean scan with an admin</b></summary>

1. When the scan finishes, open **View Evidence** in the app and click the report link to copy it.
2. Send that link to the server admin.
3. Admins open reports with their own access, so the link does not expose the report to anyone else.
</details>

<details>
<summary><b>Review the Unknown bucket (admins)</b></summary>

1. Open `review.php` with your admin token.
2. Rows are ranked by suspicion: mapped into the game, unsigned, rare, driver, or concentrated on machines with detections.
3. Use the VirusTotal link, then mark each row **Cheat** or **Clean** — the verdict applies to every future scan.
</details>

<details>
<summary><b>Deploy server-side enforcement</b></summary>

1. Generate the feed: `rechecker.php?action=resources`.
2. Save it as `cstrike/addons/rechecker/resources.ini` on your server.
3. Review the file, then start with `amx_kick` rather than a ban until you trust the rules.
</details>

## Questions

<details>
<summary>Is the scanner a virus or malware?</summary>

No. It is a read-only inspection tool. It opens the game process to read memory, hashes files and uploads a report. It does not inject code, modify the game, or keep running in the background.
</details>

<details>
<summary>Does it ban players automatically?</summary>

No. ACS produces evidence. A confirmed detection is strong evidence and review items are lower-confidence signals — but every ban or kick is a decision made by a human server operator.
</details>

<details>
<summary>Will it flag legitimate software like Steam, Discord or MSI Afterburner?</summary>

That is what client profiles and the artifact corpus prevent. Known overlays, injectors and CS 1.6 clients are recognised by name and hash; common files seen on many distinct machines are learned as clean instead of being flagged for rarity.
</details>

<details>
<summary>Does it work with non-Steam clients and emulators?</summary>

Yes. Steam, non-Steam repacks, NextClient, GSClient, GoldClient, RevEmu/RevCrew, SmartSteamEmu, Goldberg and others are identified so the report shows the real client.
</details>

<details>
<summary>Do I need administrator rights?</summary>

The scan runs without elevation, but running as administrator allows deeper memory and process inspection and produces more complete evidence. Some system processes are not readable without it.
</details>

<details>
<summary>Does the game have to be running?</summary>

Yes. The scanner attaches to a live `hl.exe`. Start Counter-Strike first.
</details>

<details>
<summary>How long does a scan take?</summary>

Typically well under a minute for the static checks, plus a short live-behaviour sample window while you play normally.
</details>

<details>
<summary>What data is stored, and for how long?</summary>

Player identity, masked IP, operating system, hardware identifiers, game build and the evidence found. Reports stay on the operator's server until an administrator deletes them.
</details>

<details>
<summary>Can a report be faked or edited?</summary>

Reports are HMAC-SHA256 signed. When the server enforces signatures, a report changed after signing is rejected. The dashboard also never trusts client-side claims for server-side behaviour.
</details>

<details>
<summary>Who can see my report?</summary>

Admins with the access token, anyone holding a single-report share link you give out, or localhost on the host machine. The recent-scans list and comparison view are admin-only.
</details>

<details>
<summary>Is there a way to prove I am clean?</summary>

Yes. Run a scan and share the resulting report link with the admin. A clean verdict with no confirmed detections is exactly the proof the system is designed to provide.
</details>

<details>
<summary>I found a false positive — what should I do?</summary>

Send the report link to support with a note. Legitimate programs are folded into the client profiles or classified clean in the corpus, which fixes the false positive for every future scan.
</details>

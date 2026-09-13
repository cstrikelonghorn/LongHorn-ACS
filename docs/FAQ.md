# FAQ — LongHorn ACS

Evidence-based anti-cheat for Counter-Strike 1.6. This page explains what ACS is, how it works, how to use it, and how your data is handled.

- [How it works](#how-it-works)
- [What it scans](#what-it-scans)
- [Using the app](#using-the-app)
- [Safety & privacy](#safety--privacy)
- [Questions](#questions)

## How it works

1. **Scan.** With Counter-Strike running, the desktop app reads the live game process — modules, memory, hooks, files, drivers and configuration.
2. **Upload.** Findings are packed into a report and signed (HMAC-SHA256) so they cannot be edited or swapped in transit.
3. **Review.** The operator's dashboard stores the report, classifies each artifact, and separates confirmed detections from lower-confidence review items.

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

## Using the app

1. **Configure.** Set `apiUrl` to your trusted operator's report API and keep the credentials private. The public package has no configured endpoint.
2. **Launch Counter-Strike.** The scanner only runs while `hl.exe` / `cstrike.exe` is already open.
3. **Start the scan** and play normally during the live-behaviour stage.
4. **Review the preview.** The app shows the complete report before anything is sent — you choose whether to upload, and to whom.

> **Tip.** Run the scanner as administrator for the deepest evidence — some memory and process reads are limited otherwise.

## Safety & privacy

- **Read-only tool** — it collects and explains; it does not ban, punish or modify your game.
- **No account password** — it reads the SteamID the game already exposes and a hardware fingerprint, never your Steam password.
- **Masked IP** — addresses are stored and displayed with the last octet hidden (`109.187.61.***`).
- **Explicit upload** — nothing leaves your PC until you accept the disclosure shown in the app.
- **Operator-controlled retention** — the receiving operator decides how long reports are kept. See [PRIVACY.md](PRIVACY.md).

## Questions

<details>
<summary><b>Is the scanner a virus or malware?</b></summary>

No. It is a read-only inspection tool. It opens the game process to read memory, hashes files and uploads a report — it does not inject code, modify the game, or keep running in the background.
</details>

<details>
<summary><b>Does it ban players automatically?</b></summary>

No. ACS produces evidence. A confirmed detection is strong evidence and review items are lower-confidence signals — but every ban or kick is a decision made by a human server operator.
</details>

<details>
<summary><b>Will it flag legitimate software like Steam, Discord or MSI Afterburner?</b></summary>

No. Known overlays, injectors and CS 1.6 clients are recognised by name and hash, and common files seen on many distinct machines are learned as clean instead of being flagged for rarity.
</details>

<details>
<summary><b>Does it work with non-Steam clients and emulators?</b></summary>

Yes — Steam, non-Steam repacks, NextClient, GSClient, GoldClient, RevEmu/RevCrew, SmartSteamEmu, Goldberg and others are identified so the report shows the real client.
</details>

<details>
<summary><b>Do I need administrator rights?</b></summary>

The scan runs without elevation, but running as administrator allows deeper memory and process inspection and produces more complete evidence.
</details>

<details>
<summary><b>Does the game have to be running?</b></summary>

Yes. The scanner attaches to a live <code>hl.exe</code> — start Counter-Strike first.
</details>

<details>
<summary><b>How long does a scan take?</b></summary>

Typically well under a minute for the static checks, plus a short live-behaviour sample window while you play normally.
</details>

<details>
<summary><b>What data is stored, and for how long?</summary>

Player identity, masked IP, operating system, hardware identifiers, game build and the evidence found. The receiving operator decides how long reports are kept.
</details>

<details>
<summary><b>Can a report be faked or edited?</summary>

Reports are HMAC-SHA256 signed. When the operator enforces signatures, a report changed after signing is rejected. The dashboard also never trusts client-side claims for server-side behaviour.
</details>

<details>
<summary><b>Is there a way to prove I am clean?</summary>

Yes. Run a scan and share the resulting report link with the admin. A clean verdict with no confirmed detections is exactly the proof the system is designed to provide.
</details>

<details>
<summary><b>I found a false positive — what should I do?</summary>

Send the report link to the operator with a note. Legitimate programs are folded into the client profiles or classified as clean in the corpus, which fixes the false positive for every future scan.
</details>

<details>
<summary><b>Where is the source code?</summary>

This is a distribution and transparency repository. The scanner source, detection databases and server code are not published here.
</details>

<div align="center">

<img src="docs/img/hero.png" alt="LongHorn ACS — Anti-Cheat Scanner" width="100%" />

# LongHorn ACS — Anti-Cheat Scanner

**Evidence-based anti-cheat for Counter-Strike 1.6.**

A Windows desktop scanner, a PHP web dashboard, and a ReHLDS server-side behavioural engine — together they produce signed, reviewable evidence instead of guesses.

[![Status](https://img.shields.io/badge/status-in%20development-orange?style=flat-square)](#project-status)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-0078d4?style=flat-square)](#download)
[![Scanner](https://img.shields.io/badge/scanner-v3.3-111?style=flat-square)](#download)
[![Web](https://img.shields.io/badge/web-PHP%208.2%2B-777bb4?style=flat-square)](#deploy-the-web-dashboard)
[![Server](https://img.shields.io/badge/server-ReHLDS%20%2F%20Metamod-e23?style=flat-square)](#server-side-engine)

[Download](#download) · [FAQ](docs/FAQ.md) · [Screenshots](#the-app) · [Architecture](docs/ARCHITECTURE.md) · [Security](SECURITY.md)

</div>

---

## What it is

Most of the surviving CS 1.6 population does not run the retail Steam client. They run repacks, NextClient, GSClient, emulators — and several of those modify the engine **by design**. A scanner that cannot tell that apart from cheating is worse than useless.

ACS is built around one idea: **collect strong evidence, explain it clearly, and let a human decide.** It never bans on its own.

| | |
|---|---|
| 🖥 **Desktop scanner** | A C# WinForms app that attaches to a running `hl.exe`, inventories the game and checks it against a signature database + artifact corpus, then uploads a **signed** report. |
| 🌐 **Web dashboard** | A PHP dashboard that stores reports, shows what was found, ranks review items, and supports compare, history and PDF export. |
| 🛡 **Server engine** | An optional ReHLDS/Metamod plugin that watches how a player actually plays — aim, recoil, movement, timing — with no client cooperation. |

## The App

<div align="center">

| Idle | Scanning |
|---|---|
| ![App idle](docs/img/app-idle.png) | ![App scanning](docs/img/app-scanning.png) |

| Detected | Review |
|---|---|
| ![App detected](docs/img/app-detected.png) | ![App warning](docs/img/app-warning.png) |

</div>

Full-size: [`docs/img/`](docs/img) · more on the [Download page](docs/DOWNLOAD.md).

## Features

- **Module code verification** — every game module's `.text` is compared byte-for-byte against the file on disk, catching inline hooks, detours, mid-function patches, IAT and EAT hooks.
- **Cheat-named & foreign modules** — DLLs mapped into `hl.exe` from outside the game/Steam/Windows paths are flagged; hashes always go to the corpus.
- **Memory evidence** — private executable regions that back no file on disk (manual-map indicator).
- **External-cheat probes** — processes holding read/write handles on the game, foreign threads, and overlay windows.
- **Script & config analysis** — resolves the `alias` graph and matches control-flow shape, so bunny-hop / rapid-fire / no-recoil scripts are caught regardless of naming.
- **Client & emulator detection** — Steam, NextClient, GSClient, GoldClient, RevEmu/RevCrew, SmartSteamEmu, Goldberg and more, so a client's own detours are not treated as cheating.
- **Artifact corpus** — every hash ever seen, classified clean / cheat / unknown by prevalence across **distinct machines**.
- **Server correlation** — client scan risk and ReHLDS behavioural risk combine into one explainable per-SteamID score.

## How it works

```text
  Windows scanner                     Web dashboard                 ReHLDS plugin
  ───────────────                     ─────────────                 ─────────────
  attach hl.exe                       verify HMAC                   usercmd stream
  inventory + integrity               store report                  aim / recoil / move
  signatures + corpus                 classify + rank               long-term stats
        │                                   ▲                             │
        │        signed report (HMAC)       │      signed telemetry       │
        └───────────────────────────────────┘◄────────────────────────────┘
                            one risk score per SteamID
```

See [Architecture](docs/ARCHITECTURE.md) for the full breakdown.

## Download

> The desktop scanner runs only while **Counter-Strike is already open**.

- **Requirements:** Windows 10/11 (x64), .NET runtime, Counter-Strike 1.6.
- Full instructions and checksums: **[docs/DOWNLOAD.md](docs/DOWNLOAD.md)**.
- Releases (once published) will appear under **Releases** with SHA-256 for every artifact.

```text
1. Configure  windows/acp-settings.json   → apiUrl + apiToken
2. Launch Counter-Strike 1.6
3. Run the scanner  →  scan  →  signed report uploads automatically
```

## Deploy the web dashboard

Requirements: **PHP 8.2+** with `json`, `fileinfo`, and `random_bytes`.

```bash
# 1. Upload the web files to your host (not windows/ or server/).
# 2. Ensure the reports/ directory is writable.
# 3. Verify:
curl "https://your-host/acp/api.php?action=health"

# 4. Configure secrets:
ACP_API_TOKEN=<long random secret>       # upload + signing token (shared with the client)
ACP_ADMIN_TOKEN=<long random secret>     # dashboard / review / classification
```

Details in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). Use **HTTPS** in production.

## Server-side engine

```bash
curl -o resources.ini "https://your-host/acp/rechecker.php?action=resources"
# drop in cstrike/addons/rechecker/resources.ini
```

See [`server/`](server/) and [docs/DETECTION.md](docs/DETECTION.md).

## Screenshots & docs

| Document | What's inside |
|---|---|
| [docs/FAQ.md](docs/FAQ.md) | How it works, how to use it, what it scans, how safe it is |
| [docs/DOWNLOAD.md](docs/DOWNLOAD.md) | Install, configure, verify |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, data flow, storage |
| [docs/DETECTION.md](docs/DETECTION.md) | Every detection channel explained |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Hosting, nginx/Apache, secrets |
| [SECURITY.md](SECURITY.md) | Threat model, report integrity, disclosure |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Project status

**In development — not production-ready.** The detection engine, web dashboard and server plugin are functional, but APIs, rules and the UI can change without notice. Treat this repository as a work in progress.

Roadmap:

- [ ] Finish the client & emulator recognition pass
- [ ] Publish signed release builds with checksums
- [ ] Complete the ReHLDS behavioural rule set
- [ ] Harden the report index for large archives
- [ ] Public documentation pass

## Security & privacy

- Reports are **HMAC-SHA256 signed** — tamper-evident, and enforceable on the server.
- Upload token and admin/classification token are **separate secrets**.
- Player IPs are stored and displayed **masked** (`109.187.61.***`).
- Report storage is kept **outside direct web access**; non-web folders ship deny-all rules.
- Please report vulnerabilities per [SECURITY.md](SECURITY.md).

## License

Private, **all rights reserved** — see [LICENSE](LICENSE). This repository is not licensed for redistribution.

<div align="center">
<sub>Created by <a href="https://www.cslonghorn.com">LongHorn</a> · cslonghorn.com</sub>
</div>

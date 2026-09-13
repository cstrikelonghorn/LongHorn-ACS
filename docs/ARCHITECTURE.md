# Architecture

ACS is three cooperating systems that share one vocabulary of evidence.

```text
┌────────────────────────┐        signed report (HMAC-SHA256)         ┌──────────────────────────┐
│   Windows scanner       │ ─────────────────────────────────────────▶ │   Web dashboard (PHP)     │
│   windows/ (C#/.NET)    │                                            │   index.php / api.php     │
│                         │                                            │                          │
│  • process inventory    │                                            │  • report storage         │
│  • module integrity     │                                            │  • corpus / prevalence    │
│  • memory & hooks       │                                            │  • client recognition     │
│  • config / scripts     │                                            │  • player risk model      │
└────────────────────────┘                                            └───────────▲──────────────┘
                                                                                  │
                                                     signed telemetry (HMAC)      │
                                                                                  │
                                                          ┌───────────────────────┴────┐
                                                          │  ReHLDS / Metamod plugin    │
                                                          │  server/ (C++)              │
                                                          │  • usercmd stream           │
                                                          │  • aim / recoil / movement  │
                                                          └────────────────────────────┘
```

## Components

### Desktop scanner — `windows/`

A C# WinForms app (`ACPScanner.csproj`).

| File | Responsibility |
|---|---|
| `ScannerEngine.cs` | Orchestrates the scan; process/module/driver/memory checks; build & server detection |
| `ModuleIntegrity.cs` | `.text` / IAT / EAT verification against the file on disk |
| `ConfigAnalyzer.cs` | Alias-graph script detection (bhop, rapid-fire, no-recoil) |
| `SystemProbe.cs` | External readers, injected threads, overlay windows |
| `MainForm.cs` / `Program.cs` | UI shell |

It attaches to a running `hl.exe`, produces a JSON report, signs it with HMAC-SHA256, and POSTs it to `api.php`.

### Web dashboard — repo root (PHP)

| File | Responsibility |
|---|---|
| `index.php` | Dashboard + report view; recent scans with search, server filtering, pagination |
| `api.php` | `health` / `database` / `upload_report` endpoints |
| `report_ingest.php` | Upload decoding, validation, counter normalisation |
| `report_index.php` | Derived SQLite index over `reports/` for fast list/search/related queries |
| `corpus.php` | Artifact corpus: every hash ever seen, with prevalence |
| `behavior.php` | Telemetry storage + the combined player risk model |
| `clients.php` | Legitimate-client compatibility profiles |
| `telemetry.php` | Signed ingestion endpoint for the ReHLDS plugin |
| `players.php` / `review.php` / `compare.php` / `export_pdf.php` | Admin surfaces |
| `rechecker.php` | Renders the signature DB into a ReChecker `resources.ini` |

### Server engine — `server/`

A Metamod plugin for ReHLDS/HLDS that analyses the usercmd stream the server already receives — aim, recoil, movement, command timing — with no client cooperation. It posts signed telemetry to `telemetry.php`.

## Data flow

1. **Scan → report.** The desktop app serializes findings and signs the exact JSON with HMAC-SHA256.
2. **Ingest.** `api.php` verifies the signature (optionally required), assigns an id, folds artifacts into the corpus, recognises the client, and computes the player's combined risk.
3. **Index.** A summary row is written to `report_index.sqlite` so list/search/related views never decode every report.
4. **Telemetry.** The ReHLDS plugin posts signed batches; `behavior.php` stores them and recomputes risk.

## Storage

| Path | Contents | Published? |
|---|---|---|
| `reports/*.json` | Full reports (player data) | ❌ deny-all |
| `database/corpus.sqlite` | Artifact corpus | ❌ deny-all |
| `database/behavior.sqlite` | Server telemetry + risk | ❌ |
| `database/report_index.sqlite` | Derived index (rebuilds itself) | ❌ |
| `database/cheats_database.json` | Built-in signatures | ✅ (tracked) |
| `database/client_profiles.json` | Known client profiles | ✅ (tracked) |

## Risk model (short)

Server-side evidence decays with a 30-day half-life. Repeats of one rule are worth far less than the first hit; independent rules agreeing counts for more; agreement across categories (aim + recoil + movement) counts for more still. Client scan risk and server risk are combined as independent probabilities — `1 − (1−s)(1−c)` — never by simple addition, so neither source alone can reach a ban.

See [DETECTION.md](DETECTION.md) for the detection channels and [DEPLOYMENT.md](DEPLOYMENT.md) for hosting.

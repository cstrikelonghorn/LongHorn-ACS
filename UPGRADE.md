# ACS 1.0.0

The desktop app has a graphite and amber Counter-Strike-inspired interface, an animated activity radar, numbered scan panels, measured elapsed time, cancellation, and clearer evidence labels. At the user's request, the web dashboard retains its original styling and layout; the added operations theme, hero, and coverage cards were removed. Scanner and reporting fixes remain in place.

## Running this build

Run `windows/release/ACPScanner.exe` — the whole app is that one file (`dotnet publish windows/ACPScanner.csproj -c Release` writes it there). It contains no server address: put `acp-settings.json` with your server API endpoint URL (`http://127.0.0.1:8000/api.php` for local testing) next to the exe or in `%APPDATA%\LongHorn ACS\`. HTTPS is required for public servers.

Serve this directory with your existing PHP deployment. Local preview: `http://127.0.0.1:8000/index.php`. No production deployment was performed.

## Engine and reporting changes

- Scan work runs off the UI thread. A single scan gate protects shared engine state, and cancellation is checked between stages and during hashing. Some native probes finish before cancellation takes effect.
- File inventory uses at most two workers to limit CPU and storage contention during gameplay. Performance is not yet benchmarked against real games.
- Hashes stream through bounded buffers and are reused only within a scan. The scanner no longer trusts the writable disk hash cache.
- Hash signatures compare exact computed hashes, never filenames or metadata containing hash text. Renaming a matching binary does not evade its content hash.
- Ordinary wheel-jump binds are no longer flagged. Static config detections become review signals because file presence does not establish execution. Suspicious filenames and local OpenGL wrappers also require review.
- INFO rules remain informational. Regex timeouts no longer crash a scan. Empty databases abort scanning, and missing module inspection produces an explicit warning.
- The scanner stops stealing foreground focus during input sampling.
- Reports record measured stage durations, download time, database content fingerprint, and scan mode. The server preserves the scanner's database counts and separately records the server database revision.
- Legacy unsigned payloads cannot bypass mandatory signatures. Oversized bodies are rejected even without a reliable Content-Length. Malformed findings and inventory structures are rejected.
- Server counters are recomputed from submitted inventory and accepted findings. These are **client observations**, not independently attested hardware measurements.
- The desktop uses the server's accepted summary after compatibility adjustments. Risk recomputation now sees the newly saved report.
- The dashboard no longer displays the visitor counter with fabricated initial values. Recent-report metrics describe the latest 25 stored reports, not an all-time detection rate.

## Signature updates

Each scan fetches the server database. Hashes explicitly marked `cheat` by an administrator in the corpus are now included as live signatures. Marking one clean or unknown removes that generated rule on the next fetch. Client labels and popularity classifications cannot create these rules.

`tools/sync_signatures.py` supports a separately curated feed. It requires HTTPS and an independently obtained SHA-256, blocks redirects, limits size, rejects future timestamps and rollbacks, and atomically installs exact hash rules in `database/curated_hashes.json`. A checksum supplied by the same compromised source is not independent authenticity verification. The trusted publisher and digest distribution remain deployment responsibilities.

```powershell
python tools/sync_signatures.py https://YOUR-TRUSTED-PUBLISHER/reviewed-hashes.json EXPECTED_SHA256
```

Feed format (example only; not installed):

```json
{
  "publishedAt": "2026-09-01T00:00:00Z",
  "hashes": [
    {
      "sha256": "64 hexadecimal characters from an independently reviewed binary",
      "family": "Reviewed cheat family",
      "source": "https://publisher.example/review-record"
    }
  ]
}
```

No trusted current feed or reviewed new binaries were supplied. No claim is made that the database is the newest, exhaustive, or equal to proprietary anti-cheat databases. No unverified cheat downloads were executed or imported.

## Compatibility and detection limits

Existing profiles cover Steam/non-Steam builds, NextClient, GoldClient, GSClient, RevEmu, and server components including ReHLDS, ReAPI, and Reunion. Profile tests verify scoped downgrades and that unrelated findings survive. They do not establish compatibility with every released build. Some profiles are inferred and lack known build hashes.

The upstream [NextClient documentation](https://github.com/CS-NextClient/NextClient) has specific engine requirements. The [ReHLDS projects](https://github.com/rehlds) document their separate server roles; server components must not be confused with desktop clients.

The desktop is an **on-demand scanner**, not a continuous protection service. The existing server plugin analyzes ongoing gameplay when installed. Wallhack/ESP detection depends on observable artifacts and code changes; aim, recoil, and speed behavior need server evidence. There is no universal detection of all private or published cheats, proof of gameplay interception from every external handle, or guarantee of bypass prevention. HMAC protects transport integrity but a modified client possessing the shared key can fabricate observations. The optional driver remains a scaffold, not a signed production driver.

Beating VAC, WarGods, or ECD requires a representative clean/cheat corpus, measured false-positive and recall rates, adversarial testing, and live testing across supported client versions. Those measurements were not performed here. No automatic banning was added.

## Verification

- PHP suites: identity, risk scoring, compatibility, upload integrity, counter normalization, reviewed-hash export/revocation.
- C++ tests: 16 synthetic checks for human and cheat-shaped aim, recoil, movement, and command timing.
- Desktop tests: manual keybinds, recursive scripts, INFO severity, content-hash matching, HTTPS policy, cancellation, and hidden UI rendering.
- Feed tests: accepted format, tampering, invalid hash, empty feed, future timestamp.
- Dashboard HTTP response and PHP syntax checked. The desktop UI render is covered by `dotnet run --project tests/desktop/ScannerChecks.csproj <output.png>`.
- Browser visual verification could not complete: the in-app browser was unavailable and automatic approval review blocked the headless browser launch. Responsive browser layout and live gameplay scans remain unverified.

```powershell
$env:ACPDIR = (Get-Location).Path
$env:SCRATCH = $env:TEMP
php tests/behavior_test.php
php tests/risk_thresholds_test.php
php tests/client_profiles_test.php
php tests/report_ingest_test.php
python tests/signature_feed_test.py
dotnet run --project tests/desktop/ScannerChecks.csproj
```

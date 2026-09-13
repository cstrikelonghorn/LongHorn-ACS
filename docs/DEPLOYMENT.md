# Deployment

How to host the ACS web dashboard securely.

## Requirements

- **PHP 8.2+** with `json`, `fileinfo`, and `random_bytes` (the ZIP extension is only needed by the broader demo-upload suite).
- A writable `reports/` directory.
- HTTPS (strongly recommended — reports carry SteamIDs, IPs and hardware identifiers).

## 1. Upload the web files

Publish **only** the web files:

```
index.php  api.php  telemetry.php  players.php  review.php  corpus.php
compare.php  export_pdf.php  rechecker.php  nav.php  theme_bar.php
config.php  behavior.php  clients.php  report_index.php  report_ingest.php
signature_store.php  privacy.php  terms.php  license.php  faq.php  download.php
assets/  database/  reports/  docs/
```

Do **not** publish `windows/`, `server/`, `tests/`, `tools/`, `tmp/` — they contain source and detection logic.

## 2. Protect non-web folders

Every non-web folder ships a deny-all `.htaccess`. **nginx ignores `.htaccess`**, so on nginx add:

```nginx
location ~ ^/(tools|tests|server|windows|tmp|database|reports)/ { deny all; }
```

## 3. Make `reports/` writable

```bash
chmod 755 reports          # or hand it to the PHP user
```

## 4. Verify

```bash
curl "https://your-host/acp/api.php?action=health"
```

Expected: `ok: true` with signature counts. Loading `index.php` shows the dashboard.

## 5. Secrets

ACS fails closed: report uploads are **local-only** until you set a token.

| Variable | Purpose |
|---|---|
| `ACP_API_TOKEN` | Scanner API access token. Assume desktop users can extract it; never reuse it for administration. |
| `ACP_ADMIN_TOKEN` | Dashboard, `review.php`, and hash classification. **Separate** from the upload token. |
| `ACP_REPORT_SECRET` | HMAC payload-integrity key (defaults to `ACP_API_TOKEN`). This is not device attestation. |
| `ACP_REQUIRE_REPORT_SIGNATURE` | `1` to reject unsigned/edited reports outright. |
| `ACP_TELEMETRY_SECRET` | HMAC key for ReHLDS plugin telemetry. |
| `ACP_CORPUS_FILE` | Corpus SQLite path (put **outside** the web root). |
| `ACP_BEHAVIOR_FILE` | Telemetry SQLite path (outside the web root). |
| `ACP_REPORT_INDEX` | Report index SQLite path. |

> `ACP_*` is still honoured for backwards compatibility; `ACS_*` is the current spelling and wins where both are set.

Instead of environment variables, the values can live in a `.acs-secrets.php` file that returns an array (`apiToken`, `adminToken`, `reportSecret`, `telemetrySecret`, `publicDashboard`). It is read from `ACS_SECRETS_FILE`, else `<vhost>/private/.acs-secrets.php`, else `<vhost>/.acs-secrets.php`. On Hestia/Vesta use `private/`: PHP's `open_basedir` there cannot read the vhost root, and the site then silently runs with **no secrets** — uploads disabled and the dashboard public.

## Who can read a report

Three ways, in order of preference:

1. **Admin** — `?token=<ACP_ADMIN_TOKEN>` once (sets an HttpOnly session cookie), or the `X-ACS-Token` header. Admins see everything.
2. **Share link** — a per-report link carrying a key derived from the report id. It opens that one report and nothing else.
3. **Localhost** — requests from `127.0.0.1` are always allowed.

With no `ACP_ADMIN_TOKEN`, remote viewing is refused rather than left open, and no share key is minted.

## ReChecker feed

```bash
curl -o resources.ini "https://your-host/acp/rechecker.php?action=resources"
# → cstrike/addons/rechecker/resources.ini
```

Only `DETECTED` + high-confidence signatures are emitted, using `MISSING` rules. Review before deploying and start with `amx_kick`, not a ban.

## Updating

1. Back up `reports/` and `database/`.
2. Replace the web files.
3. Reload `index.php`; the report index and corpus migrate themselves.

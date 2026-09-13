# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Email **support@cslonghorn.com** with:

- a description of the issue and its impact,
- steps to reproduce,
- affected version/commit,
- any proof-of-concept (please do not include real player data).

We will acknowledge within a few days and keep you updated until a fix ships.

## Threat model

ACS handles personal data (SteamIDs, IPs, hardware identifiers) and evidence that can lead to a ban, so the design assumes the desktop client is **untrusted** and the network is **hostile**.

| Asset | Protection |
|---|---|
| Report contents | HMAC-SHA256 signed end-to-end; the server can require signatures (`ACP_REQUIRE_REPORT_SIGNATURE=1`) and reject edited reports. |
| Upload credential | `ACP_API_TOKEN`, set per deployment. Ships on client machines, so it is treated as semi-public. |
| Classification / admin | `ACP_ADMIN_TOKEN`, deliberately **separate** from the upload token. |
| Report storage | Kept outside direct web access; `reports/*.json` denied on Apache and nginx. |
| Player IP | Stored and displayed **masked** (last octet hidden). |
| Server telemetry | HMAC-signed with `ACP_TELEMETRY_SECRET`; the endpoint refuses unsigned batches. |

## Deployment checklist

- [ ] HTTPS everywhere.
- [ ] `ACP_API_TOKEN`, `ACP_ADMIN_TOKEN`, `ACP_TELEMETRY_SECRET` set to long random values.
- [ ] `ACP_REQUIRE_REPORT_SIGNATURE=1` in production.
- [ ] `database/`, `reports/`, `tools/`, `tests/`, `server/`, `windows/` denied (nginx included).
- [ ] Corpus / behavior SQLite files placed **outside** the web root.
- [ ] Regular backups of `reports/` and `database/`.

## Out of scope

- False positives/negatives in detection logic (report those as normal issues).
- Vulnerabilities in third-party services the operator chooses to link (e.g. VirusTotal).
- Social engineering of server operators.

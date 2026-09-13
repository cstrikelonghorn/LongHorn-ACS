"""Build the public distribution repository and the release files, locally.

Run after `dotnet publish windows/ACPScanner.csproj -c Release`, which writes the one
self-contained executable to windows/release/. Nothing here contacts GitHub: publishing is
publish_release.py, and that step refuses to run while publication/PRIVATE_REVIEW exists.

Never copy the project root into the public repository.
"""
from pathlib import Path
import hashlib, json, os, re, shutil
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
PUB = ROOT / 'publication'
REPO = PUB / 'public-repo'
ARTIFACTS = PUB / 'artifacts'
PROJECT = ROOT / 'windows' / 'ACPScanner.csproj'
SOURCE_EXE = ROOT / 'windows' / 'release' / 'ACPScanner.exe'

# One version for everything: the number in the project file.
_match = re.search(r'<Version>\s*([0-9A-Za-z.+-]+)\s*</Version>', PROJECT.read_text(encoding='utf-8'))
assert _match, 'No <Version> in windows/ACPScanner.csproj'
VERSION = _match.group(1)
REPOSITORY = 'cstrikelonghorn/LongHorn-ACS'
BASE = 'https://github.com/' + REPOSITORY
TAG = 'v' + VERSION
ASSET = f'ACS-Scanner-{VERSION}-windows.exe'
TODAY = datetime.now(timezone.utc).strftime('%Y-%m-%d')

# Developer-run results for this build. Update them when the release is rebuilt.
VALIDATION = {
    'build': 'Succeeded; 0 errors, 130 compiler warnings',
    'desktop': '54 passed; system probes also run as a 32-bit process on 64-bit Windows (10 passed)',
    'backend': '8 suites passed; 133 assertions',
    'feed': '5 tests passed',
}

assert SOURCE_EXE.is_file(), f'Publish the app first: {SOURCE_EXE} not found'
for folder in [REPO / 'docs/assets', ARTIFACTS]:
    folder.mkdir(parents=True, exist_ok=True)


def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.strip() + '\n', encoding='utf-8')


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


# ── .NET runtime licenses ─────────────────────────────────────────────────────
# The runtime is bundled inside the single executable, so its license and third-party notices
# are published beside it as separate files, taken from the exact runtime packs the build used.
deps_file = ROOT / 'windows/obj/Release/net10.0-windows/win-x86/ACPScanner.deps.json'
assert deps_file.is_file(), 'Build output missing; run the Release publish first'
deps = json.loads(deps_file.read_text(encoding='utf-8-sig'))
nuget = Path(os.environ.get('NUGET_PACKAGES') or Path.home() / '.nuget' / 'packages')
packs = {}
for library in deps.get('libraries', {}):
    name, _, version = library.partition('/')
    packs[name.removeprefix('runtimepack.').lower()] = version

LICENSE_SOURCES = [
    ('microsoft.netcore.app.runtime.win-x86', 'LICENSE.TXT', 'DOTNET-LICENSE.txt'),
    ('microsoft.netcore.app.runtime.win-x86', 'THIRD-PARTY-NOTICES.TXT', 'DOTNET-NOTICES.txt'),
    ('microsoft.windowsdesktop.app.runtime.win-x86', 'LICENSE', 'WINDOWSDESKTOP-LICENSE.txt'),
]

# Clear the previous release first - including any archive from an earlier version - so the
# folder only ever holds what this version publishes.
for old in ARTIFACTS.iterdir():
    if old.is_file():
        old.unlink()

licenses = []
for pack, source, target in LICENSE_SOURCES:
    path = nuget / pack / packs.get(pack, '') / source
    if pack in packs and path.is_file():
        shutil.copyfile(path, ARTIFACTS / target)
        licenses.append(target)
assert {'DOTNET-LICENSE.txt', 'DOTNET-NOTICES.txt'} <= set(licenses), 'Runtime license files not found in the NuGet cache'

# ── Release files ─────────────────────────────────────────────────────────────
shutil.copyfile(SOURCE_EXE, ARTIFACTS / ASSET)
release_files = [ASSET] + sorted(licenses)
sha = digest(ARTIFACTS / ASSET)
size = (ARTIFACTS / ASSET).stat().st_size

privacy = f'''# ACS privacy and data access

Applies to ACS {VERSION}. Updated {TODAY}.

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
'''

verify = f'''# Verify ACS {VERSION}

Download only from [{REPOSITORY} Releases]({BASE}/releases). The release file is the single executable `{ASSET}`. The public repository contains release documentation; the scanner source remains private.

## Verify the exact file

Download `CHECKSUMS.sha256` from the same tagged release and compare:

```powershell
Get-FileHash .\\{ASSET} -Algorithm SHA256
```

Expected SHA-256: `{sha}`

`FILE-MANIFEST.json` lists every release file with its size and hash. A matching checksum detects differences from the published file; it does not prove safety or protect you if the publisher's release account is compromised.

Every report ACS uploads records the first 12 characters of this SHA-256 as its build fingerprint (`{sha[:12]}` for this release), so a report can always be traced to the exact executable that produced it.

## Publisher signature

```powershell
Get-AuthenticodeSignature .\\{ASSET}
```

**This release is unsigned.** Expected status: `NotSigned`. No trusted publisher certificate was available during preparation. Signing and timestamping must occur before generating a future release's final checksums.

Windows reputation warnings may occur. Do not disable antivirus, SmartScreen, or other protections to use this app. A signed release would identify its publisher and protect signed-file integrity; signing alone is not a safety certification.

## Independent review and antivirus status

No independent security audit or verified antivirus analysis of this exact release has been completed. Automated regression tests are developer checks, not a malware scan. No simulated vendor results or clean certificates are published.

Standard online malware-scanning submissions may share uploaded files with security partners. Submit only the distributable release file, never settings containing secrets or player reports. Interpret detections individually; zero detections does not prove absence of abusive behavior.

References: [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases), [Microsoft signing and reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation), [Microsoft software submissions](https://www.microsoft.com/en-us/wdsi/filesubmission).
'''

security = f'''# Security reporting

ACS {VERSION}. Independent audit, publisher signing, adversarial testing, and a full live-client compatibility matrix remain outstanding.

If the repository's Security tab offers **Report a vulnerability**, use it for private reports. Otherwise open a minimal issue requesting a private contact channel, without exploit details, credentials, player identifiers, private report links, or attachments containing personal data.

Include the version and SHA-256, expected and observed behavior, and a minimal reproduction using synthetic data. Do not test against other players or third-party servers without their permission. No bug-bounty payment or response-time commitment is offered here.

Security properties have limits: the client runs on a player-controlled machine; a shared client token is not hardware attestation; a report is produced by the client and can be forged by someone who reverse engineers it; code secrecy does not prevent reverse engineering. Server administrators must protect secrets, authenticated access, report retention and storage outside the public web root.

Maintainer: [{REPOSITORY.split('/')[0]}](https://github.com/{REPOSITORY.split('/')[0]}).
'''

notes = f'''# ACS {VERSION}

Windows 10 and 11, 32-bit and 64-bit. One portable executable with the .NET runtime built in — no installer, no extra files. Runs as administrator. Requires a running compatible Counter-Strike 1.6/GoldSrc client and an operator-provided report server configuration. No endpoint or secret is bundled.

- **Single executable.** The whole app, including its artwork, is `{ASSET}`.
- **Client identity from signatures.** Retail Steam is reported only when the launcher and engine are validly signed by Valve and no emulator loads Steam from the game folder. Non-Steam editions are named from load paths and markers, and the engine build date is read from the engine binary.
- **Modified is not forged.** A Valve-signed file changed after signing (how non-Steam editions patch the engine) is recorded with its hash instead of being reported as a forged signature. A certificate that does not chain to a trusted root is still reported as forged.
- **Stricter module trust.** A module's name alone no longer earns trust; it must be part of the game install or validly signed by a trusted publisher.
- **Automatic upload after consent.** The privacy screen before a scan states that the report uploads when the scan finishes; there is no second prompt.
- **Build fingerprint.** Each report records the SHA-256 prefix of the executable that produced it.
- Redesigned desktop interface and evidence log.

Client profiles include Steam/non-Steam distributions, NextClient, GoldClient, GSClient, RevEmu and server-platform components. Profile recognition is not a compatibility certification for every build. The desktop scans on demand. Continuous gameplay behavior analysis requires the separately deployed server plugin, which is not included.

Known limitations: unsigned executable; no independent audit; no verified antivirus report for this exact release; compiler warnings remain; no measured real-world false-positive/recall benchmark; operator-managed data retention. This release does not claim superiority to VAC, WarGods or ECD, detection of every cheat, or immunity to bypass.

See `VALIDATION.md`, `PRIVACY.md`, and `VERIFY.md` for evidence and limitations.
'''

validation = f'''# Developer validation — {VERSION}

Performed locally on 64-bit Windows, {TODAY}, including the scanner's system probes run as a 32-bit process. These are maintainer-run checks, not an independent audit or malware certification.

| Check | Result |
| --- | --- |
| Self-contained single-file 32-bit Release publish (runs on 32-bit and 64-bit Windows) | {VALIDATION['build']} |
| Desktop regression checks | {VALIDATION['desktop']} |
| Backend regression suites | {VALIDATION['backend']} |
| Signature-feed validation | {VALIDATION['feed']} |

Desktop checks cover ordinary binds versus recursive scripts, disguised executable configs, informational severity, verified file hashes versus hash-looking filenames, HTTPS requirements, cancellation, file-budget coverage, upload consent failing closed, the privacy notice, signature classification (modified versus forged), module trust by install location, and client identity from Authenticode signatures and Steam DLL load paths.

Backend checks cover identity/risk handling, compatibility-profile boundaries, signed report ingestion and server-side recomputation, report access controls, indexing, release reputation, and the report page using the scanner's signature-verified client verdict.

Client identity was additionally checked against two real installations on the development machine: a retail Steam Half-Life (verified Steam; Valve-signed launcher and engine) and a non-Steam ESK edition (identified as non-Steam; engine carries Valve's signature over modified contents).

Compiler warnings remain, chiefly nullable reference analysis and native structure fields. The executable is unsigned.

## Limits

This release has no demonstrated real-world detection-rate, false-positive-rate, or scan-speed benchmark across the claimed client families. Passing synthetic compatibility tests is not a certification for every client build. No claim of superiority to VAC, WarGods, or other products is established.

The executable has no configured report API. GitHub hosts downloads and documentation, not the report backend. An operator must deploy and configure that separately before players can scan.

Private source and test fixtures remain outside this repository. Public readers cannot independently reproduce those source-level tests from this distribution repository alone.
'''

readme = f'''# LongHorn ACS

Counter-Strike 1.6 / GoldSrc anti-cheat evidence scanner for Windows.

**Public distribution and transparency repository.** Scanner source, detection databases, server code, credentials and player reports are not published here. This repository is not an open-source release of the scanner.

## Release

Version **{VERSION}** — one portable Windows executable for 32-bit and 64-bit Windows 10/11. The app is **unsigned** and **not independently audited**. No verified antivirus analysis for this exact build is claimed. A GitHub download or matching checksum is not a guarantee of safety.

[Download {VERSION}]({BASE}/releases/tag/{TAG}) · [Verification](VERIFY.md) · [Data access and privacy](PRIVACY.md) · [Security reporting](SECURITY.md) · [Release notes](RELEASE_NOTES.md)

## Start

1. Download `{ASSET}` from the tagged release and compare its SHA-256 with `CHECKSUMS.sha256`.
2. Get `acp-settings.json` from your trusted server operator. Place it next to the executable, or in `%APPDATA%\\LongHorn ACS\\`. The executable itself contains no server address.
3. Start Counter-Strike, then run the executable.
4. Read the screen shown before scanning. It names the report destination and what is collected. **The report uploads automatically when the scan finishes** — choose **Cancel** there if you do not want it sent.

Review `PRIVACY.md` for the data collected and operator-controlled retention.

## What the evidence means

ACS inventories game artifacts and reviews code changes, signatures, scripts and suspicious signals. Warnings require interpretation. A scan with no findings does not prove that a device or player is cheat-free. The app is not affiliated with or endorsed by Valve, GitHub, or Microsoft.

## What is public

The website, documentation, per-release checksums, file manifest, dependency inventory, and the release executable with its runtime license notices. The optional server plugin and driver scaffold are not bundled. Only sanitized synthetic examples belong in public issues.

## Website

Static HTML is in `docs/`. GitHub Pages can publish `main:/docs`. It contains no PHP API or report collection endpoint.
'''

usage = f'''# Distribution and usage notice

ACS application source is not included in this distribution. No open-source license for the ACS application is granted by publishing this repository. Contact the maintainer for redistribution or commercial licensing terms.

Third-party components retain their respective licenses. The Microsoft .NET runtime is built into `{ASSET}`; its license and third-party notices are published with each release as {", ".join(f"`{n}`" for n in sorted(licenses))}. This notice does not replace those licenses or claim ownership of third-party trademarks. See `ASSET-NOTICES.md` for artwork status.

Use only on computers and game environments where you have authorization. Review findings before any enforcement decision.
'''

if (ROOT / 'README.md').is_file():
    shutil.copyfile(ROOT / 'README.md', REPO / 'README.md')
else:
    write(REPO / 'README.md', readme)

for name, content in [('PRIVACY.md', privacy), ('VERIFY.md', verify), ('SECURITY.md', security),
                      ('RELEASE_NOTES.md', notes), ('DISTRIBUTION.md', usage), ('VALIDATION.md', validation)]:
    write(REPO / name, content)
write(REPO / '.gitignore', '*.exe\n*.dll\n*.pdb\n*.zip\n*.sqlite*\n.env*\nacp-settings.json\n')
write(REPO / '.github/ISSUE_TEMPLATE/config.yml', f'blank_issues_enabled: true\ncontact_links:\n  - name: Read security reporting instructions\n    url: {BASE}/blob/main/SECURITY.md\n    about: Do not publish credentials or player reports in issues.')
write(REPO / '.github/ISSUE_TEMPLATE/bug_report.md', '''---
name: Bug report
about: Report a problem using synthetic data only
title: "[Bug] "
labels: ""
assignees: ""
---

Version, downloaded file SHA-256, and the build fingerprint shown on your report:

Windows version and game/client build:

Steps to reproduce:

Expected / actual behavior:

Do not attach raw player reports, private paths, identifiers, passwords or API tokens.
''')

manifest = {'version': VERSION, 'files': [{'path': n, 'sha256': digest(ARTIFACTS / n), 'bytes': (ARTIFACTS / n).stat().st_size} for n in release_files]}
write(ARTIFACTS / 'FILE-MANIFEST.json', json.dumps(manifest, indent=2))
write(ARTIFACTS / 'CHECKSUMS.sha256', '\n'.join(f'{digest(ARTIFACTS / n)}  {n}' for n in release_files))
inventory = {'scope': 'Dependency inventory derived from .NET publish output; not an independent vulnerability scan',
             'libraries': [{'name': name, 'type': value.get('type')} for name, value in deps.get('libraries', {}).items()]}
write(ARTIFACTS / 'DEPENDENCIES.json', json.dumps(inventory, indent=2))
for name in ['CHECKSUMS.sha256', 'FILE-MANIFEST.json', 'DEPENDENCIES.json'] + licenses:
    shutil.copyfile(ARTIFACTS / name, REPO / name)

release = {'version': VERSION, 'tag': TAG, 'repository': REPOSITORY, 'asset': ASSET, 'assets': release_files,
           'sha256': sha, 'sizeBytes': size, 'buildFingerprint': sha[:12], 'prerelease': False,
           'publisherSigning': 'not-signed', 'independentAudit': 'not-performed', 'antivirusAnalysis': 'not-verified',
           'preparedAt': datetime.now(timezone.utc).isoformat()}
write(REPO / 'release.json', json.dumps(release, indent=2))

write(REPO / 'docs/.nojekyll', '')
for name in ['PRIVACY', 'VERIFY', 'SECURITY', 'RELEASE_NOTES', 'DISTRIBUTION', 'VALIDATION']:
    shutil.copyfile(REPO / (name + '.md'), REPO / 'docs' / (name + '.md'))

write(REPO / 'docs/index.html', f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="LongHorn ACS for Counter-Strike 1.6. Download information, exact release hashes, data access, and honest security status.">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self'; img-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>LongHorn ACS — Evidence you can review</title><link rel="stylesheet" href="assets/site.css"></head>
<body><a class="skip" href="#main">Skip to content</a><header><a class="brand" href="#">ACS <span>BY LONGHORN</span></a><nav aria-label="Main"><a href="#release">Release</a><a href="#privacy">Privacy</a><a href="#verification">Verification</a><a href="{BASE}">GitHub ↗</a></nav></header>
<main id="main"><section class="hero"><div><p class="eyebrow">COUNTER-STRIKE 1.6 / GOLDSRC</p><h1>Play the match.<br><em>Review the evidence.</em></h1><p class="lede">An on-demand Windows scanner for game integrity, suspicious scripts and client evidence. See exactly what it accesses before you start a scan.</p><div class="actions"><a class="button" href="{BASE}/releases/tag/{TAG}">Download {VERSION} ↗</a><a href="#privacy">Understand data access →</a></div><p class="small">Windows 10/11 · 32-bit and 64-bit · One executable · Operator configuration required</p></div><figure><img src="assets/app.png" width="1000" height="625" alt="ACS desktop ready screen with Start scan, Cancel and View evidence buttons"><figcaption>Desktop interface, before a scan. No player data shown.</figcaption></figure></section>
<section class="trust" aria-label="Current review status"><div><span>APPLICATION SIGNING</span><strong>Unsigned</strong></div><div><span>INDEPENDENT AUDIT</span><strong>Not performed</strong></div><div><span>ANTIVIRUS ANALYSIS</span><strong>Not verified</strong></div><div><span>DATA TRANSMISSION</span><strong>Automatic after consent</strong></div></section>
<section id="release"><p class="eyebrow">01 / RELEASE DETAILS</p><h2>A download you can identify.</h2><p>ACS {VERSION} is a single portable executable. The source remains private. The checksum below identifies this exact file; it does not certify that software is safe.</p><div class="release"><div><span class="small">EXECUTABLE</span><h3>{ASSET}</h3><p>{size / 1024 / 1024:.1f} MB · Windows 10/11 · 32-bit and 64-bit</p></div><div><span class="small">SHA-256</span><code class="hash">{sha}</code><a href="{BASE}/blob/main/FILE-MANIFEST.json">Inspect the file manifest →</a></div></div><p><a href="{BASE}/blob/main/RELEASE_NOTES.md">Release notes</a> · <a href="{BASE}/blob/main/VALIDATION.md">Developer validation</a> · <a href="{BASE}/blob/main/DEPENDENCIES.json">Dependency inventory</a></p></section>
<section id="privacy"><p class="eyebrow">02 / YOUR DATA, YOUR DECISION</p><h2>Know what a scan can see.</h2><div class="grid"><article><span class="step">01</span><h3>Read before you scan.</h3><p>Before each scan, ACS shows the configured server and explains access to processes, modules, drivers, game files, memory evidence and activity traces.</p></article><article><span class="step">02</span><h3>Know what is sent.</h3><p>Reports can contain player and device identifiers, paths, hashes, signature status, memory strings, game/server information, findings and timing.</p></article><article><span class="step">03</span><h3>Decide before it starts.</h3><p>The report uploads automatically when the scan finishes. Choose Cancel on the screen before scanning if you do not want it sent — there is no second prompt.</p></article></div><div class="notice"><strong>Server access and retention are operator-controlled.</strong><p>Records may remain until the operator deletes them. Ask about private access, retention and deletion before scanning. The executable includes no endpoint or API secret.</p><a href="{BASE}/blob/main/PRIVACY.md">Read the complete data-access notice →</a></div></section>
<section id="verification"><p class="eyebrow">03 / EVIDENCE, WITH LIMITS</p><h2>Check the file. Check the claims.</h2><div class="grid two"><article><h3>Verify your download</h3><p>Compare the downloaded executable with the published checksum, and check its Windows signature. This release is unsigned.</p><pre><code>Get-FileHash .\\{ASSET}
Get-AuthenticodeSignature .\\{ASSET}</code></pre><a href="{BASE}/blob/main/VERIFY.md">Full verification instructions →</a></article><article><h3>What we have not established</h3><p>No independent audit, verified antivirus verdict, or real-world detection-rate benchmark is claimed. Tests exercise selected behaviors; they are not a malware certification. ACS does not claim to detect every cheat or prevent every bypass.</p><p>Keep Windows and antivirus protections enabled. Review unexpected warnings and use software only when you trust its source and operator.</p><a href="{BASE}/blob/main/SECURITY.md">Report a security concern →</a></article></div></section>
<section id="questions"><p class="eyebrow">04 / COMMON QUESTIONS</p><h2>Before you start.</h2><details><summary>Why is the scanner source private?</summary><p>The maintainer distributes compiled releases while keeping detection implementation private. Public documentation describes data access and limitations. Private source does not prevent reverse engineering, and is not proof of safety.</p></details><details><summary>Does it run continuously or install a driver?</summary><p>No. ACS is a single on-demand executable. It installs no background service or driver. Continuous server gameplay analysis is a separate deployment.</p></details><details><summary>Does a clean scan prove someone is not cheating?</summary><p>No. A scan is a bounded observation. Unknown cheats, unavailable inspection surfaces and evasion can affect results. Warnings and detections need review before enforcement.</p></details><details><summary>Where do I get the report server settings?</summary><p>Ask your game-server operator for their <code>acp-settings.json</code> and place it next to the executable or in <code>%APPDATA%\\LongHorn ACS\\</code>. GitHub Pages hosts this information site, not the report API.</p></details><details><summary>Is this endorsed by Valve, Microsoft or GitHub?</summary><p>No. Counter-Strike and other product names identify compatibility targets. Hosting on GitHub and bundling Microsoft runtime files do not imply endorsement.</p></details></section>
</main><footer><span>LONGHORN ACS · {VERSION}</span><a href="{BASE}/blob/main/DISTRIBUTION.md">Distribution notice</a><a href="{BASE}/issues">Support</a><span>No analytics scripts on this site</span></footer></body></html>''')

write(REPO / 'docs/assets/site.css', '''*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:90px}body{margin:0;background:#0d1115;color:#edf0f2;font:15px/1.7 "Segoe UI",Arial,sans-serif}a{color:#f0b455;text-decoration:none}a:hover{text-decoration:underline}a:focus-visible,summary:focus-visible{outline:2px solid #f0b455;outline-offset:5px}.skip{position:absolute;top:-50px;background:#111;padding:10px}.skip:focus{top:0;z-index:9}header,main,footer{max-width:1280px;margin:auto}header{display:flex;justify-content:space-between;align-items:center;padding:24px 32px;border-bottom:1px solid #2c343c}.brand{font-size:27px;font-weight:800;letter-spacing:2px}.brand span{font-size:10px;letter-spacing:1px;color:#aeb9c2;margin-left:14px}nav{display:flex;gap:25px;font-size:13px}main{padding:0 32px}.hero{display:grid;grid-template-columns:1fr 1.1fr;align-items:center;gap:42px;padding:74px 0 52px}.eyebrow{font:700 11px/1.5 Consolas,monospace;letter-spacing:2px;color:#f0b455;margin:0 0 20px}h1{font-size:clamp(38px,4.2vw,57px);line-height:1.08;letter-spacing:-1.7px;margin:0 0 24px}h1 em{color:#f0b455;font-style:normal}.lede{font-size:16px;color:#b7c3ce;max-width:470px}.actions{display:flex;gap:22px;align-items:center;flex-wrap:wrap;margin:28px 0 18px}.button{padding:12px 20px;background:#f0b455;color:#111;font-weight:700;border-radius:3px}.button:hover{background:#ffd18b;text-decoration:none}.small{font:11px/1.6 Consolas,monospace;color:#aab7c2}figure{margin:0}figure img{display:block;width:100%;height:auto;border:1px solid #3c4145;border-radius:5px;box-shadow:0 22px 60px #0008}figcaption{font-size:11px;color:#aab7c2;margin-top:10px}.trust{display:grid;grid-template-columns:repeat(4,1fr);border:1px solid #3a4148;background:#151b20}.trust div{padding:20px;border-right:1px solid #303840}.trust div:last-child{border:0}.trust span{display:block;font:10px Consolas,monospace;letter-spacing:1px;color:#aab7c2}.trust strong{display:block;margin-top:8px;font-size:16px}section[id]{padding:62px 0;border-bottom:1px solid #293139}h2{font-size:32px;letter-spacing:-.8px;margin:0 0 14px}h3{font-size:18px;margin:12px 0}section[id]>p:not(.eyebrow){color:#b7c3ce;max-width:850px}.release{display:grid;grid-template-columns:1fr 1.2fr;gap:26px;padding:28px;background:#171e25;border-left:3px solid #f0b455;margin:25px 0}.release h3{font:13px/1.6 Consolas,monospace;overflow-wrap:anywhere}.hash{display:block;overflow-wrap:anywhere;color:#f5d19c;background:#0d1216;padding:14px;margin:10px 0;font-size:12px}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin-top:25px}.grid.two{grid-template-columns:repeat(2,1fr)}article{background:#151b20;border:1px solid #2c363f;padding:25px}article p{font-size:14px;color:#b7c3ce}.step{font:24px Consolas,monospace;color:#f0b455}.notice{background:#241f16;border-left:3px solid #f0b455;margin-top:22px;padding:22px 26px}.notice p{color:#c7bdaa}pre{background:#0d1115;border:1px solid #303840;padding:16px;overflow:auto;font-size:11px;line-height:2}details{border-bottom:1px solid #2c343c;padding:20px 0}summary{cursor:pointer;font-weight:600}details p{color:#b7c3ce;max-width:850px}footer{padding:30px 32px;display:flex;flex-wrap:wrap;gap:24px;font-size:11px;color:#aab7c2}footer span:last-child{margin-left:auto}@media(max-width:900px){.hero{grid-template-columns:1fr;padding-top:45px;gap:30px}.hero figure{max-width:740px}.trust{grid-template-columns:1fr 1fr}.grid,.grid.two{grid-template-columns:1fr}.release{grid-template-columns:1fr}header{align-items:flex-start;gap:20px;flex-wrap:wrap}nav{gap:18px}}@media(max-width:520px){header,main,footer{padding-left:20px;padding-right:20px}h1{font-size:39px}.trust div{padding:14px}.trust strong{font-size:14px}nav{font-size:12px}h2{font-size:28px}section[id]{padding:42px 0}}@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}*{animation:none!important;transition:none!important}}''')

print(json.dumps({'version': VERSION, 'tag': TAG, 'asset': str(ARTIFACTS / ASSET), 'sha256': sha,
                  'releaseFiles': release_files, 'bytes': size}, indent=2))

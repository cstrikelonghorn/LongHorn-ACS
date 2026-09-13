"""Build a deliberately separated public repository and distribution archive.
Run from the project root after publishing to publication/staging/ACS-Scanner.
Never copy the project root into the public repository.
"""
from pathlib import Path
import hashlib, json, shutil, zipfile, html
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
PUB = ROOT / 'publication'
if (PUB / 'PRIVATE_REVIEW').exists():
    raise SystemExit('Public release preparation is paused for private review. Use design_review_site.py for the review website; do not overwrite the frozen release archive.')
REPO = PUB / 'public-repo'
STAGE = PUB / 'staging' / 'ACS-Scanner'
ARTIFACTS = PUB / 'artifacts'
VERSION = '3.3.1-beta.1'
REPOSITORY = 'cstrikelonghorn/LongHorn-ACS'
BASE = 'https://github.com/' + REPOSITORY
TAG = 'v' + VERSION
ZIP_NAME = f'ACS-Scanner-{VERSION}-win-x64.zip'
for folder in [REPO / 'docs/assets', ARTIFACTS]: folder.mkdir(parents=True, exist_ok=True)

def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.strip() + '\n', encoding='utf-8')

privacy = '''# ACS privacy and data access

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
'''
verify = f'''# Verify ACS {VERSION}

Download only from [{REPOSITORY} Releases]({BASE}/releases). The ZIP filename is `{ZIP_NAME}`. The public repository contains release documentation; the scanner source remains private.

## Verify the exact file

Download `CHECKSUMS.sha256` from the same tagged release and compare the ZIP hash:

```powershell
Get-FileHash .\\{ZIP_NAME} -Algorithm SHA256
```

After extraction, compare `ACPScanner.exe` and `ACPScanner.dll` with the published checksums. `FILE-MANIFEST.json` lists hashes for all packaged files. A matching checksum detects differences from the published file; it does not prove safety or protect you if the publisher's release account is compromised.

## Publisher signature

```powershell
Get-AuthenticodeSignature .\\ACS-Scanner\\ACPScanner.exe
Get-AuthenticodeSignature .\\ACS-Scanner\\ACPScanner.dll
```

**This beta is unsigned.** Expected status for the app's own EXE and DLL: `NotSigned`. No trusted publisher certificate was available during preparation. Some bundled Microsoft runtime files have their own signatures; those do not sign ACS. Signing and timestamping must occur before generating a future release's final checksums.

Windows reputation warnings may occur. Do not disable antivirus, SmartScreen, or other protections to use this app. A signed release would identify its publisher and protect signed-file integrity; signing alone is not a safety certification.

## Independent review and antivirus status

No independent security audit or verified antivirus analysis of this exact release has been completed. Automated regression tests are developer checks, not a malware scan. No simulated vendor results or clean certificates are published. Reviewers can request confidential access through the maintainer's GitHub profile; no review or NDA has been represented as completed.

Standard online malware-scanning submissions may share uploaded files with security partners. Submit only a distributable release file, never settings containing secrets or player reports. Interpret detections individually; zero detections does not prove absence of abusive behavior.

References: [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases), [Microsoft signing and reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation), [Microsoft software submissions](https://www.microsoft.com/en-us/wdsi/filesubmission).
'''
security = f'''# Security reporting

This is a prerelease. Independent audit, publisher signing, adversarial testing, and a full live-client compatibility matrix remain outstanding.

If the repository's Security tab offers **Report a vulnerability**, use it for private reports. Private vulnerability reporting must be enabled by the repository owner; do not assume it is enabled. Otherwise open a minimal issue requesting a private contact channel, without exploit details, credentials, player identifiers, private report links, or attachments containing personal data.

Include the version and SHA-256, expected and observed behavior, and a minimal reproduction using synthetic data. Do not test against other players or third-party servers without their permission. No bug-bounty payment or response-time commitment is offered here.

Security properties have limits: the client runs on a player-controlled machine; a shared client token is not hardware attestation; code secrecy does not prevent reverse engineering. Server administrators must protect secrets, authenticated access, report retention and storage outside the public web root.

Maintainer: [{REPOSITORY.split('/')[0]}](https://github.com/{REPOSITORY.split('/')[0]}).
'''
notes = f'''# ACS {VERSION} — transparency beta

Windows x64 portable build, bundled .NET runtime. Requires a running compatible Counter-Strike 1.6/GoldSrc client and an operator-provided report API configuration. No production endpoint or secret is bundled.

- Added a per-scan privacy disclosure showing the actual report destination.
- Added complete JSON report review before upload. Declining or closing the preview prevents report upload.
- Changed missing upload approval to fail closed.
- Added an explicit message when no server is configured.
- Preserved the desktop gaming interface and the existing web dashboard styles.
- Corrected the local download page's reputation logic: missing analysis is unverified; suspicious results count as flags; invented vendor/sandbox results and safety claims were removed.

Client profiles include Steam/non-Steam distributions, NextClient, GoldClient, GSClient, RevEmu and server-platform components. Profile recognition is not a compatibility certification for every build. The desktop scans on demand. Continuous gameplay behavior analysis requires the separately deployed server plugin, which is not included in this public package.

Known limitations: unsigned application binaries; no independent audit; no verified antivirus report for this exact release; compiler warnings remain; no measured real-world false-positive/recall benchmark; operator-managed data retention. This release does not claim superiority to VAC, WarGods or ECD, detection of every cheat, or immunity to bypass.

See `VALIDATION.md`, `PRIVACY.md`, and `VERIFY.md` for evidence and limitations.
'''
readme = f'''# LongHorn ACS

Counter-Strike 1.6 / GoldSrc anti-cheat evidence scanner for Windows.

**Public distribution and transparency repository.** Scanner source, detection databases, server code, credentials and player reports are not published here. This repository is not an open-source release of the scanner.

![ACS desktop ready screen](docs/assets/app.png)

## Release status

Version **{VERSION}** is a transparency beta. The app is **unsigned** and **not independently audited**. No verified antivirus analysis for this exact build is claimed. A GitHub download or matching checksum is not a guarantee of safety.

[Download the tagged beta]({BASE}/releases/tag/{TAG}) · [Verification](VERIFY.md) · [Data access and privacy](PRIVACY.md) · [Security reporting](SECURITY.md) · [Release notes](RELEASE_NOTES.md)

## Start

1. Download `{ZIP_NAME}` from the tagged GitHub release and compare its SHA-256 with `CHECKSUMS.sha256`.
2. Extract the complete ZIP. Keep the executable, libraries, settings and Assets folder together.
3. Obtain a report API address from your trusted server operator. Set `apiUrl` in `acp-settings.json`; keep operator-issued credentials private. The public package has no configured endpoint.
4. Start Counter-Strike, open `ACPScanner.exe`, and read the disclosure before scanning.
5. Inspect the complete report preview. Choose **Upload this report** only if you accept sending it to the displayed operator. **Do not upload** closes the preview without transmitting the report.

The rule download itself contacts the configured server before report review. Review `PRIVACY.md` for the data collected and operator-controlled retention.

## What the evidence means

ACS inventories game artifacts and reviews code changes, scripts and suspicious signals. Warnings require interpretation. A scan with no findings does not prove that a device or player is cheat-free. The app is not affiliated with or endorsed by Valve, GitHub, or Microsoft.

## What is public

The website, documentation, per-release checksums, file manifest, dependency inventory, and release binaries. The optional server plugin and driver scaffold are not bundled. Only sanitized synthetic examples belong in public issues.

## Website

Static HTML is in `docs/`. GitHub Pages can publish `main:/docs`. It contains no PHP API or report collection endpoint. [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/creating-a-github-pages-site) cannot host the private PHP scanner backend.
'''
usage = '''# Distribution and usage notice

ACS application source is not included in this distribution. No open-source license for the ACS application is granted by publishing this repository. Contact the maintainer for redistribution or commercial licensing terms.

Third-party components retain their respective licenses. The bundled .NET runtime license and third-party notices are included as DOTNET-LICENSE.txt and DOTNET-NOTICES.txt. This notice does not replace those licenses or claim ownership of third-party trademarks.

Use only on computers and game environments where you have authorization. Review findings before any enforcement decision.
'''
for name,content in [('README.md',readme),('PRIVACY.md',privacy),('VERIFY.md',verify),('SECURITY.md',security),('RELEASE_NOTES.md',notes),('DISTRIBUTION.md',usage)]: write(REPO/name,content)
write(REPO/'.gitignore','*.exe\n*.dll\n*.pdb\n*.zip\n*.sqlite*\n.env*\nacp-settings.json\n')
write(REPO/'.github/ISSUE_TEMPLATE/config.yml',f'blank_issues_enabled: true\ncontact_links:\n  - name: Read security reporting instructions\n    url: {BASE}/blob/main/SECURITY.md\n    about: Do not publish credentials or player reports in issues.')
write(REPO/'.github/ISSUE_TEMPLATE/bug_report.md','''---
name: Bug report
about: Report a problem using synthetic data only
title: "[Bug] "
labels: ""
assignees: ""
---

Version and downloaded file SHA-256:

Windows version and game/client build:

Steps to reproduce:

Expected / actual behavior:

Do not attach raw player reports, private paths, identifiers, passwords or API tokens.
''')
for name in ['PRIVACY.md','VERIFY.md','DISTRIBUTION.md','RELEASE_NOTES.md']:
    shutil.copyfile(REPO/name,STAGE/name)
# Explicit sanitization; never read or copy the development token to the public package.
write(STAGE/'acp-settings.json',json.dumps({'apiUrl':'','apiToken':''},indent=2))
allowed_json={'acp-settings.json','ACPScanner.deps.json','ACPScanner.runtimeconfig.json'}
files=[]
for f in sorted(STAGE.rglob('*')):
    if not f.is_file(): continue
    rel=f.relative_to(STAGE).as_posix()
    allowed=(len(f.relative_to(STAGE).parts)==1 and (f.suffix.lower() in {'.dll','.exe','.txt','.md'} or f.name in allowed_json)) or (rel.startswith('Assets/') and f.suffix.lower()=='.png')
    if not allowed: continue
    files.append((f,rel))
assert any(rel=='ACPScanner.exe' for _,rel in files)
assert all(f.suffix.lower() not in {'.cs','.pdb','.php','.sqlite','.ps1','.bat'} for f,_ in files)
def digest(p): return hashlib.file_digest(p.open('rb'),'sha256').hexdigest()
manifest={'version':VERSION,'files':[{'path':rel,'sha256':digest(f),'bytes':f.stat().st_size} for f,rel in files]}
write(ARTIFACTS/'FILE-MANIFEST.json',json.dumps(manifest,indent=2))
archive=ARTIFACTS/ZIP_NAME
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
    for f,rel in files: z.write(f,'ACS-Scanner/'+rel)
sha=digest(archive)
checks=[f'{sha}  {ZIP_NAME}',f'{digest(STAGE/"ACPScanner.exe")}  ACS-Scanner/ACPScanner.exe',f'{digest(STAGE/"ACPScanner.dll")}  ACS-Scanner/ACPScanner.dll']
write(ARTIFACTS/'CHECKSUMS.sha256','\n'.join(checks))
deps=json.loads((STAGE/'ACPScanner.deps.json').read_text(encoding='utf-8-sig'))
inventory={'scope':'Dependency inventory derived from .NET publish output; not an independent vulnerability scan','libraries':[{'name':name,'type':value.get('type')} for name,value in deps.get('libraries',{}).items()]}
write(ARTIFACTS/'DEPENDENCIES.json',json.dumps(inventory,indent=2))
for name in ['CHECKSUMS.sha256','FILE-MANIFEST.json','DEPENDENCIES.json']: shutil.copyfile(ARTIFACTS/name,REPO/name)
release={'version':VERSION,'tag':TAG,'repository':REPOSITORY,'asset':ZIP_NAME,'sha256':sha,'sizeBytes':archive.stat().st_size,'publisherSigning':'not-signed','independentAudit':'not-performed','antivirusAnalysis':'not-verified','preparedAt':datetime.now(timezone.utc).isoformat()}
write(REPO/'release.json',json.dumps(release,indent=2))
write(REPO/'docs/.nojekyll','')
for name in ['PRIVACY','VERIFY','SECURITY','RELEASE_NOTES','DISTRIBUTION','VALIDATION']:
    if (REPO/(name+'.md')).exists(): shutil.copyfile(REPO/(name+'.md'),REPO/'docs'/(name+'.md'))
write(REPO/'docs/index.html',f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="LongHorn ACS for Counter-Strike 1.6. Download information, exact release hashes, data access, and honest security status.">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self'; img-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>LongHorn ACS — Evidence you can review</title><link rel="stylesheet" href="assets/site.css"></head>
<body><a class="skip" href="#main">Skip to content</a><header><a class="brand" href="#">ACS <span>BY LONGHORN</span></a><nav aria-label="Main"><a href="#release">Release</a><a href="#privacy">Privacy</a><a href="#verification">Verification</a><a href="{BASE}">GitHub ↗</a></nav></header>
<main id="main"><section class="hero"><div><p class="eyebrow">COUNTER-STRIKE 1.6 / GOLDSRC</p><h1>Play the match.<br><em>Review the evidence.</em></h1><p class="lede">An on-demand Windows scanner for game integrity, suspicious scripts and client evidence. See what it accesses. Review your report before you send it.</p><div class="actions"><a class="button" href="{BASE}/releases/tag/{TAG}">View beta release ↗</a><a href="#privacy">Understand data access →</a></div><p class="small">Windows x64 · Runtime included · Operator configuration required</p></div><figure><img src="assets/app.png" width="1000" height="625" alt="ACS desktop ready screen with Start scan, Cancel and View evidence buttons"><figcaption>Actual desktop interface, before a scan. No player data shown.</figcaption></figure></section>
<section class="trust" aria-label="Current review status"><div><span>APPLICATION SIGNING</span><strong>Unsigned beta</strong></div><div><span>INDEPENDENT AUDIT</span><strong>Not performed</strong></div><div><span>ANTIVIRUS ANALYSIS</span><strong>Not verified</strong></div><div><span>DATA TRANSMISSION</span><strong>Review before upload</strong></div></section>
<section id="release"><p class="eyebrow">01 / RELEASE DETAILS</p><h2>A download you can identify.</h2><p>This is beta {VERSION}. The source remains private. The checksum below identifies this exact package; it does not certify that software is safe.</p><div class="release"><div><span class="small">PACKAGE</span><h3>{ZIP_NAME}</h3><p>{archive.stat().st_size/1024/1024:.1f} MB · Portable Windows x64</p></div><div><span class="small">SHA-256</span><code class="hash">{sha}</code><a href="{BASE}/blob/main/FILE-MANIFEST.json">Inspect the full file manifest →</a></div></div><p><a href="{BASE}/blob/main/RELEASE_NOTES.md">Release notes</a> · <a href="{BASE}/blob/main/VALIDATION.md">Developer validation</a> · <a href="{BASE}/blob/main/DEPENDENCIES.json">Dependency inventory</a></p></section>
<section id="privacy"><p class="eyebrow">02 / YOUR DATA, YOUR DECISION</p><h2>Know what a scan can see.</h2><div class="grid"><article><span class="step">01</span><h3>Read the disclosure.</h3><p>Before each scan, ACS shows the configured server and explains access to processes, modules, drivers, game files, memory evidence and activity traces.</p></article><article><span class="step">02</span><h3>Inspect the report.</h3><p>Reports can contain player and device identifiers, paths, hashes, memory strings, game/server information, findings and timing. The complete JSON is shown before upload.</p></article><article><span class="step">03</span><h3>Choose whether to send.</h3><p>Upload sends the report to the displayed operator. Declining keeps the report from being sent. The earlier rule download still exposes your IP address to that server.</p></article></div><div class="notice"><strong>Server access and retention are operator-controlled.</strong><p>Records may remain until the operator deletes them. Ask about private access, retention and deletion before scanning. The public beta includes no production endpoint or API secret.</p><a href="{BASE}/blob/main/PRIVACY.md">Read the complete data-access notice →</a></div></section>
<section id="verification"><p class="eyebrow">03 / EVIDENCE, WITH LIMITS</p><h2>Check the file. Check the claims.</h2><div class="grid two"><article><h3>Verify your download</h3><p>Compare the downloaded ZIP with the published checksum. Check the application's Windows signature separately. This beta is unsigned, even when Microsoft runtime files have their own signatures.</p><pre><code>Get-FileHash .\\{ZIP_NAME}
Get-AuthenticodeSignature .\\ACS-Scanner\\ACPScanner.exe</code></pre><a href="{BASE}/blob/main/VERIFY.md">Full verification instructions →</a></article><article><h3>What we have not established</h3><p>No independent audit, verified antivirus verdict, or real-world detection-rate benchmark is claimed. Tests exercise selected behaviors; they are not a malware certification. ACS does not claim to detect every cheat or prevent every bypass.</p><p>Keep Windows and antivirus protections enabled. Review unexpected warnings and use software only when you trust its source and operator.</p><a href="{BASE}/blob/main/SECURITY.md">Report a security concern →</a></article></div></section>
<section id="questions"><p class="eyebrow">04 / COMMON QUESTIONS</p><h2>Before you start.</h2><details><summary>Why is the scanner source private?</summary><p>The maintainer distributes compiled releases while keeping detection implementation private. Public documentation describes data access and limitations. Private source does not prevent reverse engineering, and is not proof of safety.</p></details><details><summary>Does it run continuously or install a driver?</summary><p>The public package is an on-demand desktop scanner. It does not include the optional server plugin or driver scaffold and installs no background service. Continuous server gameplay analysis is a separate deployment.</p></details><details><summary>Does a clean scan prove someone is not cheating?</summary><p>No. A scan is a bounded observation. Unknown cheats, unavailable inspection surfaces and evasion can affect results. Warnings and detections need review before enforcement.</p></details><details><summary>Where do I get the report server settings?</summary><p>Ask your game-server operator for their HTTPS API address and any required credential. The public package has an empty configuration. GitHub Pages hosts this information site, not the private report API.</p></details><details><summary>Is this endorsed by Valve, Microsoft or GitHub?</summary><p>No. Counter-Strike and other product names identify compatibility targets. Hosting on GitHub and bundling Microsoft runtime files do not imply endorsement.</p></details></section>
</main><footer><span>LONGHORN ACS · {VERSION}</span><a href="{BASE}/blob/main/DISTRIBUTION.md">Distribution notice</a><a href="{BASE}/issues">Support</a><span>No analytics scripts on this site</span></footer></body></html>''')
write(REPO/'docs/assets/site.css','''*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:90px}body{margin:0;background:#0d1115;color:#edf0f2;font:15px/1.7 "Segoe UI",Arial,sans-serif}a{color:#f0b455;text-decoration:none}a:hover{text-decoration:underline}a:focus-visible,summary:focus-visible{outline:2px solid #f0b455;outline-offset:5px}.skip{position:absolute;top:-50px;background:#111;padding:10px}.skip:focus{top:0;z-index:9}header,main,footer{max-width:1280px;margin:auto}header{display:flex;justify-content:space-between;align-items:center;padding:24px 32px;border-bottom:1px solid #2c343c}.brand{font-size:27px;font-weight:800;letter-spacing:2px}.brand span{font-size:10px;letter-spacing:1px;color:#aeb9c2;margin-left:14px}nav{display:flex;gap:25px;font-size:13px}main{padding:0 32px}.hero{display:grid;grid-template-columns:1fr 1.1fr;align-items:center;gap:42px;padding:74px 0 52px}.eyebrow{font:700 11px/1.5 Consolas,monospace;letter-spacing:2px;color:#f0b455;margin:0 0 20px}h1{font-size:clamp(38px,4.2vw,57px);line-height:1.08;letter-spacing:-1.7px;margin:0 0 24px}h1 em{color:#f0b455;font-style:normal}.lede{font-size:16px;color:#b7c3ce;max-width:470px}.actions{display:flex;gap:22px;align-items:center;flex-wrap:wrap;margin:28px 0 18px}.button{padding:12px 20px;background:#f0b455;color:#111;font-weight:700;border-radius:3px}.button:hover{background:#ffd18b;text-decoration:none}.small{font:11px/1.6 Consolas,monospace;color:#aab7c2}figure{margin:0}figure img{display:block;width:100%;height:auto;border:1px solid #3c4145;border-radius:5px;box-shadow:0 22px 60px #0008}figcaption{font-size:11px;color:#aab7c2;margin-top:10px}.trust{display:grid;grid-template-columns:repeat(4,1fr);border:1px solid #3a4148;background:#151b20}.trust div{padding:20px;border-right:1px solid #303840}.trust div:last-child{border:0}.trust span{display:block;font:10px Consolas,monospace;letter-spacing:1px;color:#aab7c2}.trust strong{display:block;margin-top:8px;font-size:16px}section[id]{padding:62px 0;border-bottom:1px solid #293139}h2{font-size:32px;letter-spacing:-.8px;margin:0 0 14px}h3{font-size:18px;margin:12px 0}section[id]>p:not(.eyebrow){color:#b7c3ce;max-width:850px}.release{display:grid;grid-template-columns:1fr 1.2fr;gap:26px;padding:28px;background:#171e25;border-left:3px solid #f0b455;margin:25px 0}.release h3{font:13px/1.6 Consolas,monospace;overflow-wrap:anywhere}.hash{display:block;overflow-wrap:anywhere;color:#f5d19c;background:#0d1216;padding:14px;margin:10px 0;font-size:12px}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin-top:25px}.grid.two{grid-template-columns:repeat(2,1fr)}article{background:#151b20;border:1px solid #2c363f;padding:25px}article p{font-size:14px;color:#b7c3ce}.step{font:24px Consolas,monospace;color:#f0b455}.notice{background:#241f16;border-left:3px solid #f0b455;margin-top:22px;padding:22px 26px}.notice p{color:#c7bdaa}pre{background:#0d1115;border:1px solid #303840;padding:16px;overflow:auto;font-size:11px;line-height:2}details{border-bottom:1px solid #2c343c;padding:20px 0}summary{cursor:pointer;font-weight:600}details p{color:#b7c3ce;max-width:850px}footer{padding:30px 32px;display:flex;flex-wrap:wrap;gap:24px;font-size:11px;color:#aab7c2}footer span:last-child{margin-left:auto}@media(max-width:900px){.hero{grid-template-columns:1fr;padding-top:45px;gap:30px}.hero figure{max-width:740px}.trust{grid-template-columns:1fr 1fr}.grid,.grid.two{grid-template-columns:1fr}.release{grid-template-columns:1fr}header{align-items:flex-start;gap:20px;flex-wrap:wrap}nav{gap:18px}}@media(max-width:520px){header,main,footer{padding-left:20px;padding-right:20px}h1{font-size:39px}.trust div{padding:14px}.trust strong{font-size:14px}nav{font-size:12px}h2{font-size:28px}section[id]{padding:42px 0}}@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}*{animation:none!important;transition:none!important}}''')
print(json.dumps({'publicRepository':str(REPO),'archive':str(archive),'sha256':sha,'packagedFiles':len(files),'bytes':archive.stat().st_size},indent=2))

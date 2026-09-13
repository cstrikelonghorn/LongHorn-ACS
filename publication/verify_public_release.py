"""Validate only the prepared distribution. Never print credential values. Changes nothing.

publish_release.py runs this first and stops if it fails. It confirms that what would be
uploaded is exactly what was prepared and is the version in the project file; that the
executable carries no private setting, local user path or source file; that the public
repository holds only documentation and website files; that every local website reference
resolves; and that no beta wording is left behind.
"""
import hashlib
import json
import os
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = BASE.parent
PUBLIC = BASE / 'public-repo'
ARTIFACTS = BASE / 'artifacts'
problems = []


def check(ok, message):
    print(('PASS ' if ok else 'FAIL ') + message)
    if not ok:
        problems.append(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


meta = json.loads((PUBLIC / 'release.json').read_text(encoding='utf-8'))
project = (ROOT / 'windows' / 'ACPScanner.csproj').read_text(encoding='utf-8')
version = re.search(r'<Version>\s*([0-9A-Za-z.+-]+)\s*</Version>', project).group(1)

# ── Private values that must never be published ───────────────────────────────
# The operator destination and scoped upload-access token may be intentional. They are public to
# every desktop user and grant no admin authority. Admin/report-attestation/telemetry credentials
# must never be embedded.
private_values = []
for settings in [ROOT / 'windows' / 'acp-settings.json',
                 Path(os.environ.get('APPDATA', '')) / 'LongHorn ACS' / 'acp-settings.json']:
    if not settings.is_file():
        continue
    for key, value in json.loads(settings.read_text(encoding='utf-8-sig')).items():
        sensitive = re.search(r'admin|telemetry|password|secret|private|signing', key, re.I)
        if sensitive and isinstance(value, str) and len(value) >= 8:
            private_values.extend([value.encode(), value.encode('utf-16le')])
user_path = [b'C:\\Users\\', 'C:\\Users\\'.encode('utf-16le')]

# ── Release files ─────────────────────────────────────────────────────────────
check(meta['version'] == version, f'release.json version matches the project ({version})')
check(meta['tag'] == 'v' + version, f'tag is v{version}')

assets = meta.get('assets', [meta['asset']])
manifest = json.loads((PUBLIC / 'FILE-MANIFEST.json').read_text(encoding='utf-8'))
check(manifest.get('version') == version, 'FILE-MANIFEST.json version matches')
listed = {f['path']: f for f in manifest.get('files', [])}
check(set(listed) == set(assets), 'manifest lists exactly the release files')

checksums = {}
for line in (PUBLIC / 'CHECKSUMS.sha256').read_text(encoding='utf-8').splitlines():
    if line.strip():
        value, name = line.split(None, 1)
        checksums[name.strip()] = value

forbidden_types = {'.cs', '.php', '.pdb', '.sqlite', '.sqlite3', '.db', '.ps1', '.py', '.bat', '.zip'}
for name in assets:
    path = ARTIFACTS / name
    if not path.is_file():
        check(False, f'release file present: {name}')
        continue
    data = path.read_bytes()
    digest = sha256(data)
    check(Path(name).suffix.lower() not in forbidden_types and '..' not in Path(name).parts, f'{name}: allowed file type')
    check(name in listed and listed[name]['bytes'] == len(data) and listed[name]['sha256'] == digest, f'{name}: manifest size and hash')
    check(checksums.get(name) == digest, f'{name}: CHECKSUMS.sha256 entry')
    check(all(v not in data for v in private_values), f'{name}: no private setting inside')
    check(all(p not in data for p in user_path), f'{name}: no local user path inside')

exe = ARTIFACTS / meta['asset']
if exe.is_file():
    data = exe.read_bytes()
    check(sha256(data) == meta['sha256'] and len(data) == meta['sizeBytes'], 'executable hash and size match release.json')
    source = ROOT / 'windows' / 'release' / 'ACPScanner.exe'
    check(source.is_file() and sha256(source.read_bytes()) == meta['sha256'], 'executable is the current windows/release build')


# ── Public repository ─────────────────────────────────────────────────────────
class Links(HTMLParser):
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        for key in ('src', 'href'):
            target = a.get(key, '')
            if target and not target.startswith(('https:', 'http:', '#', 'mailto:')):
                check((PUBLIC / 'docs' / target.split('#')[0]).is_file(), f'website reference resolves: {target}')
        if tag in {'script', 'iframe', 'form'}:
            check(False, f'unexpected active website content: <{tag}>')


Links().feed((PUBLIC / 'docs' / 'index.html').read_text(encoding='utf-8'))

allowed_types = {'.md', '.json', '.sha256', '.html', '.css', '.png', '.svg', '.yml', '.txt', ''}
stale = []
for path in PUBLIC.rglob('*'):
    if not path.is_file() or '.git' in path.relative_to(PUBLIC).parts:
        continue
    rel = path.relative_to(PUBLIC).as_posix()
    data = path.read_bytes()
    if path.suffix.lower() not in allowed_types or path.name == 'acp-settings.json':
        check(False, f'publication file type allowed: {rel}')
    if any(v in data for v in private_values):
        check(False, f'private setting in public repository: {rel}')
    if any(p in data for p in user_path):
        check(False, f'local user path in public repository: {rel}')
    if path.suffix.lower() in {'.md', '.html', '.json', '.yml'}:
        text = data.decode('utf-8', errors='ignore')
        if re.search(r'\bbeta\b', text, re.IGNORECASE) or '3.3.1' in text:
            stale.append(rel)
check(not stale, 'no beta or 3.3.1 wording left' + (': ' + ', '.join(stale) if stale else ''))

for name in ('README.md', 'PRIVACY.md', 'VERIFY.md', 'SECURITY.md', 'RELEASE_NOTES.md', 'VALIDATION.md', 'DISTRIBUTION.md'):
    check((PUBLIC / name).is_file(), f'public document present: {name}')

if problems:
    print(f'\n{len(problems)} problem(s). Do not publish.')
    sys.exit(1)
print('\nRelease verified.')

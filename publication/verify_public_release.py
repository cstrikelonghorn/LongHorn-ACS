"""Validate only the prepared distribution. Never print credential values."""
import hashlib
import json
import re
import zipfile
from html.parser import HTMLParser
from pathlib import Path

BASE = Path(__file__).resolve().parent
PUBLIC = BASE / 'public-repo'
meta = json.loads((PUBLIC / 'release.json').read_text())
archive = BASE / 'artifacts' / meta['asset']
assert hashlib.sha256(archive.read_bytes()).hexdigest() == meta['sha256']
assert archive.stat().st_size == meta['sizeBytes']
manifest = json.loads((PUBLIC / 'FILE-MANIFEST.json').read_text())['files']
private_values = []
settings = json.loads((BASE.parent / 'windows' / 'acp-settings.json').read_text(encoding='utf-8-sig'))
for key, value in settings.items():
    if re.search(r'token|secret|password|key', key, re.I) and isinstance(value, str) and len(value) >= 8:
        private_values.extend([value.encode(), value.encode('utf-16le')])
forbidden = {'.cs', '.php', '.pdb', '.sqlite', '.sqlite3', '.db', '.ps1', '.py', '.bat'}
with zipfile.ZipFile(archive) as z:
    names = z.namelist()
    assert len(names) == len(set(names)) == len(manifest)
    assert set(names) == {'ACS-Scanner/' + f['path'] for f in manifest}
    assert json.loads(z.read('ACS-Scanner/acp-settings.json')) == {'apiUrl': '', 'apiToken': ''}
    for f in manifest:
        path = Path(f['path'])
        assert not path.is_absolute() and '..' not in path.parts
        assert path.suffix.lower() not in forbidden
        data = z.read('ACS-Scanner/' + f['path'])
        assert len(data) == f['bytes'] and hashlib.sha256(data).hexdigest() == f['sha256']
        assert all(v not in data for v in private_values), 'Private setting found in package'
        assert b'C:\\Users\\' not in data and 'C:\\Users\\'.encode('utf-16le') not in data, 'Local user path in package'
print(f'PASS archive SHA-256, size and all {len(manifest)} file hashes')
print('PASS empty public endpoint/token; no private settings, debug symbols or source files in package')

class Links(HTMLParser):
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        for key in ('src', 'href'):
            target = a.get(key, '')
            if target and not target.startswith(('https:', 'http:', '#')):
                assert (PUBLIC / 'docs' / target.split('#')[0]).is_file(), target
        assert tag not in {'script', 'iframe', 'form'}, 'Unexpected active website content'

Links().feed((PUBLIC / 'docs' / 'index.html').read_text(encoding='utf-8'))
for path in PUBLIC.rglob('*'):
    if not path.is_file() or '.git' in path.relative_to(PUBLIC).parts:
        continue
    assert path.suffix.lower() in {'.md', '.json', '.sha256', '.html', '.css', '.png', '.yml', ''}
    data = path.read_bytes()
    assert all(v not in data for v in private_values), 'Private setting in public repository'
    assert b'C:\\Users\\' not in data, 'Local user path in public repository'
for name in ('README.md', 'PRIVACY.md', 'VERIFY.md', 'SECURITY.md', 'RELEASE_NOTES.md', 'VALIDATION.md', 'DISTRIBUTION.md'):
    assert (PUBLIC / name).is_file(), name
print('PASS public documentation, local website references and publication file types')

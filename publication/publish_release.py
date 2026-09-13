"""Publish the isolated public repository using the user's existing Git login.

No password or token is accepted on the command line or written to disk.
Run prepare_public_release.py and verify_public_release.py before publication.
"""
import hashlib
import json
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = Path(__file__).resolve().parent
PUBLIC = BASE / 'public-repo'
OWNER = 'cstrikelonghorn'
REPO = OWNER + '/LongHorn-ACS'
SITE = 'https://cstrikelonghorn.github.io/LongHorn-ACS/'


def credentials():
    p = subprocess.run(['git', 'credential', 'fill'],
        input=f'protocol=https\nhost=github.com\nusername={OWNER}\n\n',
        text=True, capture_output=True)
    if p.returncode:
        raise RuntimeError('Sign in locally through Git Credential Manager first.')
    values = dict(line.split('=', 1) for line in p.stdout.splitlines() if '=' in line)
    return values['password']


def api(path, method='GET', data=None, raw=None, content_type=None):
    url = path if path.startswith('https://') else 'https://api.github.com' + path
    assert urllib.parse.urlparse(url).hostname in {'api.github.com', 'uploads.github.com'}
    headers = {'Authorization': 'Bearer ' + TOKEN, 'Accept': 'application/vnd.github+json',
               'User-Agent': 'LongHorn-release-publisher', 'X-GitHub-Api-Version': '2022-11-28'}
    body = raw
    if data is not None:
        body = json.dumps(data).encode()
        headers['Content-Type'] = 'application/json'
    if content_type:
        headers['Content-Type'] = content_type
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=180) as response:
        payload = response.read()
        return json.loads(payload) if payload else None


def git(*args):
    return subprocess.run(['git', *args], cwd=PUBLIC, check=True, text=True, capture_output=True).stdout.strip()


def main():
    assert api('/user')['login'].lower() == OWNER, 'Wrong GitHub account; publication stopped'
    repo = api('/repos/' + REPO)
    assert repo['full_name'].lower() == REPO.lower() and not repo['private'] and repo['permissions']['push']
    if '--status' in sys.argv:
        for suffix in ('/pages', '/pages/builds/latest', '/releases/tags/v3.3.1-beta.1'):
            try:
                d = api('/repos/' + REPO + suffix)
                print(json.dumps({k: d[k] for k in ('status', 'html_url', 'source', 'https_enforced', 'draft', 'prerelease', 'error') if k in d}))
            except urllib.error.HTTPError as e:
                print(suffix, 'HTTP', e.code)
        return
    if '--publish' not in sys.argv:
        print('Authenticated as', OWNER, 'with access to', REPO)
        return

    subprocess.run([sys.executable, str(BASE / 'verify_public_release.py')], check=True)
    if not (PUBLIC / '.git').exists():
        assert repo['size'] == 0, 'Existing repository content requires review before initialization'
        git('init', '-b', 'main')
        git('config', 'user.name', 'LongHorn')
        git('config', 'user.email', 'cstrikelonghorn@users.noreply.github.com')
        git('config', 'core.autocrlf', 'false')
        git('remote', 'add', 'origin', 'https://cstrikelonghorn@github.com/' + REPO + '.git')
    assert git('rev-parse', '--show-toplevel').replace('\\', '/').lower() == PUBLIC.as_posix().lower()
    assert git('remote', 'get-url', 'origin') == 'https://cstrikelonghorn@github.com/' + REPO + '.git'
    files = sorted(p.relative_to(PUBLIC).as_posix() for p in PUBLIC.rglob('*')
                   if p.is_file() and '.git' not in p.relative_to(PUBLIC).parts)
    git('add', '--', *files)
    if git('diff', '--cached', '--name-only'):
        git('commit', '-m', 'Publish ACS beta distribution and transparency documentation')
    git('push', '-u', 'origin', 'main')
    print('Published public documentation commit', git('rev-parse', 'HEAD'), flush=True)

    meta = json.loads((PUBLIC / 'release.json').read_text())
    tag = meta['tag']
    try:
        release = api('/repos/' + REPO + '/releases/tags/' + tag)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
        release = api('/repos/' + REPO + '/releases', 'POST', {
            'tag_name': tag, 'target_commitish': git('rev-parse', 'HEAD'),
            'name': 'ACS 3.3.1-beta.1 — transparency beta', 'draft': True, 'prerelease': True,
            'body': (PUBLIC / 'RELEASE_NOTES.md').read_text(encoding='utf-8') +
                    '\n\nDownload the **ACS-Scanner-3.3.1-beta.1-win-x64.zip** asset below. '
                    'GitHub-generated Source code archives contain only this public documentation repository, not scanner source.\n\n'
                    'Package SHA-256: `' + meta['sha256'] + '`\n\n'
                    'See [verification instructions](https://github.com/' + REPO + '/blob/' + tag + '/VERIFY.md).'
        })
    assets = [BASE / 'artifacts' / meta['asset']] + [PUBLIC / n for n in
        ('CHECKSUMS.sha256', 'FILE-MANIFEST.json', 'DEPENDENCIES.json', 'release.json')]
    existing = {a['name']: a for a in release['assets']}
    for path in assets:
        content = path.read_bytes()
        digest = 'sha256:' + hashlib.sha256(content).hexdigest()
        if path.name in existing:
            assert existing[path.name].get('digest') == digest, 'Existing release asset differs; refusing to replace it'
            continue
        assert release['draft'], 'Refusing to modify a published release'
        upload = release['upload_url'].split('{')[0] + '?name=' + urllib.parse.quote(path.name)
        result = api(upload, 'POST', raw=content, content_type='application/zip' if path.suffix == '.zip' else 'application/octet-stream')
        assert result['size'] == len(content) and result.get('digest') == digest
        print('Uploaded and verified', path.name, flush=True)
    if release['draft']:
        release = api('/repos/' + REPO + '/releases/' + str(release['id']), 'PATCH', {'draft': False, 'prerelease': True, 'make_latest': 'false'})
    print('Published beta:', release['html_url'], flush=True)

    try:
        pages = api('/repos/' + REPO + '/pages')
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
        pages = api('/repos/' + REPO + '/pages', 'POST', {'build_type': 'legacy', 'source': {'branch': 'main', 'path': '/docs'}})
    assert pages['source'] == {'branch': 'main', 'path': '/docs'}, 'Review existing Pages configuration'
    if not pages.get('https_enforced'):
        api('/repos/' + REPO + '/pages', 'PUT', {'https_enforced': True})
    api('/repos/' + REPO, 'PATCH', {'description': 'Counter-Strike 1.6 / GoldSrc evidence scanner — public releases, privacy and verification documentation. Scanner source is private.', 'homepage': SITE})
    api('/repos/' + REPO + '/private-vulnerability-reporting', 'PUT')
    print('GitHub Pages configured:', pages['html_url'], flush=True)
    print('Private vulnerability reporting enabled.', flush=True)


if __name__ == '__main__':
    try:
        TOKEN = credentials()
        main()
    except urllib.error.HTTPError as e:
        print('GitHub request failed with HTTP', e.code, 'at', e.url, '(no credentials logged).', file=sys.stderr)
        print(e.read().decode('utf-8')[:1200], file=sys.stderr)
        sys.exit(1)

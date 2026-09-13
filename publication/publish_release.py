"""Publish the isolated public repository using the user's existing Git login.

No password or token is accepted on the command line or written to disk.
Run prepare_public_release.py and verify_public_release.py before publication.

    python publish_release.py                      check the signed-in account
    python publish_release.py --status             show Pages and release state
    python publish_release.py --publish            push docs and publish the release in release.json
    python publish_release.py --remove-release v3.3.1-beta.1
                                                   delete one old release (and its tag) by name

Everything that changes GitHub refuses to run while publication/PRIVATE_REVIEW exists: that
file is the owner's pause.
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
PAUSE = BASE / 'PRIVATE_REVIEW'
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
    assert repo['full_name'].lower() == REPO.lower()
    meta = json.loads((PUBLIC / 'release.json').read_text())
    if '--status' in sys.argv:
        for suffix in ('/pages', '/pages/builds/latest', '/releases/tags/' + meta['tag']):
            try:
                d = api('/repos/' + REPO + suffix)
                print(json.dumps({k: d[k] for k in ('status', 'html_url', 'source', 'https_enforced', 'draft', 'prerelease', 'error') if k in d}))
            except urllib.error.HTTPError as e:
                print(suffix, 'HTTP', e.code)
        return
    if '--publish' not in sys.argv and '--remove-release' not in sys.argv:
        print('Authenticated as', OWNER, 'with access to', REPO)
        return

    # The owner's pause guards every step that changes GitHub.
    if PAUSE.exists():
        raise SystemExit('Publication is paused (publication/PRIVATE_REVIEW exists). '
                         'Delete that file only when the owner has decided to publish.')
    assert repo['permissions']['push'], 'No push access to ' + REPO

    if '--remove-release' in sys.argv:
        index = sys.argv.index('--remove-release')
        old_tag = sys.argv[index + 1] if index + 1 < len(sys.argv) else ''
        assert old_tag and old_tag != meta['tag'], 'Name an old release tag, not the current one'
        try:
            old = api('/repos/' + REPO + '/releases/tags/' + old_tag)
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
            print('No release with tag', old_tag)
        else:
            api('/repos/' + REPO + '/releases/' + str(old['id']), 'DELETE')
            print('Deleted release', old_tag, flush=True)
        try:
            api('/repos/' + REPO + '/git/refs/tags/' + old_tag, 'DELETE')
            print('Deleted tag', old_tag, flush=True)
        except urllib.error.HTTPError as e:
            if e.code not in (404, 422):
                raise
        return

    assert not repo['private'], 'Repository must be public to publish'

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
        git('commit', '-m', 'Publish ACS ' + meta['version'] + ' distribution and documentation')
    git('push', '-u', 'origin', 'main')
    print('Published public documentation commit', git('rev-parse', 'HEAD'), flush=True)

    tag = meta['tag']
    try:
        release = api('/repos/' + REPO + '/releases/tags/' + tag)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
        release = api('/repos/' + REPO + '/releases', 'POST', {
            'tag_name': tag, 'target_commitish': git('rev-parse', 'HEAD'),
            'name': 'ACS ' + meta['version'], 'draft': True, 'prerelease': bool(meta.get('prerelease', False)),
            'body': (PUBLIC / 'RELEASE_NOTES.md').read_text(encoding='utf-8') +
                    '\n\nDownload **' + meta['asset'] + '** below - the whole app is this one file. '
                    'GitHub-generated Source code archives contain only this public documentation repository, not scanner source.\n\n'
                    'SHA-256: `' + meta['sha256'] + '`\n\n'
                    'See [verification instructions](https://github.com/' + REPO + '/blob/' + tag + '/VERIFY.md).'
        })
    assets = [BASE / 'artifacts' / n for n in meta.get('assets', [meta['asset']])] + [PUBLIC / n for n in
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
        result = api(upload, 'POST', raw=content, content_type='application/octet-stream')
        assert result['size'] == len(content) and result.get('digest') == digest
        print('Uploaded and verified', path.name, flush=True)
    if release['draft']:
        prerelease = bool(meta.get('prerelease', False))
        release = api('/repos/' + REPO + '/releases/' + str(release['id']), 'PATCH',
                      {'draft': False, 'prerelease': prerelease, 'make_latest': 'false' if prerelease else 'true'})
    print('Published', meta['version'] + ':', release['html_url'], flush=True)

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

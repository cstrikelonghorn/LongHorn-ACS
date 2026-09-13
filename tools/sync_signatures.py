"""Install a reviewed hash feed after checking its independently supplied SHA-256.

Usage: python tools/sync_signatures.py HTTPS_URL EXPECTED_SHA256
The feed format is documented in UPGRADE.md. Never downloads or runs cheat binaries.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.request
from datetime import datetime, timezone

MAX_BYTES = 4 * 1024 * 1024

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Redirects are not permitted for signature feeds')

def validate_feed(raw, expected_sha):
    if not re.fullmatch(r'[0-9a-fA-F]{64}', expected_sha):
        raise ValueError('Expected SHA-256 must contain exactly 64 hexadecimal characters')
    if len(raw) > MAX_BYTES or hashlib.sha256(raw).hexdigest() != expected_sha.lower():
        raise ValueError('Feed size or SHA-256 verification failed')
    feed = json.loads(raw)
    published = datetime.fromisoformat(feed['publishedAt'].replace('Z', '+00:00'))
    if published.tzinfo is None or published > datetime.now(timezone.utc):
        raise ValueError('publishedAt must be a past UTC timestamp')
    entries = feed.get('hashes')
    if not isinstance(entries, list) or not 1 <= len(entries) <= 10000:
        raise ValueError('Feed must contain 1–10000 reviewed hashes')
    seen = set()
    rules = []
    for entry in entries:
        sha = str(entry.get('sha256', '')).lower()
        family = entry.get('family', '')
        source = entry.get('source', '')
        if not re.fullmatch(r'[a-f0-9]{64}', sha) or sha in seen:
            raise ValueError('Invalid or duplicate hash')
        if not isinstance(family, str) or not 1 <= len(family) <= 120:
            raise ValueError('Each hash needs a cheat family name')
        if not isinstance(source, str) or not source.startswith('https://'):
            raise ValueError('Each hash needs an HTTPS provenance URL')
        seen.add(sha)
        rules.append(dict(id='acs-feed-' + sha, name=family, enabled=True,
            severity='DETECTED', confidence='high', scopes=['module', 'driver', 'process', 'hl-file'],
            match={'sha256': [sha]}, source=source))
    return {'publishedAt': published.isoformat(), 'feedSha256': expected_sha.lower(), 'signatures': rules}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url')
    parser.add_argument('sha256', help='Obtain independently from the trusted feed publisher')
    parser.add_argument('--output', type=Path, default=Path(__file__).resolve().parents[1] / 'database' / 'curated_hashes.json')
    args = parser.parse_args()
    if not args.url.startswith('https://'):
        parser.error('Feed URL must use HTTPS')
    with urllib.request.build_opener(NoRedirect).open(args.url, timeout=30) as response:
        document = validate_feed(response.read(MAX_BYTES + 1), args.sha256)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Refuse to roll back to an older feed, including accidental scheduling mistakes.
    if args.output.exists():
        previous = json.loads(args.output.read_text(encoding='utf-8'))
        if datetime.fromisoformat(previous['publishedAt']) > datetime.fromisoformat(document['publishedAt']):
            raise ValueError('Refusing signature feed rollback')
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=args.output.parent, delete=False) as temp:
            temp_path = Path(temp.name)
            json.dump(document, temp, indent=2)
            temp.flush()
            os.fsync(temp.fileno())
        os.replace(temp_path, args.output)
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink()
    print(f'Installed {len(document["signatures"])} reviewed hashes from {document["publishedAt"]}')

if __name__ == '__main__':
    main()

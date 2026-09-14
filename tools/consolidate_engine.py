"""Migrate scan signatures, profiles and legacy reviewed entries into one engine DB.

Run once per deployment BEFORE upgrading PHP. Original files are copied to
database/backups; runtime report/corpus/telemetry storage is left intact.
No network access and no sample binaries are required.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import sqlite3
from datetime import datetime, timezone


def migrate(root):
    path = root / 'cheats_database.json'
    data = json.loads(path.read_text(encoding='utf-8-sig'))
    if data.get('schema') == 'acs-engine-v3':
        print('Engine database already migrated.')
        return
    backup = root / 'backups' / datetime.now(timezone.utc).strftime('engine-%Y%m%d-%H%M%S')
    backup.mkdir(parents=True, exist_ok=False)
    shutil.copy2(path, backup / path.name)
    profiles = root / 'client_profiles.json'
    if profiles.exists():
        shutil.copy2(profiles, backup / profiles.name)
        data['clientProfiles'] = json.loads(profiles.read_text(encoding='utf-8-sig'))
    else:
        data['clientProfiles'] = {'version': 1, 'profiles': []}
    # Preserve existing lists and move only deliberate historical admin decisions.
    lists_path = root / 'file_lists.json'
    lists = json.loads(lists_path.read_text()) if lists_path.exists() else {'version': 1, 'revision': 0, 'blacklist': [], 'whitelist': []}
    if lists_path.exists():
        shutil.copy2(lists_path, backup / lists_path.name)
    corpus = root / 'corpus.sqlite'
    if corpus.exists() and corpus.stat().st_size:
        import hashlib
        with sqlite3.connect(corpus.as_uri() + '?mode=ro', uri=True) as db:
            rows = db.execute("SELECT sha256,state FROM artifacts WHERE state_source='admin' AND state IN ('cheat','clean')").fetchall()
        for sha, state in rows:
            name = 'blacklist' if state == 'cheat' else 'whitelist'
            entry_id = hashlib.sha256(f'{name}|sha256|{sha}'.encode()).hexdigest()[:24]
            if any(e['id'] == entry_id for e in lists[name]):
                continue
            lists[name].append(dict(id=entry_id, matchType='sha256', value=sha,
                severity='DETECTED' if state == 'cheat' else 'INFO', enabled=True,
                scopes=['module','hl-file','process','driver','game-process'],
                reason='Migrated explicit administrator corpus classification.'))
        if rows:
            lists['revision'] += 1
    feed = root / 'curated_hashes.json'
    if feed.exists():
        shutil.copy2(feed, backup / feed.name)
        imported = json.loads(feed.read_text())
        data['signatures'].extend(imported['signatures'])
    for rule in data['signatures']:
        match = rule.get('match', {})
        has_hash = any(k in match for k in ('sha256', 'md5', 'sha1', 'file_md5hash', 'file_hash'))
        rule.setdefault('family', rule.get('name', rule['id']))
        rule.setdefault('artifactType', 'script' if rule.get('scopes') == ['hl-config'] else 'file')
        rule.setdefault('verification', {'status': 'unverified', 'reason': 'Legacy import: provenance and sample identity require review.'})
        rule['nameSeverity'] = 'INFO'
        if not has_hash and rule.get('severity') != 'INFO':
            rule['previousSeverity'] = rule.get('severity')
            rule['severity'] = 'INFO'
        # Do not invent clean baselines, cheat samples or source attestations.
    data['version'] = 3
    data['schema'] = 'acs-engine-v3'
    data['name'] = 'LongHorn ACS Engine Database'
    data['enginePolicy'] = {
        'version': 3,
        'ruleSeverityCaps': {
            **{k: 'WARNING' for k in ['acp-inline-hook','acp-module-code-patched','acp-iat-hook','acp-eat-hook',
                'acp-forged-signature','acp-cheat-mutex','acp-config-binary-disguise','acp-external-writer',
                'acp-external-reader','acp-foreign-thread','acp-cvar-r_drawentities','acp-cvar-gl_monolights']},
            **{k: 'INFO' for k in ['acp-cheat-named-module','acp-cheat-named-game-file','acp-suspicious-tool',
                'acp-cheat-config-folder','acp-cheat-registry','acp-timestamp-restart-suspect','acp-config-big-cfg',
                'acp-multiple-hl-processes']}
        },
        'notes': 'Unknown names and popularity are not cheating. Runtime heuristics require corroboration. Administrator file rules are explicit local policy.'
    }
    data['indicators'] = {
        'tools': ['cheatengine','speedhack','vehdebug','x64dbg','x32dbg','ollydbg','scylla','extremeinjector',
                  'xenos','ghinjector','artmoney','squalr','reclass','megadumper','tsearch','wpe','winject','processhacker'],
        'mutexes': [['oxware_launcher_mutex','oxware']],
        'configFolders': [['oxware','oxware']],
        'registryKeys': [['Software\\oxware','oxware']]
    }
    data['generatedAt'] = datetime.now(timezone.utc).isoformat()
    for target, document in [(path, data), (lists_path, lists)]:
        temp = target.with_suffix('.migration.tmp')
        temp.write_text(json.dumps(document, indent=4, ensure_ascii=False) + '\n', encoding='utf-8')
        os.replace(temp, target)
    for old in (profiles, feed):
        if old.exists():
            old.unlink()  # Exact obsolete files, retained in the backup above.
    print(f'Migrated {len(data["signatures"])} rules; backup: {backup}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database-dir', type=Path, default=Path(__file__).resolve().parents[1] / 'database')
    migrate(parser.parse_args().database_dir.resolve())

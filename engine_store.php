<?php
declare(strict_types=1);

/** One scan database; inventory/reputation databases never supply live rules. */
function acs_engine_database(array $config): array
{
    $data = uds_signature_store_load($config['databaseFile']);
    $rules = [];
    $seen = [];
    foreach (uds_signature_store_rules($data) as $rule) {
        if (($rule['enabled'] ?? true) === false) continue;
        $match = (array) ($rule['match'] ?? []);
        $verified = ($rule['verification']['status'] ?? '') === 'verified';
        $rule['nameSeverity'] = $rule['nameSeverity'] ?? 'INFO';
        if (!$verified && ($rule['severity'] ?? '') === 'DETECTED') $rule['severity'] = 'WARNING';
        $scopes = (array) ($rule['scopes'] ?? []);
        sort($scopes);
        ksort($match);
        foreach ($match as &$values) {
            if (is_array($values)) { $values = array_values(array_unique($values)); sort($values); }
        }
        unset($values);
        $key = hash('sha256', json_encode([$scopes, $match], JSON_THROW_ON_ERROR));
        if (isset($seen[$key])) continue;
        $seen[$key] = true;
        $rules[] = $rule;
    }
    $data['signatures'] = $rules;
    $data['fileLists'] = acs_file_lists_load($config);
    $data['counts'] = uds_signature_store_counts($rules);
    // Includes compatibility and exceptions: any decision-changing edit changes revision.
    unset($data['revision']);
    $data['revision'] = hash('sha256', json_encode($data, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    return $data;
}

function acs_file_lists_path(array $config): string
{
    return $config['fileListsFile'] ?? (__DIR__ . '/database/file_lists.json');
}

function acs_file_lists_load(array $config): array
{
    $path = acs_file_lists_path($config);
    if (!is_file($path)) return ['version' => 1, 'revision' => 0, 'blacklist' => [], 'whitelist' => []];
    $data = json_decode((string) file_get_contents($path), true, 64, JSON_THROW_ON_ERROR);
    if (!is_array($data) || !is_array($data['blacklist'] ?? null) || !is_array($data['whitelist'] ?? null)) {
        throw new RuntimeException('Invalid admin file lists; repair the file before scanning.');
    }
    foreach (['blacklist', 'whitelist'] as $list) {
        foreach ($data[$list] as $entry) acs_file_list_validate($entry, $list);
    }
    return $data;
}

function acs_file_list_validate(array $input, string $list): array
{
    if (!in_array($list, ['blacklist', 'whitelist'], true)) throw new InvalidArgumentException('Invalid list.');
    $type = (string) ($input['matchType'] ?? 'filename');
    $value = strtolower(trim((string) ($input['value'] ?? '')));
    if ($type === 'sha256') {
        if (!preg_match('/^[a-f0-9]{64}$/D', $value)) throw new InvalidArgumentException('SHA-256 must be exactly 64 hexadecimal characters.');
    } elseif ($type === 'filename') {
        if (strlen($value) > 180 || !preg_match('/^[a-z0-9][a-z0-9._ -]*\.[a-z0-9]{1,12}$/D', $value)) {
            throw new InvalidArgumentException('Enter one exact filename, such as cscheats.dll; paths and wildcards are not allowed.');
        }
    } else throw new InvalidArgumentException('Use filename or sha256.');
    $scopes = array_values(array_unique((array) ($input['scopes'] ?? ['module', 'hl-file', 'process', 'driver', 'game-process'])));
    if (!$scopes || array_diff($scopes, ['module', 'hl-file', 'process', 'driver', 'game-process', 'hl-config'])) {
        throw new InvalidArgumentException('Select at least one valid file scope.');
    }
    $severity = $list === 'whitelist' ? 'INFO' : strtoupper((string) ($input['severity'] ?? 'WARNING'));
    if ($list === 'blacklist' && !in_array($severity, ['DETECTED', 'WARNING'], true)) throw new InvalidArgumentException('Select Cheat or Warning.');
    $reason = trim((string) ($input['reason'] ?? ''));
    if ($reason === '' || strlen($reason) > 1000) throw new InvalidArgumentException('A review reason of 1–1000 characters is required.');
    return ['id' => substr(hash('sha256', $list . '|' . $type . '|' . $value), 0, 24),
        'matchType' => $type, 'value' => $value, 'severity' => $severity, 'scopes' => $scopes,
        'reason' => $reason, 'enabled' => ($input['enabled'] ?? true) !== false];
}

/** Locked read/modify/atomic replace plus optimistic revision checking. */
function acs_file_lists_change(array $config, array $input): array
{
    $path = acs_file_lists_path($config);
    acp_ensure_dir(dirname($path));
    $lock = fopen($path . '.lock', 'c');
    if (!$lock) throw new RuntimeException('Cannot open file-list lock.');
    $temp = null;
    try {
        if (!flock($lock, LOCK_EX)) throw new RuntimeException('Cannot lock file lists.');
        $data = acs_file_lists_load($config);
        if ((int) ($input['revision'] ?? -1) !== (int) ($data['revision'] ?? 0)) {
            throw new UnexpectedValueException('File lists changed in another session. Reload and retry.');
        }
        $list = (string) ($input['list'] ?? '');
        if (!in_array($list, ['blacklist', 'whitelist'], true)) throw new InvalidArgumentException('Invalid list.');
        $entry = null;
        if (($input['operation'] ?? 'save') === 'delete') {
            $id = (string) ($input['id'] ?? '');
            if (!array_filter($data[$list], static fn($e) => $e['id'] === $id)) throw new InvalidArgumentException('Entry not found.');
        } else {
            $entry = acs_file_list_validate((array) ($input['entry'] ?? []), $list);
            $id = $entry['id'];
            $entry['updatedAt'] = gmdate('c');
        }
        $data[$list] = array_values(array_filter($data[$list], static fn($e) => $e['id'] !== $id));
        if ($entry !== null) $data[$list][] = $entry;
        $data['revision'] = (int) ($data['revision'] ?? 0) + 1;
        $data['updatedAt'] = gmdate('c');
        $temp = tempnam(dirname($path), '.file-list-');
        if ($temp === false || file_put_contents($temp, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n") === false
            || !rename($temp, $path)) throw new RuntimeException('Cannot save file lists.');
        $temp = null;
        return $data;
    } finally {
        if ($temp && is_file($temp)) unlink($temp);
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

function acs_file_basename(string $path): string
{
    return strtolower(basename(str_replace('\\', '/', trim($path))));
}

function acs_file_list_match(array $entry, string $source, string $path, string $sha): bool
{
    if (($entry['enabled'] ?? true) === false || !in_array($source, $entry['scopes'], true)) return false;
    return $entry['matchType'] === 'sha256'
        ? preg_match('/^[a-f0-9]{64}$/D', $sha) === 1 && hash_equals($entry['value'], $sha)
        : acs_file_basename($path) === $entry['value'];
}

function acs_file_decision(array $lists, string $source, string $path, string $sha): ?array
{
    // Exact clean hash > exact black hash > black filename > white filename.
    foreach ([['whitelist', 'sha256'], ['blacklist', 'sha256'], ['blacklist', 'filename'], ['whitelist', 'filename']] as [$list, $type]) {
        foreach ($lists[$list] as $entry) {
            if ($entry['matchType'] === $type && acs_file_list_match($entry, $source, $path, $sha)) return $entry + ['list' => $list];
        }
    }
    return null;
}

/** Re-evaluate file overrides from inventory, never from a client-supplied suppression flag. */
function acs_apply_file_lists(array &$report, array $lists): void
{
    $findings = [];
    foreach ((array) ($report['findings'] ?? []) as $finding) {
        if (str_starts_with((string) ($finding['ruleId'] ?? ''), 'acs-file-policy-')) continue;
        if (isset($finding['filePolicy'])) {
            $finding['severity'] = $finding['filePolicyOriginalSeverity'] ?? $finding['severity'];
            unset($finding['filePolicy'], $finding['filePolicyOriginalSeverity'], $finding['suppressed']);
        }
        $findings[] = $finding;
    }
    $artifacts = [];
    foreach (['modules' => 'module', 'hlFiles' => 'hl-file', 'processes' => 'process', 'drivers' => 'driver'] as $key => $source) {
        foreach ((array) ($report[$key] ?? []) as $row) {
            $path = (string) ($row['path'] ?? $row['relativePath'] ?? '');
            if ($path === '') continue;
            $sha = strtolower((string) ($row['sha256'] ?? ''));
            $decision = acs_file_decision($lists, $source, $path, $sha);
            $artifacts[$source . '|' . strtolower(str_replace('\\', '/', $path))] = [$decision, $sha];
        }
    }
    foreach ($findings as &$finding) {
        $path = (string) ($finding['artifactPath'] ?? $finding['subject'] ?? '');
        $key = ($finding['source'] ?? '') . '|' . strtolower(str_replace('\\', '/', $path));
        [$decision, $sha] = $artifacts[$key] ?? [null, ''];
        if ($decision === null || $decision['list'] !== 'whitelist') continue;
        // Disk identity cannot explain a runtime patch, thread, script graph or server event.
        $kind = $finding['evidenceKind'] ?? '';
        $fileFinding = in_array($kind, ['signature-hash', 'signature-name'], true)
            || in_array($finding['ruleId'] ?? '', ['acp-cheat-named-module', 'acp-cheat-named-game-file', 'acp-foreign-module', 'acp-local-opengl-hook'], true);
        if (!$fileFinding || ($decision['matchType'] === 'filename' && ($kind === 'signature-hash' || ($finding['severity'] ?? '') === 'DETECTED'))) continue;
        $finding['filePolicyOriginalSeverity'] = $finding['severity'];
        $finding['severity'] = 'INFO';
        $finding['filePolicy'] = $decision;
        $finding['suppressed'] = true;
    }
    unset($finding);
    foreach ($artifacts as $key => [$decision, $sha]) {
        if ($decision === null || $decision['list'] !== 'blacklist') continue;
        [$source, $path] = explode('|', $key, 2);
        $findings[] = ['ruleId' => 'acs-file-policy-' . $decision['id'], 'ruleName' => 'Admin blacklist: ' . $decision['value'],
            'severity' => $decision['severity'], 'confidence' => $decision['matchType'] === 'sha256' ? 'high' : 'policy',
            'category' => $source === 'module' ? 'injected' : 'loaded', 'source' => $source,
            'subject' => $path, 'artifactPath' => $path, 'artifactSha256' => $sha, 'evidenceKind' => 'admin-policy',
            'reason' => 'Administrator rule (' . $decision['matchType'] . '): ' . $decision['reason'], 'filePolicy' => $decision];
    }
    $report['findings'] = $findings;
    $report['fileListsRevision'] = $lists['revision'] ?? 0;
}

/** Same caps are consumed by the desktop; any number of heuristics stays review. */
function acs_apply_engine_policy(array &$report, array $database): void
{
    acs_reconcile_signature_findings($report, $database);
    $caps = $database['enginePolicy']['ruleSeverityCaps'] ?? [];
    $ranks = ['INFO' => 0, 'WARNING' => 1, 'DETECTED' => 2];
    foreach ((array) ($report['findings'] ?? []) as $i => $finding) {
        $id = acs_client_rule_key((string) ($finding['ruleId'] ?? ''));
        $cap = $caps[$id] ?? null;
        if (str_starts_with($id, 'acp-usn-')) $cap = 'INFO';
        if ($cap !== null && ($ranks[$finding['severity']] ?? 0) > $ranks[$cap]) {
            $report['findings'][$i]['originalSeverity'] = $finding['originalSeverity'] ?? $finding['severity'];
            $report['findings'][$i]['severity'] = $cap;
            $report['findings'][$i]['policyReason'] = 'Engine policy v3: this observation alone does not identify cheat code.';
        }
    }
    acs_apply_file_lists($report, $database['fileLists'] ?? ['blacklist' => [], 'whitelist' => []]);
    $report['findingPolicyVersion'] = 3;
}

/** Exact digests are checked again against the current DB and the submitted inventory.
 * This verifies rule semantics, not honesty of a player-controlled machine. */
function acs_reconcile_signature_findings(array &$report, array $database): void
{
    $rules = [];
    foreach ($database['signatures'] as $rule) $rules[$rule['id']] = $rule;
    $inventory = [];
    foreach (['modules' => 'module', 'hlFiles' => 'hl-file', 'processes' => 'process', 'drivers' => 'driver'] as $key => $source) {
        foreach ((array) ($report[$key] ?? []) as $row) {
            $path = (string) ($row['path'] ?? $row['relativePath'] ?? '');
            if ($path !== '') $inventory[$source . '|' . strtolower(str_replace('\\', '/', $path))] = $row;
        }
    }
    $hashRules = [];
    foreach ($rules as $id => $rule) {
        foreach ((array) ($rule['match'] ?? []) as $key => $values) {
            $algorithm = ['sha256'=>'sha256','hash_sha256'=>'sha256','md5'=>'md5','hash_md5'=>'md5','file_md5hash'=>'md5','sha1'=>'sha1','hash_sha1'=>'sha1'][$key] ?? '';
            if ($algorithm === '') continue;
            $length = ['sha256'=>64,'sha1'=>40,'md5'=>32][$algorithm];
            foreach ((array) $values as $value) {
                $value = strtolower((string) $value);
                if (strlen($value) === $length && ctype_xdigit($value)) $hashRules[$algorithm . ':' . $value][] = $id;
            }
        }
    }
    $hits = [];
    foreach ($inventory as $key => $row) {
        [$source, $path] = explode('|', $key, 2);
        foreach (['sha256', 'sha1', 'md5'] as $algorithm) {
            $digest = strtolower((string) ($row[$algorithm] ?? ''));
            foreach ($hashRules[$algorithm . ':' . $digest] ?? [] as $id) {
                $rule = $rules[$id];
                if (!in_array($source, $rule['scopes'], true) && !in_array('client-live', $rule['scopes'], true)) continue;
                $hits[$id . '|' . $key] = [
                    'ruleId' => $id, 'ruleName' => $rule['name'], 'severity' => $rule['severity'], 'confidence' => $rule['confidence'] ?? 'medium',
                    'source' => $source, 'subject' => $path, 'artifactPath' => $path, 'artifactSha256' => (string) ($row['sha256'] ?? ''),
                    'category' => $source === 'module' ? 'injected' : ($source === 'hl-file' ? 'loaded' : 'installedInOs'),
                    'evidenceKind' => 'signature-hash', 'matchedHashLength' => strlen($digest),
                    'reason' => ($rule['verification']['status'] ?? '') === 'verified'
                        ? 'Exact file digest matches a reviewed signature. File presence does not establish when it was used.'
                        : 'Exact digest matches an unverified legacy entry; independent review is required.'
                ];
            }
        }
    }
    $findings = [];
    foreach ((array) ($report['findings'] ?? []) as $finding) {
        $id = (string) ($finding['ruleId'] ?? '');
        if (isset($finding['filePolicy'])) {
            $finding['severity'] = $finding['filePolicyOriginalSeverity'] ?? $finding['severity'];
            unset($finding['filePolicy'], $finding['filePolicyOriginalSeverity'], $finding['suppressed']);
        }
        $path = (string) ($finding['artifactPath'] ?? $finding['subject'] ?? '');
        $key = $id . '|' . ($finding['source'] ?? '') . '|' . strtolower(str_replace('\\', '/', $path));
        if (isset($hits[$key])) { $findings[] = $hits[$key]; unset($hits[$key]); continue; }
        if (isset($rules[$id])) {
            $finding['originalSeverity'] = $finding['originalSeverity'] ?? $finding['severity'];
            $finding['severity'] = $rules[$id]['nameSeverity'] ?? 'INFO';
            $finding['evidenceKind'] = 'signature-name';
            $finding['policyReason'] = 'No current exact file digest match could be verified from this inventory.';
        } elseif (in_array($finding['evidenceKind'] ?? '', ['signature-hash','signature-name'], true)
            || str_starts_with($id, 'acs-reviewed-') || str_starts_with($id, 'cs16-') || str_starts_with($id, 'legacy-db-')) {
            $finding['severity'] = 'INFO';
            $finding['policyReason'] = 'This signature is retired or is not present in the current engine database.';
        }
        $findings[] = $finding;
    }
    $report['findings'] = array_merge($findings, array_values($hits));
}

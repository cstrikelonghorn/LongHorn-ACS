<?php
declare(strict_types=1);

/**
 * Shared access layer for the Unreal Demo Scanner signature store.
 *
 * The store uses one `signatures` array. Scopes decide which scanner consumes a
 * rule, while match-key prefixes keep older demo and client-report rules
 * backwards compatible.
 */

function uds_signature_store_load(string $path): array
{
    if (!is_file($path)) {
        throw new RuntimeException('Unified signature database not found: ' . $path);
    }

    $raw = file_get_contents($path);
    if ($raw === false) {
        throw new RuntimeException('Unable to read unified signature database.');
    }

    $document = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
    if (!is_array($document)) {
        throw new RuntimeException('Unified signature database must be a JSON object.');
    }

    $rules = $document['signatures'] ?? $document['rules'] ?? null;
    if (!is_array($rules)) {
        throw new RuntimeException('Unified signature database must contain a signatures array.');
    }

    return $document;
}

function uds_signature_store_rules(array $document): array
{
    $rules = $document['signatures'] ?? $document['rules'] ?? [];
    return is_array($rules) ? array_values(array_filter($rules, 'is_array')) : [];
}

function uds_signature_rule_has_match_prefix(array $rule, string $prefix): bool
{
    $match = is_array($rule['match'] ?? null) ? $rule['match'] : [];
    foreach (array_keys($match) as $key) {
        if (str_starts_with(strtolower((string) $key), strtolower($prefix))) {
            return true;
        }
    }

    return false;
}

function uds_signature_rule_has_scope(array $rule, string $scope): bool
{
    $scopes = is_array($rule['scopes'] ?? null) ? $rule['scopes'] : [];
    foreach ($scopes as $candidate) {
        if (strcasecmp((string) $candidate, $scope) === 0) {
            return true;
        }
    }

    return false;
}

function uds_signature_store_rules_for_channel(array $document, string $channel): array
{
    return array_values(array_filter(
        uds_signature_store_rules($document),
        static function (array $rule) use ($channel): bool {
            if ($channel === 'demo') {
                return uds_signature_rule_has_scope($rule, 'demo-file')
                    || (!isset($rule['scopes']) && (
                        uds_signature_rule_has_match_prefix($rule, 'output_')
                        || uds_signature_rule_has_match_prefix($rule, 'file_')
                    ));
            }

            if ($channel === 'client-report') {
                return uds_signature_rule_has_scope($rule, 'client-report')
                    || uds_signature_rule_has_match_prefix($rule, 'report_');
            }

            if ($channel === 'client-live') {
                foreach (['process', 'module', 'driver', 'memory', 'game-process', 'hl-file', 'hl-config', 'execution-trace', 'download-trace'] as $scope) {
                    if (uds_signature_rule_has_scope($rule, $scope)) {
                        return true;
                    }
                }
                return false;
            }

            return true;
        }
    ));
}

function uds_signature_store_counts(array $rules): array
{
    $counts = [
        'totalSignatures' => count($rules),
        'enabled' => 0,
        'clientLive' => 0,
        'clientReport' => 0,
        'config' => 0,
        'demoFile' => 0,
    ];

    foreach ($rules as $rule) {
        if (($rule['enabled'] ?? true) !== false) {
            $counts['enabled']++;
        }
        if (uds_signature_rule_has_scope($rule, 'demo-file')) {
            $counts['demoFile']++;
        }
        if (uds_signature_rule_has_scope($rule, 'hl-config')) {
            $counts['config']++;
        }
        if (uds_signature_rule_has_scope($rule, 'client-report') || uds_signature_rule_has_match_prefix($rule, 'report_')) {
            $counts['clientReport']++;
        }
        foreach (['process', 'module', 'driver', 'memory', 'game-process', 'hl-file', 'hl-config', 'execution-trace', 'download-trace'] as $scope) {
            if (uds_signature_rule_has_scope($rule, $scope)) {
                $counts['clientLive']++;
                break;
            }
        }
    }

    return $counts;
}

function uds_signature_store_match_report(array $rules, string $reportText): array
{
    $findings = [];
    foreach ($rules as $rule) {
        if (($rule['enabled'] ?? true) === false) {
            continue;
        }

        $match = is_array($rule['match'] ?? null) ? $rule['match'] : [];
        $matchedBy = '';
        if (isset($match['report_contains']) && stripos($reportText, (string) $match['report_contains']) !== false) {
            $matchedBy = 'report text';
        }
        if ($matchedBy === '' && isset($match['report_regex'])) {
            $pattern = (string) $match['report_regex'];
            if (@preg_match($pattern, '') === false) {
                throw new RuntimeException('Invalid report regex in signature: ' . (string) ($rule['id'] ?? 'unknown'));
            }
            if (preg_match($pattern, $reportText) === 1) {
                $matchedBy = 'report regex';
            }
        }
        if ($matchedBy === '') {
            continue;
        }

        $severity = strtoupper((string) ($rule['severity'] ?? 'WARNING'));
        if (!in_array($severity, ['DETECTED', 'WARNING', 'INFO'], true)) {
            $severity = 'WARNING';
        }
        $findings[] = [
            'id' => (string) ($rule['id'] ?? 'client-rule'),
            'name' => (string) ($rule['name'] ?? 'Client signature rule'),
            'severity' => $severity,
            'description' => (string) ($rule['description'] ?? ''),
            'matchedBy' => $matchedBy,
        ];
    }

    return $findings;
}

function uds_signature_store_save_rules(string $path, array $document, array $rules): void
{
    $document['version'] = max(2, (int) ($document['version'] ?? 2));
    $document['name'] = (string) ($document['name'] ?? 'Unreal Demo Scanner Cheat Database');
    $document['schema'] = 'single-signatures-array';
    $document['generatedAt'] = gmdate('Y-m-d\TH:i:s\Z');
    $document['counts'] = uds_signature_store_counts($rules);
    $document['signatures'] = array_values($rules);
    unset($document['rules']);

    $json = json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . PHP_EOL;
    $handle = fopen($path, 'c+b');
    if ($handle === false) {
        throw new RuntimeException('Unable to open unified signature database for writing.');
    }

    try {
        if (!flock($handle, LOCK_EX)) {
            throw new RuntimeException('Unable to lock unified signature database.');
        }
        if (!ftruncate($handle, 0) || rewind($handle) === false) {
            throw new RuntimeException('Unable to save unified signature database.');
        }
        $offset = 0;
        $length = strlen($json);
        while ($offset < $length) {
            $written = fwrite($handle, substr($json, $offset));
            if ($written === false || $written === 0) {
                throw new RuntimeException('Unable to save unified signature database.');
            }
            $offset += $written;
        }
        if (!fflush($handle)) {
            throw new RuntimeException('Unable to flush unified signature database.');
        }
        flock($handle, LOCK_UN);
    } finally {
        fclose($handle);
    }
}

/* ------------------------------------------------------------------------------------------
 * Admin Cheats Manager helpers
 * ---------------------------------------------------------------------------------------- */

/**
 * Generate a URL-safe slug ID from a cheat name.
 *
 * Example: "Vermillion D3D Multihack v2.1" → "cs16-vermillion-d3d-multihack-v2-1"
 */
function uds_signature_store_generate_id(string $name, array $existingRules): string
{
    $slug = 'cs16-' . preg_replace('/[^a-z0-9]+/', '-', strtolower(trim($name)));
    $slug = trim($slug, '-');
    if ($slug === 'cs16-' || $slug === 'cs16') {
        $slug = 'cs16-custom-rule';
    }

    $base = $slug;
    $counter = 2;
    $ids = array_column($existingRules, 'id');
    while (in_array($slug, $ids, true)) {
        $slug = $base . '-' . $counter;
        $counter++;
    }

    return $slug;
}

/** Find a single rule by its 'id' field. Returns [index, rule] or null. */
function uds_signature_store_find_by_id(array $rules, string $id): ?array
{
    foreach ($rules as $index => $rule) {
        if (($rule['id'] ?? '') === $id) {
            return [$index, $rule];
        }
    }
    return null;
}

/** Remove a rule by its 'id' field. Returns the updated rules array. */
function uds_signature_store_remove_by_id(array $rules, string $id): array
{
    return array_values(array_filter($rules, static function (array $rule) use ($id): bool {
        return ($rule['id'] ?? '') !== $id;
    }));
}

/**
 * Dry-run test: check an input string against all enabled rules.
 *
 * The input is tested against every match key: process name, module name,
 * file path, hash, report text, output text, config text. Returns an array
 * of matched rule summaries.
 */
function uds_signature_store_test_input(array $rules, string $input): array
{
    $hits = [];
    $inputLower = strtolower(trim($input));

    foreach ($rules as $rule) {
        if (($rule['enabled'] ?? true) === false) {
            continue;
        }

        $match = is_array($rule['match'] ?? null) ? $rule['match'] : [];
        $matchedBy = '';

        // Test literal-contains keys
        foreach (['report_contains', 'file_contains', 'config_contains'] as $key) {
            if (isset($match[$key])) {
                $vals = is_array($match[$key]) ? $match[$key] : [$match[$key]];
                foreach ($vals as $val) {
                    if (stripos($input, (string) $val) !== false) {
                        $matchedBy = $key;
                        break 2;
                    }
                }
            }
        }

        // Test regex keys
        if ($matchedBy === '') {
            foreach (['output_regex', 'report_regex', 'path_regex', 'driver_regex', 'config_regex'] as $key) {
                if (isset($match[$key])) {
                    $patterns = is_array($match[$key]) ? $match[$key] : [$match[$key]];
                    foreach ($patterns as $pattern) {
                        if (@preg_match((string) $pattern, $input) === 1) {
                            $matchedBy = $key;
                            break 2;
                        }
                    }
                }
            }
        }

        // Test hash keys (SHA-256, MD5)
        if ($matchedBy === '') {
            foreach (['sha256', 'md5'] as $key) {
                if (isset($match[$key])) {
                    $hashes = is_array($match[$key]) ? $match[$key] : [$match[$key]];
                    foreach ($hashes as $hash) {
                        if (strcasecmp($inputLower, strtolower((string) $hash)) === 0) {
                            $matchedBy = $key . ' hash';
                            break 2;
                        }
                    }
                }
            }
        }

        if ($matchedBy !== '') {
            $hits[] = [
                'id'          => (string) ($rule['id'] ?? ''),
                'name'        => (string) ($rule['name'] ?? ''),
                'severity'    => (string) ($rule['severity'] ?? 'WARNING'),
                'confidence'  => (string) ($rule['confidence'] ?? 'medium'),
                'description' => (string) ($rule['description'] ?? ''),
                'matchedBy'   => $matchedBy,
                'scopes'      => $rule['scopes'] ?? [],
            ];
        }
    }

    return $hits;
}

/**
 * Build a well-formed signature array from the admin form input.
 *
 * Detection types map to scope sets the way the desktop ScannerEngine consumes them:
 *   - injected-dll → module, game-process, driver, hl-file, execution-trace, download-trace
 *   - process      → process, execution-trace, download-trace, client-report
 *   - driver       → driver
 *   - game-file    → hl-file, module
 *   - config       → hl-config, client-report
 *   - exec-trace   → execution-trace, hl-file
 *   - download     → download-trace
 *   - demo         → demo-file
 */
function uds_signature_store_build_rule(array $input, array $existingRules): array
{
    $name = trim((string) ($input['name'] ?? ''));
    if ($name === '') {
        throw new InvalidArgumentException('Cheat name is required.');
    }

    $severity = strtoupper(trim((string) ($input['severity'] ?? 'DETECTED')));
    if (!in_array($severity, ['DETECTED', 'WARNING', 'INFO'], true)) {
        $severity = 'WARNING';
    }

    $confidence = strtolower(trim((string) ($input['confidence'] ?? 'high')));
    if (!in_array($confidence, ['high', 'medium', 'low'], true)) {
        $confidence = 'medium';
    }

    $detectionType = strtolower(trim((string) ($input['detectionType'] ?? 'process')));
    $scopeMap = [
        'injected-dll' => ['module', 'game-process', 'driver', 'hl-file', 'execution-trace', 'download-trace'],
        'process'      => ['process', 'execution-trace', 'download-trace', 'client-report'],
        'driver'       => ['driver'],
        'game-file'    => ['hl-file', 'module'],
        'config'       => ['hl-config', 'client-report'],
        'exec-trace'   => ['execution-trace', 'hl-file'],
        'download'     => ['download-trace'],
        'demo'         => ['demo-file'],
        'memory'       => ['memory', 'module', 'game-process'],
    ];
    $scopes = $scopeMap[$detectionType] ?? ['process', 'execution-trace'];

    $matchType = strtolower(trim((string) ($input['matchType'] ?? 'path_regex')));
    $matchValue = trim((string) ($input['matchValue'] ?? ''));
    if ($matchValue === '') {
        throw new InvalidArgumentException('Match value (target) is required.');
    }

    // Build the match block
    $match = [];
    switch ($matchType) {
        case 'sha256':
            $hashes = array_values(array_filter(array_map('trim', preg_split('/[\r\n,]+/', $matchValue))));
            $match['sha256'] = $hashes;
            break;
        case 'md5':
            $hashes = array_values(array_filter(array_map('trim', preg_split('/[\r\n,]+/', $matchValue))));
            $match['md5'] = $hashes;
            break;
        case 'path_regex':
            // If it looks like a bare name (no regex chars), wrap it automatically
            if (preg_match('/^[\w\s.\-]+$/', $matchValue)) {
                $escaped = preg_quote($matchValue, '/');
                $match['path_regex'] = '/(?i)' . str_replace(' ', '\\s*', $escaped) . '/';
            } else {
                $match['path_regex'] = $matchValue;
            }
            break;
        case 'file_contains':
            $match['file_contains'] = $matchValue;
            break;
        case 'output_regex':
            $match['output_regex'] = $matchValue;
            break;
        case 'report_regex':
            $match['report_regex'] = $matchValue;
            break;
        case 'config_regex':
            $match['config_regex'] = $matchValue;
            break;
        case 'driver_regex':
            $match['driver_regex'] = $matchValue;
            break;
        default:
            $match['path_regex'] = $matchValue;
    }

    $id = trim((string) ($input['id'] ?? ''));
    if ($id === '') {
        $id = uds_signature_store_generate_id($name, $existingRules);
    }

    return [
        'id'          => $id,
        'enabled'     => ($input['enabled'] ?? true) !== false && ($input['enabled'] ?? 'true') !== 'false',
        'name'        => $name,
        'severity'    => $severity,
        'confidence'  => $confidence,
        'description' => trim((string) ($input['description'] ?? '')),
        'sourceGroup' => trim((string) ($input['sourceGroup'] ?? 'admin-panel')),
        'scopes'      => $scopes,
        'match'       => $match,
    ];
}

<?php
declare(strict_types=1);

require __DIR__ . '/config.php';

try {
    acp_ensure_dir($acpConfig['reportsDir']);

    $action = (string) ($_GET['action'] ?? 'database');

    if ($action === 'health') {
        $database = acp_load_database($acpConfig);
        acp_json_response([
            'ok' => true,
            'service' => 'ACS Scanner API',
            'database' => $database['counts'] ?? [],
            'uploadAuthentication' => ($acpConfig['apiToken'] ?? '') !== '' ? 'required' : 'local-only-until-configured',
            'serverTime' => gmdate('Y-m-d\TH:i:s\Z'),
        ]);
    }

    // The full signature database is only for authenticated scanner clients. The
    // dashboard shows counts via health and never the raw rules, so the download
    // button was removed and this endpoint now requires the client token.
    if ($action === 'database') {
        acp_json_response(acp_load_database($acpConfig));
    }

    // Corpus scale, the way WarGods surfaces its module count. No hashes leave here.
    if ($action === 'corpus') {
        $pdo = acp_corpus_open($acpConfig);
        acp_json_response(['ok' => true, 'corpus' => acp_corpus_stats($pdo)]);
    }

    // Three-state lookup for a single hash: clean / cheat / unknown.
    if ($action === 'lookup') {
        $sha = strtolower(trim((string) ($_GET['sha256'] ?? '')));
        if (!preg_match('/^[0-9a-f]{64}$/', $sha)) {
            acp_json_response(['ok' => false, 'error' => 'sha256 must be 64 hex characters'], 400);
        }

        $pdo = acp_corpus_open($acpConfig);
        $summary = acp_corpus_summarise($pdo, [$sha]);
        $known = $summary['states'][$sha] ?? null;

        acp_json_response([
            'ok' => true,
            'sha256' => $sha,
            'state' => $known['state'] ?? 'unseen',
            'machines' => $known['machines'] ?? 0,
            'source' => $known['source'] ?? '',
            'virustotal' => acp_corpus_virustotal_url($sha),
        ]);
    }

    // Review queue: the Unknown bucket, most suspicious first.
    if ($action === 'queue') {
        acp_require_admin($acpConfig);
        $pdo = acp_corpus_open($acpConfig);
        acp_corpus_autoclassify($pdo);

        $state = (string) ($_GET['state'] ?? 'unknown');
        $limit = (int) ($_GET['limit'] ?? 100);
        acp_json_response([
            'ok' => true,
            'state' => $state,
            'items' => acp_corpus_queue($pdo, $limit, $state),
        ]);
    }

    // Classify a hash. One call turns an Unknown into a signature for every future scan.
    if ($action === 'classify') {
        acp_require_admin($acpConfig);
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            acp_json_response(['ok' => false, 'error' => 'POST required'], 405);
        }

        $body = json_decode((string) file_get_contents('php://input'), true);
        $body = is_array($body) ? $body : [];
        $sha = (string) ($body['sha256'] ?? $_POST['sha256'] ?? '');
        $state = (string) ($body['state'] ?? $_POST['state'] ?? '');
        $note = (string) ($body['note'] ?? $_POST['note'] ?? '');

        try {
            $pdo = acp_corpus_open($acpConfig);
            $changed = acp_corpus_classify($pdo, $sha, $state, $note);
        } catch (InvalidArgumentException $e) {
            acp_json_response(['ok' => false, 'error' => $e->getMessage()], 400);
        }

        acp_json_response([
            'ok' => $changed,
            'error' => $changed ? null : 'No artifact with that hash is in the corpus',
            'sha256' => strtolower(trim($sha)),
            'state' => $state,
        ], $changed ? 200 : 404);
    }

    // The legitimate-client profile database, so the desktop app can identify a client
    // locally and explain its own findings before upload.
    if ($action === 'clients') {
        acp_require_upload_auth($acpConfig);
        $db = acs_client_profiles($acpConfig);
        acp_json_response([
            'ok'       => true,
            'version'  => $db['version'] ?? 0,
            'updated'  => $db['updated'] ?? '',
            'profiles' => $db['profiles'] ?? [],
        ]);
    }

    // Behavioural scale, alongside ?action=corpus. Counts only, no player identities.
    if ($action === 'behavior') {
        $pdo = acp_behavior_open($acpConfig);
        acp_json_response(['ok' => true, 'behavior' => acp_behavior_stats($pdo)]);
    }

    // Ranked player risk: the correlated view across server telemetry and desktop
    // reports. Admin-gated, because unlike a hash lookup these rows name people.
    if ($action === 'players') {
        acp_require_admin($acpConfig);
        $pdo = acp_behavior_open($acpConfig);
        acp_json_response([
            'ok'      => true,
            'verdict' => (string) ($_GET['verdict'] ?? ''),
            'players' => acp_behavior_queue($pdo, (int) ($_GET['limit'] ?? 100), (string) ($_GET['verdict'] ?? '')),
        ]);
    }

    if ($action === 'player') {
        acp_require_admin($acpConfig);
        $steam64 = trim((string) ($_GET['steam64'] ?? ''));
        if ($steam64 === '') {
            acp_json_response(['ok' => false, 'error' => 'steam64 is required'], 400);
        }

        $pdo = acp_behavior_open($acpConfig);

        // Recompute on read so the client half of the score reflects any report uploaded
        // since the last telemetry batch, rather than whatever was true at ingest time.
        // acp_behavior_recompute refuses to create a row for an id it knows nothing
        // about, so an unknown SteamID 404s instead of being conjured into the table.
        $scored = acp_behavior_recompute($pdo, $steam64, $acpConfig);
        $player = ($scored['known'] ?? false) ? acp_behavior_player($pdo, $steam64) : null;
        if ($player === null) {
            acp_json_response(['ok' => false, 'error' => 'No such player'], 404);
        }

        acp_json_response(['ok' => true, 'player' => $player, 'scoring' => $scored]);
    }

    if ($action === 'upload_report') {
        acp_require_upload_auth($acpConfig);
        acs_require_rate_limit('upload_report', 10, 60, $acpConfig);
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            acp_json_response(['ok' => false, 'error' => 'POST required'], 405);
        }

        $length = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
        if ($length > $acpConfig['maxReportBytes']) {
            acp_json_response(['ok' => false, 'error' => 'Report is too large'], 413);
        }

        $raw = (string) file_get_contents('php://input', false, null, 0, $acpConfig['maxReportBytes'] + 1);
        if (strlen($raw) > $acpConfig['maxReportBytes']) {
            acp_json_response(['ok' => false, 'error' => 'Report is too large'], 413);
        }
        $payload = json_decode($raw, true);
        if (!is_array($payload)) {
            acp_json_response(['ok' => false, 'error' => 'Invalid JSON report'], 400);
        }

        try {
            [$report, $signatureValid] = acp_decode_upload($payload, $acpConfig);
        } catch (UnexpectedValueException $e) {
            acp_json_response(['ok' => false, 'error' => $e->getMessage()], 401);
        } catch (InvalidArgumentException | JsonException $e) {
            acp_json_response(['ok' => false, 'error' => $e->getMessage()], 400);
        }

        $id = bin2hex(random_bytes(8));
        $now = gmdate('Y-m-d\TH:i:s\Z');
        $database = acp_load_database($acpConfig);

        $report['id'] = $id;
        $report['uploadedAt'] = $now;
        $report['signatureVerified'] = $signatureValid;
        $report['remoteAddress'] = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        $report['serverDatabaseCounts'] = $database['counts'] ?? [];
        $report['serverDatabaseRevision'] = $database['revision'] ?? '';
        // A client-side HMAC detects accidental/tampered transport payloads, but every player
        // controls their own client and its credential. It is never device attestation.
        $report['reportTrust'] = 'client-supplied-untrusted';
        $report['clientIntegrityCheck'] = $signatureValid ? 'hmac-valid' : 'not-verified';
        $report['identityKeys'] = acp_identity_keys($report);

        // Re-score legacy evidence and apply the current client compatibility profile before
        // anything reads the findings.
        acp_apply_current_finding_policy($report, $acpConfig);
        acp_normalize_report($report);
        $report['previousScans'] = acp_find_related_reports($acpConfig, $report, 10);

        // Fold every hashed artifact in this report into the corpus, then attach what the
        // corpus already knew so the report page can show clean / cheat / unknown per module.
        // A corpus failure must never cost us the report itself.
        try {
            $pdo = acp_corpus_open($acpConfig);
            $report['corpus'] = acp_corpus_ingest($pdo, $report, $id);
            acp_corpus_autoclassify($pdo);
        } catch (Throwable $corpusError) {
            $report['corpus'] = ['error' => $corpusError->getMessage()];
        }

        // Record the server connection for history tracking.
        try {
            acp_server_history_record($acpConfig, $report);
        } catch (Throwable $histError) {
            error_log('[ACS] Server history: ' . $histError->getMessage());
        }

        $path = acp_report_path($acpConfig, $id);
        $json = json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($json === false || file_put_contents($path, $json, LOCK_EX) === false) {
            acp_json_response(['ok' => false, 'error' => 'Unable to save report'], 500);
        }

        // Index before scoring. The client half of the risk score is now answered from the
        // report index, so the report that was just written has to be in it - otherwise a
        // player's newest scan would not count towards their own score.
        try {
            acp_report_index_put(acp_report_index_open($acpConfig), $report, (int) @filemtime($path));
        } catch (Throwable $indexError) {
            error_log('[ACS] Report index: ' . $indexError->getMessage());
        }

        // Fold this report into the player's combined risk, so a scan and the server-side
        // behavioural evidence for the same SteamID reinforce each other instead of
        // sitting in two systems that never meet. Like the corpus above, a failure here
        // must not cost us the report.
        try {
            $steam64 = trim((string) ($report['steamId'] ?? ''));
            if ($steam64 !== '') {
                $behaviorPdo = acp_behavior_open($acpConfig);
                $report['riskScore'] = acp_behavior_recompute($behaviorPdo, $steam64, $acpConfig);
            }
        } catch (Throwable $riskError) {
            $report['riskScore'] = ['error' => $riskError->getMessage()];
        }

        // Risk includes the report just saved. Persist the attached risk result too.
        $enriched = json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($enriched !== false) {
            file_put_contents($path, $enriched, LOCK_EX);
            // Re-stamp the index with the new mtime, otherwise the next sync sees the file
            // as changed and re-parses this whole report for nothing.
            try {
                acp_report_index_put(acp_report_index_open($acpConfig), $report, (int) @filemtime($path));
            } catch (Throwable $indexError) {
                error_log('[ACS] Report index: ' . $indexError->getMessage());
            }
        }

        $viewKey = acp_report_view_key($acpConfig, $id);
        $reportUrl = 'index.php?report=' . rawurlencode($id)
            . ($viewKey !== '' ? '&k=' . rawurlencode($viewKey) : '');
        acp_json_response([
            'ok' => true,
            'id' => $id,
            'url' => $reportUrl,
            'summary' => acp_report_summary($report),
        ]);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Server Connection Verification API
    // ────────────────────────────────────────────────────────────────────────

    /**
     * Verify a server connection claim by querying the server via A2S_INFO.
     * This provides independent server-side verification that the claimed server
     * actually exists and is reachable, helping detect fake server claims.
     *
     * GET api.php?action=verify_server&address=ip:port
     *
     * Returns server info if reachable, error otherwise.
     */
    if ($action === 'verify_server') {
        acs_require_rate_limit('verify_server', 30, 60, $acpConfig);

        $address = trim((string) ($_GET['address'] ?? ''));
        if ($address === '' || !preg_match('/^[0-9a-zA-Z\.\-]+:[0-9]+$/', $address)) {
            acp_json_response(['ok' => false, 'error' => 'Invalid server address format (expected ip:port)'], 400);
        }

        // Validate port range
        $port = (int) substr($address, strrpos($address, ':') + 1);
        if ($port < 1024 || $port > 65535) {
            acp_json_response(['ok' => false, 'error' => 'Invalid port number'], 400);
        }

        $serverInfo = acp_query_a2s($address);

        if ($serverInfo === null) {
            acp_json_response([
                'ok' => false,
                'address' => $address,
                'error' => 'Server did not respond to A2S_INFO query',
                'reachable' => false,
            ], 404);
        }

        acp_json_response([
            'ok' => true,
            'address' => $address,
            'reachable' => true,
            'server' => $serverInfo,
            'verifiedAt' => gmdate('Y-m-d\TH:i:s\Z'),
        ]);
    }

    /**
     * Verify a report's server connection evidence chain.
     * Checks that the evidence chain is internally consistent and optionally
     * verifies the server is still reachable.
     *
     * GET api.php?action=verify_report_server&id=report_id
     */
    if ($action === 'verify_report_server') {
        acs_require_rate_limit('verify_report_server', 20, 60, $acpConfig);

        $reportId = trim((string) ($_GET['id'] ?? ''));
        if ($reportId === '' || !preg_match('/^[0-9a-f]{16}$/', $reportId)) {
            acp_json_response(['ok' => false, 'error' => 'Invalid report ID'], 400);
        }

        $path = acp_report_path($acpConfig, $reportId);
        if (!is_file($path)) {
            acp_json_response(['ok' => false, 'error' => 'Report not found'], 404);
        }

        $report = json_decode((string) file_get_contents($path), true);
        if (!is_array($report)) {
            acp_json_response(['ok' => false, 'error' => 'Invalid report data'], 500);
        }

        $detection = is_array($report['serverDetection'] ?? null) ? $report['serverDetection'] : null;
        $evidence = is_array($detection['evidenceChain'] ?? null) ? $detection['evidenceChain'] : null;

        $result = [
            'ok' => true,
            'reportId' => $reportId,
            'hasEvidenceChain' => $evidence !== null,
            'serverAddress' => (string) ($report['serverAddress'] ?? ''),
            'serverName' => (string) ($report['serverName'] ?? ''),
            'verification' => [
                'status' => 'unknown',
                'checks' => [],
            ],
        ];

        // Check 1: Evidence chain exists and is valid
        if ($evidence !== null) {
            $proofPoints = is_array($evidence['proofPoints'] ?? null) ? $evidence['proofPoints'] : [];
            $result['verification']['checks'][] = [
                'name' => 'Evidence chain present',
                'passed' => true,
                'detail' => count($proofPoints) . ' proof points recorded',
            ];

            // Check 2: Chain hash verification
            $chainHash = (string) ($evidence['chainHash'] ?? '');
            if ($chainHash !== '') {
                $result['verification']['checks'][] = [
                    'name' => 'Chain hash present',
                    'passed' => true,
                    'detail' => substr($chainHash, 0, 16) . '...',
                ];
            }

            // Check 3: Connection consistency
            $consistent = (bool) ($evidence['consistentConnection'] ?? true);
            $disconnects = (int) ($evidence['disconnectionEvents'] ?? 0);
            $result['verification']['checks'][] = [
                'name' => 'Connection consistency',
                'passed' => $consistent && $disconnects === 0,
                'detail' => $consistent ? 'Stable connection throughout scan' : "Unstable: {$disconnects} disconnection(s)",
            ];

            // Check 4: Final status
            $finalStatus = (string) ($evidence['finalStatus'] ?? '');
            $result['verification']['checks'][] = [
                'name' => 'Final connection status',
                'passed' => $finalStatus === 'connected',
                'detail' => $finalStatus,
            ];

            $result['verification']['status'] = $consistent && $disconnects === 0 && $finalStatus === 'connected'
                ? 'verified' : 'suspicious';
        } else {
            $result['verification']['checks'][] = [
                'name' => 'Evidence chain present',
                'passed' => false,
                'detail' => 'No continuous monitoring evidence (older scanner version)',
            ];
            $result['verification']['status'] = 'legacy';
        }

        // Check 5: Server still reachable (optional live verification)
        $serverAddress = (string) ($report['serverAddress'] ?? '');
        if ($serverAddress !== '') {
            $liveCheck = acp_query_a2s($serverAddress);
            $result['verification']['liveServerCheck'] = $liveCheck !== null ? [
                'reachable' => true,
                'name' => $liveCheck['name'] ?? '',
                'map' => $liveCheck['map'] ?? '',
                'players' => $liveCheck['players'] ?? 0,
            ] : ['reachable' => false];

            if ($liveCheck !== null) {
                $nameMatch = strcasecmp(trim($liveCheck['name'] ?? ''), trim($result['serverName'])) === 0;
                $result['verification']['checks'][] = [
                    'name' => 'Live server verification',
                    'passed' => $nameMatch,
                    'detail' => $nameMatch ? 'Server name matches report' : 'Server name differs from report',
                ];
            }
        }

        acp_json_response($result);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Admin Cheats Manager API
    // ────────────────────────────────────────────────────────────────────────

    // List all signatures, with optional search
    if ($action === 'signatures') {
        acp_require_admin($acpConfig);
        $document = uds_signature_store_load($acpConfig['databaseFile']);
        $rules = uds_signature_store_rules($document);
        $search = strtolower(trim((string) ($_GET['q'] ?? '')));

        if ($search !== '') {
            $rules = array_values(array_filter($rules, static function (array $r) use ($search): bool {
                return stripos(($r['id'] ?? '') . ' ' . ($r['name'] ?? '') . ' ' . ($r['description'] ?? ''), $search) !== false;
            }));
        }

        acp_json_response([
            'ok'         => true,
            'total'      => count(uds_signature_store_rules($document)),
            'filtered'   => count($rules),
            'counts'     => uds_signature_store_counts(uds_signature_store_rules($document)),
            'signatures' => $rules,
        ]);
    }

    // Add a new signature
    if ($action === 'signature_add') {
        acp_require_admin($acpConfig);
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            acp_json_response(['ok' => false, 'error' => 'POST required'], 405);
        }

        $body = json_decode((string) file_get_contents('php://input'), true);
        if (!is_array($body)) {
            acp_json_response(['ok' => false, 'error' => 'Invalid JSON body'], 400);
        }

        $document = uds_signature_store_load($acpConfig['databaseFile']);
        $rules = uds_signature_store_rules($document);

        try {
            $newRule = uds_signature_store_build_rule($body, $rules);
        } catch (InvalidArgumentException $e) {
            acp_json_response(['ok' => false, 'error' => $e->getMessage()], 400);
        }

        // Reject duplicate IDs
        if (uds_signature_store_find_by_id($rules, $newRule['id']) !== null) {
            acp_json_response(['ok' => false, 'error' => 'A signature with ID "' . $newRule['id'] . '" already exists'], 409);
        }

        $rules[] = $newRule;
        uds_signature_store_save_rules($acpConfig['databaseFile'], $document, $rules);

        acp_json_response(['ok' => true, 'signature' => $newRule, 'total' => count($rules)]);
    }

    // Edit an existing signature
    if ($action === 'signature_edit') {
        acp_require_admin($acpConfig);
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            acp_json_response(['ok' => false, 'error' => 'POST required'], 405);
        }

        $body = json_decode((string) file_get_contents('php://input'), true);
        if (!is_array($body)) {
            acp_json_response(['ok' => false, 'error' => 'Invalid JSON body'], 400);
        }

        $id = trim((string) ($body['id'] ?? ''));
        if ($id === '') {
            acp_json_response(['ok' => false, 'error' => 'Signature ID is required'], 400);
        }

        $document = uds_signature_store_load($acpConfig['databaseFile']);
        $rules = uds_signature_store_rules($document);
        $found = uds_signature_store_find_by_id($rules, $id);

        if ($found === null) {
            acp_json_response(['ok' => false, 'error' => 'Signature not found: ' . $id], 404);
        }

        [$index, $existing] = $found;

        // Merge: only overwrite fields that were explicitly provided
        $merged = $existing;
        foreach (['name', 'severity', 'confidence', 'description', 'sourceGroup'] as $field) {
            if (isset($body[$field]) && trim((string) $body[$field]) !== '') {
                $merged[$field] = trim((string) $body[$field]);
            }
        }
        if (isset($body['enabled'])) {
            $merged['enabled'] = $body['enabled'] !== false && $body['enabled'] !== 'false';
        }
        if (isset($body['scopes']) && is_array($body['scopes'])) {
            $merged['scopes'] = $body['scopes'];
        }
        if (isset($body['match']) && is_array($body['match'])) {
            $merged['match'] = $body['match'];
        }
        // Rebuild match from matchType + matchValue (admin form shortcut)
        if (isset($body['matchType'], $body['matchValue']) && trim((string) $body['matchValue']) !== '') {
            try {
                $rebuilt = uds_signature_store_build_rule(array_merge($merged, $body), $rules);
                $merged['match'] = $rebuilt['match'];
                $merged['scopes'] = $rebuilt['scopes'];
            } catch (InvalidArgumentException $e) {
                // Ignore rebuild errors, keep existing match
            }
        }

        $rules[$index] = $merged;
        uds_signature_store_save_rules($acpConfig['databaseFile'], $document, $rules);

        acp_json_response(['ok' => true, 'signature' => $merged]);
    }

    // Delete a signature
    if ($action === 'signature_delete') {
        acp_require_admin($acpConfig);
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            acp_json_response(['ok' => false, 'error' => 'POST required'], 405);
        }

        $body = json_decode((string) file_get_contents('php://input'), true);
        $id = trim((string) ($body['id'] ?? $_POST['id'] ?? ''));
        if ($id === '') {
            acp_json_response(['ok' => false, 'error' => 'Signature ID is required'], 400);
        }

        $document = uds_signature_store_load($acpConfig['databaseFile']);
        $rules = uds_signature_store_rules($document);

        if (uds_signature_store_find_by_id($rules, $id) === null) {
            acp_json_response(['ok' => false, 'error' => 'Signature not found: ' . $id], 404);
        }

        $rules = uds_signature_store_remove_by_id($rules, $id);
        uds_signature_store_save_rules($acpConfig['databaseFile'], $document, $rules);

        acp_json_response(['ok' => true, 'deleted' => $id, 'total' => count($rules)]);
    }

    // Test an input against all rules (dry-run)
    if ($action === 'signature_test') {
        acp_require_admin($acpConfig);
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            acp_json_response(['ok' => false, 'error' => 'POST required'], 405);
        }

        $body = json_decode((string) file_get_contents('php://input'), true);
        $input = trim((string) ($body['input'] ?? ''));
        if ($input === '') {
            acp_json_response(['ok' => false, 'error' => 'Test input is required'], 400);
        }

        $document = uds_signature_store_load($acpConfig['databaseFile']);
        $rules = uds_signature_store_rules($document);
        $hits = uds_signature_store_test_input($rules, $input);

        acp_json_response([
            'ok'      => true,
            'input'   => $input,
            'matches' => count($hits),
            'hits'    => $hits,
        ]);
    }

    // Bulk import hashes as new signatures
    if ($action === 'signature_import') {
        acp_require_admin($acpConfig);
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            acp_json_response(['ok' => false, 'error' => 'POST required'], 405);
        }

        $body = json_decode((string) file_get_contents('php://input'), true);
        if (!is_array($body)) {
            acp_json_response(['ok' => false, 'error' => 'Invalid JSON body'], 400);
        }

        $name = trim((string) ($body['name'] ?? 'Imported Cheat Hash'));
        $severity = strtoupper(trim((string) ($body['severity'] ?? 'DETECTED')));
        $description = trim((string) ($body['description'] ?? 'Bulk-imported cheat file hash.'));
        $hashType = strtolower(trim((string) ($body['hashType'] ?? 'sha256')));
        $hashes = trim((string) ($body['hashes'] ?? ''));

        if ($hashes === '') {
            acp_json_response(['ok' => false, 'error' => 'Hash list is required'], 400);
        }
        if (!in_array($hashType, ['sha256', 'md5'], true)) {
            acp_json_response(['ok' => false, 'error' => 'hashType must be sha256 or md5'], 400);
        }

        $hashList = array_values(array_unique(array_filter(
            array_map('strtolower', array_map('trim', preg_split('/[\r\n,;\s]+/', $hashes))),
            static function (string $h) use ($hashType): bool {
                return $hashType === 'sha256'
                    ? (bool) preg_match('/^[0-9a-f]{64}$/', $h)
                    : (bool) preg_match('/^[0-9a-f]{32}$/', $h);
            }
        )));

        if ($hashList === []) {
            acp_json_response(['ok' => false, 'error' => 'No valid hashes found in input'], 400);
        }

        $document = uds_signature_store_load($acpConfig['databaseFile']);
        $rules = uds_signature_store_rules($document);

        // Collect existing hashes to avoid duplicates
        $existingHashes = [];
        foreach ($rules as $rule) {
            $m = $rule['match'] ?? [];
            foreach (['sha256', 'md5'] as $ht) {
                $vals = $m[$ht] ?? [];
                if (!is_array($vals)) { $vals = [$vals]; }
                foreach ($vals as $v) {
                    $existingHashes[strtolower((string) $v)] = true;
                }
            }
        }

        $added = 0;
        $skipped = 0;

        foreach ($hashList as $hash) {
            if (isset($existingHashes[$hash])) {
                $skipped++;
                continue;
            }

            $id = uds_signature_store_generate_id($name, $rules);
            $rules[] = [
                'id'          => $id,
                'enabled'     => true,
                'name'        => $name,
                'severity'    => in_array($severity, ['DETECTED', 'WARNING', 'INFO'], true) ? $severity : 'DETECTED',
                'confidence'  => 'high',
                'description' => $description,
                'sourceGroup' => 'admin-import',
                'scopes'      => ['module', 'driver', 'hl-file', 'process'],
                'match'       => [$hashType => [$hash]],
            ];
            $existingHashes[$hash] = true;
            $added++;
        }

        if ($added > 0) {
            uds_signature_store_save_rules($acpConfig['databaseFile'], $document, $rules);
        }

        acp_json_response([
            'ok'      => true,
            'added'   => $added,
            'skipped' => $skipped,
            'total'   => count($rules),
        ]);
    }

    // Promote a corpus "Unknown" artifact into a cheat signature
    if ($action === 'signature_promote') {
        acp_require_admin($acpConfig);
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            acp_json_response(['ok' => false, 'error' => 'POST required'], 405);
        }

        $body = json_decode((string) file_get_contents('php://input'), true);
        if (!is_array($body)) {
            acp_json_response(['ok' => false, 'error' => 'Invalid JSON body'], 400);
        }

        $sha256 = strtolower(trim((string) ($body['sha256'] ?? '')));
        if (!preg_match('/^[0-9a-f]{64}$/', $sha256)) {
            acp_json_response(['ok' => false, 'error' => 'sha256 must be 64 hex characters'], 400);
        }

        $cheatName = trim((string) ($body['name'] ?? ''));

        // Look up the artifact in the corpus for its metadata
        $pdo = acp_corpus_open($acpConfig);
        $stmt = $pdo->prepare('SELECT name, path_sample, kind FROM artifacts WHERE sha256 = ?');
        $stmt->execute([$sha256]);
        $artifact = $stmt->fetch();

        if ($cheatName === '' && $artifact) {
            $cheatName = (string) ($artifact['name'] ?? 'Unknown cheat');
        }
        if ($cheatName === '') {
            $cheatName = 'Promoted cheat hash';
        }

        // Classify in corpus
        acp_corpus_classify($pdo, $sha256, 'cheat', 'Promoted to signature via Admin Cheats Manager');

        // Also add to cheats_database.json so it matches by hash even without corpus
        $document = uds_signature_store_load($acpConfig['databaseFile']);
        $rules = uds_signature_store_rules($document);

        $id = uds_signature_store_generate_id($cheatName, $rules);
        $rules[] = [
            'id'          => $id,
            'enabled'     => true,
            'name'        => $cheatName,
            'severity'    => strtoupper(trim((string) ($body['severity'] ?? 'DETECTED'))),
            'confidence'  => 'high',
            'description' => trim((string) ($body['description'] ?? 'Flagged from corpus review.')),
            'sourceGroup' => 'corpus-promote',
            'scopes'      => ['module', 'driver', 'hl-file', 'process'],
            'match'       => ['sha256' => [$sha256]],
        ];
        uds_signature_store_save_rules($acpConfig['databaseFile'], $document, $rules);

        acp_json_response([
            'ok'        => true,
            'id'        => $id,
            'name'      => $cheatName,
            'sha256'    => $sha256,
            'total'     => count($rules),
        ]);
    }

    acp_json_response(['ok' => false, 'error' => 'Unknown action'], 404);
} catch (Throwable $e) {
    // Detail goes to the server log, not to the caller: the message can carry absolute paths
    // and database internals.
    error_log('[ACS] ' . $e->getMessage());
    acp_json_response(['ok' => false, 'error' => 'Internal error'], 500);
}

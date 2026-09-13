<?php
declare(strict_types=1);
require_once __DIR__ . '/signature_store.php';
require_once __DIR__ . '/corpus.php';
require_once __DIR__ . '/behavior.php';
require_once __DIR__ . '/clients.php';
require_once __DIR__ . '/report_index.php';
require_once __DIR__ . '/report_ingest.php';

/**
 * Reads a configuration value from the environment.
 *
 * ACS_* is the current name. ACP_* is still honoured because the project was renamed
 * after desktop clients had already shipped with ACP_API_TOKEN baked into them and
 * servers were already running with ACP_* in their environment - a rename that silently
 * turns off report uploads is a worse outcome than carrying an alias.
 */
function acs_env(string $name, string $default = ''): string
{
    $value = getenv('ACS_' . $name);
    if ($value === false || trim((string) $value) === '') {
        $value = getenv('ACP_' . $name);
    }

    return $value === false ? $default : trim((string) $value);
}

$acpConfig = [
    'databaseFile' => __DIR__ . '/database/cheats_database.json',
    'reportsDir' => __DIR__ . '/reports',
    'maxReportBytes' => 20 * 1024 * 1024,
    'apiToken' => acs_env('API_TOKEN'),
    // Artifact corpus: every hash ever observed, with prevalence.
    //
    // A static .sqlite file is served by the web server directly, bypassing PHP, so .htaccess
    // is the only thing standing between it and the internet -- and nginx ignores .htaccess
    // entirely. Set ACP_CORPUS_FILE to a path OUTSIDE the web root on any real deployment.
    'corpusFile' => acs_env('CORPUS_FILE') ?: (__DIR__ . '/database/corpus.sqlite'),
    // Separate from the upload token: classifying a hash changes verdicts for every player,
    // so it must not be doable with the secret that ships on every client machine.
    'adminToken' => acs_env('ADMIN_TOKEN'),

    // Server-side behavioural telemetry from the ReHLDS plugin. Same reasoning as the
    // corpus: keep the file outside the web root on any real deployment, because nginx
    // will happily serve a .sqlite that .htaccess thinks it is protecting.
    'behaviorFile' => acs_env('BEHAVIOR_FILE') ?: (__DIR__ . '/database/behavior.sqlite'),

    // Server connection history: which server each player was on at scan time.
    // Separate from behavior.sqlite because this is populated by the desktop scanner,
    // not the ReHLDS plugin.
    'serverHistoryFile' => acs_env('SERVER_HISTORY_FILE') ?: (__DIR__ . '/database/server_history.sqlite'),

    // The HMAC key game servers sign telemetry with. Deliberately NOT defaulted to
    // apiToken: that secret ships inside the desktop client on every player's machine,
    // and anyone holding it could post fabricated evidence against any SteamID. With no
    // telemetry secret set, the endpoint refuses every upload rather than accepting
    // unsigned ones.
    'telemetrySecret' => acs_env('TELEMETRY_SECRET'),
    'maxTelemetryBytes' => 2 * 1024 * 1024,

    // Known-legitimate CS 1.6 client distributions. Most of the surviving player base
    // does not run the retail Steam client, and several of these mods detour the engine
    // by design - without this file those players look like cheaters.
    'clientProfilesFile' => acs_env('CLIENT_PROFILES') ?: (__DIR__ . '/database/client_profiles.json'),

    // Derived index over reports/, so list views stop opening and JSON-decoding every
    // stored report. Safe to delete: it rebuilds itself from the files.
    'reportIndexFile' => acs_env('REPORT_INDEX') ?: (__DIR__ . '/database/report_index.sqlite'),

    // Optional VirusTotal API key for live v3 file/hash queries and automated scans on the download page
    'virustotalApiKey' => acs_env('VIRUSTOTAL_API_KEY') ?: '9b11dc4115f0f0a4279f39ad10704323fd4a24e14a8f669b4d81362994f591e3',
];

// Report integrity: the ACS desktop client HMAC-signs the serialized report so a report body
// cannot be swapped or edited in transit. The secret reuses the API token unless overridden.
$acpConfig['signatureSecret'] = (acs_env('REPORT_SECRET') ?: $acpConfig['apiToken']);
$acpConfig['requireReportSignature'] = filter_var(acs_env('REQUIRE_REPORT_SIGNATURE') ?: '0', FILTER_VALIDATE_BOOLEAN);

function acp_h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function acp_ensure_dir(string $path): void
{
    if (!is_dir($path) && !mkdir($path, 0755, true) && !is_dir($path)) {
        throw new RuntimeException('Unable to create directory: ' . $path);
    }
}

function acp_json_response(array $payload, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

function acp_load_database(array $config): array
{
    $data = uds_signature_store_load($config['databaseFile']);
    $feedPath = $config['signatureFeedFile'] ?? (__DIR__ . '/database/curated_hashes.json');
    if (is_file($feedPath)) {
        $feed = uds_signature_store_load($feedPath);
        $data['signatures'] = array_merge($data['signatures'], $feed['signatures']);
        $data['feedPublishedAt'] = $feed['publishedAt'] ?? '';
        $data['feedSha256'] = $feed['feedSha256'] ?? '';
    }
    // Only explicit administrator classifications become live hash rules. Popularity
    // and client-submitted labels cannot add detection signatures.
    $data['reviewedHashRules'] = 0;
    try {
        $pdo = acp_corpus_open($config);
        $rows = $pdo->query("SELECT sha256 FROM artifacts WHERE state = 'cheat' AND state_source = 'admin' ORDER BY sha256");
        foreach ($rows as $row) {
            $sha = (string) $row['sha256'];
            if (!preg_match('/^[a-f0-9]{64}$/', $sha)) continue;
            $data['signatures'][] = [
                'id' => 'acs-reviewed-' . $sha, 'name' => 'Administrator-reviewed cheat hash',
                'severity' => 'DETECTED', 'confidence' => 'high', 'enabled' => true,
                'scopes' => ['module', 'driver', 'hl-file', 'process'], 'match' => ['sha256' => [$sha]],
            ];
            $data['reviewedHashRules']++;
        }
    } catch (Throwable $e) {
        $data['reviewedHashRulesAvailable'] = false;
        error_log('[ACS] Reviewed signatures unavailable: ' . $e->getMessage());
    }
    $data['counts'] = uds_signature_store_counts(uds_signature_store_rules($data));
    $data['revision'] = hash('sha256', json_encode($data['signatures'], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    return $data;
}

function acp_request_token(): string
{
    $authorization = trim((string) ($_SERVER['HTTP_AUTHORIZATION'] ?? ''));
    if (preg_match('/^Bearer\s+(.+)$/i', $authorization, $match)) {
        return trim($match[1]);
    }

    $acs = trim((string) ($_SERVER['HTTP_X_ACS_TOKEN'] ?? ''));
    if ($acs !== '') {
        return $acs;
    }

    // Pre-rename clients still send X-ACP-Token.
    return trim((string) ($_SERVER['HTTP_X_ACP_TOKEN'] ?? ''));
}

function acp_sign_report(string $payload, string $secret): string
{
    return base64_encode(hash_hmac('sha256', $payload, $secret, true));
}

function acp_verify_report_signature(string $payload, string $signature, string $secret): bool
{
    if ($payload === '' || $signature === '') {
        return false;
    }

    return hash_equals(acp_sign_report($payload, $secret), $signature);
}

function acp_require_upload_auth(array $config): void
{
    $expected = (string) ($config['apiToken'] ?? '');
    if ($expected === '') {
        $remote = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        if (in_array($remote, ['127.0.0.1', '::1', ''], true)) {
            return;
        }
        acp_json_response(['ok' => false, 'error' => 'Report uploads are disabled until ACP_API_TOKEN is configured'], 503);
    }

    $provided = acp_request_token();
    if ($provided === '' || !hash_equals($expected, $provided)) {
        acp_json_response(['ok' => false, 'error' => 'Unauthorized report upload'], 401);
    }
}

/**
 * Admin gate for corpus classification.
 *
 * Fails closed: with no ACP_ADMIN_TOKEN set, classification is refused outright rather than
 * left open. An unset token must never mean "anyone may reclassify".
 */
function acp_require_admin(array $config): void
{
    $expected = (string) ($config['adminToken'] ?? '');
    if ($expected === '') {
        acp_json_response([
            'ok' => false,
            'error' => 'Corpus administration is disabled until ACP_ADMIN_TOKEN is configured',
        ], 503);
    }

    $supplied = acp_request_token();
    if ($supplied === '' || !hash_equals($expected, $supplied)) {
        acp_json_response(['ok' => false, 'error' => 'Admin token required'], 401);
    }
}

// ---------------------------------------------------------------------------
// Viewing player data
//
// reports/.htaccess blocks the files, but the dashboard reads the same files and hands
// them straight back - including ?download=json, which returns the raw report with the
// SteamID, IP, disk serial, process list and driver list in it. Blocking the directory
// while leaving index.php open protects nothing.
//
// Three ways in, in order of preference:
//   * the admin token, as a header, ?token=, or the cookie a successful ?token= sets
//   * a per-report share key, so an accused player can hand an admin one link without
//     the admin needing a token and without exposing every other report
//   * a request from localhost, so a local deployment keeps working untouched
// ---------------------------------------------------------------------------

function acp_is_local_request(): bool
{
    return in_array((string) ($_SERVER['REMOTE_ADDR'] ?? ''), ['127.0.0.1', '::1', ''], true);
}

function acp_admin_authenticated(array $config): bool
{
    $expected = (string) ($config['adminToken'] ?? '');
    if ($expected === '') {
        return false;
    }

    $supplied = acp_request_token();
    if ($supplied === '') {
        $supplied = trim((string) ($_GET['token'] ?? $_COOKIE['acs_admin'] ?? ''));
    }

    return $supplied !== '' && hash_equals($expected, $supplied);
}

/**
 * Unguessable per-report key. Derived rather than stored so it needs no schema, and
 * scoped to one report id so a leaked link cannot enumerate the rest.
 */
function acp_report_view_key(array $config, string $id): string
{
    $secret = (string) ($config['signatureSecret'] ?? '');
    if ($secret === '') {
        $secret = (string) ($config['adminToken'] ?? '');
    }
    if ($secret === '') {
        // No secret configured at all: the key would be guessable, so refuse to mint one
        // rather than hand out a link that looks private and is not.
        return '';
    }

    return substr(hash_hmac('sha256', 'acs-report-view:' . $id, $secret), 0, 32);
}

function acp_can_view_report(array $config, string $id): bool
{
    if (acp_admin_authenticated($config) || acp_is_local_request()) {
        return true;
    }

    $supplied = trim((string) ($_GET['k'] ?? ''));
    $expected = acp_report_view_key($config, $id);

    return $supplied !== '' && $expected !== '' && hash_equals($expected, $supplied);
}

function acp_deny_view(string $message): never
{
    http_response_code(403);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8">'
       . '<meta name="viewport" content="width=device-width,initial-scale=1"><title>Access denied</title>'
       . '<style>body{background:#0e1217;color:#f0f6fc;font:15px/1.6 system-ui,sans-serif;margin:0;'
       . 'display:grid;place-items:center;min-height:100vh;padding:24px}main{max-width:52ch}'
       . 'h1{font-size:1.3rem;margin:0 0 .6em}p{opacity:.8;margin:0 0 .8em}'
       . 'code{background:#1b222c;padding:2px 6px;border-radius:3px;font-size:.9em}</style></head>'
       . '<body><main><h1>Access denied</h1><p>' . acp_h($message) . '</p>'
       . '<p>Sign in by appending <code>?token=YOUR_ADMIN_TOKEN</code>, or open the report through '
       . 'its share link.</p></main></body></html>';
    exit;
}

/** Gate for anything that lists or aggregates reports. Admin or localhost only. */
function acp_require_dashboard_access(array $config): void
{
    if (acp_admin_authenticated($config) || acp_is_local_request()) {
        return;
    }

    acp_deny_view((string) ($config['adminToken'] ?? '') === ''
        ? 'This dashboard lists scan reports containing player identifiers, so it stays closed '
          . 'until ACS_ADMIN_TOKEN is configured on the server.'
        : 'Scan reports contain player identifiers (SteamID, IP, disk serial) and are not public.');
}

/** Gate for a single report. Admin, localhost, or a valid share key for THAT report. */
function acp_require_report_access(array $config, string $id): void
{
    if (acp_can_view_report($config, $id)) {
        return;
    }

    acp_deny_view('This report contains player identifiers and is not public.');
}

/** Remembers a correct ?token= so an admin does not have to re-append it on every link. */
function acp_admin_remember_token(array $config): void
{
    $supplied = trim((string) ($_GET['token'] ?? ''));
    if ($supplied === '' || !acp_admin_authenticated($config)) {
        return;
    }

    setcookie('acs_admin', $supplied, [
        'expires'  => time() + 43200,
        'path'     => '/',
        'httponly' => true,
        'samesite' => 'Strict',
        'secure'   => !empty($_SERVER['HTTPS']),
    ]);
}

function acp_report_path(array $config, string $id): string
{
    $safeId = preg_replace('/[^a-zA-Z0-9_-]/', '', $id) ?: '';
    return $config['reportsDir'] . '/' . $safeId . '.json';
}

function acp_load_report(array $config, string $id): ?array
{
    $path = acp_report_path($config, $id);
    if (!is_file($path)) {
        return null;
    }

    $data = json_decode((string) file_get_contents($path), true);
    return is_array($data) ? $data : null;
}

function acp_report_findings(array $report): array
{
    $findings = $report['findings'] ?? [];
    if (!is_array($findings)) {
        return [];
    }

    return array_values(array_filter($findings, static fn($finding): bool => is_array($finding) && !acp_suppressed_finding($finding)));
}

function acp_suppressed_finding(array $finding): bool
{
    $rule = strtolower((string) ($finding['ruleName'] ?? ''));
    $ruleId = strtolower((string) ($finding['ruleId'] ?? ''));
    $subject = strtolower(basename((string) ($finding['subject'] ?? '')));
    $trustedAsi = ['mp3dec.asi', 'mssv12.asi', 'mssv29.asi'];

    if ($rule === 'asi module loaded into hl.exe' && in_array($subject, $trustedAsi, true)) {
        return true;
    }

    return $ruleId === 'acp-steam-emulator-artifact'
        || $ruleId === 'acp-local-steamclient'
        || $ruleId === 'acp-steam-overlay-not-loaded'
        || $rule === 'steam emulator / no-steam artifact'
        || $rule === 'local steamclient.dll in game directory'
        || $rule === 'steam overlay module not loaded';
}

function acp_report_summary(array $report): array
{
    $findings = acp_report_findings($report);
    $categories = $report['detectedCheats'] ?? [];
    $severity = ['DETECTED' => 0, 'WARNING' => 0, 'INFO' => 0];
    $categoryCounts = [
        'injected' => 0,
        'loaded' => 0,
        'resources' => 0,
        'behavioral' => 0,
        'previouslyLaunched' => 0,
        'installedInOs' => 0,
        'downloaded' => 0,
    ];

    if (is_array($findings)) {
        foreach ($findings as $finding) {
            $key = strtoupper((string) ($finding['severity'] ?? 'INFO'));
            if (!array_key_exists($key, $severity)) {
                $key = 'INFO';
            }
            $severity[$key]++;
        }
    }

    if (is_array($categories)) {
        foreach ($categoryCounts as $key => $_) {
            $value = $categories[$key] ?? [];
            $categoryCounts[$key] = is_array($value) ? count($value) : 0;
        }
    }

    $ip = (string) ($report['remoteAddress'] ?? '');
    
    // In-game active detections (injected in memory, loaded in game dir, cheat player models/resources, or live behavioral cheat)
    $inGameActive = 0;
    if (is_array($findings)) {
        foreach ($findings as $f) {
            $sev = strtoupper((string) ($f['severity'] ?? 'INFO'));
            if ($sev === 'DETECTED') {
                $cat = strtolower((string) ($f['category'] ?? ''));
                if (in_array($cat, ['injected', 'loaded', 'resources', 'memory', 'behavioral'], true)) {
                    $inGameActive++;
                }
            }
        }
    }
    // ECD Parity: DETECTED (Red) requires active in-game cheat. If detections only exist in historical/offline traces, status is WARNING (Yellow / Suspect).
    $evidenceStatus = $inGameActive > 0 ? 'DETECTED' : (($severity['DETECTED'] > 0 || $severity['WARNING'] > 0) ? 'WARNING' : 'CLEAN');


    return [
        'id' => (string) ($report['id'] ?? ''),
        'scanner' => (string) ($report['scanner'] ?? 'ACS Scanner'),
        'scannerVersion' => (string) ($report['scannerVersion'] ?? ''),
        'uploadedAt' => (string) ($report['uploadedAt'] ?? $report['createdAt'] ?? ''),
        'createdAt' => (string) ($report['createdAt'] ?? ''),
        'scanStartedAt' => (string) ($report['scanStartedAt'] ?? ''),
        'scanFinishedAt' => (string) ($report['scanFinishedAt'] ?? ''),
        'scanDurationMs' => (int) ($report['scanDurationMs'] ?? 0),
        'gameLaunchTime' => (string) ($report['gameLaunchTime'] ?? ''),
        'localTime' => (string) ($report['localTime'] ?? ''),
        'utcOffsetMinutes' => (int) ($report['utcOffsetMinutes'] ?? 0),
        'timeZoneName' => (string) ($report['timeZoneName'] ?? ''),
        'serverAddress' => (string) ($report['serverAddress'] ?? ''),
        'serverName' => (string) ($report['serverName'] ?? ''),
        'serverMap' => (string) ($report['serverMap'] ?? ''),
        'machine' => (string) ($report['machineName'] ?? 'Unknown'),
        'playerName' => (string) ($report['playerName'] ?? getenv('USERNAME') ?: 'Unknown'),
        'playerId' => (string) ($report['playerId'] ?? substr(hash('sha256', (string) ($report['machineName'] ?? 'unknown')), 0, 8)),
        'steamId' => (string) ($report['steamId'] ?? ''),
        'steamAccountId' => (string) ($report['steamAccountId'] ?? ''),
        'steamId2' => (string) ($report['steamId2'] ?? ''),
        'steamId3' => (string) ($report['steamId3'] ?? ''),
        'steamIdentitySource' => (string) ($report['steamIdentitySource'] ?? ''),
        'hddSerial' => (string) ($report['hddSerial'] ?? ''),
        'deviceFingerprint' => (string) ($report['deviceFingerprint'] ?? ''),
        'ip' => $ip,
        'maskedIp' => acp_mask_ip($ip),
        'os' => (string) ($report['osVersion'] ?? ''),
        'gameBuild' => (string) ($report['gameBuild'] ?? 'Counter-Strike: 1.6'),
        'renderMode' => (string) ($report['renderMode'] ?? 'Unknown'),
        'gameWindowMode' => (string) ($report['gameWindowMode'] ?? 'Unknown'),
        'gameWindowTitle' => (string) ($report['gameWindowTitle'] ?? ''),
        'gameWindowBounds' => (string) ($report['gameWindowBounds'] ?? ''),
        'gameRoot' => (string) ($report['gameRoot'] ?? ''),
        'steamPath' => (string) ($report['steamPath'] ?? ''),
        'configPath' => (string) ($report['configPath'] ?? ''),
        'hlPath' => (string) ($report['hlPath'] ?? ''),
        'hooked' => (bool) ($report['hooked'] ?? false),
        'hookedAddr' => (string) ($report['hookedAddr'] ?? ''),
        'status' => $evidenceStatus,
        'detected' => $severity['DETECTED'],
        'warnings' => $severity['WARNING'],
        'info' => $severity['INFO'],
        'categoryCounts' => $categoryCounts,
        'scannedProcesses' => (int) ($report['summary']['processes'] ?? 0),
        'scannedDrivers' => (int) ($report['summary']['drivers'] ?? 0),
        'scannedFiles' => (int) ($report['summary']['hlFiles'] ?? 0),
        'scannedModules' => (int) ($report['summary']['modules'] ?? 0),
        'scannedMemoryArtifacts' => (int) ($report['summary']['memoryArtifacts'] ?? 0),
        'scannedLiveBehaviorSamples' => (int) ($report['summary']['liveBehaviorSamples'] ?? 0),
    ];
}

function acp_mask_ip(string $ip): string
{
    // Privacy: the whole last octet is hidden (109.187.61.***), not just its final
    // digit, so a public report never narrows a player down to one host.
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return preg_replace('/\.\d{1,3}$/', '.***', $ip) ?? $ip;
    }

    return $ip;
}

/**
 * Classify the exact client/build the player used.
 *
 * The desktop scanner already labels NextClient / GSClient / RevEmu / SmartSteamEmu /
 * cracked builds in `gameBuild`; older reports only carry the raw module list, so the
 * same keywords are re-checked here against modules, paths and identity source.
 *
 * Returns ['label' => human text, 'class' => badge css class].
 */
function acp_game_build_badge(array $report, string $gameBuild): array
{
    $surface = strtolower($gameBuild . ' ' . (string) ($report['gameRoot'] ?? '') . ' ' . (string) ($report['hlPath'] ?? '') . ' ' . (string) ($report['steamIdentitySource'] ?? ''));
    
    // Check all loaded module names and paths
    $modules = is_array($report['modules'] ?? null) ? $report['modules'] : [];
    $moduleNames = [];
    $hasLocalSteamClient = false;
    $hasSteamApiC = false;
    $hasRevSrvBrowser = false;
    
    $gameRootNorm = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, strtolower(trim((string) ($report['gameRoot'] ?? ''))));
    $hlPathNorm = strtolower((string) ($report['hlPath'] ?? ''));
    
    foreach ($modules as $module) {
        if (!is_array($module)) continue;
        $mName = strtolower((string) ($module['name'] ?? ''));
        $mPath = strtolower((string) ($module['path'] ?? ''));
        $moduleNames[] = $mName;
        $surface .= ' ' . $mName . ' ' . $mPath;
        
        if ($mName === 'steam_api_c.dll') {
            $hasSteamApiC = true;
        }
        if ($mName === 'revsrvbrowser.dll') {
            $hasRevSrvBrowser = true;
        }
        if ($mName === 'steamclient.dll' && $gameRootNorm !== '' && str_contains($mPath, $gameRootNorm)) {
            $hasLocalSteamClient = true;
        }
    }

    $hasEsk = str_contains($hlPathNorm, 'esk') || str_contains($surface, 'counter-strike esk') || str_contains($surface, 'cs esk');
    $hasWarzone = str_contains($hlPathNorm, 'warzone') || str_contains($surface, 'cs warzone');

    // 1. NextClient
    if (str_contains($surface, 'nextclient')) {
        return [
            'label' => 'NextClient (Non-Steam)',
            'class' => 'nextclient',
            'isSteam' => false,
            'cleanBuild' => 'Counter-Strike: 1.6 NextClient'
        ];
    }

    // 2. GSClient
    if (str_contains($surface, 'gsclient')) {
        return [
            'label' => 'GSClient (Non-Steam)',
            'class' => 'gsclient',
            'isSteam' => false,
            'cleanBuild' => 'Counter-Strike: 1.6 GSClient'
        ];
    }

    // 3. GoldClient
    if (str_contains($surface, 'goldclient') || str_contains($surface, 'goldsrc.dll')) {
        return [
            'label' => 'GoldClient (Non-Steam)',
            'class' => 'goldclient',
            'isSteam' => false,
            'cleanBuild' => 'Counter-Strike: 1.6 GoldClient'
        ];
    }

    // 4. RevEmu / RevCrew
    if ($hasRevSrvBrowser || str_contains($surface, 'revemu') || str_contains($surface, 'rev_emu') || str_contains($surface, 'revloader') || str_contains($surface, 'rev.ini') || str_contains($surface, 'revcrew') || str_contains($surface, 'revsrvbrowser')) {
        $label = $hasEsk ? 'Non-Steam (RevEmu / ESK)' : 'Non-Steam (RevEmu)';
        return [
            'label' => $label,
            'class' => 'revemu',
            'isSteam' => false,
            'cleanBuild' => 'Counter-Strike: 1.6 Non-Steam (RevEmu)'
        ];
    }

    // 4b. MultiEmulator
    if (str_contains($surface, 'multiemulator') || str_contains($surface, 'multiemu') || str_contains($surface, 'avsmp') || str_contains($surface, 'avs.dll')) {
        return [
            'label' => 'MultiEmulator (Non-Steam)',
            'class' => 'multiemu',
            'isSteam' => false,
            'cleanBuild' => 'Counter-Strike: 1.6 Non-Steam (MultiEmulator)'
        ];
    }

    // 5. SmartSteamEmu
    if (str_contains($surface, 'smartsteamemu') || str_contains($surface, 'sselauncher') || str_contains($surface, 'smartsteamloader')) {
        return [
            'label' => 'SmartSteamEmu (Non-Steam)',
            'class' => 'smartsteamemu',
            'isSteam' => false,
            'cleanBuild' => 'Counter-Strike: 1.6 Non-Steam (SmartSteamEmu)'
        ];
    }

    // 6. Goldberg
    if (str_contains($surface, 'goldberg') || str_contains($surface, 'steam_settings') || str_contains($surface, 'libsteam_api')) {
        return [
            'label' => 'Goldberg Emulator (Non-Steam)',
            'class' => 'goldberg',
            'isSteam' => false,
            'cleanBuild' => 'Counter-Strike: 1.6 Non-Steam (Goldberg)'
        ];
    }

    // 7. ESK distribution
    if ($hasEsk) {
        return [
            'label' => 'CS 1.6 ESK (Non-Steam)',
            'class' => 'nonsteam',
            'isSteam' => false,
            'cleanBuild' => 'Counter-Strike: 1.6 Non-Steam (ESK Edition)'
        ];
    }

    // 8. Warzone distribution
    if ($hasWarzone) {
        return [
            'label' => 'CS 1.6 Warzone (Non-Steam)',
            'class' => 'nonsteam',
            'isSteam' => false,
            'cleanBuild' => 'Counter-Strike: 1.6 Non-Steam (Warzone)'
        ];
    }

    // 9. ReHLDS / DProto server platform
    foreach (['reunion_mm', 'dproto', 'dproto_mm', 'reapi_amxx', 'amxmodx_mm', 'regamedll', 'swds.dll', 'rehlds'] as $needle) {
        if (str_contains($surface, $needle)) {
            return [
                'label' => 'ReHLDS / DProto Server Platform',
                'class' => 'rehlds',
                'isSteam' => false,
                'cleanBuild' => 'ReHLDS / DProto Dedicated Platform'
            ];
        }
    }

    // 10. Non-Steam detection via local wrappers
    if ($hasSteamApiC || $hasLocalSteamClient || str_contains($surface, 'nonsteam') || str_contains($surface, 'nosteam')) {
        return [
            'label' => 'Non-Steam',
            'class' => 'nonsteam',
            'isSteam' => false,
            'cleanBuild' => 'Counter-Strike: 1.6 Non-Steam'
        ];
    }

    // 11. Genuine Steam verification: MUST be in steamapps/common/Half-Life without local emulator DLLs
    $isSteamPath = str_contains($hlPathNorm, 'steamapps') && (str_contains($hlPathNorm, 'half-life') || str_contains($hlPathNorm, 'counter-strike'));
    if ($isSteamPath && in_array('steamclient.dll', $moduleNames, true) && !$hasLocalSteamClient && !$hasSteamApiC) {
        return [
            'label' => 'Steam (Official)',
            'class' => 'steam',
            'isSteam' => true,
            'cleanBuild' => 'Counter-Strike: 1.6 (Steam Retail)'
        ];
    }

    // If outside Steam directory, it cannot be genuine Steam retail
    if (!str_contains($hlPathNorm, 'steamapps')) {
        return [
            'label' => 'Non-Steam',
            'class' => 'nonsteam',
            'isSteam' => false,
            'cleanBuild' => 'Counter-Strike: 1.6 Non-Steam'
        ];
    }

    return [
        'label' => 'Non-Steam',
        'class' => 'nonsteam',
        'isSteam' => false,
        'cleanBuild' => 'Counter-Strike: 1.6 Non-Steam'
    ];
}

/**
 * Total scans ever seen for this player's Steam identity OR IP range.
 *
 * Counts the current report plus every stored report whose identity keys overlap on
 * steam/steam2/steam3/account or the /24 IP prefix (device-only matches are excluded:
 * the column promises "for that Steam ID and IP").
 */
function acp_count_total_scans(array $config, array $report): int
{
    $wanted = [];
    foreach (acp_identity_keys($report) as $key) {
        if (preg_match('/^(steam|steam2|steam3|account|ip24):/', $key)) {
            $wanted[$key] = true;
        }
    }
    if (count($wanted) === 0) {
        return 1;
    }

    $total = 1;
    foreach (glob($config['reportsDir'] . '/*.json') ?: [] as $path) {
        if (basename($path, '.json') === (string) ($report['id'] ?? '')) {
            continue;
        }

        $candidate = json_decode((string) @file_get_contents($path), true);
        if (!is_array($candidate) || (string) ($candidate['id'] ?? '') === (string) ($report['id'] ?? '')) {
            continue;
        }

        foreach (acp_identity_keys($candidate) as $key) {
            if (isset($wanted[$key])) {
                $total++;
                break;
            }
        }
    }

    return $total;
}

function acp_fmt_time(string $iso): string
{
    if (trim($iso) === '') {
        return '';
    }

    $ts = strtotime($iso);
    return $ts === false ? $iso : gmdate('Y-m-d H:i:s', $ts) . ' UTC';
}

/**
 * Compact list timestamp: "Today 14:22", "Yesterday 09:05", else "Y-m-d H:i".
 *
 * Day comparison uses the server's local date, which is what a reviewer reads as
 * "today" on the dashboard.
 */
function acp_short_time(string $iso): string
{
    $iso = trim($iso);
    if ($iso === '') {
        return '';
    }

    $ts = strtotime($iso);
    if ($ts === false) {
        return $iso;
    }

    $day  = date('Y-m-d', $ts);
    $time = date('H:i', $ts);

    if ($day === date('Y-m-d')) {
        return 'Today ' . $time;
    }
    if ($day === date('Y-m-d', time() - 86400)) {
        return 'Yesterday ' . $time;
    }

    return date('Y-m-d H:i', $ts);
}

function acp_time_ago(string $iso): string
{
    $ts = strtotime($iso);
    if ($ts === false) {
        return '';
    }

    $diff = time() - $ts;
    if ($diff < 0) {
        return 'in the future';
    }
    if ($diff < 60) {
        return 'just now';
    }
    if ($diff < 3600) {
        return intdiv($diff, 60) . ' min ago';
    }
    if ($diff < 86400) {
        $h = intdiv($diff, 3600);
        $m = intdiv($diff % 3600, 60);
        return $h . 'h ' . $m . 'm ago';
    }
    $d = intdiv($diff, 86400);
    return $d . ($d === 1 ? ' day ago' : ' days ago');
}

function acp_clean_os(string $raw): string
{
    $clean = trim($raw);
    if ($clean === '') {
        return 'Unknown OS';
    }

    if (preg_match('/10\.0\.(2[2-9]\d{3}|[3-9]\d{4})/', $clean, $m)) {
        return 'Windows 11 (build ' . $m[1] . ')';
    }
    if (preg_match('/10\.0\.(\d+)/', $clean, $m)) {
        return 'Windows 10 (build ' . $m[1] . ')';
    }
    if (preg_match('/6\.3\.(\d+)/', $clean)) {
        return 'Windows 8.1';
    }
    if (preg_match('/6\.2\.(\d+)/', $clean)) {
        return 'Windows 8';
    }
    if (preg_match('/6\.1\.(\d+)/', $clean)) {
        return 'Windows 7';
    }

    $clean = str_replace(['Microsoft Windows NT ', 'Microsoft Windows '], 'Windows ', $clean);
    return $clean;
}

function acp_fmt_duration_clean(int $ms): string
{
    if ($ms <= 0) {
        return 'Instant';
    }
    if ($ms < 1000) {
        return $ms . ' ms';
    }
    return number_format($ms / 1000, 2) . ' sec';
}

function acp_session_delta_text(string $launchIso, string $scanIso): string
{
    if (trim($launchIso) === '' || trim($scanIso) === '') {
        return 'Launch time not recorded';
    }
    $launchTs = strtotime($launchIso);
    $scanTs = strtotime($scanIso);
    if ($launchTs === false || $scanTs === false) {
        return 'Timeline not synced';
    }
    $diff = $scanTs - $launchTs;
    if ($diff < 0) {
        return 'Game launched after scan started';
    }
    if ($diff < 60) {
        return 'Game launched ' . $diff . 's before scan';
    }
    $mins = intdiv($diff, 60);
    $secs = $diff % 60;
    if ($mins < 60) {
        return 'Game running ' . $mins . 'm ' . ($secs > 0 ? $secs . 's ' : '') . 'before scan';
    }
    $hrs = intdiv($mins, 60);
    $remMins = $mins % 60;
    return 'Game running ' . $hrs . 'h ' . $remMins . 'm before scan';
}

/**
 * Sanitize local paths to protect player privacy (masks C:\Users\<username>\ to C:\Users\***\).
 */
function acp_sanitize_path(string $path): string
{
    if (trim($path) === '') {
        return '';
    }
    $clean = preg_replace('#([\\\\/]Users[\\\\/])[^\\\\/]+([\\\\/])#i', '$1***$2', $path) ?? $path;
    $clean = preg_replace('#([\\\\/]home[\\\\/])[^\\\\/]+([\\\\/])#i', '$1***$2', $clean) ?? $clean;
    return $clean;
}

/**
 * Mask hardware IDs (HDD serial, etc.) to prevent targeted HWID attacks or hardware cloning.
 */
function acp_mask_hwid(string $serial): string
{
    $clean = trim($serial);
    if ($clean === '' || $clean === 'Not found' || $clean === 'Unknown') {
        return 'Not captured';
    }
    $len = strlen($clean);
    if ($len <= 4) {
        return '****';
    }
    return substr($clean, 0, 4) . '****';
}

/**
 * Sanitize process inventory for public anti-cheat reports:
 * Masks private user paths and shields sensitive personal utilities from public exposure.
 */
function acp_sanitize_processes(array $processes): array
{
    $safe = [];
    $shieldedKeywords = [
        'password', 'keepass', 'bitwarden', '1password', 'auth', 'bank', 'crypto',
        'wallet', 'telegram', 'signal', 'whatsapp', 'viber', 'slack', 'outlook',
        'thunderbird', 'vpn', 'wireguard', 'openvpn', 'nordvpn', 'expressvpn'
    ];

    foreach ($processes as $proc) {
        if (!is_array($proc)) {
            continue;
        }
        $name = strtolower((string) ($proc['name'] ?? ''));
        $path = (string) ($proc['path'] ?? '');

        $isShielded = false;
        foreach ($shieldedKeywords as $keyword) {
            if (str_contains($name, $keyword) || str_contains(strtolower($path), $keyword)) {
                $isShielded = true;
                break;
            }
        }

        if ($isShielded) {
            $proc['name'] = '[Protected Process]';
            $proc['path'] = 'C:\\***\\protected.exe';
            $proc['sha256'] = '—';
            $proc['md5'] = '—';
        } else {
            $proc['path'] = acp_sanitize_path($path);
        }

        $safe[] = $proc;
    }

    return $safe;
}

if (!function_exists('acp_items')) {
    function acp_items(array $report, string $key): array
    {
        $items = $report['detectedCheats'][$key] ?? [];
        return is_array($items) ? $items : [];
    }
}

function acp_gamer_detection(array $item): array
{
    $type = (string) ($item['type'] ?? '');
    $cheat = (string) ($item['cheat'] ?? '');
    $evidence = (string) ($item['evidence'] ?? '');
    $reason = (string) ($item['reason'] ?? '');
    $time = (string) ($item['time'] ?? '');

    $module = 'hl.exe';
    $rest = $evidence;
    if (preg_match('/^([a-zA-Z0-9_\.-]+\.(?:dll|exe|asi|cfg|ini|sys)):?\s*(.*)$/i', $evidence, $m)) {
        $module = $m[1];
        $rest = $m[2];
    } elseif (stripos($evidence, 'opengl32.dll') !== false || stripos($cheat, 'opengl') !== false) {
        $module = 'opengl32.dll';
    } elseif (stripos($evidence, 'steamclient.dll') !== false) {
        $module = 'steamclient.dll';
    }

    $vector = 'Injected Hook';
    $symbol = $module;
    $destination = '';
    $category = 'INJECTION';
    $impact = 'Unauthorized code injected into game process memory.';
    $severity = 'DETECTED';

    if (stripos($cheat, 'Export table') !== false || stripos($cheat, 'Export') !== false) {
        $vector = 'Export Rewrite';
        $category = 'WALLHACK / GRAPHICS';
        if (preg_match('/^([a-zA-Z0-9_]+)\s*(?:RVA\s+([0-9a-fx]+)\s*->\s*([0-9a-fx]+))?/i', $rest, $sm)) {
            $symbol = $sm[1];
            $destination = !empty($sm[2]) ? 'RVA ' . $sm[2] . ' -> ' . ($sm[3] ?? '0x0') : '';
        }
        $impactMap = [
            'wglDeleteContext' => 'Wallhack / cham hook: intercepts OpenGL context cleanup routine',
            'wglShareLists' => 'ESP geometry hook: intercepts shared OpenGL display lists',
            'wglMakeCurrent' => 'Render pipeline hijack: hooks active OpenGL thread to draw visual ESP',
            'wglCreateLayerContext' => 'Overlay injection: spawns hidden rendering layer for visual cheats',
            'wglChoosePixelFormat' => 'Depth bypass: forces custom rendering format to disable flash & smoke',
            'wglDescribePixelFormat' => 'Buffer intercept: queries & tampers with frame buffer depth testing',
            'wglSwapBuffers' => 'Frame presentation hook: renders cheat visuals right before screen refresh',
            'glFinish' => 'Render sync hook: forces synchronization to render wallhack overlays',
            'glBegin' => 'Primitive rendering hook: modifies game models during rasterization',
            'glEnd' => 'Primitive rendering hook: injects cheat geometries after rasterization',
        ];
        $impact = $impactMap[$symbol] ?? ('Exported graphic function ' . $symbol . ' redirected to cheat module.');
    } elseif (stripos($cheat, 'Import redirected') !== false) {
        $vector = 'Import Redirect';
        $category = 'CODE HIJACK';
        if (preg_match('/^([a-zA-Z0-9_\.-]+![a-zA-Z0-9_?!@]+)\s*->\s*(.*)$/i', $rest, $sm)) {
            $symbol = $sm[1];
            $destination = $sm[2];
        } else {
            $symbol = $rest ?: 'IAT Hook';
        }
        $impactMap = [
            'msvcrt.dll!pow' => 'Aimbot trajectory math: calculation redirected into unbacked cheat memory',
            'msvcrt.dll!memset' => 'Memory scrubbing: routine clearing cheat traces in RAM redirected',
            'msvcrt.dll!memcmp' => 'Signature bypass: memory comparator redirected to cheat code',
            'msvcrt.dll!__C_specific_handler' => 'Anti-crash protection: SEH exception handler hijacked by cheat',
            'msvcrt.dll!floor' => 'Recoil / coordinate math: view angle routine redirected to cheat',
            'msvcrt.dll!??1type_info@@UEAA@XZ' => 'RTTI type destructor hijacked by cheat payload',
            'msvcrt.dll!sin' => 'Ballistic angle calculation diverted into unbacked cheat memory',
            'msvcrt.dll!memcpy' => 'Memory injection buffer copier redirected into unbacked cheat memory',
            'msvcrt.dll!_onexit' => 'Process exit intercept: executes persistence routine on shutdown',
            'msvcrt.dll!__dllonexit' => 'DLL termination intercept: detours module unload callbacks',
        ];
        $impact = $impactMap[$symbol] ?? ('Engine import ' . $symbol . ' diverted into unbacked memory ' . $destination);
    } elseif (stripos($cheat, 'code modified') !== false || stripos($cheat, 'patch') !== false) {
        $vector = 'Code Detour';
        if (preg_match('/at\s+(0x[0-9a-fA-F]+)/', $rest, $sm)) {
            $symbol = $sm[1];
            $impact = 'Active in-memory code detour: live rendering bytes modified in memory.';
        } elseif (preg_match('/(\d+\s*byte\(s\))/i', $rest, $sm)) {
            $symbol = $sm[1] . ' detour';
            $impact = 'Live process detour: 1 byte patched in Steam client authentication memory.';
        } else {
            $symbol = 'Live Detour';
            $impact = 'Executable code in memory modified from official binary on disk.';
        }
        $category = ($module === 'steamclient.dll') ? 'SECURITY BYPASS' : 'GRAPHICS DETOUR';
    } elseif (stripos($type, 'behavior') !== false) {
        $vector = 'Behavioral';
        $category = 'AIM / MOVEMENT';
        $symbol = $cheat ?: 'Combat Input';
        $impact = 'Automated snap targeting, unnatural trigger speed, or recoil assist detected.';
    } elseif (stripos($type, 'resource') !== false || stripos($type, 'asset') !== false || stripos($type, 'model') !== false) {
        $vector = 'Cheat Resource';
        $category = 'ASSETS / MODELS';
        $symbol = $cheat ?: 'Cheat Model / Sprite';
        $impact = 'Modified transparent player model, sprite, or cheat asset detected in game folder.';
        $severity = 'DETECTED';
    } elseif (stripos($type, 'download') !== false) {
        $vector = 'Downloaded Artifact';
        $category = 'DOWNLOAD';
        $symbol = $cheat ?: 'Downloaded Cheat';
        $impact = 'Cheat installer, archive, or script package downloaded onto local storage.';
        $severity = 'WARNING';
    } elseif (stripos($type, 'loaded') !== false || stripos($type, 'game folder') !== false) {
        $vector = 'Game File';
        $category = 'GAME DIRECTORY';
        $symbol = $cheat ?: 'Cheat File / Library';
        $impact = 'Unauthorized binary, disguise, or cheat asset detected in game installation.';
        $severity = 'DETECTED';
    } elseif (stripos($type, 'previously') !== false || stripos($type, 'started') !== false) {
        $vector = 'Execution History';
        $category = 'PRE-LAUNCH';
        $symbol = $cheat ?: 'Banned Utility';
        $impact = 'Known cheat loader or banned utility was executed on this PC prior to the scan.';
        $severity = 'WARNING';
    } elseif (stripos($type, 'installed') !== false) {
        $vector = 'On-Disk Artifact';
        $category = 'FILE ARTIFACT';
        $symbol = $cheat ?: 'Cheat File';
        $impact = 'Files matching known cheat binaries or scripts detected on local disk storage.';
        $severity = 'WARNING';
    }

    if (!empty($item['severity'])) {
        $severity = strtoupper((string) $item['severity']);
    }

    // -------------------------------------------------------------------------
    // Human-Friendly Resolution (ECD Report #400587 Parity)
    // -------------------------------------------------------------------------
    // 1. Clean Category & Badge Class
    $cleanType = 'Injected';
    $typeBadgeClass = 'badge-injected';
    $typeIcon = 'fa-syringe';

    if (stripos($type, 'injected') !== false) {
        $cleanType = 'Injected';
        $typeBadgeClass = 'badge-injected';
        $typeIcon = 'fa-syringe';
    } elseif (stripos($type, 'download') !== false) {
        $cleanType = 'Downloaded';
        $typeBadgeClass = 'badge-downloaded';
        $typeIcon = 'fa-download';
    } elseif (stripos($type, 'resource') !== false || stripos($type, 'asset') !== false || stripos($type, 'model') !== false || stripos($type, 'sprite') !== false) {
        $cleanType = 'Resource';
        $typeBadgeClass = 'badge-resource';
        $typeIcon = 'fa-cube';
    } elseif (stripos($type, 'previously') !== false || stripos($type, 'started') !== false || stripos($type, 'history') !== false) {
        $cleanType = 'Prev. Executed';
        $typeBadgeClass = 'badge-prev';
        $typeIcon = 'fa-history';
    } elseif (stripos($type, 'installed') !== false) {
        $cleanType = 'Installed in OS';
        $typeBadgeClass = 'badge-installed';
        $typeIcon = 'fa-hdd-o';
    } elseif (stripos($type, 'loaded') !== false || stripos($type, 'game folder') !== false) {
        $cleanType = 'Loaded';
        $typeBadgeClass = 'badge-loaded';
        $typeIcon = 'fa-folder-open';
    } elseif (stripos($type, 'behavior') !== false) {
        $cleanType = 'Behavioral';
        $typeBadgeClass = 'badge-behavior';
        $typeIcon = 'fa-crosshairs';
    } else {
        $cleanType = ucfirst($type ?: 'Violation');
        $typeBadgeClass = 'badge-general';
        $typeIcon = 'fa-exclamation-triangle';
    }

    // 2. Clean Name, Location, and Plain Impact
    $cleanName = '';
    $cleanLocation = '';
    $cleanImpact = '';

    // Check for ROT13 UserAssist artifacts (e.g. RkYbnqre_Vafgnyyre.rkr -> ExLoader_Installer.exe)
    $rotDecoded = str_rot13($evidence);
    $isExLoader = stripos($evidence, 'exloader') !== false || stripos($cheat, 'exloader') !== false || stripos($rotDecoded, 'exloader') !== false || stripos($evidence, 'RkYbnqre') !== false;

    if ($isExLoader) {
        $cleanName = 'ExLoader Cheat Installer';
        if (preg_match('/([a-zA-Z0-9_\.-]+\.(?:zip|rar|7z|exe|rkr))/i', $evidence, $fm)) {
            $fn = $fm[1];
            if (str_ends_with(strtolower($fn), '.rkr')) {
                $fn = str_rot13($fn);
            }
            $cleanLocation = (stripos($evidence, 'UserAssist') !== false ? 'Windows UserAssist (' : '') . $fn . (stripos($evidence, 'UserAssist') !== false ? ')' : '');
        } elseif (stripos($evidence, 'download') !== false) {
            $cleanLocation = 'Downloads\ExLoader_Installer.zip';
        } else {
            $cleanLocation = 'exloader_installer.exe';
        }
        $cleanImpact = 'Cheats installer and loader for CS 1.6 and CS 2 (aimbot, wallhack, visuals).';
    } elseif ($vector === 'Export Rewrite') {
        $glHookNames = [
            'wglSwapBuffers' => ['OpenGL Wallhack Hook (wglSwapBuffers)', 'Modifies OpenGL presentation routine to render enemy players visible through solid walls right before screen refresh.'],
            'wglDeleteContext' => ['OpenGL Visual Hook (wglDeleteContext)', 'Detours OpenGL cleanup routine to maintain continuous transparent model wallhack rendering across frames.'],
            'wglShareLists' => ['OpenGL ESP Geometry Hook (wglShareLists)', 'Intercepts shared OpenGL display lists to track player positions across the entire map.'],
            'wglMakeCurrent' => ['OpenGL Render Pipeline Hijack (wglMakeCurrent)', 'Hijacks active OpenGL graphics thread to inject visual ESP overlays directly into the viewport.'],
            'wglChoosePixelFormat' => ['OpenGL Depth Bypass (No-Smoke/Flash)', 'Forces custom rendering format to disable flashbang blindness and smoke grenade visibility blocks.'],
            'wglDescribePixelFormat' => ['OpenGL Buffer Intercept (No-Flash)', 'Queries and tampers with frame buffer depth testing to bypass visual smoke and flash effects.'],
            'wglCreateLayerContext' => ['OpenGL Overlay Injection (wglCreateLayerContext)', 'Spawns a hidden transparent rendering layer over the game window for visual cheats.'],
            'glFinish' => ['OpenGL Render Sync Hook (glFinish)', 'Forces synchronization of graphics engine to draw cheat ESP geometries prior to buffer swap.'],
            'glBegin' => ['OpenGL Model Rasterization Hook (glBegin)', 'Intercepts primitive polygon rendering to display wireframe or textured player models through walls.'],
            'glEnd' => ['OpenGL Geometry Detour (glEnd)', 'Injects custom cheat primitives and cham overlays into the rendering queue after polygon completion.'],
        ];

        if (isset($glHookNames[$symbol])) {
            $cleanName = $glHookNames[$symbol][0];
            $cleanImpact = $glHookNames[$symbol][1];
        } else {
            $cleanName = 'OpenGL Rendering Hook (' . $symbol . ')';
            $cleanImpact = 'Exported graphic function ' . $symbol . ' redirected to cheat module in memory.';
        }
        $cleanLocation = $module . ' ! ' . $symbol;
    } elseif ($vector === 'Import Redirect') {
        $iatMap = [
            'msvcrt.dll!pow' => ['Ballistic Aimbot Math Hook (msvcrt!pow)', 'Diverts game bullet trajectory and aim angle calculations into unbacked cheat memory to assist targeting.'],
            'msvcrt.dll!memset' => ['Anti-Cheat Memory Scrubber (msvcrt!memset)', 'Routine clearing cheat traces in RAM intercepted to hide injected code from anti-cheat scanning.'],
            'msvcrt.dll!memcmp' => ['Signature Comparison Bypass (msvcrt!memcmp)', 'Memory comparator redirected to injected cheat code to bypass signature scans.'],
            'msvcrt.dll!__C_specific_handler' => ['Anti-Crash Exception Shield (SEH Detour)', 'Exception handler hijacked by cheat payload to prevent game crash when accessing restricted memory.'],
            'msvcrt.dll!floor' => ['Aimbot Recoil / View-Angle Detour (msvcrt!floor)', 'Trigonometric coordinate and recoil calculation routine diverted into injected cheat code.'],
            'msvcrt.dll!sin' => ['Aimbot Ballistic Angle Calculation (msvcrt!sin)', 'Ballistic angle calculation routine diverted into unbacked cheat memory.'],
            'msvcrt.dll!memcpy' => ['Payload Injection Buffer Detour (msvcrt!memcpy)', 'Memory buffer copier redirected to stream cheat code payload into game process memory.'],
            'msvcrt.dll!??1type_info@@UEAA@XZ' => ['RTTI Type Destructor Hijack', 'C++ runtime type destructor hijacked by cheat payload for process persistence.'],
            'msvcrt.dll!_onexit' => ['Process Exit Intercept (Persistence Hook)', 'Process exit callback intercepted to execute cheat cleanup and persistence routines on shutdown.'],
            'msvcrt.dll!__dllonexit' => ['DLL Termination Detour (Module Hook)', 'Dynamic library unload callbacks diverted to prevent cheat detection during module termination.'],
        ];

        if (isset($iatMap[$symbol])) {
            $cleanName = $iatMap[$symbol][0];
            $cleanImpact = $iatMap[$symbol][1];
        } else {
            $cleanName = 'Import Table Detour (' . $symbol . ')';
            $cleanImpact = 'Engine import ' . $symbol . ' diverted into unbacked memory ' . $destination;
        }
        $cleanLocation = $module . ' ! ' . $symbol . ($destination !== '' ? ' -> ' . $destination : '');
    } elseif ($vector === 'Code Detour' || stripos($cheat, 'code modified') !== false) {
        if ($module === 'steamclient.dll') {
            $cleanName = 'Client Authentication Bypass Patch';
            $cleanLocation = 'steamclient.dll (1-byte memory patch)';
            $cleanImpact = 'Modifies Steam client authentication routines in process memory to bypass license and integrity verification.';
        } elseif ($module === 'opengl32.dll') {
            $cleanName = 'OpenGL Live Render Detour';
            $cleanLocation = 'opengl32.dll ' . (preg_match('/at\s+(0x[0-9a-fA-F]+)/', $evidence, $sm) ? $sm[1] : 'in-memory patch');
            $cleanImpact = 'Active in-memory code detour: live OpenGL rendering bytes modified in game process memory.';
        } else {
            $cleanName = 'Live Memory Detour (' . $module . ')';
            $cleanLocation = $module . ' (executable memory)';
            $cleanImpact = 'Executable code in process memory modified from official binary on disk.';
        }
    } elseif ($cleanType === 'Resource' || stripos($evidence, '.mdl') !== false || stripos($evidence, '.spr') !== false) {
        if (stripos($evidence, 'models/player') !== false || stripos($evidence, 'models\\player') !== false) {
            $cleanName = 'Player Model Wallhack (Chams)';
            $cleanImpact = 'Modified transparent or high-visibility player model designed to grant unfair visibility through solid walls.';
        } elseif (stripos($evidence, '.spr') !== false) {
            $cleanName = 'No-Smoke / Transparent Sprite Cheat';
            $cleanImpact = 'Replaces game smoke or flash sprites with transparent assets to negate smoke grenade blindness.';
        } else {
            $cleanName = 'Cheat Game Asset';
            $cleanImpact = 'Modified asset or resource file detected in game directory granting unfair visual advantage.';
        }
        $cleanLocation = preg_match('/([a-zA-Z0-9_\\\\\\/\.-]+\\.(?:mdl|spr|wav|tga|bmp))/i', $evidence, $fm) ? $fm[1] : $evidence;
    } elseif ($cleanType === 'Loaded' || stripos($type, 'loaded') !== false || stripos($type, 'game folder') !== false) {
        $cleanLocation = preg_match('/([a-zA-Z0-9_\\\\\\/\.-]+\\.(?:dll|asi|exe|cfg|ini))/i', $evidence, $fm) ? $fm[1] : $evidence;
        $cleanName = $cheat ?: ('Cheat Library (' . basename($cleanLocation) . ')');
        $cleanImpact = 'Unauthorized third-party cheat binary or disguised library loaded by the game engine.';
    } elseif ($cleanType === 'Prev. Executed') {
        $cleanName = $cheat ?: 'Banned Cheat Utility';
        $cleanLocation = preg_match('/([a-zA-Z0-9_\\\\\\/\.-]+\\.(?:exe|rkr|dll))/i', $evidence, $fm) ? $fm[1] : $evidence;
        if (str_ends_with(strtolower($cleanLocation), '.rkr')) {
            $cleanLocation = str_rot13($cleanLocation);
        }
        $cleanImpact = 'Known cheat loader or banned utility was executed on this PC prior to the scan session.';
    } elseif ($cleanType === 'Installed in OS') {
        $cleanName = $cheat ?: 'Cheat Suite Installation';
        $cleanLocation = $evidence ?: 'Windows Software Registry';
        $cleanImpact = 'Known cheat package or loader registered in operating system software installation records.';
    } elseif ($cleanType === 'Downloaded') {
        $cleanLocation = preg_match('/([a-zA-Z0-9_\\\\\\/\.-]+\\.(?:zip|rar|7z|exe|dll))/i', $evidence, $fm) ? $fm[1] : $evidence;
        $cleanName = $cheat ?: ('Cheat Download (' . basename($cleanLocation) . ')');
        $cleanImpact = 'Cheat installer or script archive downloaded from external site found on local disk.';
    } elseif ($cleanType === 'Behavioral') {
        $cleanName = $cheat ?: 'Combat Input Automation';
        $cleanLocation = 'Server Combat Telemetry';
        $cleanImpact = 'Automated crosshair snap targeting, unnatural trigger speed, or recoil assist exceeding human limits.';
    }

    if ($cleanName === '') {
        $cleanName = $cheat ?: 'Memory Tampering Violation';
    }
    if ($cleanLocation === '') {
        $cleanLocation = $destination ?: ($symbol ?: $module);
    }
    if ($cleanImpact === '') {
        $cleanImpact = $impact ?: ($reason ?: 'Unauthorized game memory modification.');
    }
    $cleanTime = !empty($time) ? (acp_fmt_time($time) ?: $time) : 'Active in game';

    return [
        'module' => $module,
        'vector' => $vector,
        'symbol' => $symbol,
        'destination' => $destination,
        'category' => $category,
        'impact' => $impact,
        'title' => $cleanName,
        'target' => $module,
        'gamerDesc' => $cleanImpact,
        'severity' => $severity,
        'rawType' => $type,
        'rawCheat' => $cheat,
        'rawEvidence' => $evidence,
        'rawReason' => $reason,
        'time' => $time,
        // Enriched human-friendly fields (ECD report #400587 parity)
        'cleanName' => $cleanName,
        'cleanLocation' => $cleanLocation,
        'cleanImpact' => $cleanImpact,
        'cleanType' => $cleanType,
        'typeBadgeClass' => $typeBadgeClass,
        'typeIcon' => $typeIcon,
        'cleanTime' => $cleanTime,
    ];
}

function acp_gamer_finding(array $finding): array
{
    $rule = (string) ($finding['ruleName'] ?? '');
    $subject = (string) ($finding['subject'] ?? '');
    $reason = (string) ($finding['reason'] ?? '');
    $severity = (string) ($finding['severity'] ?? 'WARNING');
    $source = (string) ($finding['source'] ?? '');

    $target = 'Environment';
    $vector = 'Environment Flag';
    $symbol = $rule ?: 'System Anomaly';
    $impact = 'Unusual environment flag or system anomaly detected during scan.';

    if (preg_match('/^([a-zA-Z0-9_\\\\\\/\.-]+\\.(?:cfg|rc|ini|dll|exe|asi)):?\\s*(.*)$/i', $subject, $m)) {
        $target = $m[1];
        $symbol = $m[2] !== '' ? $m[2] : $rule;
    } elseif ($source !== '') {
        $target = $source;
    }

    if (stripos($rule, 'Scripted wait-loop') !== false || stripos($subject, 'wait') !== false) {
        $vector = 'Scripted Wait-Loop';
        $impact = 'Automated execution throttle script: self-referencing alias cycle using engine \'wait\' primitive.';
    } elseif (stripos($rule, 'SuspiciousMemoryRegion') !== false || stripos($subject, 'Executable private memory') !== false) {
        $vector = 'Private Memory';
        $impact = 'Memory region inside hl.exe marked executable without backing from a legitimate DLL.';
    } elseif (stripos($rule, 'Cvar') !== false || stripos($subject, 'cvar') !== false) {
        $vector = 'Restricted Cvar';
        $impact = 'Protected game cvar changed from sanctioned competitive value.';
    } elseif (stripos($rule, 'Process') !== false) {
        $vector = 'Debugging Utility';
        $impact = 'Background program capable of memory inspection or code injection active during play.';
    } elseif (stripos($rule, 'Driver') !== false) {
        $vector = 'Unsigned Driver';
        $impact = 'Kernel driver running without Microsoft or recognized vendor digital certificate.';
    }

    return [
        'target' => acp_sanitize_path($target),
        'vector' => $vector,
        'symbol' => $symbol,
        'impact' => $impact,
        'title' => $rule ?: 'System Anomaly',
        'category' => $vector,
        'gamerDesc' => $impact,
        'severity' => $severity,
        'status' => 'REVIEW REQUIRED',
        'rawRule' => $rule,
        'rawSubject' => acp_sanitize_path($subject),
        'rawReason' => $reason,
        'rawSeverity' => $severity,
        'source' => $source,
    ];
}

/**
 * Country lookup for a player's IP, cached on disk.
 *
 * Done server-side (never in the browser) so the raw IP is not embedded in the
 * page — the visible report only ever shows the masked form. Failures are not
 * cached; successes live for 30 days in database/ip_geo.json.
 */
function acp_ip_geo(string $ip): array
{
    $unknown = ['code' => '', 'country' => '', 'isp' => '', 'as' => ''];

    if ($ip === '') {
        return $unknown;
    }

    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return ['code' => '', 'country' => 'Local / private range', 'isp' => '', 'as' => ''];
    }

    $cacheFile = __DIR__ . '/database/ip_geo.json';
    $cache = [];
    if (is_file($cacheFile)) {
        $decoded = json_decode((string) @file_get_contents($cacheFile), true);
        $cache = is_array($decoded) ? $decoded : [];
    }

    $entry = $cache[$ip] ?? null;
    if (is_array($entry) && (time() - (int) ($entry['at'] ?? 0)) < 30 * 86400) {
        return [
            'code' => (string) ($entry['code'] ?? ''),
            'country' => (string) ($entry['country'] ?? ''),
            'isp' => (string) ($entry['isp'] ?? ''),
            'as' => (string) ($entry['as'] ?? ''),
        ];
    }

    $context = stream_context_create(['http' => ['timeout' => 2, 'ignore_errors' => true]]);
    $body = @file_get_contents('http://ip-api.com/json/' . rawurlencode($ip) . '?fields=status,country,countryCode,isp,as', false, $context);
    if (!is_string($body) || $body === '') {
        return $unknown;
    }

    $data = json_decode($body, true);
    $geo = is_array($data) && ($data['status'] ?? '') === 'success'
        ? [
            'code' => strtolower((string) ($data['countryCode'] ?? '')),
            'country' => (string) ($data['country'] ?? ''),
            'isp' => (string) ($data['isp'] ?? ''),
            'as' => (string) ($data['as'] ?? ''),
        ]
        : $unknown;

    $cache[$ip] = ['code' => $geo['code'], 'country' => $geo['country'], 'isp' => $geo['isp'], 'as' => $geo['as'], 'at' => time()];
    @file_put_contents($cacheFile, json_encode($cache, JSON_UNESCAPED_SLASHES), LOCK_EX);

    return $geo;
}

function acp_clean_map(string $map): string
{
    $map = trim($map);
    if ($map === '') {
        return '';
    }

    $map = preg_replace('#^maps?/#i', '', $map) ?? $map;
    return preg_replace('/\.bsp$/i', '', $map) ?? $map;
}

// ---------------------------------------------------------------------------
// Server connection history
// ---------------------------------------------------------------------------

function acp_server_history_open(array $config): PDO
{
    $path = $config['serverHistoryFile'] ?? (__DIR__ . '/database/server_history.sqlite');
    acp_ensure_dir(dirname($path));

    $pdo = new PDO('sqlite:' . $path, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);

    $pdo->exec('PRAGMA journal_mode = WAL');
    $pdo->exec('PRAGMA synchronous = NORMAL');
    $pdo->exec('PRAGMA busy_timeout = 5000');

    $pdo->exec(<<<'SQL'
        CREATE TABLE IF NOT EXISTS server_history (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id       TEXT NOT NULL,
            steam_id        TEXT,
            player_name     TEXT,
            server_address  TEXT NOT NULL,
            server_name     TEXT,
            server_map      TEXT,
            scanned_at      TEXT NOT NULL,
            created_at      TEXT DEFAULT CURRENT_TIMESTAMP
        )
    SQL);

    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_sh_steam ON server_history (steam_id)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_sh_server ON server_history (server_address)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_sh_time ON server_history (scanned_at)');

    return $pdo;
}

/**
 * Record a server connection from a scan report.
 */
function acp_server_history_record(array $config, array $report): void
{
    $address = trim((string) ($report['serverAddress'] ?? ''));
    if ($address === '') {
        return;
    }

    try {
        $pdo = acp_server_history_open($config);
        $pdo->prepare('INSERT INTO server_history (report_id, steam_id, player_name, server_address, server_name, server_map, scanned_at)
                       VALUES (:rid, :sid, :name, :addr, :sname, :smap, :at)')
            ->execute([
                ':rid' => (string) ($report['id'] ?? ''),
                ':sid' => (string) ($report['steamId'] ?? ''),
                ':name' => mb_substr((string) ($report['playerName'] ?? ''), 0, 64),
                ':addr' => $address,
                ':sname' => mb_substr((string) ($report['serverName'] ?? ''), 0, 128),
                ':smap' => mb_substr((string) ($report['serverMap'] ?? ''), 0, 64),
                ':at' => (string) ($report['createdAt'] ?? $report['uploadedAt'] ?? gmdate('c')),
            ]);
    } catch (Throwable $e) {
        error_log('[ACP] Server history record failed: ' . $e->getMessage());
    }
}

/**
 * Get server history for a player (by Steam ID).
 */
function acp_server_history_for_player(array $config, string $steamId, int $limit = 20): array
{
    if ($steamId === '') {
        return [];
    }

    try {
        $pdo = acp_server_history_open($config);
        $stmt = $pdo->prepare('SELECT * FROM server_history WHERE steam_id = :sid ORDER BY scanned_at DESC LIMIT :lim');
        $stmt->bindValue(':sid', $steamId);
        $stmt->bindValue(':lim', max(1, min(100, $limit)), PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    } catch (Throwable) {
        return [];
    }
}

/**
 * Get all players seen on a specific server.
 */
function acp_server_history_for_server(array $config, string $address, int $limit = 50): array
{
    if ($address === '') {
        return [];
    }

    try {
        $pdo = acp_server_history_open($config);
        $stmt = $pdo->prepare('SELECT DISTINCT steam_id, player_name, MAX(scanned_at) as last_seen, COUNT(*) as scan_count
                               FROM server_history WHERE server_address = :addr
                               GROUP BY steam_id ORDER BY last_seen DESC LIMIT :lim');
        $stmt->bindValue(':addr', $address);
        $stmt->bindValue(':lim', max(1, min(200, $limit)), PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    } catch (Throwable) {
        return [];
    }
}

function acp_identity_keys(array $report): array
{
    $keys = [];
    $steamId = trim((string) ($report['steamId'] ?? ''));
    $steamId2 = trim((string) ($report['steamId2'] ?? ''));
    $steamId3 = trim((string) ($report['steamId3'] ?? ''));
    $steamAccountId = trim((string) ($report['steamAccountId'] ?? ''));
    $device = trim((string) ($report['deviceFingerprint'] ?? ''));
    $hdd = trim((string) ($report['hddSerial'] ?? ''));
    $ip = trim((string) ($report['remoteAddress'] ?? ''));

    if ($steamId !== '') {
        $keys[] = 'steam:' . $steamId;
    }
    if ($steamId2 !== '') {
        $keys[] = 'steam2:' . strtoupper($steamId2);
    }
    if ($steamId3 !== '') {
        $keys[] = 'steam3:' . strtoupper($steamId3);
    }
    if ($steamAccountId !== '') {
        $keys[] = 'account:' . $steamAccountId;
    }
    if ($device !== '') {
        $keys[] = 'device:' . $device;
    }
    if ($hdd !== '') {
        $keys[] = 'hdd:' . strtoupper($hdd);
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $parts = explode('.', $ip);
        $keys[] = 'ip24:' . $parts[0] . '.' . $parts[1] . '.' . $parts[2];
    }

    return array_values(array_unique($keys));
}

function acp_find_related_reports(array $config, array $report, int $limit = 10): array
{
    // Answered from the report index. This used to open and JSON-decode EVERY stored
    // report, with no cap, on every single upload - at ~1.5 MB a report that is the most
    // expensive thing the upload path did, and it grew with the archive.
    try {
        return acp_report_index_related($config, $report, $limit);
    } catch (Throwable $e) {
        error_log('[ACS] related-report lookup fell back to direct read: ' . $e->getMessage());
    }

    $currentId = (string) ($report['id'] ?? '');
    $keys = acp_identity_keys($report);
    if (count($keys) === 0) {
        return [];
    }

    $paths = glob($config['reportsDir'] . '/*.json') ?: [];
    usort($paths, static fn(string $a, string $b): int => filemtime($b) <=> filemtime($a));

    $matches = [];
    // Bounded even on the fallback path, so a cold or broken index cannot turn one upload
    // into an unbounded scan of the whole archive.
    foreach (array_slice($paths, 0, 400) as $path) {
        $candidate = json_decode((string) file_get_contents($path), true);
        if (!is_array($candidate) || (string) ($candidate['id'] ?? '') === $currentId) {
            continue;
        }

        $shared = array_values(array_intersect($keys, acp_identity_keys($candidate)));
        if (count($shared) === 0) {
            continue;
        }

        $summary = acp_report_summary($candidate);
        $summary['matchedBy'] = implode(', ', array_map(static fn(string $key): string => preg_replace('/:.*/', '', $key) ?: $key, $shared));
        $matches[] = $summary;
        if (count($matches) >= $limit) {
            break;
        }
    }

    return $matches;
}

/**
 * Fill in server connection details on previous-scan rows.
 *
 * `previousScans` is a snapshot taken at ingest, so rows written before the scanner
 * captured server name/address have neither. This reads those reports once (bounded to
 * the handful already in the list) so the "Server Connection History" column is not
 * permanently blank on older reports.
 */
function acp_enrich_previous_scans(array $config, array $scans): array
{
    foreach ($scans as $i => $scan) {
        if (!is_array($scan)) {
            continue;
        }

        $hasServer = trim((string) ($scan['serverName'] ?? '')) !== ''
            || trim((string) ($scan['serverAddress'] ?? '')) !== '';
        if ($hasServer) {
            continue;
        }

        $id = (string) ($scan['id'] ?? '');
        if ($id === '') {
            continue;
        }

        $full = acp_load_report($config, $id);
        if ($full === null) {
            continue;
        }

        $scans[$i]['serverName'] = (string) ($full['serverName'] ?? '');
        $scans[$i]['serverAddress'] = (string) ($full['serverAddress'] ?? '');
        $scans[$i]['serverMap'] = (string) ($full['serverMap'] ?? '');
        if (trim((string) ($scans[$i]['steamId2'] ?? '')) === '') {
            $scans[$i]['steamId2'] = (string) ($full['steamId2'] ?? '');
        }
    }

    return $scans;
}

function acp_duration_ms(int $ms): string
{
    if ($ms <= 0) {
        return '';
    }

    if ($ms < 1000) {
        return $ms . ' ms';
    }

    return rtrim(rtrim(number_format($ms / 1000, 2), '0'), '.') . ' sec';
}

function acp_recent_reports(array $config, int $limit = 25): array
{
    // Served from the index so the dashboard does not decode 25 multi-megabyte reports on
    // every page load. The direct read stays as a fallback: if SQLite is unavailable the
    // dashboard should still render, just more slowly.
    try {
        return acp_report_index_recent($config, $limit);
    } catch (Throwable $e) {
        error_log('[ACS] report index unavailable, falling back to direct read: ' . $e->getMessage());
    }

    acp_ensure_dir($config['reportsDir']);
    $paths = glob($config['reportsDir'] . '/*.json') ?: [];
    usort($paths, static fn(string $a, string $b): int => filemtime($b) <=> filemtime($a));

    $reports = [];
    foreach (array_slice($paths, 0, $limit) as $path) {
        $data = json_decode((string) file_get_contents($path), true);
        if (is_array($data)) {
            $reports[] = acp_report_summary($data);
        }
    }

    return $reports;
}

/** One page of the newest reports, for the paginated dashboard. */
function acp_recent_reports_page(array $config, int $limit = 20, int $offset = 0): array
{
    try {
        return acp_report_index_recent_page($config, $limit, $offset);
    } catch (Throwable $e) {
        error_log('[ACS] report index unavailable, falling back to direct read: ' . $e->getMessage());
    }

    acp_ensure_dir($config['reportsDir']);
    $paths = glob($config['reportsDir'] . '/*.json') ?: [];
    usort($paths, static fn(string $a, string $b): int => filemtime($b) <=> filemtime($a));

    $reports = [];
    foreach (array_slice($paths, max(0, $offset), max(1, $limit)) as $path) {
        $data = json_decode((string) file_get_contents($path), true);
        if (is_array($data)) {
            $reports[] = acp_report_summary($data);
        }
    }

    return $reports;
}

/** One page of reports matching a player-name / server-name search. */
function acp_search_reports(array $config, string $query, string $scope, int $limit = 20, int $offset = 0): array
{
    try {
        return acp_report_index_search($config, $query, $scope, $limit, $offset);
    } catch (Throwable $e) {
        error_log('[ACS] report index search unavailable, falling back: ' . $e->getMessage());
    }

    $needle = mb_strtolower(trim($query));
    if ($needle === '') {
        return [];
    }

    acp_ensure_dir($config['reportsDir']);
    $paths = glob($config['reportsDir'] . '/*.json') ?: [];
    usort($paths, static fn(string $a, string $b): int => filemtime($b) <=> filemtime($a));

    $matches = [];
    foreach ($paths as $path) {
        $data = json_decode((string) file_get_contents($path), true);
        if (!is_array($data)) {
            continue;
        }

        $summary = acp_report_summary($data);
        if (acp_search_matches($summary, $needle, $scope)) {
            $matches[] = $summary;
        }
    }

    return array_slice($matches, max(0, $offset), max(1, $limit));
}

/** Number of reports matching a search. */
function acp_search_report_count(array $config, string $query, string $scope): int
{
    try {
        return acp_report_index_search_count($config, $query, $scope);
    } catch (Throwable $e) {
        error_log('[ACS] report index search count unavailable, falling back: ' . $e->getMessage());
    }

    return count(acp_search_reports($config, $query, $scope, 500, 0));
}

/** Shared matcher used by the directory fallback. */
function acp_search_matches(array $summary, string $needle, string $scope): bool
{
    $name = mb_strtolower((string) ($summary['playerName'] ?? ''));
    $srv  = mb_strtolower((string) ($summary['serverName'] ?? ''));
    $addr = mb_strtolower((string) ($summary['serverAddress'] ?? ''));

    if ($scope === 'name') {
        return str_contains($name, $needle);
    }
    if ($scope === 'server') {
        return str_contains($srv, $needle) || str_contains($addr, $needle);
    }

    return str_contains($name, $needle) || str_contains($srv, $needle) || str_contains($addr, $needle);
}

/** Dashboard statistic totals for the report archive. */
function acp_report_status_counts(array $config): array
{
    try {
        return acp_report_index_status_counts($config);
    } catch (Throwable $e) {
        error_log('[ACS] report index status counts unavailable, falling back: ' . $e->getMessage());
    }

    $stats = ['total' => 0, 'detected' => 0, 'clean' => 0];
    foreach (acp_recent_reports($config, 500) as $summary) {
        $stats['total']++;
        $status = strtoupper((string) ($summary['status'] ?? ''));
        if ($status === 'DETECTED') {
            $stats['detected']++;
        } elseif ($status === 'CLEAN') {
            $stats['clean']++;
        }
    }

    return $stats;
}

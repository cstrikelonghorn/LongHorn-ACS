<?php
declare(strict_types=1);

// Report index.
//
// Reports are files, and every list view used to answer its question by opening and JSON
// decoding all of them. At roughly 1.5 MB per report that does not scale:
//
//   acp_find_related_reports   decoded EVERY report, on EVERY upload, with no cap
//   acp_behavior_client_risk   decoded up to 400, on every upload and player page
//   acp_recent_reports         decoded 25 on every dashboard load
//
// A thousand stored reports meant roughly 1.5 GB of JSON parsed per upload.
//
// The reports stay on disk as the record of truth - nothing here replaces them. This is a
// derived index holding the one thing the list views actually need: the summary. It can be
// deleted at any time and will rebuild itself.

const ACP_REPORT_INDEX_SCHEMA = 3;

// How many not-yet-indexed reports one request will absorb. Bounds the worst case on a
// cold index while still converging without anyone running a tool.
const ACP_REPORT_INDEX_SYNC_BUDGET = 150;

function acp_report_index_path(array $config): string
{
    return $config['reportIndexFile'] ?? (__DIR__ . '/database/report_index.sqlite');
}

function acp_report_index_open(array $config): PDO
{
    static $handles = [];
    $path = acp_report_index_path($config);
    if (isset($handles[$path])) {
        return $handles[$path];
    }

    acp_ensure_dir(dirname($path));
    $pdo = new PDO('sqlite:' . $path, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec('PRAGMA journal_mode = WAL');
    $pdo->exec('PRAGMA synchronous = NORMAL');
    $pdo->exec('PRAGMA busy_timeout = 5000');

    acp_report_index_migrate($pdo);
    return $handles[$path] = $pdo;
}

function acp_report_index_migrate(PDO $pdo): void
{
    $pdo->exec('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)');
    $current = (int) ($pdo->query("SELECT value FROM meta WHERE key = 'schema'")->fetchColumn() ?: 0);
    if ($current >= ACP_REPORT_INDEX_SCHEMA) {
        return;
    }

    $pdo->exec(<<<'SQL'
        CREATE TABLE IF NOT EXISTS reports (
            id             TEXT PRIMARY KEY,
            mtime          INTEGER NOT NULL,
            uploaded_at    TEXT,
            player_name    TEXT,
            steam64        TEXT,
            steam2         TEXT,
            account_id     TEXT,
            device         TEXT,
            hdd            TEXT,
            ip24           TEXT,
            status         TEXT,
            detected       INTEGER DEFAULT 0,
            warnings       INTEGER DEFAULT 0,
            server_name    TEXT,
            server_address TEXT,
            summary_json   TEXT
        )
SQL);

    // Upgrade an index created before the server columns existed.
    $columns = [];
    foreach ($pdo->query('PRAGMA table_info(reports)')->fetchAll() as $col) {
        $columns[(string) ($col['name'] ?? '')] = true;
    }
    if (!isset($columns['server_name'])) {
        $pdo->exec('ALTER TABLE reports ADD COLUMN server_name TEXT');
    }
    if (!isset($columns['server_address'])) {
        $pdo->exec('ALTER TABLE reports ADD COLUMN server_address TEXT');
    }
    if ($current < 2) {
        // Backfill from the stored summary; no need to re-read report files.
        try {
            $pdo->exec("UPDATE reports SET
                server_name = COALESCE(server_name, json_extract(summary_json, '$.serverName')),
                server_address = COALESCE(server_address, json_extract(summary_json, '$.serverAddress'))");
        } catch (Throwable $e) {
            error_log('[ACS] report index server backfill skipped: ' . $e->getMessage());
        }
    }
    if ($current < 3) {
        // Finding policy v2 changes effective severities. The index is derived data, so force
        // every stored report through the current policy on the next bounded sync.
        $pdo->exec('DELETE FROM reports');
    }

    foreach ([
        'CREATE INDEX IF NOT EXISTS idx_reports_mtime  ON reports (mtime DESC)',
        'CREATE INDEX IF NOT EXISTS idx_reports_steam  ON reports (steam64)',
        'CREATE INDEX IF NOT EXISTS idx_reports_device ON reports (device)',
        'CREATE INDEX IF NOT EXISTS idx_reports_hdd    ON reports (hdd)',
        'CREATE INDEX IF NOT EXISTS idx_reports_ip24   ON reports (ip24)',
        'CREATE INDEX IF NOT EXISTS idx_reports_server ON reports (server_name)',
    ] as $sql) {
        $pdo->exec($sql);
    }

    $pdo->prepare("INSERT INTO meta (key, value) VALUES ('schema', :v)
                   ON CONFLICT(key) DO UPDATE SET value = :v")
        ->execute([':v' => (string) ACP_REPORT_INDEX_SCHEMA]);
}

/** The identity columns, pulled straight off the report rather than re-derived. */
function acp_report_index_identity(array $report): array
{
    $ip = trim((string) ($report['remoteAddress'] ?? ''));
    $ip24 = '';
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $parts = explode('.', $ip);
        $ip24 = $parts[0] . '.' . $parts[1] . '.' . $parts[2];
    }

    return [
        'steam64'    => trim((string) ($report['steamId'] ?? '')),
        'steam2'     => strtoupper(trim((string) ($report['steamId2'] ?? ''))),
        'account_id' => trim((string) ($report['steamAccountId'] ?? '')),
        'device'     => trim((string) ($report['deviceFingerprint'] ?? '')),
        'hdd'        => strtoupper(trim((string) ($report['hddSerial'] ?? ''))),
        'ip24'       => $ip24,
    ];
}

function acp_report_index_put(PDO $pdo, array $report, int $mtime = 0): void
{
    $id = (string) ($report['id'] ?? '');
    if ($id === '') {
        return;
    }

    $summary  = acp_report_summary($report);
    $identity = acp_report_index_identity($report);

    $pdo->prepare(
        'INSERT INTO reports
            (id, mtime, uploaded_at, player_name, steam64, steam2, account_id, device, hdd,
             ip24, status, detected, warnings, server_name, server_address, summary_json)
         VALUES (:id, :mtime, :uploaded, :name, :steam64, :steam2, :account, :device, :hdd,
                 :ip24, :status, :detected, :warnings, :srv_name, :srv_addr, :summary)
         ON CONFLICT(id) DO UPDATE SET
            mtime = excluded.mtime, uploaded_at = excluded.uploaded_at,
            player_name = excluded.player_name, steam64 = excluded.steam64,
            steam2 = excluded.steam2, account_id = excluded.account_id,
            device = excluded.device, hdd = excluded.hdd, ip24 = excluded.ip24,
            status = excluded.status, detected = excluded.detected,
            warnings = excluded.warnings, server_name = excluded.server_name,
            server_address = excluded.server_address, summary_json = excluded.summary_json'
    )->execute([
        ':id'       => $id,
        ':mtime'    => $mtime > 0 ? $mtime : time(),
        ':uploaded' => (string) ($report['uploadedAt'] ?? ''),
        ':name'     => (string) ($summary['playerName'] ?? ''),
        ':steam64'  => $identity['steam64'],
        ':steam2'   => $identity['steam2'],
        ':account'  => $identity['account_id'],
        ':device'   => $identity['device'],
        ':hdd'      => $identity['hdd'],
        ':ip24'     => $identity['ip24'],
        ':status'   => (string) ($summary['status'] ?? ''),
        ':detected' => (int) ($summary['detected'] ?? 0),
        ':warnings' => (int) ($summary['warnings'] ?? 0),
        ':srv_name' => (string) ($summary['serverName'] ?? ''),
        ':srv_addr' => (string) ($summary['serverAddress'] ?? ''),
        ':summary'  => json_encode($summary, JSON_UNESCAPED_SLASHES),
    ]);
}

/**
 * Brings the index up to date with the reports directory.
 *
 * Listing the directory is cheap; parsing reports is not. So this compares filenames and
 * modification times against what is already indexed and only opens what actually changed,
 * up to a per-request budget.
 */
function acp_report_index_sync(array $config, PDO $pdo, int $budget = ACP_REPORT_INDEX_SYNC_BUDGET): int
{
    acp_ensure_dir($config['reportsDir']);
    $paths = glob($config['reportsDir'] . '/*.json') ?: [];
    if (count($paths) === 0) {
        return 0;
    }

    $known = [];
    foreach ($pdo->query('SELECT id, mtime FROM reports')->fetchAll() as $row) {
        $known[(string) $row['id']] = (int) $row['mtime'];
    }

    // Newest first, so a cold index becomes useful for the dashboard immediately.
    usort($paths, static fn(string $a, string $b): int => filemtime($b) <=> filemtime($a));

    $indexed = 0;
    foreach ($paths as $path) {
        if ($indexed >= $budget) {
            break;
        }
        $id = basename($path, '.json');
        $mtime = (int) filemtime($path);
        if (isset($known[$id]) && $known[$id] === $mtime) {
            continue;
        }

        $data = json_decode((string) @file_get_contents($path), true);
        if (!is_array($data)) {
            continue;
        }
        $data['id'] = $data['id'] ?? $id;
        acp_apply_current_finding_policy($data, $config);
        acp_report_index_put($pdo, $data, $mtime);
        $indexed++;
    }

    // Drop rows whose file is gone, so deleting a report removes it from the dashboard.
    $onDisk = array_map(static fn(string $p): string => basename($p, '.json'), $paths);
    foreach (array_diff(array_keys($known), $onDisk) as $goneId) {
        $pdo->prepare('DELETE FROM reports WHERE id = :id')->execute([':id' => $goneId]);
    }

    return $indexed;
}

function acp_report_index_decode(array $rows): array
{
    $out = [];
    foreach ($rows as $row) {
        $summary = json_decode((string) ($row['summary_json'] ?? ''), true);
        if (is_array($summary)) {
            $out[] = $summary;
        }
    }
    return $out;
}

function acp_report_index_recent(array $config, int $limit = 25): array
{
    $pdo = acp_report_index_open($config);
    acp_report_index_sync($config, $pdo);

    $stmt = $pdo->prepare('SELECT summary_json FROM reports ORDER BY mtime DESC LIMIT :lim');
    $stmt->bindValue(':lim', max(1, min(500, $limit)), PDO::PARAM_INT);
    $stmt->execute();

    return acp_report_index_decode($stmt->fetchAll());
}

/** One page of the newest reports, for the paginated dashboard. */
function acp_report_index_recent_page(array $config, int $limit, int $offset): array
{
    $pdo = acp_report_index_open($config);
    acp_report_index_sync($config, $pdo);

    $stmt = $pdo->prepare('SELECT summary_json FROM reports ORDER BY mtime DESC LIMIT :lim OFFSET :off');
    $stmt->bindValue(':lim', max(1, min(500, $limit)), PDO::PARAM_INT);
    $stmt->bindValue(':off', max(0, $offset), PDO::PARAM_INT);
    $stmt->execute();

    return acp_report_index_decode($stmt->fetchAll());
}

/**
 * Build the WHERE clause for a dashboard search.
 *
 * scope: 'name' (player only), 'server' (server name/address only) or 'all'.
 */
function acp_report_index_search_where(string $query, string $scope): array
{
    $query = trim($query);
    if ($query === '') {
        return ['', []];
    }

    $like = '%' . $query . '%';
    if ($scope === 'name') {
        return ['player_name LIKE :q', [':q' => $like]];
    }
    if ($scope === 'server') {
        return ['(server_name LIKE :q1 OR server_address LIKE :q2)', [':q1' => $like, ':q2' => $like]];
    }

    return ['(player_name LIKE :q1 OR server_name LIKE :q2 OR server_address LIKE :q3)', [':q1' => $like, ':q2' => $like, ':q3' => $like]];
}

/** One page of reports matching a player-name / server-name query. */
function acp_report_index_search(array $config, string $query, string $scope, int $limit, int $offset): array
{
    [$where, $args] = acp_report_index_search_where($query, $scope);
    if ($where === '') {
        return [];
    }

    $pdo = acp_report_index_open($config);
    acp_report_index_sync($config, $pdo);

    $stmt = $pdo->prepare('SELECT summary_json FROM reports WHERE ' . $where . ' ORDER BY mtime DESC LIMIT :lim OFFSET :off');
    foreach ($args as $key => $value) {
        $stmt->bindValue($key, $value);
    }
    $stmt->bindValue(':lim', max(1, min(500, $limit)), PDO::PARAM_INT);
    $stmt->bindValue(':off', max(0, $offset), PDO::PARAM_INT);
    $stmt->execute();

    return acp_report_index_decode($stmt->fetchAll());
}

/** How many reports match a search. */
function acp_report_index_search_count(array $config, string $query, string $scope): int
{
    [$where, $args] = acp_report_index_search_where($query, $scope);
    if ($where === '') {
        return 0;
    }

    $pdo = acp_report_index_open($config);
    acp_report_index_sync($config, $pdo);

    $stmt = $pdo->prepare('SELECT COUNT(*) FROM reports WHERE ' . $where);
    $stmt->execute($args);

    return (int) $stmt->fetchColumn();
}

/** Totals for the dashboard stat strip. */
function acp_report_index_status_counts(array $config): array
{
    $pdo = acp_report_index_open($config);
    acp_report_index_sync($config, $pdo);

    $row = $pdo->query(
        "SELECT COUNT(*) AS total,
                SUM(CASE WHEN status = 'DETECTED' THEN 1 ELSE 0 END) AS detected,
                SUM(CASE WHEN status = 'WARNING'  THEN 1 ELSE 0 END) AS warning,
                SUM(CASE WHEN status = 'CLEAN'    THEN 1 ELSE 0 END) AS clean
         FROM reports"
    )->fetch();

    return [
        'total'    => (int) ($row['total'] ?? 0),
        'detected' => (int) ($row['detected'] ?? 0),
        'warning'  => (int) ($row['warning'] ?? 0),
        'clean'    => (int) ($row['clean'] ?? 0),
    ];
}

/** Other reports that share an identifier with this one. */
function acp_report_index_related(array $config, array $report, int $limit = 10): array
{
    $identity = acp_report_index_identity($report);
    $currentId = (string) ($report['id'] ?? '');

    $clauses = [];
    $args    = [':id' => $currentId];
    foreach (['steam64', 'device', 'hdd', 'ip24'] as $column) {
        if (($identity[$column] ?? '') !== '') {
            $clauses[] = "$column = :$column";
            $args[":$column"] = $identity[$column];
        }
    }
    if (count($clauses) === 0) {
        return [];
    }

    $pdo = acp_report_index_open($config);
    acp_report_index_sync($config, $pdo);

    $sql = 'SELECT summary_json, steam64, device, hdd, ip24 FROM reports
            WHERE id != :id AND (' . implode(' OR ', $clauses) . ')
            ORDER BY mtime DESC LIMIT ' . max(1, min(100, $limit));
    $stmt = $pdo->prepare($sql);
    $stmt->execute($args);

    $out = [];
    foreach ($stmt->fetchAll() as $row) {
        $summary = json_decode((string) $row['summary_json'], true);
        if (!is_array($summary)) {
            continue;
        }
        $shared = [];
        foreach (['steam64' => 'steam', 'device' => 'device', 'hdd' => 'hdd', 'ip24' => 'ip24'] as $col => $label) {
            if (($identity[$col] ?? '') !== '' && (string) $row[$col] === $identity[$col]) {
                $shared[] = $label;
            }
        }
        $summary['matchedBy'] = implode(', ', $shared);
        $out[] = $summary;
    }

    return $out;
}

/** Newest report for one SteamID, for the client half of the player risk score. */
function acp_report_index_latest_for_steam(array $config, string $steam64): ?array
{
    if ($steam64 === '') {
        return null;
    }

    $pdo = acp_report_index_open($config);
    acp_report_index_sync($config, $pdo);

    $stmt = $pdo->prepare('SELECT summary_json FROM reports WHERE steam64 = :s ORDER BY mtime DESC LIMIT 1');
    $stmt->execute([':s' => $steam64]);
    $row = $stmt->fetch();
    if (!$row) {
        return null;
    }

    $summary = json_decode((string) $row['summary_json'], true);
    return is_array($summary) ? $summary : null;
}

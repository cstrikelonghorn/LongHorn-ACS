<?php
declare(strict_types=1);

// Server-side behavioural telemetry: storage, and the player risk model.
//
// The corpus scores *artifacts* - a hash is clean or it is not. This file scores
// *players*, which is a different problem, because a player is never simply one or the
// other and the evidence arrives from two independent directions: the ReHLDS plugin
// watching how they play, and the desktop scanner watching what is loaded into their
// game. The job here is to combine those without letting either one shout.

const ACP_BEHAVIOR_SCHEMA = 1;

// Evidence ages out. A snap pattern from four months ago is not what a player is doing
// now, and a ban list that never forgets accumulates people who reinstalled Windows.
const ACP_RISK_HALF_LIFE_DAYS = 30.0;

function acp_behavior_path(array $config): string
{
    return $config['behaviorFile'] ?? (__DIR__ . '/database/behavior.sqlite');
}

function acp_behavior_open(array $config): PDO
{
    $path = acp_behavior_path($config);
    acp_ensure_dir(dirname($path));

    $pdo = new PDO('sqlite:' . $path, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);

    // Game servers post continuously; WAL stops a dashboard query from blocking them.
    $pdo->exec('PRAGMA journal_mode = WAL');
    $pdo->exec('PRAGMA synchronous = NORMAL');
    $pdo->exec('PRAGMA busy_timeout = 5000');

    acp_behavior_migrate($pdo);
    return $pdo;
}

function acp_behavior_migrate(PDO $pdo): void
{
    $pdo->exec('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)');
    $current = (int) ($pdo->query("SELECT value FROM meta WHERE key = 'schema'")->fetchColumn() ?: 0);
    if ($current >= ACP_BEHAVIOR_SCHEMA) {
        return;
    }

    $pdo->exec(<<<'SQL'
        CREATE TABLE IF NOT EXISTS servers (
            server_id   TEXT PRIMARY KEY,
            first_seen  TEXT,
            last_seen   TEXT,
            events      INTEGER DEFAULT 0
        )
SQL);

    $pdo->exec(<<<'SQL'
        CREATE TABLE IF NOT EXISTS sessions (
            session_id  TEXT PRIMARY KEY,
            server_id   TEXT,
            steam64     TEXT,
            auth_id     TEXT,
            name        TEXT,
            ip_masked   TEXT,
            started     TEXT,
            ended       TEXT,
            duration    REAL DEFAULT 0,
            ticks       INTEGER DEFAULT 0,
            risk        REAL DEFAULT 0,
            stats_json  TEXT
        )
SQL);

    $pdo->exec(<<<'SQL'
        CREATE TABLE IF NOT EXISTS evidence (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT,
            server_id   TEXT,
            steam64     TEXT,
            auth_id     TEXT,
            name        TEXT,
            rule_id     TEXT,
            rule_name   TEXT,
            severity    TEXT,
            confidence  TEXT,
            category    TEXT,
            subject     TEXT,
            reason      TEXT,
            occurrence  INTEGER DEFAULT 1,
            weight      REAL DEFAULT 0,
            game_time   REAL DEFAULT 0,
            created     TEXT
        )
SQL);

    $pdo->exec(<<<'SQL'
        CREATE TABLE IF NOT EXISTS players (
            steam64      TEXT PRIMARY KEY,
            auth_id      TEXT,
            name         TEXT,
            first_seen   TEXT,
            last_seen    TEXT,
            sessions     INTEGER DEFAULT 0,
            play_seconds REAL DEFAULT 0,
            detected     INTEGER DEFAULT 0,
            warnings     INTEGER DEFAULT 0,
            server_risk  REAL DEFAULT 0,
            client_risk  REAL DEFAULT 0,
            risk         REAL DEFAULT 0,
            verdict      TEXT DEFAULT 'clean',
            computed     TEXT
        )
SQL);

    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_evidence_player ON evidence (steam64)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_evidence_rule   ON evidence (rule_id)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_evidence_time   ON evidence (created)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_sessions_player ON sessions (steam64)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_players_risk    ON players (risk DESC)');

    $stmt = $pdo->prepare("INSERT INTO meta (key, value) VALUES ('schema', :v)
                           ON CONFLICT(key) DO UPDATE SET value = :v");
    $stmt->execute([':v' => (string) ACP_BEHAVIOR_SCHEMA]);
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

// STEAM_X:Y:Z -> 64-bit id, so server evidence and desktop reports land on one key.
//
// The universe digit X is ignored on purpose. HLDS reports STEAM_0: and newer clients
// report STEAM_1: for the same account, and treating those as two different players
// would silently split every profile in half.
function acp_steam_to_64(string $authId): string
{
    $authId = strtoupper(trim($authId));

    if (preg_match('/^STEAM_\d+:([01]):(\d+)$/', $authId, $m)) {
        $account = ((int) $m[2]) * 2 + (int) $m[1];
        return (string) (76561197960265728 + $account);
    }
    if (preg_match('/^\[U:1:(\d+)\]$/', $authId, $m)) {
        return (string) (76561197960265728 + (int) $m[1]);
    }
    if (preg_match('/^7656119\d{10}$/', $authId)) {
        return $authId;
    }

    // LAN / no-Steam / pending. These cannot be attributed to an account, so they get a
    // namespaced key of their own rather than being merged into one shared bucket.
    return $authId === '' ? '' : 'anon:' . substr(hash('sha256', $authId), 0, 16);
}

// ---------------------------------------------------------------------------
// Ingestion
// ---------------------------------------------------------------------------

function acp_behavior_ingest(PDO $pdo, array $payload, string $serverId): array
{
    $events = is_array($payload['events'] ?? null) ? $payload['events'] : [];
    $now    = gmdate('Y-m-d\TH:i:s\Z');

    $stored   = 0;
    $touched  = [];

    $pdo->beginTransaction();
    try {
        $pdo->prepare('INSERT INTO servers (server_id, first_seen, last_seen, events)
                       VALUES (:id, :now, :now, 0)
                       ON CONFLICT(server_id) DO UPDATE SET last_seen = :now')
            ->execute([':id' => $serverId, ':now' => $now]);

        foreach ($events as $event) {
            if (!is_array($event)) {
                continue;
            }
            $type    = (string) ($event['type'] ?? '');
            $authId  = (string) ($event['authId'] ?? '');
            $steam64 = acp_steam_to_64($authId);
            if ($steam64 === '') {
                continue;
            }
            $touched[$steam64] = true;

            if ($type === 'session_start') {
                $pdo->prepare('INSERT INTO sessions (session_id, server_id, steam64, auth_id, name, ip_masked, started)
                               VALUES (:sid, :srv, :s64, :auth, :name, :ip, :now)
                               ON CONFLICT(session_id) DO NOTHING')
                    ->execute([
                        ':sid'  => (string) ($event['sessionId'] ?? ''),
                        ':srv'  => $serverId,
                        ':s64'  => $steam64,
                        ':auth' => $authId,
                        ':name' => mb_substr((string) ($event['name'] ?? ''), 0, 64),
                        ':ip'   => acp_mask_ip((string) ($event['ip'] ?? '')),
                        ':now'  => $now,
                    ]);
                $stored++;
                continue;
            }

            if ($type === 'session_stats') {
                $pdo->prepare('UPDATE sessions
                               SET ended = :now, duration = :dur, ticks = :ticks,
                                   risk = :risk, stats_json = :stats
                               WHERE session_id = :sid')
                    ->execute([
                        ':now'   => $now,
                        ':dur'   => (float) ($event['durationSec'] ?? 0),
                        ':ticks' => (int) ($event['ticks'] ?? 0),
                        ':risk'  => (float) ($event['risk'] ?? 0),
                        ':stats' => json_encode($event, JSON_UNESCAPED_SLASHES),
                        ':sid'   => (string) ($event['sessionId'] ?? ''),
                    ]);
                $stored++;
                continue;
            }

            if ($type === 'evidence') {
                $pdo->prepare('INSERT INTO evidence
                               (session_id, server_id, steam64, auth_id, name, rule_id, rule_name,
                                severity, confidence, category, subject, reason, occurrence,
                                weight, game_time, created)
                               VALUES (:sid, :srv, :s64, :auth, :name, :rule, :rname, :sev, :conf,
                                       :cat, :subj, :reason, :occ, :w, :gt, :now)')
                    ->execute([
                        ':sid'    => (string) ($event['sessionId'] ?? ''),
                        ':srv'    => $serverId,
                        ':s64'    => $steam64,
                        ':auth'   => $authId,
                        ':name'   => mb_substr((string) ($event['name'] ?? ''), 0, 64),
                        ':rule'   => mb_substr((string) ($event['ruleId'] ?? ''), 0, 64),
                        ':rname'  => mb_substr((string) ($event['ruleName'] ?? ''), 0, 128),
                        ':sev'    => (string) ($event['severity'] ?? 'INFO'),
                        ':conf'   => (string) ($event['confidence'] ?? 'low'),
                        ':cat'    => mb_substr((string) ($event['category'] ?? ''), 0, 32),
                        ':subj'   => mb_substr((string) ($event['subject'] ?? ''), 0, 512),
                        ':reason' => mb_substr((string) ($event['reason'] ?? ''), 0, 1024),
                        ':occ'    => (int) ($event['occurrence'] ?? 1),
                        ':w'      => (float) ($event['weight'] ?? 0),
                        ':gt'     => (float) ($event['gameTime'] ?? 0),
                        ':now'    => $now,
                    ]);
                $stored++;
            }
        }

        $pdo->prepare('UPDATE servers SET events = events + :n WHERE server_id = :id')
            ->execute([':n' => $stored, ':id' => $serverId]);

        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }

    foreach (array_keys($touched) as $steam64) {
        acp_behavior_recompute($pdo, (string) $steam64);
    }

    return ['stored' => $stored, 'players' => count($touched)];
}

// ---------------------------------------------------------------------------
// Risk
// ---------------------------------------------------------------------------

function acp_risk_decay(string $created, float $halfLifeDays = ACP_RISK_HALF_LIFE_DAYS): float
{
    $ts = strtotime($created);
    if ($ts === false) {
        return 1.0;
    }
    $ageDays = max(0.0, (time() - $ts) / 86400.0);
    return (float) (2 ** (-$ageDays / $halfLifeDays));
}

// Turns a player's raw server-side evidence into one number.
//
// Three properties this has to get right, and each one is a decision about what evidence
// actually means rather than an arithmetic convenience:
//
//  1. Repeats of one rule are worth far less than the first hit. A player who trips the
//     bhop rule two hundred times has one fact about them, observed repeatedly - not two
//     hundred facts. So each rule contributes its single strongest decayed instance.
//
//  2. Independent rules agreeing is worth much more than one rule shouting. Summing rules
//     flat would let a single noisy detector reach a ban score alone, so the rules are
//     sorted and combined with sharply diminishing weights.
//
//  3. Agreement across categories counts. Aim, recoil and movement failing together is a
//     different claim than any one of them failing, because they share no code path and
//     no input assumption.
function acp_behavior_server_risk(PDO $pdo, string $steam64): array
{
    $rows = $pdo->prepare('SELECT rule_id, rule_name, severity, category, subject, weight,
                                  created, session_id
                           FROM evidence WHERE steam64 = :s ORDER BY created DESC LIMIT 2000');
    $rows->execute([':s' => $steam64]);

    $byRule = [];
    foreach ($rows->fetchAll() as $row) {
        $rule = (string) $row['rule_id'];
        $score = ((float) $row['weight']) * acp_risk_decay((string) $row['created']);

        if (!isset($byRule[$rule])) {
            $byRule[$rule] = [
                'rule'     => $rule,
                'name'     => (string) $row['rule_name'],
                'severity' => (string) $row['severity'],
                'category' => (string) $row['category'],
                'subject'  => (string) $row['subject'],
                'score'    => 0.0,
                'hits'     => 0,
                'sessions' => [],
                'last'     => (string) $row['created'],
            ];
        }
        $byRule[$rule]['hits']++;
        $byRule[$rule]['sessions'][(string) $row['session_id']] = true;
        if ($score > $byRule[$rule]['score']) {
            $byRule[$rule]['score']    = $score;
            $byRule[$rule]['subject']  = (string) $row['subject'];
            $byRule[$rule]['severity'] = (string) $row['severity'];
        }
    }

    if (count($byRule) === 0) {
        return ['risk' => 0.0, 'rules' => [], 'categories' => []];
    }

    // A rule seen across several separate sessions is more convincing than the same rule
    // seen many times inside one - a single session can be one bad connection or one
    // unlucky stretch of play.
    foreach ($byRule as $rule => $info) {
        $sessions = max(1, count($info['sessions']));
        $byRule[$rule]['session_count'] = $sessions;
        $byRule[$rule]['score'] = $info['score'] * min(1.6, 1.0 + 0.3 * log($sessions, 2));
        unset($byRule[$rule]['sessions']);
    }

    $scores = array_column($byRule, 'score');
    rsort($scores);

    $factors = [1.00, 0.60, 0.40, 0.25, 0.15, 0.10];
    $risk = 0.0;
    foreach ($scores as $i => $s) {
        $risk += $s * ($factors[$i] ?? 0.05);
    }

    $categories = array_values(array_unique(array_filter(array_column($byRule, 'category'))));
    if (count($categories) >= 3) {
        $risk *= 1.15;
    }

    uasort($byRule, static fn(array $a, array $b): int => $b['score'] <=> $a['score']);

    return [
        'risk'       => (float) min(100.0, $risk),
        'rules'      => array_values($byRule),
        'categories' => $categories,
    ];
}

// The desktop scanner's view of the same player, read from the uploaded reports.
//
// Reports are files rather than rows, so this is a scan. It is bounded to the most recent
// few hundred, which is the same bound acp_recent_reports already lives with, and it is
// only called when a player's risk is recomputed rather than per request.
function acp_behavior_client_risk(array $config, string $steam64): array
{
    if (str_starts_with($steam64, 'anon:')) {
        return ['risk' => 0.0, 'report' => null];
    }

    // Straight lookup by SteamID in the report index. This previously opened and decoded
    // up to 400 reports - on every upload AND every player page - to find one row.
    try {
        $summary = acp_report_index_latest_for_steam($config, $steam64);
    } catch (Throwable $e) {
        error_log('[ACS] client-risk lookup fell back to direct read: ' . $e->getMessage());
        $summary = null;

        $paths = glob($config['reportsDir'] . '/*.json') ?: [];
        usort($paths, static fn(string $a, string $b): int => filemtime($b) <=> filemtime($a));
        foreach (array_slice($paths, 0, 400) as $path) {
            $report = json_decode((string) @file_get_contents($path), true);
            if (!is_array($report)) {
                continue;
            }
            if (trim((string) ($report['steamId'] ?? '')) === $steam64) {
                $summary = acp_report_summary($report);
                break;
            }
        }
    }

    if (!is_array($summary)) {
        return ['risk' => 0.0, 'report' => null];
    }

    $detected = (int) ($summary['detected'] ?? 0);
    $warnings = (int) ($summary['warnings'] ?? 0);

    // Client warnings are capped at 30.0 max: reviews alone can NEVER reach 40 (review) or 75 (cheat)
    $warningRisk = min(30.0, $warnings * 3.0);
    $detectedRisk = $detected > 0 ? (50.0 + ($detected - 1) * 25.0) : 0.0;
    $risk = min(100.0, $detectedRisk + $warningRisk);
    $risk *= acp_risk_decay((string) ($summary['uploadedAt'] ?? gmdate('c')));

    return [
        'risk'     => $risk,
        'report'   => (string) ($summary['id'] ?? ''),
        'detected' => $detected,
        'warnings' => $warnings,
        'name'     => (string) ($summary['playerName'] ?? ''),
        'at'       => (string) ($summary['uploadedAt'] ?? ''),
    ];
}

// Combines the two viewpoints as independent evidence rather than by adding them.
//
// Addition is wrong here: two sources at 60 would produce 120, and capping that at 100
// would mean a player is "certainly" cheating on evidence neither source considers
// conclusive. Treating them as independent probabilities of the same claim gives
// 60 + 60 -> 84, which says "both agree, and that is stronger than either" without
// pretending to certainty.
function acp_behavior_combine(float $serverRisk, float $clientRisk): float
{
    $s = max(0.0, min(100.0, $serverRisk)) / 100.0;
    $c = max(0.0, min(100.0, $clientRisk)) / 100.0;
    return (float) round(100.0 * (1.0 - (1.0 - $s) * (1.0 - $c)), 1);
}

function acp_behavior_verdict(float $risk, int $detected = 0, float $serverRisk = 0.0): string
{
    // A player CANNOT have verdict 'cheat' without verified in-game DETECTED evidence or authoritative server telemetry
    if ($risk >= 75.0 && ($detected > 0 || $serverRisk >= 50.0)) return 'cheat';
    if ($risk >= 40.0) return 'review';
    return 'clean';
}

function acp_behavior_recompute(PDO $pdo, string $steam64, ?array $config = null): array
{
    $server = acp_behavior_server_risk($pdo, $steam64);

    $client = ['risk' => 0.0];
    if ($config !== null) {
        $client = acp_behavior_client_risk($config, $steam64);
    } else {
        // Keep whatever the last full recompute established rather than silently
        // dropping the client half of the score on a telemetry-only update.
        $prev = $pdo->prepare('SELECT client_risk FROM players WHERE steam64 = :s');
        $prev->execute([':s' => $steam64]);
        $client['risk'] = (float) ($prev->fetchColumn() ?: 0.0);
    }

    $risk = acp_behavior_combine($server['risk'], (float) $client['risk']);
    $now  = gmdate('Y-m-d\TH:i:s\Z');

    $agg = $pdo->prepare("SELECT
            COUNT(*)                                              AS sessions,
            COALESCE(SUM(duration), 0)                            AS play_seconds,
            MIN(started)                                          AS first_seen,
            MAX(COALESCE(ended, started))                         AS last_seen,
            MAX(name)                                             AS name,
            MAX(auth_id)                                          AS auth_id
        FROM sessions WHERE steam64 = :s");
    $agg->execute([':s' => $steam64]);
    $a = $agg->fetch() ?: [];

    $counts = $pdo->prepare("SELECT
            SUM(CASE WHEN severity = 'DETECTED' THEN 1 ELSE 0 END) AS detected,
            SUM(CASE WHEN severity = 'WARNING'  THEN 1 ELSE 0 END) AS warnings,
            COUNT(*) AS rows_total,
            MAX(name) AS name, MAX(auth_id) AS auth_id
        FROM evidence WHERE steam64 = :s");
    $counts->execute([':s' => $steam64]);
    $c = $counts->fetch() ?: [];

    $totalDetected = ((int) ($client['detected'] ?? 0)) + ((int) ($c['detected'] ?? 0));
    $verdict = acp_behavior_verdict($risk, $totalDetected, (float) $server['risk']);

    // Nothing is known about this id. Writing a row anyway would let any caller conjure
    // players into the table - and into the dashboard counts - just by asking about an
    // arbitrary SteamID.
    //
    // "Nothing" has to include the client side. A player who has never been seen by a game
    // server but who uploaded a desktop scan carrying detections is very much known, and an
    // earlier version of this check dropped them on the floor: it tested only the telemetry
    // tables, so a scan-only cheater scored 0 and read as clean.
    $clientKnown = ((float) ($client['risk'] ?? 0)) > 0.0 || !empty($client['report']);

    if ((int) ($a['sessions'] ?? 0) === 0 && (int) ($c['rows_total'] ?? 0) === 0 && !$clientKnown) {
        return [
            'steam64'    => $steam64,
            'serverRisk' => 0.0,
            'clientRisk' => round((float) $client['risk'], 1),
            'risk'       => 0.0,
            'verdict'    => 'clean',
            'rules'      => [],
            'categories' => [],
            'clientReport' => $client['report'] ?? null,
            'known'      => false,
        ];
    }

    // A player with sessions but no evidence has no name in the evidence table, so the
    // session record is the fallback rather than leaving the dashboard row blank.
    $name   = (string) ($c['name'] ?? '');
    $authId = (string) ($c['auth_id'] ?? '');
    if ($name === '')   { $name   = (string) ($a['name'] ?? ''); }
    if ($authId === '') { $authId = (string) ($a['auth_id'] ?? ''); }

    // A player known only from a desktop scan has no telemetry row to take a name from,
    // so the report's own player name is the last fallback - otherwise the dashboard
    // shows a blank row for exactly the players an admin most needs to identify.
    if ($name === '') { $name = (string) ($client['name'] ?? ''); }

    $pdo->prepare('INSERT INTO players
            (steam64, auth_id, name, first_seen, last_seen, sessions, play_seconds,
             detected, warnings, server_risk, client_risk, risk, verdict, computed)
         VALUES (:s, :auth, :name, :first, :last, :sess, :play, :det, :warn, :sr, :cr, :r, :v, :now)
         ON CONFLICT(steam64) DO UPDATE SET
             auth_id = COALESCE(NULLIF(excluded.auth_id, \'\'), players.auth_id),
             name    = COALESCE(NULLIF(excluded.name, \'\'), players.name),
             first_seen = COALESCE(players.first_seen, excluded.first_seen),
             last_seen = excluded.last_seen,
             sessions = excluded.sessions,
             play_seconds = excluded.play_seconds,
             detected = excluded.detected,
             warnings = excluded.warnings,
             server_risk = excluded.server_risk,
             client_risk = excluded.client_risk,
             risk = excluded.risk,
             verdict = excluded.verdict,
             computed = excluded.computed')
        ->execute([
            ':s'     => $steam64,
            ':auth'  => $authId,
            ':name'  => $name,
            ':first' => (string) ($a['first_seen'] ?? $now),
            ':last'  => (string) ($a['last_seen'] ?? $now),
            ':sess'  => (int) ($a['sessions'] ?? 0),
            ':play'  => (float) ($a['play_seconds'] ?? 0),
            ':det'   => (int) ($c['detected'] ?? 0),
            ':warn'  => (int) ($c['warnings'] ?? 0),
            ':sr'    => round($server['risk'], 1),
            ':cr'    => round((float) $client['risk'], 1),
            ':r'     => $risk,
            ':v'     => $verdict,
            ':now'   => $now,
        ]);

    return [
        'steam64'     => $steam64,
        'serverRisk'  => round($server['risk'], 1),
        'clientRisk'  => round((float) $client['risk'], 1),
        'risk'        => $risk,
        'verdict'     => $verdict,
        'rules'       => $server['rules'],
        'categories'  => $server['categories'],
        'clientReport' => $client['report'] ?? null,
        'known'       => true,
    ];
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

function acp_behavior_queue(PDO $pdo, int $limit = 100, string $verdict = ''): array
{
    $sql = 'SELECT * FROM players';
    $args = [];
    if ($verdict !== '' && in_array($verdict, ['clean', 'review', 'cheat'], true)) {
        $sql .= ' WHERE verdict = :v';
        $args[':v'] = $verdict;
    }
    $sql .= ' ORDER BY risk DESC, last_seen DESC LIMIT :lim';

    $stmt = $pdo->prepare($sql);
    foreach ($args as $k => $v) {
        $stmt->bindValue($k, $v);
    }
    $stmt->bindValue(':lim', max(1, min(500, $limit)), PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll();
}

function acp_behavior_player(PDO $pdo, string $steam64): ?array
{
    $stmt = $pdo->prepare('SELECT * FROM players WHERE steam64 = :s');
    $stmt->execute([':s' => $steam64]);
    $player = $stmt->fetch();
    if (!$player) {
        return null;
    }

    $ev = $pdo->prepare('SELECT * FROM evidence WHERE steam64 = :s ORDER BY created DESC LIMIT 200');
    $ev->execute([':s' => $steam64]);

    $se = $pdo->prepare('SELECT * FROM sessions WHERE steam64 = :s ORDER BY started DESC LIMIT 50');
    $se->execute([':s' => $steam64]);

    $player['evidence'] = $ev->fetchAll();
    $player['sessions_list'] = $se->fetchAll();
    return $player;
}

function acp_behavior_stats(PDO $pdo): array
{
    $row = $pdo->query("SELECT
            (SELECT COUNT(*) FROM players)                          AS players,
            (SELECT COUNT(*) FROM players WHERE verdict = 'cheat')  AS cheats,
            (SELECT COUNT(*) FROM players WHERE verdict = 'review') AS review,
            (SELECT COUNT(*) FROM sessions)                         AS sessions,
            (SELECT COUNT(*) FROM evidence)                         AS evidence,
            (SELECT COUNT(*) FROM servers)                          AS servers")->fetch();
    return is_array($row) ? array_map('intval', $row) : [];
}

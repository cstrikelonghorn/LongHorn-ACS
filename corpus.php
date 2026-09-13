<?php
declare(strict_types=1);

/**
 * ACS artifact corpus.
 *
 * WHY THIS EXISTS
 *   WarGods' real asset is not its signature list -- it is the ~2.9 million module records it has
 *   accumulated, each classified clean / cheat / UNKNOWN. A hand-written rule list can never
 *   compete with that on volume, because cheat authors only have to rename a file to defeat it.
 *
 *   So ACS records every hash it has ever seen, exactly like WarGods, and then does the thing
 *   WarGods does by hand: it scores the Unknown bucket automatically. Prevalence is the signal --
 *   a binary present on hundreds of clean machines is not a cheat whatever it is called, and a
 *   rare unsigned binary mapped into hl.exe on machines that also flagged behaviourally is worth
 *   a human's attention. That inverts the economics: the database grows by itself and the
 *   reviewer only ever looks at the top of a ranked queue.
 *
 * STORAGE
 *   SQLite, because it needs no server-side setup on a shared PHP host, which is where these
 *   deployments actually live. The schema is created on first use and is safe to re-run.
 */

const ACP_CORPUS_SCHEMA = 4;

/** A hash on this many distinct machines with no associated detections is treated as clean. */
const ACP_PREVALENCE_CLEAN_MACHINES = 25;

/** Below this, a binary is "rare" and scores as more suspicious. */
const ACP_RARE_MACHINES = 3;

function acp_corpus_path(array $config): string
{
    return $config['corpusFile'] ?? (__DIR__ . '/database/corpus.sqlite');
}

function acp_corpus_open(array $config): PDO
{
    $path = acp_corpus_path($config);
    acp_ensure_dir(dirname($path));

    $pdo = new PDO('sqlite:' . $path, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);

    // WAL keeps a long-running review page from blocking report uploads.
    $pdo->exec('PRAGMA journal_mode = WAL');
    $pdo->exec('PRAGMA synchronous = NORMAL');
    $pdo->exec('PRAGMA busy_timeout = 5000');

    acp_corpus_migrate($pdo);
    return $pdo;
}

function acp_corpus_migrate(PDO $pdo): void
{
    $pdo->exec('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)');
    $current = (int) ($pdo->query("SELECT value FROM meta WHERE key = 'schema'")->fetchColumn() ?: 0);

    if ($current >= ACP_CORPUS_SCHEMA) {
        return;
    }

    $pdo->exec(<<<'SQL'
        CREATE TABLE IF NOT EXISTS artifacts (
            sha256          TEXT PRIMARY KEY,
            md5             TEXT,
            name            TEXT,
            path_sample     TEXT,
            kind            TEXT,      -- module | driver | file | process
            state           TEXT NOT NULL DEFAULT 'unknown',   -- unknown | clean | cheat
            state_source    TEXT,      -- prevalence | admin | signature | import
            state_note      TEXT,
            signer          TEXT,
            signed          INTEGER NOT NULL DEFAULT 0,
            company         TEXT,
            size            INTEGER,
            first_seen      TEXT,
            last_seen       TEXT,
            times_seen      INTEGER NOT NULL DEFAULT 0,
            machines        INTEGER NOT NULL DEFAULT 0,
            loaded_in_game  INTEGER NOT NULL DEFAULT 0,
            dirty_reports   INTEGER NOT NULL DEFAULT 0,
            dirty_machines  INTEGER NOT NULL DEFAULT 0,
            classified_at   TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_artifacts_state    ON artifacts (state);
        CREATE INDEX IF NOT EXISTS idx_artifacts_md5      ON artifacts (md5);
        CREATE INDEX IF NOT EXISTS idx_artifacts_lastseen ON artifacts (last_seen);

        -- Distinct-machine counting. Without this, one player scanning fifty times would look
        -- like fifty machines and prevalence would whitelist their cheat.
        CREATE TABLE IF NOT EXISTS artifact_machines (
            sha256 TEXT NOT NULL,
            device TEXT NOT NULL,
            dirty  INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (sha256, device)
        );

        CREATE TABLE IF NOT EXISTS report_index (
            id          TEXT PRIMARY KEY,
            created_at  TEXT,
            status      TEXT,
            detected    INTEGER,
            warnings    INTEGER,
            steam_id    TEXT,
            device      TEXT,
            player      TEXT,
            ip          TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_report_device ON report_index (device);
        CREATE INDEX IF NOT EXISTS idx_report_steam  ON report_index (steam_id);
    SQL);

    $stmt = $pdo->prepare("INSERT INTO meta (key, value) VALUES ('schema', ?) "
        . "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
    $stmt->execute([(string) ACP_CORPUS_SCHEMA]);
}

/* ------------------------------------------------------------------------------------------
 * Ingest
 * ---------------------------------------------------------------------------------------- */

/**
 * Record a report and every hashed artifact in it.
 *
 * Returns a summary of what the corpus already knew, which the API echoes back so the client
 * and the report page can show clean / cheat / unknown per module the way WarGods does.
 */
function acp_corpus_ingest(PDO $pdo, array $report, string $reportId): array
{
    $now = gmdate('Y-m-d\TH:i:s\Z');
    $device = (string) ($report['deviceFingerprint'] ?? '');
    if ($device === '') {
        $device = 'unknown:' . substr(hash('sha256', (string) ($report['machineName'] ?? $reportId)), 0, 16);
    }

    $detected = (int) ($report['summary']['detected'] ?? 0);
    $dirty = $detected > 0 ? 1 : 0;

    $pdo->beginTransaction();

    try {
        $stmt = $pdo->prepare(
            'INSERT INTO report_index (id, created_at, status, detected, warnings, steam_id, device, player, ip)
             VALUES (:id, :created, :status, :detected, :warnings, :steam, :device, :player, :ip)
             ON CONFLICT(id) DO NOTHING'
        );
        $stmt->execute([
            ':id' => $reportId,
            ':created' => (string) ($report['createdAt'] ?? $now),
            ':status' => (string) ($report['status'] ?? 'UNKNOWN'),
            ':detected' => $detected,
            ':warnings' => (int) ($report['summary']['warnings'] ?? 0),
            ':steam' => (string) ($report['steamId'] ?? ''),
            ':device' => $device,
            ':player' => (string) ($report['playerName'] ?? ''),
            ':ip' => (string) ($report['remoteAddress'] ?? ''),
        ]);

        $seen = [];
        foreach (acp_corpus_collect($report) as $item) {
            $sha = strtolower(trim((string) ($item['sha256'] ?? '')));
            if (!preg_match('/^[0-9a-f]{64}$/', $sha) || isset($seen[$sha])) {
                continue;
            }
            $seen[$sha] = true;
            acp_corpus_record($pdo, $sha, $item, $device, $dirty, $now);
        }

        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }

    return acp_corpus_summarise($pdo, array_keys($seen));
}

/** Flatten the report's inventories into one stream of hashable artifacts. */
function acp_corpus_collect(array $report): iterable
{
    foreach (['modules' => 'module', 'drivers' => 'driver', 'hlFiles' => 'file'] as $key => $kind) {
        $rows = $report[$key] ?? [];
        if (!is_array($rows)) {
            continue;
        }

        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }

            $row['__kind'] = $kind;
            // Only a module row means the file was mapped into the live game process.
            $row['__inGame'] = $kind === 'module' ? 1 : 0;
            yield $row;
        }
    }
}

function acp_corpus_record(PDO $pdo, string $sha, array $item, string $device, int $dirty, string $now): void
{
    $kind = (string) ($item['__kind'] ?? 'file');
    $inGame = (int) ($item['__inGame'] ?? 0);
    $path = (string) ($item['path'] ?? $item['relativePath'] ?? '');
    $name = (string) ($item['name'] ?? basename($path));
    $signer = (string) ($item['signer'] ?? '');
    $signed = !empty($item['signatureValid']) ? 1 : 0;

    $stmt = $pdo->prepare(
        'INSERT INTO artifacts
            (sha256, md5, name, path_sample, kind, signer, signed, company, size,
             first_seen, last_seen, times_seen, machines, loaded_in_game, dirty_reports)
         VALUES
            (:sha, :md5, :name, :path, :kind, :signer, :signed, :company, :size,
             :now, :now, 1, 0, :ingame, :dirty)
         ON CONFLICT(sha256) DO UPDATE SET
            last_seen      = :now,
            times_seen     = times_seen + 1,
            loaded_in_game = loaded_in_game + :ingame,
            dirty_reports  = dirty_reports + :dirty,
            -- Keep the first non-empty descriptive values we ever saw.
            name           = COALESCE(NULLIF(artifacts.name, ""), :name),
            path_sample    = COALESCE(NULLIF(artifacts.path_sample, ""), :path),
            signer         = COALESCE(NULLIF(artifacts.signer, ""), :signer),
            signed         = MAX(artifacts.signed, :signed)'
    );

    $stmt->execute([
        ':sha' => $sha,
        ':md5' => strtolower((string) ($item['md5'] ?? '')),
        ':name' => $name,
        ':path' => $path,
        ':kind' => $kind,
        ':signer' => $signer,
        ':signed' => $signed,
        ':company' => (string) ($item['company'] ?? ''),
        ':size' => (int) ($item['size'] ?? 0),
        ':now' => $now,
        ':ingame' => $inGame,
        ':dirty' => $dirty,
    ]);

    // Distinct-machine accounting, done explicitly so both counters stay exact.
    //
    //   machines       - how many different machines have ever carried this hash
    //   dirty_machines - how many of those machines ever produced a DETECTED report
    //
    // Counting machines rather than scans is what stops one player scanning two hundred times
    // from making their own cheat look commonplace.
    $existing = $pdo->prepare('SELECT dirty FROM artifact_machines WHERE sha256 = ? AND device = ?');
    $existing->execute([$sha, $device]);
    $seenBefore = $existing->fetchColumn();

    if ($seenBefore === false) {
        $pdo->prepare('INSERT INTO artifact_machines (sha256, device, dirty) VALUES (?, ?, ?)')
            ->execute([$sha, $device, $dirty]);
        $pdo->prepare('UPDATE artifacts SET machines = machines + 1, dirty_machines = dirty_machines + ? WHERE sha256 = ?')
            ->execute([$dirty, $sha]);
    } elseif ((int) $seenBefore === 0 && $dirty === 1) {
        // This machine was clean before and has now produced a detection.
        $pdo->prepare('UPDATE artifact_machines SET dirty = 1 WHERE sha256 = ? AND device = ?')
            ->execute([$sha, $device]);
        $pdo->prepare('UPDATE artifacts SET dirty_machines = dirty_machines + 1 WHERE sha256 = ?')
            ->execute([$sha]);
    }
}

/* ------------------------------------------------------------------------------------------
 * Classification
 * ---------------------------------------------------------------------------------------- */

/**
 * Suspicion score for the Unknown bucket, as a SQL expression.
 *
 * Deliberately simple and inspectable -- a reviewer has to be able to see why a row is at the
 * top. Prevalence dominates: being common on clean machines outweighs every other signal.
 */
function acp_corpus_score_sql(): string
{
    $cleanAt = ACP_PREVALENCE_CLEAN_MACHINES;
    $rareAt = ACP_RARE_MACHINES;

    return "(
        (CASE WHEN loaded_in_game > 0 THEN 3 ELSE 0 END)
      + (CASE WHEN signed = 0        THEN 2 ELSE 0 END)
      -- Proportional, not absolute: every legitimate game file also sits on cheaters' machines,
      -- so what matters is whether this hash is concentrated among them.
      + (CASE WHEN dirty_machines * 2 >= machines AND dirty_machines > 0 THEN 4
              WHEN dirty_machines > 0 THEN 2 ELSE 0 END)
      + (CASE WHEN machines <= {$rareAt} THEN 2 ELSE 0 END)
      + (CASE WHEN kind = 'driver'   THEN 2 ELSE 0 END)
      - (CASE WHEN machines >= {$cleanAt} AND dirty_machines = 0 THEN 6 ELSE 0 END)
    )";
}

/**
 * Prevalence auto-whitelist. This is the part WarGods leaves to humans, and it is what stops
 * the Unknown bucket growing without bound: anything common and never associated with a
 * detection stops being a question.
 */
function acp_corpus_autoclassify(PDO $pdo): int
{
    $stmt = $pdo->prepare(
        "UPDATE artifacts
            SET state = 'clean',
                state_source = 'prevalence',
                state_note = 'Seen on ' || machines || ' distinct machines, ' || dirty_machines || ' of which reported detections',
                classified_at = :now
          WHERE state = 'unknown'
            AND machines >= :machines
            -- Tolerate incidental appearances on cheaters' machines (every game file does that)
            -- but never auto-clear something concentrated among them.
            AND dirty_machines * 10 <= machines
            AND (signed = 1 OR machines >= :hard)"
    );

    $stmt->execute([
        ':now' => gmdate('Y-m-d\TH:i:s\Z'),
        ':machines' => ACP_PREVALENCE_CLEAN_MACHINES,
        // An unsigned binary needs to be far more common before prevalence alone clears it.
        ':hard' => ACP_PREVALENCE_CLEAN_MACHINES * 4,
    ]);

    return $stmt->rowCount();
}

/** Admin action: pin a hash to a state. Overrides prevalence permanently. */
function acp_corpus_classify(PDO $pdo, string $sha256, string $state, string $note = ''): bool
{
    if (!in_array($state, ['unknown', 'clean', 'cheat'], true)) {
        throw new InvalidArgumentException('State must be unknown, clean or cheat.');
    }

    $sha = strtolower(trim($sha256));
    if (!preg_match('/^[0-9a-f]{64}$/', $sha)) {
        throw new InvalidArgumentException('sha256 must be 64 hex characters.');
    }

    $stmt = $pdo->prepare(
        'UPDATE artifacts
            SET state = :state, state_source = "admin", state_note = :note, classified_at = :now
          WHERE sha256 = :sha'
    );
    $stmt->execute([
        ':state' => $state,
        ':note' => $note,
        ':now' => gmdate('Y-m-d\TH:i:s\Z'),
        ':sha' => $sha,
    ]);

    return $stmt->rowCount() > 0;
}

/* ------------------------------------------------------------------------------------------
 * Queries
 * ---------------------------------------------------------------------------------------- */

/** The review queue: unknown artifacts, most suspicious first. */
function acp_corpus_queue(PDO $pdo, int $limit = 100, string $state = 'unknown'): array
{
    $score = acp_corpus_score_sql();
    $limit = max(1, min(500, $limit));

    $stmt = $pdo->prepare(
        "SELECT sha256, md5, name, path_sample, kind, state, state_source, state_note,
                signer, signed, first_seen, last_seen, times_seen, machines,
                loaded_in_game, dirty_reports, dirty_machines, {$score} AS score
           FROM artifacts
          WHERE state = :state
       ORDER BY score DESC, dirty_machines DESC, last_seen DESC
          LIMIT {$limit}"
    );
    $stmt->execute([':state' => $state]);

    return $stmt->fetchAll();
}

/** Three-state lookup for a set of hashes, as WarGods reports them per module. */
function acp_corpus_summarise(PDO $pdo, array $hashes): array
{
    $summary = ['clean' => 0, 'cheat' => 0, 'unknown' => 0, 'states' => []];
    if ($hashes === []) {
        return $summary;
    }

    $chunks = array_chunk($hashes, 400);
    foreach ($chunks as $chunk) {
        $in = implode(',', array_fill(0, count($chunk), '?'));
        $stmt = $pdo->prepare("SELECT sha256, state, machines, state_source FROM artifacts WHERE sha256 IN ({$in})");
        $stmt->execute($chunk);

        foreach ($stmt->fetchAll() as $row) {
            $state = (string) $row['state'];
            $summary['states'][$row['sha256']] = [
                'state' => $state,
                'machines' => (int) $row['machines'],
                'source' => (string) ($row['state_source'] ?? ''),
            ];
            if (isset($summary[$state])) {
                $summary[$state]++;
            }
        }
    }

    return $summary;
}

function acp_corpus_stats(PDO $pdo): array
{
    $row = $pdo->query(
        "SELECT
            (SELECT COUNT(*) FROM artifacts)                          AS artifacts,
            (SELECT COUNT(*) FROM artifacts WHERE state = 'unknown')  AS unknown,
            (SELECT COUNT(*) FROM artifacts WHERE state = 'clean')    AS clean,
            (SELECT COUNT(*) FROM artifacts WHERE state = 'cheat')    AS cheat,
            (SELECT COUNT(*) FROM report_index)                       AS reports,
            (SELECT COUNT(DISTINCT device) FROM report_index)         AS machines"
    )->fetch();

    return array_map('intval', $row ?: []);
}

/** VirusTotal lookup URL, the same escape hatch WarGods puts on its Unknown records. */
function acp_corpus_virustotal_url(string $sha256): string
{
    return 'https://www.virustotal.com/gui/file/' . rawurlencode(strtolower($sha256));
}

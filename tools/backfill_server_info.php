<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This script runs from the command line only.');
}

/**
 * Backfill server name/map for old reports.
 *
 * Scans all stored reports, finds ones that have a serverAddress captured but
 * are missing serverName or serverMap, and queries the game server via A2S_INFO
 * to fill in the missing fields. Safe to run multiple times.
 *
 * Usage: php tools/backfill_server_info.php [--dry-run]
 */

require __DIR__ . '/../config.php';

$dryRun = in_array('--dry-run', $argv, true);

echo "ACP Server Info Backfill\n";
echo "========================\n\n";

if ($dryRun) {
    echo "[DRY RUN] No changes will be saved.\n\n";
}

$reportsDir = $acpConfig['reportsDir'];
$files = glob($reportsDir . '/*.json') ?: [];

if (count($files) === 0) {
    echo "No reports found in {$reportsDir}\n";
    exit(0);
}

$stats = ['total' => 0, 'skipped' => 0, 'updated' => 0, 'failed' => 0];

foreach ($files as $file) {
    $stats['total']++;
    $reportId = basename($file, '.json');

    $report = json_decode((string) file_get_contents($file), true);
    if (!is_array($report)) {
        echo "  [{$reportId}] Invalid JSON, skipped\n";
        $stats['skipped']++;
        continue;
    }

    $serverAddress = trim((string) ($report['serverAddress'] ?? ''));
    $serverName = trim((string) ($report['serverName'] ?? ''));
    $serverMap = trim((string) ($report['serverMap'] ?? ''));

    // Skip if no server address or already has both name and map
    if ($serverAddress === '') {
        $stats['skipped']++;
        continue;
    }

    if ($serverName !== '' && $serverMap !== '') {
        $stats['skipped']++;
        continue;
    }

    echo "  [{$reportId}] Querying {$serverAddress}... ";

    $info = acp_query_a2s($serverAddress);
    if ($info === null) {
        echo "FAILED (server unreachable)\n";
        $stats['failed']++;
        continue;
    }

    $updated = false;
    if ($serverName === '' && $info['name'] !== '') {
        $report['serverName'] = $info['name'];
        $updated = true;
    }
    if ($serverMap === '' && $info['map'] !== '') {
        $report['serverMap'] = $info['map'];
        $updated = true;
    }

    if (!$updated) {
        echo "no new data\n";
        $stats['skipped']++;
        continue;
    }

    if (!$dryRun) {
        $json = json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (file_put_contents($file, $json, LOCK_EX) === false) {
            echo "FAILED (write error)\n";
            $stats['failed']++;
            continue;
        }
    }

    echo "OK (name=\"{$info['name']}\", map=\"{$info['map']}\")\n";
    $stats['updated']++;
}

echo "\n";
echo "Summary:\n";
echo "  Total reports: {$stats['total']}\n";
echo "  Updated:       {$stats['updated']}\n";
echo "  Skipped:       {$stats['skipped']}\n";
echo "  Failed:        {$stats['failed']}\n";

/**
 * Query a Source/GoldSrc server via A2S_INFO.
 *
 * Returns ['name' => string, 'map' => string] or null on failure.
 */
function acp_query_a2s(string $address): ?array
{
    $parts = explode(':', $address);
    if (count($parts) !== 2) {
        return null;
    }

    [$host, $port] = $parts;
    $port = (int) $port;
    if ($port <= 0 || $port > 65535) {
        return null;
    }

    $socket = @fsockopen("udp://{$host}", $port, $errno, $errstr, 2);
    if (!$socket) {
        return null;
    }

    stream_set_timeout($socket, 2);

    // A2S_INFO request: 0xFF 0xFF 0xFF 0xFF 'T' "Source Engine Query\0"
    $request = "\xFF\xFF\xFF\xFFTSource Engine Query\0";

    for ($attempt = 0; $attempt < 2; $attempt++) {
        fwrite($socket, $request);
        $response = fread($socket, 4096);

        if ($response === false || strlen($response) < 6) {
            fclose($socket);
            return null;
        }

        // Check for split packet (0xFE) — not handling multi-packet responses
        if (substr($response, 0, 4) === "\xFF\xFF\xFF\xFE") {
            fclose($socket);
            return null;
        }

        if (substr($response, 0, 4) !== "\xFF\xFF\xFF\xFF") {
            fclose($socket);
            return null;
        }

        $type = $response[4];

        // Challenge response: resend with challenge number
        if ($type === "\x41" && strlen($response) >= 9) {
            $challenge = substr($response, 5, 4);
            $request = "\xFF\xFF\xFF\xFFTSource Engine Query\0" . $challenge;
            continue;
        }

        // Source A2S_INFO response ('I')
        if ($type === "\x49") {
            $offset = 6; // skip header + type + protocol
            $name = acp_read_null_string($response, $offset);
            $map = acp_read_null_string($response, $offset);
            fclose($socket);
            return ['name' => $name, 'map' => $map];
        }

        // GoldSrc legacy response ('m')
        if ($type === "\x6D") {
            $offset = 9; // skip header + type + request id
            acp_read_null_string($response, $offset); // skip address string
            $name = acp_read_null_string($response, $offset);
            $map = acp_read_null_string($response, $offset);
            fclose($socket);
            return ['name' => $name, 'map' => $map];
        }

        fclose($socket);
        return null;
    }

    fclose($socket);
    return null;
}

function acp_read_null_string(string $data, int &$offset): string
{
    $start = $offset;
    $len = strlen($data);
    while ($offset < $len && $data[$offset] !== "\0") {
        $offset++;
    }
    $str = substr($data, $start, $offset - $start);
    if ($offset < $len) {
        $offset++; // skip NUL
    }
    return $str;
}

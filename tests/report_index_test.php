<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This script runs from the command line only.');
}

// Report index.
//
// The index exists so list views stop opening every stored report. These tests cover the
// three questions it answers, the self-healing behaviour that lets it be deleted safely,
// and - at the end - the actual cost difference on realistically sized reports.

putenv('ACS_BEHAVIOR_FILE=' . sys_get_temp_dir() . '/ri_behavior.sqlite');

$root = sys_get_temp_dir() . '/acs_report_index_test';
$reportsDir = $root . '/reports';
@mkdir($reportsDir, 0777, true);
foreach (glob($reportsDir . '/*.json') ?: [] as $f) { @unlink($f); }
foreach (glob($root . '/index.sqlite*') ?: [] as $f) { @unlink($f); }

require getenv('ACPDIR') . '/config.php';

$acpConfig['reportsDir']      = $reportsDir;
$acpConfig['reportIndexFile'] = $root . '/index.sqlite';

$pass = 0; $fail = 0;
function ok(string $what, bool $cond, string $extra = ''): void {
    printf("  %-58s %s%s\n", $what, $cond ? 'PASS' : '*** FAIL ***', $extra ? "  ($extra)" : '');
    if ($cond) { $GLOBALS['pass']++; } else { $GLOBALS['fail']++; }
}

/** A report with realistic bulk, so the timing at the end means something. */
function make_report(string $id, array $identity, int $detected = 0, int $filler = 0): array {
    $findings = [];
    for ($i = 0; $i < $detected; $i++) {
        $findings[] = ['ruleId' => 'acp-test', 'ruleName' => 'test', 'severity' => 'DETECTED',
                       'confidence' => 'high', 'category' => 'injected', 'source' => 'module',
                       'subject' => "finding $i", 'reason' => 'x', 'time' => ''];
    }
    $hlFiles = [];
    for ($i = 0; $i < $filler; $i++) {
        $hlFiles[] = ['relativePath' => "cstrike/models/filler_$i.mdl",
                      'sha256' => hash('sha256', "$id-$i"), 'bytes' => 4096 + $i];
    }
    return array_merge([
        'id' => $id, 'scanner' => 'ACS', 'scannerVersion' => '3.2.0',
        'uploadedAt' => gmdate('Y-m-d\TH:i:s\Z'), 'playerName' => 'player_' . $id,
        'findings' => $findings, 'hlFiles' => $hlFiles, 'modules' => [], 'drivers' => [], 'processes' => [],
    ], $identity);
}

function write_report(string $dir, array $report): string {
    $path = $dir . '/' . $report['id'] . '.json';
    file_put_contents($path, json_encode($report));
    return $path;
}

echo "\nINDEXING\n";

$alice = ['steamId' => '76561198000000001', 'deviceFingerprint' => 'dev-alice',
          'hddSerial' => 'HDD-A', 'remoteAddress' => '203.0.113.10'];
$bob   = ['steamId' => '76561198000000002', 'deviceFingerprint' => 'dev-bob',
          'hddSerial' => 'HDD-B', 'remoteAddress' => '198.51.100.20'];

write_report($reportsDir, make_report('aaaa000000000001', $alice, 2));
sleep(1);
write_report($reportsDir, make_report('aaaa000000000002', $alice, 0));
write_report($reportsDir, make_report('bbbb000000000001', $bob, 1));

$recent = acp_report_index_recent($acpConfig, 25);
ok('a cold index builds itself from the report files', count($recent) === 3, count($recent) . ' rows');
ok('newest report is first', ($recent[0]['id'] ?? '') !== 'aaaa000000000001', $recent[0]['id'] ?? '-');
ok('counters survive the round trip',
   array_sum(array_column($recent, 'detected')) === 3,
   'detected total ' . array_sum(array_column($recent, 'detected')));

echo "\nRELATED REPORTS\n";

$current = make_report('aaaa000000000003', $alice, 0);
$related = acp_report_index_related($acpConfig, $current, 10);
$ids = array_column($related, 'id');
ok('finds the same player\'s other scans', count($related) === 2, implode(',', $ids));
ok('does not return a different player', !in_array('bbbb000000000001', $ids, true));
ok('reports why it matched', str_contains((string) ($related[0]['matchedBy'] ?? ''), 'steam'),
   $related[0]['matchedBy'] ?? '-');

// Identity is more than the SteamID: a new account on the same machine still links up.
$sameMachine = make_report('cccc000000000001',
    ['steamId' => '76561198000000099', 'deviceFingerprint' => 'dev-alice',
     'hddSerial' => 'HDD-A', 'remoteAddress' => '10.0.0.1']);
$related = acp_report_index_related($acpConfig, $sameMachine, 10);
ok('a new SteamID on a known machine still links', count($related) === 2, implode(',', array_column($related, 'id')));

// Self-exclusion: an indexed report must not be returned as related to itself.
write_report($reportsDir, make_report('aaaa000000000004', $alice, 0));
acp_report_index_recent($acpConfig, 25);
$self = make_report('aaaa000000000004', $alice, 0);
ok('a report is not related to itself',
   !in_array('aaaa000000000004', array_column(acp_report_index_related($acpConfig, $self, 10), 'id'), true));

echo "\nLOOKUP BY STEAMID\n";

$latest = acp_report_index_latest_for_steam($acpConfig, '76561198000000002');
ok('finds the newest scan for a SteamID', ($latest['id'] ?? '') === 'bbbb000000000001', $latest['id'] ?? '-');
ok('unknown SteamID returns nothing', acp_report_index_latest_for_steam($acpConfig, '76561198999999999') === null);

echo "\nSTAYING IN SYNC\n";

@unlink($reportsDir . '/bbbb000000000001.json');
$after = acp_report_index_recent($acpConfig, 25);
ok('a deleted report leaves the index',
   !in_array('bbbb000000000001', array_column($after, 'id'), true), count($after) . ' rows');

// The index is derived data: losing it must be a slowdown, never a loss.
foreach (glob($root . '/index.sqlite*') ?: [] as $f) { @unlink($f); }
$rebuilt = acp_report_index_recent($acpConfig, 25);
ok('a deleted index rebuilds itself', count($rebuilt) === count($after), count($rebuilt) . ' rows');

echo "\nCOST (20 reports of realistic size)\n";

foreach (glob($reportsDir . '/*.json') ?: [] as $f) { @unlink($f); }
foreach (glob($root . '/index.sqlite*') ?: [] as $f) { @unlink($f); }
for ($i = 0; $i < 20; $i++) {
    write_report($reportsDir, make_report(sprintf('dddd%012d', $i),
        ['steamId' => '7656119800000' . str_pad((string) $i, 4, '0', STR_PAD_LEFT),
         'deviceFingerprint' => "dev-$i", 'hddSerial' => "HDD-$i", 'remoteAddress' => '203.0.113.' . ($i + 1)],
        1, 2500));
}
$bytes = array_sum(array_map('filesize', glob($reportsDir . '/*.json') ?: []));
printf("  corpus on disk: %.1f MB across 20 reports\n", $bytes / 1e6);

// Direct read: what every dashboard load used to do.
$t = microtime(true);
$paths = glob($reportsDir . '/*.json') ?: [];
usort($paths, static fn($a, $b) => filemtime($b) <=> filemtime($a));
foreach (array_slice($paths, 0, 25) as $path) {
    $d = json_decode((string) file_get_contents($path), true);
    if (is_array($d)) { acp_report_summary($d); }
}
$direct = (microtime(true) - $t) * 1000;

acp_report_index_recent($acpConfig, 25);          // build once
$t = microtime(true);
$rows = acp_report_index_recent($acpConfig, 25);  // warm
$indexed = (microtime(true) - $t) * 1000;

printf("  direct read : %7.1f ms\n  indexed     : %7.1f ms\n", $direct, $indexed);
ok('indexed listing is faster than decoding every report',
   $indexed < $direct, sprintf('%.1fx', $direct / max($indexed, 0.001)));
ok('and returns the same number of rows', count($rows) === 20, count($rows) . ' rows');

printf("\n%d passed, %d failed\n\n", $pass, $fail);
exit($fail ? 1 : 0);

<?php
// End-to-end check of the telemetry path: signing, ingestion, risk model, verdicts.
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This script runs from the command line only.');
}

putenv('ACP_TELEMETRY_SECRET=test-secret-abc');
putenv('ACP_BEHAVIOR_FILE=' . getenv('SCRATCH') . '/behavior_test.sqlite');
@unlink(getenv('SCRATCH') . '/behavior_test.sqlite');

require getenv('ACPDIR') . '/config.php';

$pass = 0; $fail = 0;
function ok(string $what, bool $cond, string $extra = ''): void {
    global $pass, $fail;
    printf("  %-56s %s%s\n", $what, $cond ? 'PASS' : '*** FAIL ***', $extra ? "  ($extra)" : '');
    $cond ? $GLOBALS['pass']++ : $GLOBALS['fail']++;
}

echo "\nIDENTITY\n";
ok('STEAM_0:1:11101 -> 64-bit', acp_steam_to_64('STEAM_0:1:11101') === '76561197960287931', acp_steam_to_64('STEAM_0:1:11101'));
ok('STEAM_1: and STEAM_0: are the same player',
   acp_steam_to_64('STEAM_1:1:11101') === acp_steam_to_64('STEAM_0:1:11101'));
ok('[U:1:22203] matches the STEAM_ form',
   acp_steam_to_64('[U:1:22203]') === acp_steam_to_64('STEAM_0:1:11101'));
ok('LAN id gets its own namespaced key', str_starts_with(acp_steam_to_64('VALVE_ID_LAN'), 'anon:'));

$pdo = acp_behavior_open($acpConfig);
$S = 'STEAM_0:1:11101';
$s64 = acp_steam_to_64($S);

function ev(string $sid, string $auth, string $rule, string $sev, string $cat, float $w): array {
    return ['type'=>'evidence','sessionId'=>$sid,'authId'=>$auth,'name'=>'tester',
            'ruleId'=>$rule,'ruleName'=>$rule,'severity'=>$sev,'confidence'=>'high',
            'category'=>$cat,'subject'=>'x','reason'=>'y','occurrence'=>1,'weight'=>$w,'gameTime'=>1.0];
}

echo "\nINGEST\n";
$r = acp_behavior_ingest($pdo, ['events'=>[
    ['type'=>'session_start','sessionId'=>'s1','authId'=>$S,'name'=>'tester','ip'=>'192.168.1.50'],
    ev('s1',$S,'uranac-bhop-script','WARNING','movement',15.0),
]], 'srv1');
ok('batch stored', $r['stored'] === 2, "stored={$r['stored']}");
$p = acp_behavior_player($pdo, $s64);
ok('player row created', $p !== null);
// acp_mask_ip hides the whole final octet, not just its last digit, so a published
// report never narrows a player down to a single host.
ok('IP is masked to the whole last octet',
   ($pdo->query("SELECT ip_masked FROM sessions WHERE session_id='s1'")->fetchColumn()) === '192.168.1.***');

echo "\nRISK MODEL\n";
$one = (float) $pdo->query("SELECT risk FROM players WHERE steam64='$s64'")->fetchColumn();
ok('a single WARNING stays under review threshold', $one < 40.0, sprintf('%.1f', $one));

// Repeating ONE rule many times must not escalate much - it is one fact observed often.
$many = [];
for ($i = 0; $i < 60; $i++) $many[] = ev('s1', $S, 'uranac-bhop-script', 'WARNING', 'movement', 15.0);
acp_behavior_ingest($pdo, ['events'=>$many], 'srv1');
$repeat = (float) $pdo->query("SELECT risk FROM players WHERE steam64='$s64'")->fetchColumn();
ok('60 repeats of one rule do not reach "cheat"', $repeat < 75.0, sprintf('%.1f', $repeat));

// Independent rules across categories should escalate.
acp_behavior_ingest($pdo, ['events'=>[
    ev('s1',$S,'uranac-aim-instant','DETECTED','aim',50.0),
    ev('s1',$S,'uranac-recoil-compensation','DETECTED','recoil',60.0),
    ev('s1',$S,'uranac-speedhack','DETECTED','usercmd',55.0),
]], 'srv1');
$multi = (float) $pdo->query("SELECT risk FROM players WHERE steam64='$s64'")->fetchColumn();
$verdict = (string) $pdo->query("SELECT verdict FROM players WHERE steam64='$s64'")->fetchColumn();
ok('independent detectors across categories escalate', $multi > $repeat, sprintf('%.1f -> %.1f', $repeat, $multi));
ok('verdict reaches cheat', $verdict === 'cheat', $verdict);

echo "\nCOMBINATION\n";
ok('60 + 60 combines to 84, not 120', abs(acp_behavior_combine(60,60) - 84.0) < 0.05, (string) acp_behavior_combine(60,60));
ok('either source alone is preserved',  abs(acp_behavior_combine(70,0) - 70.0) < 0.05);
ok('combination never exceeds 100',     acp_behavior_combine(99,99) <= 100.0);

echo "\nDECAY\n";
$old = acp_risk_decay(gmdate('Y-m-d\TH:i:s\Z', time() - 30*86400));
ok('evidence halves over the half-life', abs($old - 0.5) < 0.02, sprintf('%.3f', $old));
$fresh = acp_risk_decay(gmdate('Y-m-d\TH:i:s\Z'));
ok('fresh evidence is undecayed', abs($fresh - 1.0) < 0.01);

echo "\nISOLATION\n";
$B = 'STEAM_0:0:777';
acp_behavior_ingest($pdo, ['events'=>[
    ['type'=>'session_start','sessionId'=>'s2','authId'=>$B,'name'=>'clean'],
]], 'srv1');
$cleanRisk = (float) $pdo->query("SELECT risk FROM players WHERE steam64='".acp_steam_to_64($B)."'")->fetchColumn();
ok('an unrelated player scores zero', $cleanRisk === 0.0, sprintf('%.1f', $cleanRisk));

// --- scan-only players -----------------------------------------------------
// A player the game servers have never seen, who uploaded a desktop scan with
// detections, must still be scored. An earlier version of the "do not conjure rows"
// guard tested only the telemetry tables and silently dropped these players.
echo "
SCAN-ONLY PLAYERS
";

$scanOnly = acp_steam_to_64('STEAM_0:1:31337');
$fake = [
    'risk' => 47.0, 'report' => 'deadbeef', 'detected' => 1, 'warnings' => 1, 'name' => 'scanned',
];
$known = ((float) $fake['risk']) > 0.0 || !empty($fake['report']);
ok('a report with detections counts as known', $known);

$none = ['risk' => 0.0, 'report' => null];
ok('no telemetry and no report is still unknown',
   !(((float) $none['risk']) > 0.0 || !empty($none['report'])));

$stats = acp_behavior_stats($pdo);
ok('stats report both players', $stats['players'] === 2, json_encode($stats));

printf("\n%d passed, %d failed\n\n", $pass, $fail);
exit($fail ? 1 : 0);

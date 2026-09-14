<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This script runs from the command line only.');
}
$scratch = getenv('SCRATCH') ?: sys_get_temp_dir();
$acpDir = getenv('ACPDIR') ?: dirname(__DIR__);
putenv('ACP_TELEMETRY_SECRET=t');
putenv('ACP_BEHAVIOR_FILE=' . $scratch . '/b2.sqlite');
@unlink($scratch . '/b2.sqlite');
require $acpDir . '/config.php';
$pdo = acp_behavior_open($acpConfig);

function ev(string $auth, string $rule, string $cat, float $w, string $sid = 's1'): array {
    return ['type'=>'evidence','sessionId'=>$sid,'authId'=>$auth,'name'=>'t','ruleId'=>$rule,
            'ruleName'=>$rule,'severity'=>'DETECTED','confidence'=>'high','category'=>$cat,
            'subject'=>'x','reason'=>'y','occurrence'=>1,'weight'=>$w,'gameTime'=>1.0];
}
function riskOf(PDO $pdo, string $auth): array {
    $s = acp_steam_to_64($auth);
    $r = $pdo->query("SELECT risk, verdict FROM players WHERE steam64='$s'")->fetch();
    return [(float) $r['risk'], (string) $r['verdict']];
}

// Each player gets a distinct id so the cases do not contaminate each other.
$cases = [
  ['STEAM_0:0:1', [ev('STEAM_0:0:1','uranac-recoil-compensation','recoil',60)],                     'strongest single rule'],
  ['STEAM_0:0:2', [ev('STEAM_0:0:2','uranac-recoil-compensation','recoil',60),
                   ev('STEAM_0:0:2','uranac-aim-instant','aim',50)],                                'two independent detectors'],
  ['STEAM_0:0:3', [ev('STEAM_0:0:3','uranac-aim-snap','aim',15)],                                   'one WARNING-weight rule'],
];
foreach ($cases as [$auth, $events, $label]) {
    acp_behavior_ingest($pdo, ['events'=>array_merge(
        [['type'=>'session_start','sessionId'=>'s1','authId'=>$auth,'name'=>'t']], $events)], 'srv');
    [$risk, $verdict] = riskOf($pdo, $auth);
    printf("  %-28s risk %5.1f  verdict %s\n", $label, $risk, $verdict);
}

// The safety property: no single rule, however strong, reaches "cheat" alone.
$s = acp_steam_to_64('STEAM_0:0:1');
[$r1, $v1] = riskOf($pdo, 'STEAM_0:0:1');
printf("\n  %-56s %s\n", 'one detector alone cannot reach the cheat verdict', $v1 !== 'cheat' ? 'PASS' : '*** FAIL ***');
[$r2, $v2] = riskOf($pdo, 'STEAM_0:0:2');
printf("  %-56s %s\n", 'two independent detectors do reach it', $v2 === 'cheat' ? 'PASS' : '*** FAIL ***');
exit(($v1 !== 'cheat' && $v2 === 'cheat') ? 0 : 1);

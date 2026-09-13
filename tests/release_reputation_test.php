<?php
declare(strict_types=1);
require dirname(__DIR__) . '/release_reputation.php';
$checks = 0;
function expect(bool $value, string $name): void {
    if (!$value) throw new RuntimeException($name);
    $GLOBALS['checks']++;
    echo "PASS $name\n";
}
$sha = str_repeat('a', 64);
expect(acs_release_reputation($sha, null)['threats_detected'] === null, 'unverified does not mean zero detections');
expect(acs_release_reputation($sha, null)['vendors'] === [], 'no invented vendor results');
$fixture = ['data' => ['id' => $sha, 'attributes' => ['last_analysis_date' => 1700000000,
    'last_analysis_stats' => ['undetected' => 30, 'malicious' => 0, 'suspicious' => 1]]]];
expect(acs_release_reputation($sha, $fixture)['status'] === 'flagged', 'suspicious vendor result is a flag');
expect(acs_release_reputation(str_repeat('b', 64), $fixture)['is_indexed'] === false, 'another binary hash cannot supply reputation');
$fixture['data']['attributes']['last_analysis_stats']['suspicious'] = 0;
expect(acs_release_reputation($sha, $fixture)['status'] === 'no-detections', 'no detections does not claim certified safe');
$fixture['data']['attributes']['last_analysis_stats']['undetected'] = 0;
expect(!acs_release_reputation($sha, $fixture)['is_indexed'], 'zero engine results is unverified');
echo "$checks passed\n";

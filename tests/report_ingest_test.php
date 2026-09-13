<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This script runs from the command line only.');
}
require dirname(__DIR__) . '/config.php';
$passed = 0;
function check(bool $condition, string $name): void {
    if (!$condition) throw new RuntimeException($name);
    $GLOBALS['passed']++;
    echo "PASS $name\n";
}
$config = ['requireReportSignature' => true, 'signatureSecret' => 'test-only-secret'];
$report = ['scanner' => 'ACS', 'findings' => [], 'modules' => [['name' => 'hw.dll']], 'summary' => ['modules' => 9000, 'detected' => 500], 'status' => 'DETECTED'];
$json = json_encode($report);
$valid = ['reportJson' => $json, 'signature' => acp_sign_report($json, $config['signatureSecret']), 'algorithm' => 'hmac-sha256'];
[$decoded, $verified] = acp_decode_upload($valid, $config);
check($verified && $decoded === $report, 'valid signed report accepted');
foreach (['legacy' => ['report' => $report], 'bare' => $report, 'tampered' => array_replace($valid, ['reportJson' => $json . ' ']), 'empty' => []] as $case => $payload) {
    $rejected = false;
    try { acp_decode_upload($payload, $config); } catch (UnexpectedValueException $e) { $rejected = true; }
    check($rejected, "$case cannot bypass required signatures");
}
[$legacy, $verified] = acp_decode_upload(['report' => $report], ['requireReportSignature' => false]);
check(!$verified && $legacy === $report, 'legacy remains available when explicitly permitted');
acp_normalize_report($decoded);
check($decoded['status'] === 'CLEAN' && $decoded['summary']['detected'] === 0, 'submitted verdict and detection total recomputed');
check($decoded['summary']['modules'] === 1, 'inventory totals recomputed');
$stale = [
    'findings' => [[
        'ruleId' => 'acp-inline-hook', 'ruleName' => 'Inline hook', 'severity' => 'WARNING',
        'category' => 'injected', 'subject' => 'opengl32.dll', 'reason' => 'profile downgrade',
    ]],
    'detectedCheats' => ['injected' => [['severity' => 'DETECTED', 'cheat' => 'stale cache']]],
];
$staleSummary = acp_report_summary($stale);
check($staleSummary['detected'] === 0 && $staleSummary['categoryCounts']['injected'] === 0
    && $staleSummary['reviewCategoryCounts']['injected'] === 1,
    'canonical findings override stale detectedCheats severities');
$steamFinding = ['findings' => [[
    'ruleId' => 'acp-local-steamclient', 'ruleName' => 'Local steamclient.dll',
    'severity' => 'WARNING', 'category' => 'loaded', 'subject' => 'steamclient.dll',
]]];
check(count(acp_report_findings($steamFinding)) === 1, 'Steam findings are not globally suppressed without profile evidence');
$rejected = false;
try { acp_decode_upload(['report' => ['findings' => [['severity' => 'fake']]]], []); } catch (InvalidArgumentException $e) { $rejected = true; }
check($rejected, 'malformed findings rejected');

$temp = tempnam(sys_get_temp_dir(), 'acs-rules-');
try {
    $cfg = $acpConfig;
    $cfg['corpusFile'] = $temp;
    $pdo = acp_corpus_open($cfg);
    $sha = str_repeat('a', 64);
    $insert = $pdo->prepare("INSERT INTO artifacts (sha256, state, state_source) VALUES (?, 'cheat', ?)");
    $insert->execute([$sha, 'admin']);
    $insert->execute([str_repeat('b', 64), 'signature']);
    $database = acp_load_database($cfg);
    check($database['reviewedHashRules'] === 1, 'only admin-reviewed hashes exported as live rules');
    check(strlen($database['revision']) === 64, 'database revision is reproducible SHA-256');
    acp_corpus_classify($pdo, $sha, 'clean');
    check(acp_load_database($cfg)['reviewedHashRules'] === 0, 'reclassification revokes hash detection on next download');
} finally {
    $insert = null;
    $pdo = null;
    foreach ([$temp, $temp . '-wal', $temp . '-shm'] as $f) if (is_file($f)) unlink($f);
}
echo "$passed passed\n";

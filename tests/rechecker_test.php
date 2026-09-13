<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') { http_response_code(403); exit; }
require dirname(__DIR__) . '/rechecker.php';

$passed = 0;
function rc_ok(bool $condition, string $name): void {
    if (!$condition) throw new RuntimeException($name);
    $GLOBALS['passed']++;
    echo "PASS $name\n";
}

$db = [
    'databaseRevision' => 'test',
    'signatures' => [
        [
            'id' => 'exact', 'name' => 'Exact bad file', 'enabled' => true,
            'severity' => 'DETECTED', 'confidence' => 'high',
            'match' => ['path_regex' => '(?i)\\baimbot\\.dll\\b', 'md5' => ['0123456789abcdef0123456789abcdef']],
        ],
        [
            'id' => 'prefix', 'name' => 'Known prefix', 'enabled' => true,
            'severity' => 'DETECTED', 'confidence' => 'high',
            'match' => ['path_regex' => '(?i)\\btrace\\.asi\\b', 'md5' => ['deadbeef']],
        ],
        [
            'id' => 'boundary', 'name' => 'Boundary name', 'enabled' => true,
            'severity' => 'DETECTED', 'confidence' => 'high',
            'match' => ['report_regex' => '(?i)\\binjmthd\\.ini\\b'],
        ],
    ],
];

$safe = acp_rechecker_render($db);
rc_ok(!preg_match('/^[^;\r\n]*\bMISSING\b/m', $safe), 'generator never emits an active MISSING detector');
rc_ok(str_contains($safe, '"aimbot.dll"' . "\t" . '0123456789abcdef0123456789abcdef'), 'full MD5 is emitted without a CRC32 prefix');
rc_ok(str_contains($safe, '"trace.asi"' . "\t" . 'deadbeef'), 'four-byte MD5 prefix is emitted');
rc_ok(str_contains($safe, '; REVIEW name-only: "injmthd.ini"'), 'name-only rule is commented by default');
rc_ok(!str_contains($safe, 'binjmthd.ini'), 'word-boundary token does not become part of a filename');

$optIn = acp_rechecker_render($db, 'amx_kick', 0, true);
rc_ok((bool) preg_match('/^"injmthd\.ini"\s+UNKNOWN\s+/m', $optIn), 'explicit name-only opt-in uses UNKNOWN');
rc_ok(!preg_match('/^[^;\r\n]*\bMISSING\b/m', $optIn), 'opt-in output still never reverses MISSING semantics');

echo "$passed passed\n";

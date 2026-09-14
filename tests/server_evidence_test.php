<?php
declare(strict_types=1);

// Test the updated acs_server_view function with evidence chain support

require __DIR__ . '/../config.php';

$pass = 0; $fail = 0;
function ok(string $what, bool $cond, string $extra = ''): void {
    printf("  %-62s %s%s\n", $what, $cond ? 'PASS' : '*** FAIL ***', $extra ? "  ($extra)" : '');
    if ($cond) { $GLOBALS['pass']++; } else { $GLOBALS['fail']++; }
}

echo "SERVER VIEW WITH EVIDENCE CHAIN\n";
echo str_repeat("=", 70) . "\n\n";

// Test 1: Connected with evidence chain
$connected = acs_server_view(['serverDetection' => [
    'status' => 'connected',
    'address' => '217.156.22.149:27015',
    'name' => 'LongHorn Server',
    'map' => 'de_dust2',
    'capturedAt' => '2026-09-13T06:47:12Z',
    'packetsSent' => 181,
    'packetsReceived' => 164,
    'sampleMs' => 2500,
    'evidenceChain' => [
        'sessionId' => 'abc123def456',
        'chainHash' => 'hash123',
        'finalStatus' => 'connected',
        'consistentConnection' => true,
        'disconnectionEvents' => 0,
        'proofPointCount' => 15,
        'proofPoints' => [
            ['seq' => 1, 'time' => '2026-09-13T06:47:12Z', 'status' => 'connected', 'endpoint' => '217.156.22.149:27015'],
            ['seq' => 2, 'time' => '2026-09-13T06:47:14Z', 'status' => 'connected', 'endpoint' => '217.156.22.149:27015'],
        ],
    ],
]]);

ok('connected: server name shown', $connected['name'] === 'LongHorn Server');
ok('connected: address shown', $connected['address'] === '217.156.22.149:27015');
ok('connected: map shown', $connected['map'] === 'de_dust2');
ok('connected: verified flag', $connected['verified'] === true);
ok('connected: evidence present', $connected['evidence'] !== null);
ok('connected: no warnings', empty($connected['warnings']));
ok('connected: proof count in note', str_contains($connected['note'], '15 proof points'));

// Test 2: Connected but disconnected during scan
$disconnected = acs_server_view(['serverDetection' => [
    'status' => 'connected',
    'address' => '217.156.22.149:27015',
    'name' => 'LongHorn Server',
    'map' => 'de_dust2',
    'evidenceChain' => [
        'sessionId' => 'abc123',
        'chainHash' => 'hash123',
        'finalStatus' => 'disconnected-during-scan',
        'consistentConnection' => false,
        'disconnectionEvents' => 2,
        'proofPointCount' => 10,
        'proofPoints' => [],
    ],
]]);

ok('disconnected during scan: warning shown', in_array('Disconnected during scan', $disconnected['warnings']));
ok('disconnected during scan: note contains warning', str_contains($disconnected['note'], 'disconnected'));

// Test 3: Connected but unstable
$unstable = acs_server_view(['serverDetection' => [
    'status' => 'connected',
    'address' => '217.156.22.149:27015',
    'name' => 'LongHorn Server',
    'map' => 'de_dust2',
    'evidenceChain' => [
        'sessionId' => 'abc123',
        'chainHash' => 'hash123',
        'finalStatus' => 'connected',
        'consistentConnection' => false,
        'disconnectionEvents' => 0,
        'proofPointCount' => 8,
        'proofPoints' => [],
    ],
]]);

ok('unstable connection: warning shown', in_array('Connection unstable', $unstable['warnings']));

// Test 4: Not connected with evidence
$notConnected = acs_server_view(['serverDetection' => [
    'status' => 'not-connected',
    'reason' => 'no UDP ports open',
    'evidenceChain' => [
        'sessionId' => 'abc123',
        'chainHash' => 'hash123',
        'finalStatus' => 'not-connected',
        'consistentConnection' => true,
        'disconnectionEvents' => 0,
        'proofPointCount' => 12,
        'proofPoints' => [],
    ],
]]);

ok('not connected: "No Server Detected"', $notConnected['name'] === 'No Server Detected');
ok('not connected: map is "No Server Detected"', $notConnected['map'] === 'No Server Detected');
ok('not connected: verified', $notConnected['verified'] === true);

// Test 5: Legacy report without evidence chain
$legacy = acs_server_view(['serverDetection' => [
    'status' => 'connected',
    'address' => '85.10.20.7:27015',
    'name' => 'Old Server',
    'map' => 'de_inferno',
]]);

ok('legacy: still works', $legacy['name'] === 'Old Server');
ok('legacy: evidence is null', $legacy['evidence'] === null);
ok('legacy: no warnings', empty($legacy['warnings']));

// Test 6: Old-style report without serverDetection
$oldStyle = acs_server_view([
    'serverAddress' => '85.10.20.7:27015',
    'serverName' => 'Very Old Server',
    'serverMap' => 'de_nuke',
]);

ok('old style: name shown', $oldStyle['name'] === 'Very Old Server');
ok('old style: not verified', $oldStyle['verified'] === false);
ok('old style: evidence is null', $oldStyle['evidence'] === null);

// Test 7: No server at all
$noServer = acs_server_view([]);

ok('no server: "No Server Detected"', $noServer['name'] === 'No Server Detected');
ok('no server: not verified', $noServer['verified'] === false);

echo "\n" . str_repeat("=", 70) . "\n";
printf("%d passed, %d failed\n", $pass, $fail);
exit($fail === 0 ? 0 : 1);

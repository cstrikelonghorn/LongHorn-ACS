<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This script runs from the command line only.');
}

// Report card: GAME CLIENT & ENGINE.
//
// A real scan of a non-Steam client in C:\Counter-Strike ESK was shown to admins as
// "GENUINE STEAM". The scanner now proves the distribution from Authenticode signatures and
// where Steam's DLLs were loaded from, and ships that verdict in an `engine` block. These
// tests pin the page to that verdict:
//
//   1. With an engine block, the page uses it and never re-derives Steam from paths.
//   2. "Steam" is only ever a verified claim - a Steam-looking folder buys nothing.
//   3. Reports from the old scanner still render, but a Steam guess is not presented as proof.
//
// The engine blocks below are the scanner's actual output for the two installs on the
// development machine (a retail Steam Half-Life and the ESK client), not invented shapes.

require_once (getenv('ACPDIR') ?: dirname(__DIR__)) . '/config.php';

$pass = 0; $fail = 0;
function ok(string $what, bool $cond, string $extra = ''): void {
    printf("  %-62s %s%s\n", $what, $cond ? 'PASS' : '*** FAIL ***', $extra ? "  ($extra)" : '');
    if ($cond) { $GLOBALS['pass']++; } else { $GLOBALS['fail']++; }
}

function steamEngine(): array {
    return [
        'distribution' => 'Steam (retail)', 'family' => '', 'steamVerified' => true,
        'confidence' => 'verified', 'trust' => 'valve-signed', 'module' => 'hw.dll',
        'buildDate' => 'Oct  7 2024',
        'sha256' => '9ba9a2db5e07598fd59afa35507a98c86162e4e15b3835177b78c11842cd2295',
        'launcherSigned' => true, 'launcherSigner' => 'Valve Corp.',
        'steamClientOrigin' => 'Steam installation',
        'evidence' => [
            ['name' => 'Launcher signature', 'value' => 'valid — Valve Corp.', 'source' => 'Authenticode (WinVerifyTrust)'],
            ['name' => 'Engine signature', 'value' => 'valid — Valve Corp.', 'source' => 'Authenticode (WinVerifyTrust)'],
        ],
    ];
}

function eskEngine(): array {
    return [
        'distribution' => 'Non-Steam — ESK Edition', 'family' => 'esk', 'steamVerified' => false,
        'confidence' => 'verified', 'trust' => 'unverified', 'module' => 'hw.dll',
        'buildDate' => 'Jun 15 2009',
        'sha256' => '932a1bc2bbec73c1e5a7afebef2ad50d4d3d9a3a84ab6995d4bf9e2f5b26178a',
        'launcherSigned' => false, 'launcherSigner' => '',
        'steamClientOrigin' => 'game folder (emulator)',
        'evidence' => [
            ['name' => 'Launcher signature', 'value' => 'not signed / not verifiable', 'source' => 'Authenticode (WinVerifyTrust)'],
            ['name' => 'steamclient.dll origin', 'value' => 'game folder (emulator)', 'source' => 'loaded module list'],
        ],
    ];
}

/** Module list a Steam emulator would present: right names, Steam-looking install path. */
function steamLookingModules(string $root): array {
    return [
        ['name' => 'hl.exe', 'path' => $root . '\\hl.exe'],
        ['name' => 'hw.dll', 'path' => $root . '\\hw.dll'],
        ['name' => 'steamclient.dll', 'path' => 'C:\\Program Files (x86)\\Steam\\steamclient.dll'],
    ];
}

echo "SCANNER VERDICT IS USED AS-IS\n";

$b = acp_game_build_badge(['engine' => steamEngine()], 'Counter-Strike 1.6 — Steam (retail)');
ok('verified retail Steam is shown as Steam', $b['isSteam'] === true && $b['class'] === 'steam', $b['label']);
ok('and is marked as signature-verified', ($b['verified'] ?? false) === true);
ok('engine build date reaches the card', $b['engineBuildDate'] === 'Oct  7 2024');
ok('evidence reaches the card', count($b['evidence']) === 2);

$b = acp_game_build_badge(['engine' => eskEngine()], 'Counter-Strike 1.6 — Non-Steam — ESK Edition');
ok('ESK client is NOT shown as Steam', $b['isSteam'] === false, $b['label']);
ok('ESK client is named', str_contains($b['label'], 'ESK Edition'), $b['label']);

echo "\nA STEAM-LOOKING REPORT DOES NOT GET THE STEAM BADGE\n";

// The exact bypass: an emulator installed under steamapps\common\Half-Life, with Steam's
// DLL names in the module list. The old path-based heuristic calls this retail Steam. The
// scanner's verdict for it is non-Steam, and that verdict must win.
$root = 'C:\\Program Files (x86)\\Steam\\steamapps\\common\\Half-Life';
$disguised = [
    'hlPath' => $root . '\\hl.exe', 'gameRoot' => $root,
    'modules' => steamLookingModules($root),
    'engine' => ['distribution' => 'Non-Steam — Steam emulator', 'family' => '', 'steamVerified' => false,
                 'confidence' => 'verified', 'launcherSigned' => false, 'evidence' => []],
];
$legacyView = acp_game_build_badge(array_diff_key($disguised, ['engine' => 1]), 'Counter-Strike: 1.6 (Steam)');
ok('(control) without the verdict, the old heuristic says Steam', $legacyView['isSteam'] === true, $legacyView['label']);
$b = acp_game_build_badge($disguised, 'Counter-Strike: 1.6 (Steam)');
ok('with the verdict, the same install is NOT Steam', $b['isSteam'] === false, $b['label']);

// Signed launcher, engine swapped for an unsigned build.
$swapped = steamEngine();
$swapped['distribution'] = 'Steam — engine binary is not Valve-signed';
$swapped['steamVerified'] = false;
$swapped['confidence'] = 'review';
$b = acp_game_build_badge(['engine' => $swapped], '');
ok('Steam launcher + non-Valve engine is NOT Steam retail', $b['isSteam'] === false, $b['label']);
ok('and is styled for review, not as ordinary non-Steam', $b['class'] === 'review');

// A truthy string must not pass for a verified boolean.
$spoof = steamEngine();
$spoof['steamVerified'] = 'true';
$b = acp_game_build_badge(['engine' => $spoof], '');
ok('steamVerified must be a real boolean, not a truthy string', $b['isSteam'] === false);

echo "\nOLDER REPORTS STILL RENDER\n";

$report = __DIR__ . '/../reports/73a967ae94fb09b8.json';
if (is_file($report)) {
    $old = json_decode((string) file_get_contents($report), true);
    $b = acp_game_build_badge($old, (string) ($old['gameBuild'] ?? ''));
    ok('old ESK report (no engine block) is not Steam', $b['isSteam'] === false, $b['label']);
    ok('old report is not marked signature-verified', ($b['verified'] ?? false) === false);
} else {
    ok('old ESK report fixture present (skipped: not in this checkout)', true);
}

$b = acp_game_build_badge(['hlPath' => '', 'modules' => []], 'Counter-Strike: 1.6');
ok('an empty legacy report still returns a badge', isset($b['label'], $b['class']));
ok('and is not marked verified', ($b['verified'] ?? false) === false);

echo "\nACTIVE SERVER / SERVER MAP SHOW ONLY WHAT THE APP CAPTURED\n";

$joined = acs_server_view(['serverDetection' => [
    'status' => 'connected', 'address' => '217.156.22.149:27015', 'name' => 'ULTRA-CS # RESPAWN [Ranks]',
    'map' => 'de_dust2', 'capturedAt' => '2026-09-13T06:47:12Z',
]]);
ok('joined: exact server name', $joined['name'] === 'ULTRA-CS # RESPAWN [Ranks]');
ok('joined: exact IP:Port', $joined['address'] === '217.156.22.149:27015');
ok('joined: map as the server reported it', $joined['map'] === 'de_dust2');

$menu = acs_server_view(['serverDetection' => ['status' => 'not-connected', 'reason' => 'the engine holds no live server connection'],
                         // an old-style stray value must not leak into the view
                         'serverAddress' => '85.10.20.7:27015', 'serverName' => 'Some Server']);
ok('game open, not joined: "No Server Detected"', $menu['name'] === 'No Server Detected' && $menu['map'] === 'No Server Detected');
ok('not joined: no address shown, even if a stray one exists', $menu['address'] === '');

$live = acs_server_view(['serverDetection' => [
    'status' => 'connected', 'address' => '217.156.22.149:27015', 'name' => 'ULTRA-CS', 'map' => 'de_dust2',
    'packetsSent' => 181, 'packetsReceived' => 164, 'sampleMs' => 2500,
]]);
ok('joined: the live traffic proof is shown with it', str_contains($live['note'], '181 sent / 164 received in 2.5s'));

$noAdmin = acs_server_view(['serverDetection' => ['status' => 'unverified',
    'reason' => 'live game traffic can only be read when ACS runs as administrator']]);
ok('no admin rights: "Not verified" with the reason, never "No Server"', $noAdmin['name'] === 'Not verified'
    && str_contains($noAdmin['note'], 'administrator'));

$quiet = acs_server_view(['serverDetection' => ['status' => 'connected', 'address' => '1.2.3.4:27016', 'name' => '', 'map' => '']]);
ok('joined but server did not answer: IP:Port kept, name says so', $quiet['address'] === '1.2.3.4:27016' && $quiet['name'] === 'Name not reported by server');

$unread = acs_server_view(['serverDetection' => ['status' => 'unverified', 'reason' => 'the game process could not be opened for reading']]);
ok('unreadable engine is "Not verified", never "No Server"', $unread['name'] === 'Not verified' && !$unread['verified']);

$legacy = acs_server_view(['serverAddress' => '85.10.20.7:27015', 'serverName' => 'Old', 'serverMap' => 'de_inferno']);
ok('older app report is shown with a not-verified note', !$legacy['verified'] && str_contains($legacy['note'], 'not verified'));

echo "\nNON-STEAM CLIENT IS WHITELISTED, NOT REVIEW EVIDENCE\n";

$report = ['findings' => [
    ['ruleId' => 'acs-client-distribution', 'severity' => 'INFO', 'ruleName' => 'Non-Steam Counter-Strike client', 'subject' => 'hw.dll'],
    ['ruleId' => 'acs-engine-no-version-resource', 'severity' => 'INFO', 'ruleName' => 'x', 'subject' => 'hw.dll'],
    ['ruleId' => 'acs-signed-module-modified', 'severity' => 'INFO', 'ruleName' => 'x', 'subject' => 'hw.dll'],
    ['ruleId' => 'acs-signed-module-modified', 'severity' => 'WARNING', 'ruleName' => 'x', 'subject' => 'C:\\Temp\\hw.dll'],
    ['ruleId' => 'acp-fake-sprite', 'severity' => 'WARNING', 'ruleName' => 'Fake sprite', 'subject' => 'muzzIeflash5.spr'],
]];
$kept = array_map(static fn($f) => $f['ruleId'] . '/' . $f['severity'], acp_report_findings($report));
ok('"Non-Steam Counter-Strike client" is not shown for review', !in_array('acs-client-distribution/INFO', $kept, true));
ok('the non-Steam client\'s patched engine note is not shown either', !in_array('acs-signed-module-modified/INFO', $kept, true));
ok('an unexplained modified module is still reviewed', in_array('acs-signed-module-modified/WARNING', $kept, true));
ok('unrelated evidence is untouched', in_array('acp-fake-sprite/WARNING', $kept, true));

printf("\n%d passed, %d failed\n", $pass, $fail);
exit($fail === 0 ? 0 : 1);

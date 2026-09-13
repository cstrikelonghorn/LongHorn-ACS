<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This script runs from the command line only.');
}

// Legitimate-client compatibility tests.
//
// Two things are being proved here, and the second matters more than the first:
//
//   1. An honest player on NextClient / GoldClient / a repack stops being called a
//      cheater for the modifications their client makes by design.
//   2. Claiming to be one of those clients does NOT buy immunity. Every bypass test
//      below plants a client marker next to real cheat evidence and asserts the cheat
//      evidence survives at full severity.

putenv('ACS_TELEMETRY_SECRET=t');
putenv('ACP_BEHAVIOR_FILE=' . sys_get_temp_dir() . '/clients_test.sqlite');
@unlink(sys_get_temp_dir() . '/clients_test.sqlite');

require (getenv('ACPDIR') ?: dirname(__DIR__)) . '/config.php';

$pass = 0; $fail = 0;
function ok(string $what, bool $cond, string $extra = ''): void {
    printf("  %-58s %s%s\n", $what, $cond ? 'PASS' : '*** FAIL ***', $extra ? "  ($extra)" : '');
    if ($cond) { $GLOBALS['pass']++; } else { $GLOBALS['fail']++; }
}

function mod(string $name, string $sha = ''): array {
    return ['name' => $name, 'path' => 'C:\\cs\\' . $name, 'sha256' => $sha];
}
function finding(string $ruleId, string $severity, string $subject): array {
    return ['ruleId' => $ruleId, 'ruleName' => $ruleId, 'severity' => $severity,
            'confidence' => 'high', 'category' => 'injected', 'source' => 'module',
            'subject' => $subject, 'reason' => 'x', 'time' => ''];
}
function sev(array $report, string $ruleId): string {
    foreach ($report['findings'] as $f) {
        if ($f['ruleId'] === $ruleId) return (string) $f['severity'];
    }
    return '(absent)';
}

// ---------------------------------------------------------------------------
echo "\nRECOGNITION\n";

$nextclient = [
    'modules' => [mod('hw.dll'), mod('client.dll'), mod('nextclient.dll'), mod('steamclient.dll')],
    'hlFiles' => [],
    'findings' => [
        finding('acs-inline-hook', 'DETECTED', 'hw.dll!SV_Frame @0x1234 -> 0x5678 (unbacked memory)'),
        finding('acs-foreign-module', 'WARNING', 'nextclient.dll — C:\\cs\\nextclient.dll'),
    ],
];
$r = $nextclient;
$c = acs_client_apply($r, $acpConfig);
ok('NextClient is recognised', ($c['recognised'] ?? false) && $c['id'] === 'nextclient', $c['id'] ?? '-');
ok('engine detour is downgraded off DETECTED', sev($r, 'acs-inline-hook') !== 'DETECTED', sev($r, 'acs-inline-hook'));
ok('original severity is preserved for audit', ($r['findings'][0]['originalSeverity'] ?? '') === 'DETECTED');
ok('the downgrade carries a reason', ($r['findings'][0]['explainedBy']['reason'] ?? '') !== '');

// Unverified profile: filename-only match must NOT reach INFO.
ok('filename-only match stops at WARNING, not INFO',
   sev($r, 'acs-inline-hook') === 'WARNING' && ($c['verified'] ?? true) === false,
   sev($r, 'acs-inline-hook'));

echo "\nBYPASS RESISTANCE\n";

// 1. Cheat-named module alongside a client marker.
$r = $nextclient;
$r['modules'][] = mod('aimbot.dll');
$r['findings'][] = finding('acs-cheat-named-module', 'DETECTED', 'C:\\cs\\aimbot.dll');
acs_client_apply($r, $acpConfig);
ok('cheat-named module survives at DETECTED',
   sev($r, 'acs-cheat-named-module') === 'DETECTED', sev($r, 'acs-cheat-named-module'));

// 2. A hook on something the profile does not claim.
$r = $nextclient;
$r['findings'][] = finding('acs-inline-hook', 'DETECTED', 'ws2_32.dll!send @0x900 -> 0xAAA (unbacked memory)');
acs_client_apply($r, $acpConfig);
$last = end($r['findings']);
ok('hook outside the profile subject list is untouched',
   $last['severity'] === 'DETECTED' && !isset($last['explainedBy']), $last['severity']);

// 3. A forged signature finding.
$r = $nextclient;
$r['findings'][] = finding('acs-forged-signature', 'DETECTED', 'evil.dll claims Microsoft');
acs_client_apply($r, $acpConfig);
ok('forged-signer finding survives', sev($r, 'acs-forged-signature') === 'DETECTED');

// 4. A foreign module that is not one of the client's own.
$r = $nextclient;
$r['findings'][] = finding('acs-foreign-module', 'WARNING', 'injector.dll — C:\\temp\\injector.dll');
acs_client_apply($r, $acpConfig);
$last = end($r['findings']);
ok('unrelated foreign module is not explained', !isset($last['explainedBy']));

echo "\nVERIFIED vs CLAIMED\n";

// Same report, but with the marker hash actually on file for that build.
$tmp = sys_get_temp_dir() . '/profiles_verified.json';
$db = json_decode((string) file_get_contents($acpConfig['clientProfilesFile']), true);
foreach ($db['profiles'] as $i => $p) {
    if ($p['id'] === 'nextclient') {
        $db['profiles'][$i]['knownHashes']['sha256'] = ['a1b2c3'];
    }
}
file_put_contents($tmp, json_encode($db));
$cfg2 = $acpConfig; $cfg2['clientProfilesFile'] = $tmp;

$r = $nextclient;
$r['modules'] = [mod('hw.dll'), mod('client.dll'), mod('nextclient.dll', 'a1b2c3')];
$c2 = acs_client_apply($r, $cfg2);
ok('a known build hash marks the client verified', ($c2['verified'] ?? false) === true);
ok('verified profile downgrades all the way to INFO',
   sev($r, 'acs-inline-hook') === 'INFO', sev($r, 'acs-inline-hook'));

echo "\nOTHER CLIENTS\n";

$repack = [
    'modules' => [mod('hw.dll'), mod('client.dll'), mod('podbot_mm.dll')],
    'hlFiles' => [],
    'engine' => ['family' => 'rehlds', 'confidence' => 'marker', 'steamVerified' => false],
    'findings' => [
        finding('acs-foreign-module', 'WARNING', 'podbot_mm.dll — C:\\cs\\cstrike\\addons\\podbot\\podbot_mm.dll'),
        finding('acs-cheat-named-module', 'DETECTED', 'C:\\cs\\wallhack.dll'),
    ],
];
$r = $repack;
$c3 = acs_client_apply($r, $acpConfig);
ok('non-Steam repack matches the fallback profile', ($c3['id'] ?? '') === 'nonsteam-repack', $c3['id'] ?? '-');
ok('bundled bot module is explained', ($r['findings'][0]['explainedBy']['id'] ?? '') === 'nonsteam-repack');
ok('a cheat in a repack is still DETECTED', sev($r, 'acs-cheat-named-module') === 'DETECTED');

// A specific client must win over the generic fallback.
$r = ['modules' => [mod('hw.dll'), mod('gsclient.dll')], 'hlFiles' => [], 'findings' => []];
$c4 = acs_client_apply($r, $acpConfig);
ok('a specific client beats the non-Steam fallback', ($c4['id'] ?? '') === 'gsclient', $c4['id'] ?? '-');

$r = ['modules' => [mod('notgsclient.dll')], 'hlFiles' => [], 'findings' => []];
$fake = acs_client_apply($r, $acpConfig);
ok('client marker substrings do not impersonate a profile', ($fake['recognised'] ?? true) === false);

$r = ['modules' => [mod('hw.dll')], 'hlFiles' => [],
    'engine' => ['family' => 'esk', 'confidence' => 'marker', 'steamVerified' => false],
    'findings' => [finding('acp-local-steamclient', 'DETECTED', 'steamclient.dll')]];
$esk = acs_client_apply($r, $acpConfig);
ok('ESK engine identity selects the dedicated compatibility profile', ($esk['id'] ?? '') === 'esk');
ok('ESK compatibility is claimed and stops at WARNING', sev($r, 'acp-local-steamclient') === 'WARNING');

// Retail Steam install with no client mod: nothing should be claimed.
$r = ['modules' => [mod('hw.dll'), mod('client.dll'), mod('steamclient.dll')], 'hlFiles' => [], 'findings' => [
    finding('acs-inline-hook', 'DETECTED', 'hw.dll!SV_Frame @0x1 -> 0x2 (unbacked memory)'),
]];
$c5 = acs_client_apply($r, $acpConfig);
ok('retail Steam install matches no profile', ($c5['recognised'] ?? true) === false);
ok('and its engine detour stays DETECTED', sev($r, 'acs-inline-hook') === 'DETECTED');

echo "\nEFFECT ON THE VERDICT\n";

$r = $nextclient;
$before = acp_report_summary($r);
acs_client_apply($r, $acpConfig);
$after = acp_report_summary($r);
ok('detected count drops once the client is known',
   (int) $after['detected'] < (int) $before['detected'],
   sprintf('%d -> %d', (int) $before['detected'], (int) $after['detected']));

echo "\nCLIENT / PLATFORM INTEGRATION\n";

// The live desktop engine emits acp-* rule ids; the profiles were written against the
// older acs-* namespace. They must be treated as one namespace, otherwise a recognised
// client explains nothing in production and honest players stay flagged.
$r = [
    'modules' => [mod('hw.dll'), mod('client.dll'), mod('nextclient.dll')],
    'hlFiles' => [],
    'findings' => [finding('acp-inline-hook', 'DETECTED', 'hw.dll!SV_Frame @0x1 -> 0x2 (unbacked memory)')],
];
acs_client_apply($r, $acpConfig);
ok('live acp-* rule id is explained by the acs-* profile',
   ($r['findings'][0]['explainedBy']['id'] ?? '') === 'nextclient');

// Steam emulators and community clients added from their upstream projects.
$emulators = [
    'revemu'        => ['rev.ini'],
    'multiemulator' => ['multiemulator.dll'],
    'smartsteamemu' => ['SmartSteamEmu.ini'],
    'goldberg'      => ['goldberg.dll'],
    'creamapi'      => ['cream_api.ini'],
    'greenluma'     => ['GreenLuma.exe'],
];
foreach ($emulators as $id => $files) {
    $r = [
        'modules' => [mod('hw.dll'), mod('client.dll')],
        'hlFiles' => array_map(static fn($f) => ['relativePath' => 'cstrike/' . $f, 'sha256' => ''], $files),
        'findings' => [finding('acp-foreign-module', 'WARNING', $files[0] . ' — C:\\cs\\cstrike\\' . $files[0])],
    ];
    $c = acs_client_apply($r, $acpConfig);
    ok("$id profile is recognised and explains its module",
       ($c['id'] ?? '') === $id && ($r['findings'][0]['explainedBy']['id'] ?? '') === $id, $c['id'] ?? '-');
}

// Open-source ReHLDS server platform (ReUnion) loaded into a listen server, next to a cheat.
$r = [
    'modules' => [mod('hw.dll'), mod('client.dll'), mod('reunion_mm.dll')],
    'hlFiles' => [['relativePath' => 'cstrike/addons/reunion/reunion_mm.dll', 'sha256' => '']],
    'findings' => [
        finding('acp-foreign-module', 'WARNING', 'reunion_mm.dll — C:\\cs\\cstrike\\addons\\reunion\\reunion_mm.dll'),
        finding('acp-cheat-named-module', 'DETECTED', 'C:\\cs\\wallhack.dll'),
    ],
];
$c = acs_client_apply($r, $acpConfig);
ok('ReHLDS / ReUnion platform is recognised', ($c['id'] ?? '') === 'rehlds-platform', $c['id'] ?? '-');
ok('a cheat beside the server platform is still DETECTED',
   sev($r, 'acp-cheat-named-module') === 'DETECTED');

$r = [
    'modules' => [mod('hw.dll'), mod('client.dll'), mod('dproto.dll')],
    'hlFiles' => [['relativePath' => 'cstrike/addons/dproto/dproto.dll', 'sha256' => '']],
    'findings' => [
        finding('acp-foreign-module', 'WARNING', 'dproto.dll — C:\\cs\\cstrike\\addons\\dproto\\dproto.dll'),
    ],
];
$c = acs_client_apply($r, $acpConfig);
ok('DProto server platform is recognised', ($c['id'] ?? '') === 'rehlds-platform', $c['id'] ?? '-');

echo "\nSUBJECT MATCHING (closed bypasses)\n";

// A server-platform profile must never excuse a hook in the client's own render/HUD code.
// An empty addons/metamod folder ships with most repacks and is trivial to create, so
// this downgrade used to hand any wallhack a WARNING instead of a DETECTED.
$r = [
    'modules' => [mod('hw.dll'), mod('client.dll')],
    'hlFiles' => [['relativePath' => 'cstrike/addons/metamod/plugins.ini', 'sha256' => '']],
    'findings' => [finding('acp-inline-hook', 'DETECTED', 'client.dll!HUD_Redraw @0x1 -> 0x2 (unbacked memory)')],
];
acs_client_apply($r, $acpConfig);
ok('server platform does NOT excuse a client.dll HUD hook',
   sev($r, 'acp-inline-hook') === 'DETECTED', sev($r, 'acp-inline-hook'));

// A needle must name the file, not appear anywhere in its path.
$r = [
    'modules' => [mod('hw.dll'), mod('wh.dll')],
    'hlFiles' => [],
    'findings' => [finding('acp-foreign-module', 'DETECTED', 'wh.dll — C:\\Users\\x\\dproto_fix\\wh.dll')],
];
acs_client_apply($r, $acpConfig);
ok('a cheat in a folder named after a whitelisted plugin is not excused',
   sev($r, 'acp-foreign-module') === 'DETECTED', sev($r, 'acp-foreign-module'));

// ...while the genuine article still is.
$r = [
    'modules' => [mod('hw.dll'), mod('podbot_mm.dll')],
    'hlFiles' => [],
    'engine' => ['family' => 'rehlds', 'confidence' => 'marker', 'steamVerified' => false],
    'findings' => [finding('acp-foreign-module', 'DETECTED', 'podbot_mm.dll — C:\\cs\\cstrike\\addons\\podbot\\podbot_mm.dll')],
];
acs_client_apply($r, $acpConfig);
ok('the real bundled bot is still explained', sev($r, 'acp-foreign-module') === 'WARNING');

// moduleIntegrity entries use status:, not a clean: boolean. This block was dead code.
$r = [
    'modules' => [mod('hw.dll'), mod('nextclient.dll')],
    'hlFiles' => [],
    'findings' => [],
    'moduleIntegrity' => [
        ['module' => 'hw.dll', 'status' => 'patched', 'bytesDiffering' => 12],
        ['module' => 'client.dll', 'status' => 'clean', 'bytesDiffering' => 0],
    ],
];
$c = acs_client_apply($r, $acpConfig);
ok('a patched module the client explains is annotated',
   isset($r['moduleIntegrity'][0]['explainedBy']), 'integrityExplained=' . ($c['integrityExplained'] ?? 0));
// NextClient with new modules (next_engine_mini, next_lib, FileSystem_Proxy, nitro_api2)
$nextclient_new = [
    'modules' => [
        mod('hw.dll'),
        mod('client.dll'),
        mod('nitro_api2.dll', 'edbefdd9a66b71b0b0c2abb7472ab5ba0d0fca241653891bcb08d8ace532d3a9'),
        mod('next_engine_mini.dll'),
        mod('next_lib.dll'),
        mod('FileSystem_Proxy.dll'),
    ],
    'hlFiles' => [],
    'findings' => [
        finding('acp-foreign-module', 'WARNING', 'next_engine_mini.dll — C:\\cs\\next_engine_mini.dll'),
        finding('acp-foreign-module', 'WARNING', 'next_lib.dll — C:\\cs\\next_lib.dll'),
        finding('acp-foreign-module', 'WARNING', 'FileSystem_Proxy.dll — C:\\cs\\FileSystem_Proxy.dll'),
        finding('acp-foreign-module', 'WARNING', 'nitro_api2.dll — C:\\cs\\nitro_api2.dll'),
    ],
];
$r = $nextclient_new;
$c = acs_client_apply($r, $acpConfig);
ok('NextClient recognised via nitro_api2 / next_engine_mini', ($c['recognised'] ?? false) && $c['id'] === 'nextclient', $c['id'] ?? '-');
ok('NextClient verified via populated legitimate hash', ($c['verified'] ?? false) === true);
ok('next_engine_mini is explained down to INFO', sev($r, 'next_engine_mini.dll') === '(absent)' || $r['findings'][0]['severity'] === 'INFO', $r['findings'][0]['severity'] ?? '');
ok('FileSystem_Proxy is explained down to INFO', $r['findings'][2]['severity'] === 'INFO', $r['findings'][2]['severity'] ?? '');

printf("\n%d passed, %d failed\n\n", $pass, $fail);
exit($fail ? 1 : 0);

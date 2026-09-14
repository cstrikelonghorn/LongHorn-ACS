<?php
declare(strict_types=1);

// Access control for report data.
//
// reports/.htaccess blocks the raw files, but index.php / export_pdf.php / compare.php
// read the same files and render them, and ?download=json hands back the whole thing -
// SteamID, IP, disk serial, process and driver lists. These tests cover the gate that
// closes that path, including the case that makes a share link worth having: a key for
// one report must not open a different one.

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('CLI only');
}

putenv('ACS_ADMIN_TOKEN=admin-secret-token');
putenv('ACS_PUBLIC_DASHBOARD=0'); // Test private sharing regardless of deployment defaults.
putenv('ACS_REPORT_SECRET=report-signing-secret');
putenv('ACS_BEHAVIOR_FILE=' . sys_get_temp_dir() . '/access_test.sqlite');

require getenv('ACPDIR') . '/config.php';

$pass = 0; $fail = 0;
function ok(string $what, bool $cond, string $extra = ''): void {
    printf("  %-58s %s%s\n", $what, $cond ? 'PASS' : '*** FAIL ***', $extra ? "  ($extra)" : '');
    if ($cond) { $GLOBALS['pass']++; } else { $GLOBALS['fail']++; }
}

/** Simulate one HTTP request's inputs. */
function request(string $remote, array $get = [], array $cookie = [], array $headers = []): void {
    $_SERVER = array_merge($_SERVER, ['REMOTE_ADDR' => $remote]);
    unset($_SERVER['HTTP_X_ACS_TOKEN'], $_SERVER['HTTP_X_ACP_TOKEN'], $_SERVER['HTTP_AUTHORIZATION']);
    foreach ($headers as $k => $v) { $_SERVER[$k] = $v; }
    $_GET = $get;
    $_COOKIE = $cookie;
}

$REPORT = 'aabbccdd11223344';
$OTHER  = 'ffeeddcc99887766';

echo "\nREMOTE VIEWER (the public internet)\n";

request('203.0.113.9');
ok('anonymous remote cannot view a report', !acp_can_view_report($acpConfig, $REPORT));
ok('anonymous remote is not admin', !acp_admin_authenticated($acpConfig));

request('203.0.113.9', ['token' => 'wrong-token']);
ok('wrong admin token is rejected', !acp_admin_authenticated($acpConfig));

request('203.0.113.9', ['token' => 'admin-secret-token']);
ok('correct admin token in the query is accepted', acp_admin_authenticated($acpConfig));
ok('and it grants report access', acp_can_view_report($acpConfig, $REPORT));

request('203.0.113.9', [], ['acs_admin' => 'admin-secret-token']);
ok('the admin cookie is accepted', acp_admin_authenticated($acpConfig));

request('203.0.113.9', [], [], ['HTTP_X_ACS_TOKEN' => 'admin-secret-token']);
ok('the X-ACS-Token header is accepted', acp_admin_authenticated($acpConfig));

echo "\nSHARE KEYS\n";

request('203.0.113.9');
$key      = acp_report_view_key($acpConfig, $REPORT);
$otherKey = acp_report_view_key($acpConfig, $OTHER);

ok('a share key is minted', $key !== '' && strlen($key) === 32, $key);
ok('keys differ per report', $key !== $otherKey);

request('203.0.113.9', ['report' => $REPORT, 'k' => $key]);
ok('the right key opens its report', acp_can_view_report($acpConfig, $REPORT));

// The whole point of scoping: a leaked link must not become a master key.
request('203.0.113.9', ['report' => $OTHER, 'k' => $key]);
ok('a key for one report does NOT open another', !acp_can_view_report($acpConfig, $OTHER));

request('203.0.113.9', ['report' => $REPORT, 'k' => substr($key, 0, 31) . 'x']);
ok('a tampered key is rejected', !acp_can_view_report($acpConfig, $REPORT));

request('203.0.113.9', ['report' => $REPORT, 'k' => '']);
ok('an empty key is rejected', !acp_can_view_report($acpConfig, $REPORT));

echo "\nLOCAL DEPLOYMENT STILL WORKS\n";

request('127.0.0.1');
ok('localhost can view reports', acp_can_view_report($acpConfig, $REPORT));

echo "\nNO SECRET CONFIGURED\n";

// With nothing configured, a minted key would be guessable. Refusing to mint one is the
// safe answer; handing out a link that looks private but is not would be worse.
$bare = $acpConfig;
$bare['adminToken'] = '';
$bare['signatureSecret'] = '';
request('203.0.113.9');
ok('no secret means no share key is minted', acp_report_view_key($bare, $REPORT) === '');
ok('and remote access stays denied', !acp_can_view_report($bare, $REPORT));

printf("\n%d passed, %d failed\n\n", $pass, $fail);
exit($fail ? 1 : 0);

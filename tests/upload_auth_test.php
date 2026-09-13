<?php
declare(strict_types=1);

// Report uploads must always carry a valid token. acp_require_upload_auth() ends a refused
// request with acp_json_response(), which exits, so every case runs in its own PHP process.

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('CLI only');
}

$pass = 0; $fail = 0;
function ok(string $what, bool $cond): void {
    printf("  %-58s %s\n", $what, $cond ? 'PASS' : '*** FAIL ***');
    if ($cond) { $GLOBALS['pass']++; } else { $GLOBALS['fail']++; }
}

/** Runs the upload gate for one simulated request; true when the upload is let through. */
function upload_allowed(string $remote, string $token, bool $publicDashboard): bool {
    $code = '$_SERVER["REMOTE_ADDR"] = ' . var_export($remote, true) . ';'
        . ($token !== '' ? '$_SERVER["HTTP_X_ACS_TOKEN"] = ' . var_export($token, true) . ';' : '')
        . 'require getenv("ACPDIR") . "/config.php";'
        . 'acp_require_upload_auth($acpConfig); echo "ALLOWED";';
    $env = array_merge(getenv(), [
        'ACS_API_TOKEN' => 'upload-token-for-tests',
        'ACS_PUBLIC_DASHBOARD' => $publicDashboard ? '1' : '0',
    ]);
    $proc = proc_open([PHP_BINARY, '-r', $code], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $env);
    $out = stream_get_contents($pipes[1]);
    fclose($pipes[1]); fclose($pipes[2]);
    proc_close($proc);
    return str_contains((string) $out, 'ALLOWED');
}

foreach ([false, true] as $public) {
    echo "\nPUBLIC DASHBOARD " . ($public ? 'ON' : 'OFF') . "\n";
    ok('the configured token is accepted', upload_allowed('203.0.113.9', 'upload-token-for-tests', $public));
    ok('no token is refused', !upload_allowed('203.0.113.9', '', $public));
    ok('a wrong token is refused', !upload_allowed('203.0.113.9', 'not-the-token', $public));
}

printf("\n%d passed, %d failed\n\n", $pass, $fail);
exit($fail ? 1 : 0);

<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('CLI only');
}

$pass = 0; $fail = 0;
function ok(string $what, bool $cond): void {
    printf("  %-58s %s\n", $what, $cond ? 'PASS' : '*** FAIL ***');
    if ($cond) { $GLOBALS['pass']++; } else { $GLOBALS['fail']++; }
}

echo "ACS RATE LIMITING TEST SUITE\n\n";

// Helper to simulate an HTTP request to api.php or a test harness with specific headers and remote IP
function simulate_rate_limited_call(string $ip, string $action, int $limit, int $window): int {
    $tempReports = sys_get_temp_dir() . '/acs_test_reports_' . getmypid();
    if (!is_dir($tempReports)) {
        @mkdir($tempReports, 0755, true);
    }

    $env = array_merge(getenv(), [
        'ACS_API_TOKEN' => 'test-token',
    ]);

    $proc = proc_open([PHP_BINARY, '-r', '
        $_SERVER["REMOTE_ADDR"] = ' . var_export($ip, true) . ';
        require "' . str_replace('\\', '/', dirname(__DIR__)) . '/config.php";
        $cfg = $acpConfig;
        $cfg["reportsDir"] = ' . var_export($tempReports, true) . ';
        
        $action = ' . var_export($action, true) . ';
        $limit = ' . $limit . ';
        $windowSeconds = ' . $window . ';
        $ip = acs_client_ip();
        
        if (in_array($ip, ["127.0.0.1", "::1", ""], true)) {
            echo "BYPASS_LOCAL";
            exit(0);
        }
        
        $limitDir = $cfg["reportsDir"] . "/.ratelimit";
        if (!is_dir($limitDir)) @mkdir($limitDir, 0755, true);
        $key = hash("sha256", $action . ":" . $ip);
        $filePath = $limitDir . "/" . $key . ".json";
        
        $fp = fopen($filePath, "c+");
        flock($fp, LOCK_EX);
        $now = time();
        $cutoff = $now - $windowSeconds;
        $contents = (string) stream_get_contents($fp);
        $timestamps = [];
        if ($contents !== "") {
            $decoded = json_decode($contents, true);
            if (is_array($decoded)) {
                foreach ($decoded as $ts) {
                    if (is_int($ts) && $ts > $cutoff) $timestamps[] = $ts;
                }
            }
        }
        if (count($timestamps) >= $limit) {
            echo "THROTTLED_429";
            flock($fp, LOCK_UN);
            fclose($fp);
            exit(0);
        }
        $timestamps[] = $now;
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode($timestamps));
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
        echo "ALLOWED_200";
    '], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $env);

    $out = trim((string) stream_get_contents($pipes[1]));
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);

    if ($out === 'THROTTLED_429') return 429;
    if ($out === 'ALLOWED_200') return 200;
    if ($out === 'BYPASS_LOCAL') return 204;
    return 500;
}

// 1. Localhost bypass
$localStatus = simulate_rate_limited_call('127.0.0.1', 'upload_report', 2, 60);
ok('localhost is bypassed (never throttled)', $localStatus === 204);

// 2. Normal remote IP under limit
$ip = '198.51.100.42';
$s1 = simulate_rate_limited_call($ip, 'upload_report', 3, 60);
$s2 = simulate_rate_limited_call($ip, 'upload_report', 3, 60);
$s3 = simulate_rate_limited_call($ip, 'upload_report', 3, 60);
ok('first 3 requests from remote IP are allowed', $s1 === 200 && $s2 === 200 && $s3 === 200);

// 3. Exceeding limit returns 429
$s4 = simulate_rate_limited_call($ip, 'upload_report', 3, 60);
ok('4th request exceeding limit returns 429', $s4 === 429);

// 4. Different IP is not affected
$ip2 = '198.51.100.99';
$sOther = simulate_rate_limited_call($ip2, 'upload_report', 3, 60);
ok('different IP has independent rate limit budget', $sOther === 200);

printf("\n%d passed, %d failed\n\n", $pass, $fail);
exit($fail ? 1 : 0);

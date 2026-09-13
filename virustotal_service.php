<?php
declare(strict_types=1);

/**
 * VirusTotal API v3 Client & Automated Upload / Scan Integration
 *
 * Supports:
 * - Querying existing reports by SHA-256
 * - Automated upload of small files (<= 32MB) directly to /api/v3/files
 * - Automated upload of large files (> 32MB up to 650MB) via /api/v3/files/upload_url
 * - Polling analysis status /api/v3/analyses/{id}
 * - Local caching in database/virustotal_cache.json to avoid rate limits
 *
 * TLS certificate verification is always enabled. Hosts without a system CA
 * store (typical for PHP on Windows) must either set ACS_VT_CAINFO to a
 * cacert.pem bundle or drop one at database/cacert.pem.
 */

// Cached verdicts older than this are re-verified against the live API so
// updated engine verdicts eventually surface on the download page.
const VT_CACHE_TTL_SECONDS = 604800; // 7 days

function vt_get_cache_file(): string
{
    return __DIR__ . '/database/virustotal_cache.json';
}

function vt_load_cache(): array
{
    $file = vt_get_cache_file();
    if (file_exists($file)) {
        $data = @json_decode((string) file_get_contents($file), true);
        if (is_array($data)) return $data;
    }
    return [];
}

function vt_save_cache(array $cache): void
{
    $file = vt_get_cache_file();
    @file_put_contents($file, json_encode($cache, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

function vt_api_key(): string
{
    return trim((string) (getenv('ACS_VIRUSTOTAL_API_KEY') ?: getenv('ACP_VIRUSTOTAL_API_KEY') ?: ''));
}

/**
 * Optional explicit CA bundle for TLS verification on hosts without a system
 * CA store. Resolution order: ACS_VT_CAINFO env var, then database/cacert.pem.
 */
function vt_ca_bundle(): string
{
    static $ca = null;
    if ($ca !== null) return $ca;
    $ca = '';
    $envCa = trim((string) (getenv('ACS_VT_CAINFO') ?: getenv('ACP_VT_CAINFO') ?: ''));
    if ($envCa !== '' && is_file($envCa)) {
        $ca = $envCa;
    } elseif (is_file(__DIR__ . '/database/cacert.pem')) {
        $ca = __DIR__ . '/database/cacert.pem';
    }
    return $ca;
}

/**
 * Shared GET request helper. TLS peer verification stays on (libcurl defaults).
 * Returns ['status' => int, 'data' => decoded json|null, 'error' => string].
 */
function vt_curl_json(string $url, string $apiKey, int $timeout): array
{
    $ch = curl_init($url);
    $opts = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'x-apikey: ' . $apiKey,
            'Accept: application/json',
        ],
        CURLOPT_TIMEOUT => $timeout,
    ];
    $ca = vt_ca_bundle();
    if ($ca !== '') $opts[CURLOPT_CAINFO] = $ca;
    curl_setopt_array($ch, $opts);

    $raw = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr = curl_error($ch);
    curl_close($ch);

    if ($raw === false || $curlErr !== '') {
        return ['status' => 0, 'data' => null, 'error' => 'cURL error: ' . $curlErr];
    }
    return ['status' => $httpCode, 'data' => @json_decode((string) $raw, true), 'error' => ''];
}

function vt_query_file_report(string $sha256, string $apiKey): array
{
    if ($apiKey === '' || !preg_match('/^[a-f0-9]{64}$/i', $sha256)) {
        return ['ok' => false, 'status' => 400, 'error' => 'Invalid API key or hash format', 'data' => null];
    }

    $res = vt_curl_json('https://www.virustotal.com/api/v3/files/' . strtolower($sha256), $apiKey, 15);

    return [
        'ok' => ($res['status'] === 200),
        'status' => $res['status'],
        'data' => $res['data'],
        'error' => $res['error'],
    ];
}

function vt_query_analysis(string $analysisId, string $apiKey): array
{
    if ($apiKey === '' || $analysisId === '') {
        return ['ok' => false, 'status' => 400, 'error' => 'Invalid API key or analysis ID', 'data' => null];
    }

    $res = vt_curl_json('https://www.virustotal.com/api/v3/analyses/' . urlencode($analysisId), $apiKey, 15);

    return [
        'ok' => ($res['status'] === 200),
        'status' => $res['status'],
        'data' => $res['data'],
        'error' => $res['error'],
    ];
}

function vt_upload_file(string $filePath, string $apiKey): array
{
    if (!file_exists($filePath) || !is_readable($filePath)) {
        return ['ok' => false, 'error' => 'File not accessible on server'];
    }
    if ($apiKey === '') {
        return ['ok' => false, 'error' => 'VirusTotal API key is empty'];
    }

    $fileSize = filesize($filePath);
    $uploadUrl = 'https://www.virustotal.com/api/v3/files';

    // If file is > 32MB, request large file upload URL first
    if ($fileSize > 32 * 1024 * 1024) {
        $urlRes = vt_curl_json('https://www.virustotal.com/api/v3/files/upload_url', $apiKey, 20);
        if ($urlRes['status'] === 200 && is_array($urlRes['data']) && is_string($urlRes['data']['data'] ?? null)) {
            $uploadUrl = $urlRes['data']['data'];
        } else {
            return [
                'ok' => false,
                'status' => $urlRes['status'],
                'error' => ($urlRes['error'] !== '' ? $urlRes['error'] : 'Failed to obtain large file upload URL from VirusTotal'),
            ];
        }
    }

    // Now upload the binary via multipart form-data
    $mime = str_ends_with(strtolower($filePath), '.zip') ? 'application/zip' : 'application/octet-stream';
    $ch = curl_init($uploadUrl);
    $opts = [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => ['file' => new CURLFile($filePath, $mime, basename($filePath))],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'x-apikey: ' . $apiKey,
            'Accept: application/json',
        ],
        CURLOPT_TIMEOUT => 300, // 5 min timeout for 45MB upload
    ];
    $ca = vt_ca_bundle();
    if ($ca !== '') $opts[CURLOPT_CAINFO] = $ca;
    curl_setopt_array($ch, $opts);

    $response = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr = curl_error($ch);
    curl_close($ch);

    if ($response === false || $curlErr !== '') {
        return ['ok' => false, 'error' => 'Upload failed: ' . $curlErr];
    }

    $json = @json_decode((string) $response, true);
    if ($httpCode === 200 && isset($json['data']['id'])) {
        return [
            'ok' => true,
            'status' => 200,
            'analysis_id' => (string) $json['data']['id'],
            'type' => (string) ($json['data']['type'] ?? 'analysis'),
        ];
    }

    return [
        'ok' => false,
        'status' => $httpCode,
        'error' => $json['error']['message'] ?? ('HTTP ' . $httpCode . ': ' . substr((string) $response, 0, 300)),
        'raw' => $json,
    ];
}

/**
 * Converts a VirusTotal analysis `stats` block (identical shape on both the
 * /files/{id} report and the /analyses/{id} endpoints) into the verdict
 * numbers the download gate relies on. Returns null when the block carries
 * no usable engine data - never invents a clean verdict from nothing.
 */
function vt_stats_to_verdict(array $stats): ?array
{
    $threats = (int) ($stats['malicious'] ?? 0) + (int) ($stats['suspicious'] ?? 0);
    $clean = (int) ($stats['undetected'] ?? 0) + (int) ($stats['harmless'] ?? 0);
    $total = $clean + $threats + (int) ($stats['timeout'] ?? 0) + (int) ($stats['type-unsupported'] ?? 0);
    if ($total <= 0) return null;
    return ['threats' => $threats, 'clean' => $clean, 'total' => $total];
}

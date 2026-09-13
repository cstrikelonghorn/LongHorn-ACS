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
 */

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

function vt_query_file_report(string $sha256, string $apiKey): array
{
    if ($apiKey === '' || !preg_match('/^[a-f0-9]{64}$/i', $sha256)) {
        return ['ok' => false, 'status' => 400, 'error' => 'Invalid API key or hash format'];
    }

    $ch = curl_init('https://www.virustotal.com/api/v3/files/' . strtolower($sha256));
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'x-apikey: ' . $apiKey,
            'Accept: application/json',
        ],
        CURLOPT_TIMEOUT => 15,
        CURLOPT_SSL_VERIFYPEER => false,
    ]);

    $raw = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr = curl_error($ch);
    curl_close($ch);

    if ($raw === false || $curlErr !== '') {
        return ['ok' => false, 'status' => 0, 'error' => 'cURL error: ' . $curlErr];
    }

    $json = @json_decode((string) $raw, true);

    return [
        'ok' => ($httpCode === 200),
        'status' => $httpCode,
        'data' => $json,
    ];
}

function vt_query_analysis(string $analysisId, string $apiKey): array
{
    if ($apiKey === '' || $analysisId === '') {
        return ['ok' => false, 'status' => 400, 'error' => 'Invalid API key or analysis ID'];
    }

    $ch = curl_init('https://www.virustotal.com/api/v3/analyses/' . urlencode($analysisId));
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'x-apikey: ' . $apiKey,
            'Accept: application/json',
        ],
        CURLOPT_TIMEOUT => 15,
        CURLOPT_SSL_VERIFYPEER => false,
    ]);

    $raw = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr = curl_error($ch);
    curl_close($ch);

    if ($raw === false || $curlErr !== '') {
        return ['ok' => false, 'status' => 0, 'error' => 'cURL error: ' . $curlErr];
    }

    $json = @json_decode((string) $raw, true);

    return [
        'ok' => ($httpCode === 200),
        'status' => $httpCode,
        'data' => $json,
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
        $chUrl = curl_init('https://www.virustotal.com/api/v3/files/upload_url');
        curl_setopt_array($chUrl, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'x-apikey: ' . $apiKey,
                'Accept: application/json',
            ],
            CURLOPT_TIMEOUT => 20,
            CURLOPT_SSL_VERIFYPEER => false,
        ]);
        $urlRaw = curl_exec($chUrl);
        $urlCode = (int) curl_getinfo($chUrl, CURLINFO_HTTP_CODE);
        curl_close($chUrl);

        if ($urlCode === 200 && is_string($urlRaw)) {
            $urlJson = @json_decode($urlRaw, true);
            if (!empty($urlJson['data']) && is_string($urlJson['data'])) {
                $uploadUrl = $urlJson['data'];
            } else {
                return ['ok' => false, 'error' => 'Failed to obtain large file upload URL from VirusTotal'];
            }
        } else {
            return ['ok' => false, 'status' => $urlCode, 'error' => 'VirusTotal upload_url endpoint returned HTTP ' . $urlCode . ': ' . substr((string)$urlRaw, 0, 200)];
        }
    }

    // Now upload the binary via multipart form-data
    $mime = str_ends_with(strtolower($filePath), '.zip') ? 'application/zip' : 'application/octet-stream';
    $postFields = [
        'file' => new CURLFile($filePath, $mime, basename($filePath)),
    ];

    $ch = curl_init($uploadUrl);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $postFields,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'x-apikey: ' . $apiKey,
            'Accept: application/json',
        ],
        CURLOPT_TIMEOUT => 300, // 5 min timeout for 45MB upload
        CURLOPT_SSL_VERIFYPEER => false,
    ]);

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
        'error' => $json['error']['message'] ?? ('HTTP ' . $httpCode . ': ' . substr((string)$response, 0, 300)),
        'raw' => $json,
    ];
}

/**
 * Convert any URL to its VirusTotal v3 base64 URL identifier
 */
function vt_url_to_id(string $url): string
{
    return rtrim(strtr(base64_encode(trim($url)), '+/', '-_'), '=');
}

/**
 * Submit a URL to VirusTotal for cloud scanning: POST /api/v3/urls
 */
function vt_submit_url(string $url, string $apiKey): array
{
    if ($url === '') {
        return ['ok' => false, 'error' => 'URL cannot be empty'];
    }
    if ($apiKey === '') {
        return ['ok' => false, 'error' => 'VirusTotal API key is empty'];
    }

    $ch = curl_init('https://www.virustotal.com/api/v3/urls');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query(['url' => $url]),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'x-apikey: ' . $apiKey,
            'Content-Type: application/x-www-form-urlencoded',
            'Accept: application/json',
        ],
        CURLOPT_TIMEOUT => 20,
        CURLOPT_SSL_VERIFYPEER => false,
    ]);

    $response = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr = curl_error($ch);
    curl_close($ch);

    if ($response === false || $curlErr !== '') {
        return ['ok' => false, 'status' => 0, 'error' => 'cURL error: ' . $curlErr];
    }

    $json = @json_decode((string) $response, true);
    $urlId = vt_url_to_id($url);

    if ($httpCode === 200 && isset($json['data']['id'])) {
        return [
            'ok' => true,
            'status' => 200,
            'analysis_id' => (string) $json['data']['id'],
            'url_id' => $urlId,
            'url' => $url,
            'virustotal_url' => 'https://www.virustotal.com/gui/url/' . $urlId,
        ];
    }

    return [
        'ok' => false,
        'status' => $httpCode,
        'error' => $json['error']['message'] ?? ('HTTP ' . $httpCode . ': ' . substr((string) $response, 0, 300)),
        'url_id' => $urlId,
        'url' => $url,
        'virustotal_url' => 'https://www.virustotal.com/gui/url/' . $urlId,
    ];
}

/**
 * Query an existing URL report: GET /api/v3/urls/{url_id}
 */
function vt_query_url_report(string $urlOrId, string $apiKey): array
{
    if ($urlOrId === '' || $apiKey === '') {
        return ['ok' => false, 'status' => 400, 'error' => 'Invalid parameters'];
    }

    $urlId = (str_starts_with($urlOrId, 'http://') || str_starts_with($urlOrId, 'https://'))
        ? vt_url_to_id($urlOrId)
        : $urlOrId;

    $ch = curl_init('https://www.virustotal.com/api/v3/urls/' . urlencode($urlId));
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'x-apikey: ' . $apiKey,
            'Accept: application/json',
        ],
        CURLOPT_TIMEOUT => 15,
        CURLOPT_SSL_VERIFYPEER => false,
    ]);

    $raw = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr = curl_error($ch);
    curl_close($ch);

    if ($raw === false || $curlErr !== '') {
        return ['ok' => false, 'status' => 0, 'error' => 'cURL error: ' . $curlErr];
    }

    $json = @json_decode((string) $raw, true);

    return [
        'ok' => ($httpCode === 200),
        'status' => $httpCode,
        'url_id' => $urlId,
        'virustotal_url' => 'https://www.virustotal.com/gui/url/' . $urlId,
        'data' => $json,
    ];
}


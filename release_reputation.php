<?php
declare(strict_types=1);

/** Describe only a real, hash-matched VirusTotal response. No synthetic safety verdicts. */
function acs_release_reputation(string $sha256, ?array $response): array
{
    $out = ['is_indexed' => false, 'status' => 'unverified', 'verdict' => 'No verified antivirus results for this release',
        'engines_scanned' => null, 'threats_detected' => null, 'vendors' => [], 'analysis_timestamp' => null];
    if (($response['data']['id'] ?? '') !== $sha256 || !preg_match('/^[a-f0-9]{64}$/', $sha256)) return $out;
    $attributes = $response['data']['attributes'] ?? [];
    $stats = $attributes['last_analysis_stats'] ?? null;
    if (!is_array($stats) || !isset($attributes['last_analysis_date'])) return $out;
    foreach ($stats as $count) if (!is_int($count) || $count < 0) return $out;
    if (array_sum($stats) === 0) return $out;
    $out['is_indexed'] = true;
    $out['engines_scanned'] = array_sum($stats);
    $out['threats_detected'] = ($stats['malicious'] ?? 0) + ($stats['suspicious'] ?? 0);
    $out['status'] = $out['threats_detected'] > 0 ? 'flagged' : 'no-detections';
    $out['verdict'] = $out['threats_detected'] > 0 ? 'Antivirus flags reported — review before running' : 'No malicious or suspicious detections reported; not a safety certification';
    $out['analysis_timestamp'] = gmdate('c', (int) $attributes['last_analysis_date']);
    foreach (($attributes['last_analysis_results'] ?? []) as $id => $engine) {
        $out['vendors'][] = ['name' => (string) ($engine['engine_name'] ?? $id),
            'category' => (string) ($engine['category'] ?? 'unknown'),
            'result' => (string) ($engine['result'] ?? $engine['category'] ?? 'unknown'),
            'version' => (string) ($engine['engine_version'] ?? '')];
    }
    return $out;
}

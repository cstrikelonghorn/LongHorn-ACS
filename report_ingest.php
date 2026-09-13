<?php
declare(strict_types=1);

/** Decode both protocol versions, enforcing the same signature policy on each. */
function acp_decode_upload(array $payload, array $config): array
{
    $reportJson = $payload['reportJson'] ?? '';
    if (!is_string($reportJson)) {
        throw new InvalidArgumentException('reportJson must be a string');
    }
    $signature = $payload['signature'] ?? '';
    $verified = $reportJson !== '' && is_string($signature)
        && ($payload['algorithm'] ?? '') === 'hmac-sha256'
        && ($config['signatureSecret'] ?? '') !== ''
        && acp_verify_report_signature($reportJson, $signature, $config['signatureSecret']);
    if (($config['requireReportSignature'] ?? false) && !$verified) {
        throw new UnexpectedValueException('Invalid or missing report signature');
    }
    $report = $reportJson !== '' ? json_decode($reportJson, true, 128, JSON_THROW_ON_ERROR)
        : ($payload['report'] ?? $payload);
    if (!is_array($report) || array_is_list($report)
        || !isset($report['findings']) || !is_array($report['findings']) || !array_is_list($report['findings'])) {
        throw new InvalidArgumentException('Report must contain a findings array');
    }
    foreach ($report['findings'] as $finding) {
        if (!is_array($finding) || !in_array($finding['severity'] ?? '', ['DETECTED', 'WARNING', 'INFO'], true)) {
            throw new InvalidArgumentException('Invalid finding severity');
        }
    }
    foreach (['modules', 'drivers', 'processes', 'hlFiles', 'engineChecks', 'scanStages'] as $key) {
        if (isset($report[$key]) && (!is_array($report[$key]) || !array_is_list($report[$key]))) {
            throw new InvalidArgumentException("Invalid $key inventory");
        }
        foreach ($report[$key] ?? [] as $row) {
            if (!is_array($row)) throw new InvalidArgumentException("Invalid $key entry");
        }
    }
    if (isset($report['summary']) && !is_array($report['summary'])) {
        throw new InvalidArgumentException('Invalid report summary');
    }
    return [$report, $verified];
}

/** Recompute counters from accepted inventory and findings, never submitted totals. */
function acp_normalize_report(array &$report): void
{
    $summary = acp_report_summary($report);
    $report['status'] = $summary['status'];
    $report['summary'] = is_array($report['summary'] ?? null) ? $report['summary'] : [];
    foreach (['processes', 'modules', 'drivers', 'hlFiles', 'memoryArtifacts'] as $key) {
        $report['summary'][$key] = is_array($report[$key] ?? null) ? count($report[$key]) : 0;
    }
    foreach (['detected', 'warnings', 'info'] as $key) $report['summary'][$key] = $summary[$key];
    $report['summary']['findings'] = count(acp_report_findings($report));
}

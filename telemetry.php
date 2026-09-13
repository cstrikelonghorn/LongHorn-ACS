<?php
declare(strict_types=1);

// Telemetry ingestion for the ACS ReHLDS plugin.
//
// This endpoint accepts claims about named players from machines the backend does not
// control, which makes authentication the whole story: anyone who can post here
// unauthenticated can manufacture a ban-worthy record against any SteamID. So it fails
// closed - with no ACS_TELEMETRY_SECRET configured it refuses every request rather than
// falling back to accepting unsigned ones.
//
// The secret is deliberately separate from ACP_API_TOKEN, which ships inside the desktop
// client on every player's machine and must therefore be assumed public.

require __DIR__ . '/config.php';

try {
    $action = (string) ($_GET['action'] ?? 'ingest');

    if ($action === 'health') {
        $configured = ($acpConfig['telemetrySecret'] ?? '') !== '';
        acp_json_response([
            'ok'      => true,
            'service' => 'ACS telemetry',
            'accepting' => $configured,
            'reason'  => $configured ? null : 'ACS_TELEMETRY_SECRET is not set; uploads are refused',
            'serverTime' => gmdate('Y-m-d\TH:i:s\Z'),
        ]);
    }

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        acp_json_response(['ok' => false, 'error' => 'POST required'], 405);
    }

    $secret = (string) ($acpConfig['telemetrySecret'] ?? '');
    if ($secret === '') {
        acp_json_response([
            'ok' => false,
            'error' => 'Telemetry is not configured. Set ACS_TELEMETRY_SECRET on the backend '
                     . 'and the matching secret in the plugin config.',
        ], 503);
    }

    $length = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($length > (int) $acpConfig['maxTelemetryBytes']) {
        acp_json_response(['ok' => false, 'error' => 'Batch too large'], 413);
    }

    $raw = (string) file_get_contents('php://input');
    if ($raw === '' || strlen($raw) > (int) $acpConfig['maxTelemetryBytes']) {
        acp_json_response(['ok' => false, 'error' => 'Empty or oversized body'], 400);
    }

    $signature = trim((string) ($_SERVER['HTTP_X_ACS_SIGNATURE'] ?? $_SERVER['HTTP_X_URANAC_SIGNATURE'] ?? ''));
    $serverId  = trim((string) ($_SERVER['HTTP_X_ACS_SERVER'] ?? $_SERVER['HTTP_X_URANAC_SERVER'] ?? ''));

    // hash_equals, not ==, so a wrong signature cannot be recovered byte by byte from
    // response timing.
    $expected = hash_hmac('sha256', $raw, $secret);
    if ($signature === '' || !hash_equals($expected, strtolower($signature))) {
        acp_json_response(['ok' => false, 'error' => 'Invalid signature'], 401);
    }

    $payload = json_decode($raw, true);
    if (!is_array($payload)) {
        acp_json_response(['ok' => false, 'error' => 'Invalid JSON'], 400);
    }

    // The server id is self-declared, but it is signed with the shared secret, so it
    // identifies which of *your* servers sent this - not an arbitrary caller.
    if ($serverId === '') {
        $serverId = (string) ($payload['serverId'] ?? '');
    }
    $serverId = mb_substr($serverId, 0, 64);
    if ($serverId === '') {
        $serverId = 'unnamed';
    }

    $pdo    = acp_behavior_open($acpConfig);
    $result = acp_behavior_ingest($pdo, $payload, $serverId);

    acp_json_response([
        'ok'      => true,
        'stored'  => $result['stored'],
        'players' => $result['players'],
    ]);
} catch (Throwable $e) {
    error_log('[ACS] ' . $e->getMessage());
    acp_json_response(['ok' => false, 'error' => 'Internal error'], 500);
}

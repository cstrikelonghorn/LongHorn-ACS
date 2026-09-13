<?php
declare(strict_types=1);

/**
 * Export report to PDF / Printable Format.
 *
 * Matches the exact modern, sleek dark UI design of the LongHorn ACS report.
 * Provides a "Print / Save as PDF" action for standard browser PDF printing (Ctrl+P).
 *
 * Usage: export_pdf.php?report=<id>
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/theme_bar.php';

if (!function_exists('acp_items')) {
    function acp_items(array $report, string $key): array
    {
        $items = $report['detectedCheats'][$key] ?? [];
        return is_array($items) ? $items : [];
    }
}

$report = null;
$error = '';

try {
    $id = trim((string) ($_GET['report'] ?? ''));
    if ($id === '') {
        $error = 'No report ID provided.';
    } else {
        // A printable export is the same player data in another wrapper, so it answers to
        // the same gate as the report page.
        acp_admin_remember_token($acpConfig);
        acp_require_report_access($acpConfig, $id);

        $report = acp_load_report($acpConfig, $id);
        if ($report === null) {
            $error = "Report '{$id}' not found.";
        }
    }
} catch (Throwable $e) {
    $error = $e->getMessage();
}

if ($error !== '') {
    http_response_code(404);
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Error</title><style>body{background:#0e1217;color:#e8e3d8;font-family:sans-serif;padding:40px;}</style></head><body><h1>Report Error</h1><p>' . acp_h($error) . '</p></body></html>';
    exit;
}

$summary = acp_report_summary($report);
$cc = $summary['categoryCounts'];
$totalScans = acp_count_total_scans($acpConfig, $report);
$buildBadge = acp_game_build_badge($report, $summary['gameBuild']);
$geo = acp_ip_geo($summary['ip']);

$statusText = $summary['status'] === 'DETECTED' ? 'Cheats detected' : ($summary['status'] === 'WARNING' ? 'Review required' : 'No cheats detected');
$statusColor = $summary['status'] === 'DETECTED' ? '#ff3b5c' : ($summary['status'] === 'WARNING' ? 'var(--warn)' : '#00f0a8');

$createdAtRaw = $summary['createdAt'] ?: $summary['uploadedAt'];
$createdAtFmt = acp_fmt_time($createdAtRaw);
$launchFmt = acp_fmt_time($summary['gameLaunchTime']);
$sessionDelta = acp_session_delta_text((string) $summary['gameLaunchTime'], (string) $createdAtRaw);

$allDetectedRows = array_merge(
    acp_items($report, 'injected'),
    acp_items($report, 'behavioral'),
    acp_items($report, 'previouslyLaunched'),
    acp_items($report, 'installedInOs'),
    acp_items($report, 'downloaded')
);
// Only DETECTED is a confirmed cheat; WARNING items belong in the review table below.
$detectedRows = array_values(array_filter(
    $allDetectedRows,
    static fn($r) => strtoupper((string) ($r['severity'] ?? '')) === 'DETECTED'
));
$parsedDetections = array_map('acp_gamer_detection', $detectedRows);

$allReportFindings = acp_report_findings($report);
$reviewFindings = array_values(array_filter(
    $allReportFindings,
    static fn(array $f): bool => strtoupper((string) ($f['severity'] ?? '')) !== 'DETECTED'
));
$parsedReview = array_map('acp_gamer_finding', $reviewFindings);

/* ---------------------------------------------------------------------------
 * Everything the report page shows, rendered as printable tables.
 * ------------------------------------------------------------------------- */
function pdf_table(array $rows, array $columns, string $empty): void
{
    echo '<div class="table-wrap"><table><thead><tr>';
    foreach ($columns as $label => $_) {
        echo '<th>' . acp_h((string) $label) . '</th>';
    }
    echo '</tr></thead><tbody>';

    foreach ($rows as $row) {
        echo '<tr>';
        foreach ($columns as $field) {
            $raw = is_array($row) ? ($row[$field] ?? '') : '';
            if (is_bool($raw)) {
                $value = $raw ? 'Yes' : 'No';
            } else {
                $value = (string) $raw;
            }

            if ($field === 'corpusState' && $value !== '') {
                $map = ['cheat' => 'DETECTED', 'unknown' => 'WARNING', 'clean' => 'CLEAN'];
                $cls = $map[$value] ?? 'INFO';
                echo '<td><span class="badge ' . $cls . '">' . acp_h(strtoupper($value)) . '</span></td>';
                continue;
            }

            if (($field === 'severity' || $field === 'status') && $value !== '') {
                $cls = strtoupper($value);
                if (!in_array($cls, ['DETECTED', 'WARNING', 'CLEAN', 'OK', 'REVIEW', 'INFO'], true)) {
                    $cls = 'INFO';
                }
                if ($cls === 'OK') {
                    $cls = 'CLEAN';
                } elseif ($cls === 'REVIEW') {
                    $cls = 'WARNING';
                }
                echo '<td><span class="badge ' . $cls . '">' . acp_h($value) . '</span></td>';
                continue;
            }

            echo '<td>' . acp_h($value) . '</td>';
        }
        echo '</tr>';
    }

    if (count($rows) === 0) {
        echo '<tr><td colspan="' . count($columns) . '" class="empty-cell">' . acp_h($empty) . '</td></tr>';
    }

    echo '</tbody></table></div>';
}

function pdf_field(string $label, string $value, bool $mono = false): void
{
    $empty = trim($value) === '' || $value === 'Not found';
    echo '<div class="spec-row"><div class="spec-key">' . acp_h($label) . '</div>';
    echo '<div class="spec-val' . ($mono ? ' mono' : '') . ($empty ? ' is-empty' : '') . '">' . acp_h($empty ? 'Not found' : $value) . '</div></div>';
}

function pdf_field_group(string $label): void
{
    echo '<div class="spec-group">' . acp_h($label) . '</div>';
}

$database = acp_load_database($acpConfig);
$counts = $database['counts'] ?? [];

$previousScans = acp_enrich_previous_scans(
    $acpConfig,
    is_array($report['previousScans'] ?? null) ? $report['previousScans'] : []
);

$corpusStates = is_array($report['corpus']['states'] ?? null) ? $report['corpus']['states'] : [];
$pdfModules = array_map(static function ($m) use ($corpusStates) {
    if (is_array($m) && isset($m['path'])) {
        $m['path'] = acp_sanitize_path((string) $m['path']);
    }
    $sha = strtolower((string) ($m['sha256'] ?? ''));
    $state = $corpusStates[$sha]['state'] ?? 'unseen';
    $machines = $corpusStates[$sha]['machines'] ?? null;
    $m['corpusState'] = $state;
    $m['corpusSeen'] = $machines === null ? '' : ($machines . ' machines');
    return $m;
}, array_slice($report['modules'] ?? [], 0, 500));

$pdfDrivers = array_map(static function ($d) {
    if (is_array($d) && isset($d['path'])) {
        $d['path'] = acp_sanitize_path((string) $d['path']);
    }
    return $d;
}, array_slice($report['drivers'] ?? [], 0, 500));

$pdfHlFiles = array_map(static function ($f) {
    if (is_array($f) && isset($f['relativePath'])) {
        $f['relativePath'] = acp_sanitize_path((string) $f['relativePath']);
    }
    return $f;
}, array_slice($report['hlFiles'] ?? [], 0, 500));

$pdfProcesses = acp_sanitize_processes(array_slice($report['processes'] ?? [], 0, 500));
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ACS — Report <?= acp_h((string) ($summary['id'] ?? '')) ?></title>
    <link rel="stylesheet" href="assets/theme.css">
<?php uds_theme_head(); ?>
    <link rel="stylesheet" href="assets/acp.css?v=<?= filemtime(__DIR__ . '/assets/acp.css') ?>">
    <style>
        html[data-uds-theme] body { padding: 0; }
        html[data-uds-theme] .pdf-wrap { width: min(1180px, calc(100% - 40px)); margin: 0 auto; padding: 22px 0 60px; }
        html[data-uds-theme] .pdf-header { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 14px 18px; margin-bottom: 18px; background: var(--surface); border: 1px solid var(--line); border-radius: var(--r); box-shadow: var(--shadow); }
        html[data-uds-theme] .pdf-title { font-family: var(--f-display); font-size: 22px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; color: var(--text); }
        html[data-uds-theme] .pdf-title em { font-style: normal; color: var(--accent); }
        html[data-uds-theme] .pdf-sub { margin-top: 2px; font-family: var(--f-mono); font-size: 11px; color: var(--muted); }
        html[data-uds-theme] .print-btn { display: inline-flex; align-items: center; gap: 8px; padding: 10px 18px; font-family: var(--f-ui); font-size: 12.5px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; color: #04121a; background: linear-gradient(135deg, var(--accent), var(--accent-2)); border: 1px solid transparent; border-radius: var(--r); cursor: pointer; }
        html[data-uds-theme] .print-btn:hover { filter: brightness(1.08); }
        html[data-uds-theme] .section-heading { display: flex; align-items: center; gap: 10px; margin: 22px 0 12px; padding-bottom: 8px; border-bottom: 1px solid var(--line-soft); font-family: var(--f-display); font-size: 16px; font-weight: 700; letter-spacing: 1.2px; text-transform: uppercase; color: var(--text); }
        html[data-uds-theme] .section-heading::before { content: ""; width: 3px; height: 15px; flex: none; background: var(--accent); box-shadow: 0 0 10px var(--accent-glow); }
        html[data-uds-theme] .t-val { font-size: 12.5px; color: var(--text-2); overflow-wrap: anywhere; }
        html[data-uds-theme] .pdf-table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 12.5px; }
        html[data-uds-theme] .pdf-table th { padding: 9px 12px; text-align: left; white-space: nowrap; background: var(--surface-2); border-bottom: 1px solid var(--line); font-family: var(--f-mono); font-size: 10px; font-weight: 600; letter-spacing: 1.4px; text-transform: uppercase; color: var(--muted); }
        html[data-uds-theme] .pdf-table td { padding: 9px 12px; border-bottom: 1px solid var(--line-soft); vertical-align: top; color: var(--text-2); }
        html[data-uds-theme] .pdf-vec-badge { display: inline-block; padding: 2px 8px; border-radius: var(--r); border: 1px solid var(--line-strong); font-family: var(--f-mono); font-size: 9.5px; letter-spacing: 1px; text-transform: uppercase; color: var(--muted); }
        html[data-uds-theme] .pdf-badge-danger { display: inline-block; padding: 2px 9px; border-radius: 999px; background: var(--danger-dim); color: var(--danger); border: 1px solid color-mix(in srgb, var(--danger) 42%, transparent); font-family: var(--f-mono); font-size: 10px; font-weight: 700; letter-spacing: 1.2px; text-transform: uppercase; }
        html[data-uds-theme] .pdf-badge-warn { display: inline-block; padding: 2px 9px; border-radius: 999px; background: var(--warn-dim); color: var(--warn); border: 1px solid color-mix(in srgb, var(--warn) 42%, transparent); font-family: var(--f-mono); font-size: 10px; font-weight: 700; letter-spacing: 1.2px; text-transform: uppercase; }
        html[data-uds-theme] .pdf-chip { display: inline-block; padding: 2px 8px; border-radius: 999px; background: color-mix(in srgb, var(--accent-2) 13%, transparent); color: #b6a4ff; border: 1px solid color-mix(in srgb, var(--accent-2) 40%, transparent); font-family: var(--f-mono); font-size: 9.5px; letter-spacing: 1px; text-transform: uppercase; }
        html[data-uds-theme] .pdf-mono { font-family: var(--f-mono); font-size: 11px; color: var(--muted); }
        html[data-uds-theme] .pdf-footer { display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-top: 26px; padding-top: 14px; border-top: 1px solid var(--line-soft); color: var(--muted); font-family: var(--f-mono); font-size: 11px; }
        @media print {
            html[data-uds-theme] .print-btn { display: none; }
            html[data-uds-theme] .pdf-wrap { width: 100%; padding: 0; }
            html[data-uds-theme] .telemetry-card, html[data-uds-theme] .pdf-table, html[data-uds-theme] .table-wrap { break-inside: avoid; }
            html[data-uds-theme] details.pdf-acc > .inner { display: block !important; }
            html[data-uds-theme] details.pdf-acc > summary { list-style: none; }
            html[data-uds-theme] .table-wrap { overflow: visible; }
            html[data-uds-theme] .table-wrap table { min-width: 0; }
        }
    </style>
</head>
<body>
    <div class="pdf-wrap">
    <div class="pdf-header">
        <div class="pdf-brand">
            <div>
                <div class="pdf-title">ACS <em>Anti-Cheat</em> Report</div>
                <div class="pdf-sub">LongHorn Official Forensic Evidence Console</div>
            </div>
        </div>
        <div>
            <button type="button" class="print-btn" onclick="document.querySelectorAll('details').forEach(function(d){d.open=true;}); setTimeout(function(){ window.print(); }, 60);">Print / Save as PDF</button>
        </div>
    </div>

    <!-- Compact Verdict matching Web UI -->
    <div class="verdict v-<?= acp_h($summary['status']) ?> verdict-compact">
        <div class="verdict-main">
            <span class="verdict-status-badge"><?= acp_h($summary['status']) ?></span>
            <div class="verdict-title"><?= acp_h($statusText) ?></div>
        </div>
        <div class="verdict-counters">
            <div class="v-counter-cell <?= $cc['injected'] > 0 ? 'is-active' : '' ?>">
                <span class="vc-num"><?= (int) $cc['injected'] ?></span>
                <span class="vc-lbl">Injected</span>
            </div>
            <div class="v-counter-cell <?= $cc['behavioral'] > 0 ? 'is-active' : '' ?>">
                <span class="vc-num"><?= (int) $cc['behavioral'] ?></span>
                <span class="vc-lbl">Behavior</span>
            </div>
            <div class="v-counter-cell <?= $cc['previouslyLaunched'] > 0 ? 'is-active' : '' ?>">
                <span class="vc-num"><?= (int) $cc['previouslyLaunched'] ?></span>
                <span class="vc-lbl">Launched</span>
            </div>
            <div class="v-counter-cell <?= $cc['installedInOs'] > 0 ? 'is-active' : '' ?>">
                <span class="vc-num"><?= (int) $cc['installedInOs'] ?></span>
                <span class="vc-lbl">Installed</span>
            </div>
            <div class="v-counter-cell <?= $cc['downloaded'] > 0 ? 'is-active' : '' ?>">
                <span class="vc-num"><?= (int) $cc['downloaded'] ?></span>
                <span class="vc-lbl">Downloaded</span>
            </div>
        </div>
    </div>

    <!-- Telemetry Cards matching Web UI -->
    <div class="section-heading">Gaming Telemetry &amp; Basic Data</div>
    <div class="telemetry-grid">
        <!-- Card 1: Player Identity -->
        <div class="telemetry-card">
            <div class="t-card-header">
                <span class="t-card-title">Player Identity</span>
                <span class="mono" style="color:var(--muted);"><?= (int) $totalScans ?> <?= $totalScans === 1 ? 'Scan' : 'Scans' ?></span>
            </div>
            <div class="t-row"><span class="t-label">Nickname</span><span class="t-val"><?= acp_h($summary['playerName'] ?: 'Unknown') ?></span></div>
            <div class="t-row"><span class="t-label">Player ID</span><span class="t-val mono"><?= acp_h($summary['playerId'] ?: '—') ?></span></div>
            <div class="t-row"><span class="t-label">Steam ID (Steam2)</span><span class="t-val mono"><?= acp_h($summary['steamId2'] ?: $summary['steamId'] ?: 'Not found') ?></span></div>
            <div class="t-row"><span class="t-label">Player IP</span><span class="t-val mono"><?= acp_h(acp_mask_ip($summary['ip'])) ?><?= $geo['country'] !== '' ? ' (' . acp_h($geo['country']) . ')' : '' ?></span></div>
            <div class="t-row"><span class="t-label">Host Machine</span><span class="t-val"><?= acp_h($summary['machine']) ?></span></div>
        </div>

        <!-- Card 2: Game Client & Engine Environment -->
        <div class="telemetry-card">
            <div class="t-card-header">
                <span class="t-card-title">Game Client &amp; Engine</span>
                <span class="build-badge b-<?= acp_h($buildBadge['class']) ?>"><?= acp_h($buildBadge['label']) ?></span>
            </div>
<?php
            // Same rule as the report page: "Official Steam Retail" only with signature proof.
            $engineVerified = ($buildBadge['verified'] ?? false) === true;
            $pdfDistribution = match (true) {
                $engineVerified && $buildBadge['isSteam'] => 'Official Steam Retail (Valve signature verified)',
                $engineVerified && ($buildBadge['confidence'] ?? '') === 'review' => 'Steam install — engine not genuine',
                $engineVerified && ($buildBadge['confidence'] ?? '') === 'none' => 'Unverified client',
                !$engineVerified && $buildBadge['isSteam'] => 'Steam (not verified — old scanner)',
                default => 'Non-Steam Client',
            };
?>
            <div class="t-row"><span class="t-label">Distribution</span><span class="t-val"><?= acp_h($pdfDistribution) ?></span></div>
            <div class="t-row"><span class="t-label">Game Build</span><span class="t-val"><?= acp_h($buildBadge['cleanBuild']) ?></span></div>
            <?php if ($engineVerified): ?>
<?php
            $pdfEngine = array_filter([
                (string) ($buildBadge['engineModule'] ?? ''),
                ($buildBadge['engineVersion'] ?? '') !== '' ? 'v' . $buildBadge['engineVersion'] : '',
                ($buildBadge['engineBuildNumber'] ?? null) !== null ? 'build ' . $buildBadge['engineBuildNumber'] : '',
            ]);
?>
            <div class="t-row"><span class="t-label">Engine Build</span><span class="t-val mono"><?= acp_h($pdfEngine ? implode(' · ', $pdfEngine) : 'not found') ?></span></div>
            <?php endif; ?>
            <div class="t-row"><span class="t-label">Renderer / Mode</span><span class="t-val"><?= acp_h($summary['renderMode']) ?> &middot; <?= acp_h($summary['gameWindowMode']) ?></span></div>
            <?php $pdfServer = acs_server_view($report); ?>
            <div class="t-row"><span class="t-label">Active Server</span><span class="t-val"><?= acp_h($pdfServer['status'] === 'connected' ? $pdfServer['name'] . ' · ' . $pdfServer['address'] : $pdfServer['name']) ?></span></div>
            <div class="t-row"><span class="t-label">Server Map</span><span class="t-val mono"><?= acp_h($pdfServer['status'] === 'connected' ? acp_clean_map($pdfServer['map']) : $pdfServer['map']) ?></span></div>
        </div>

        <!-- Card 3: Security & Integrity -->
        <div class="telemetry-card">
            <div class="t-card-header">
                <span class="t-card-title">Security &amp; Integrity</span>
            </div>
            <div class="t-row"><span class="t-label">Operating System</span><span class="t-val"><?= acp_h(acp_clean_os($summary['os'])) ?></span></div>
            <div class="t-row"><span class="t-label">OpenGL Hook</span><span class="t-val"><?= $summary['hooked'] ? ($summary['status'] === 'DETECTED' ? 'Hook Detected (' . acp_h($summary['hookedAddr']) . ')' : 'Hook signal - review (' . acp_h($summary['hookedAddr']) . ')') : 'Clean (None)' ?></span></div>
            <div class="t-row"><span class="t-label">Injected Code</span><span class="t-val"><?php $injRev = (int) ($summary['reviewCategoryCounts']['injected'] ?? 0); ?><?= $cc['injected'] > 0 ? (int) $cc['injected'] . ' Injected Mod(s)' : ($injRev > 0 ? $injRev . ' hook/patch signal(s) - review' : 'Clean (Byte-Exact)') ?></span></div>
            <div class="t-row"><span class="t-label">HDD Serial</span><span class="t-val mono"><?= acp_h(acp_mask_hwid($summary['hddSerial'])) ?></span></div>
            <div class="t-row"><span class="t-label">Client payload</span><span class="t-val"><?= ($report['signatureVerified'] ?? false) ? 'HMAC valid (not device attestation)' : 'Unverified client payload' ?></span></div>
        </div>

        <!-- Card 4: Session Timeline Audit -->
        <div class="telemetry-card">
            <div class="t-card-header">
                <span class="t-card-title">Session Timeline Audit</span>
            </div>
            <div class="t-row"><span class="t-label">Report Created</span><span class="t-val mono"><?= acp_h($createdAtFmt ?: 'Unknown') ?></span></div>
            <div class="t-row"><span class="t-label">Game Launched</span><span class="t-val mono"><?= acp_h($launchFmt ?: 'Not running') ?></span></div>
            <div class="t-row"><span class="t-label">Scan Duration</span><span class="t-val mono"><?= acp_h(acp_fmt_duration_clean((int) $summary['scanDurationMs'])) ?></span></div>
            <div class="t-row"><span class="t-label">Session Sync Delta</span><span class="t-val mono"><?= acp_h($sessionDelta) ?></span></div>
            <div class="t-row"><span class="t-label">Report ID</span><span class="t-val mono">#<?= acp_h($summary['id']) ?></span></div>
        </div>
    </div>

    <!-- Extended Hardware & Forensic Identity -->
    <div class="section-heading">Extended Hardware &amp; Forensic Identity</div>
    <div class="spec">
        <?php pdf_field_group('Hardware & Identity Forensics'); ?>
        <?php pdf_field('Report number', '#' . $summary['id'], true); ?>
        <?php pdf_field('Unique player ID', $summary['playerId'], true); ?>
        <?php pdf_field('Player nickname', $summary['playerName']); ?>
        <?php pdf_field('Machine name', $summary['machine']); ?>
        <?php pdf_field('HDD Serial', acp_mask_hwid($summary['hddSerial']), true); ?>
        <?php pdf_field('Device Fingerprint', $summary['deviceFingerprint'], true); ?>

        <?php pdf_field_group('Steam Identifiers'); ?>
        <?php pdf_field('SteamID64', $summary['steamId'], true); ?>
        <?php pdf_field('Steam2', $summary['steamId2'], true); ?>
        <?php pdf_field('Steam3', $summary['steamId3'], true); ?>
        <?php pdf_field('Steam Account ID', $summary['steamAccountId'], true); ?>
        <?php pdf_field('Identity Source', $summary['steamIdentitySource']); ?>

        <?php pdf_field_group('Installation Paths & Bounds'); ?>
        <?php pdf_field('Game window bounds', trim($summary['gameWindowTitle'] . ' ' . $summary['gameWindowBounds'])); ?>
        <?php pdf_field('Game root directory', acp_sanitize_path($summary['gameRoot']), true); ?>
        <?php pdf_field('Config file', acp_sanitize_path($summary['configPath']), true); ?>
        <?php pdf_field('Steam installation path', acp_sanitize_path($summary['steamPath']), true); ?>
        <?php pdf_field('Signature Database', (string) ((int) ($counts['totalSignatures'] ?? count($database['signatures'] ?? []))) . ' integrated signatures'); ?>
    </div>

    <!-- Previous scans -->
    <div class="section-heading">Previous Scans For This Player (<?= count($previousScans) ?>)</div>
    <?php if (count($previousScans) > 0): ?>
    <table class="pdf-table">
        <thead>
            <tr><th>Time</th><th>Status</th><th>Nickname</th><th>Steam ID</th><th>IP</th><th>Server Connection History</th></tr>
        </thead>
        <tbody>
        <?php foreach ($previousScans as $scan):
            $scanSteam = trim((string) ($scan['steamId2'] ?? ''));
            if ($scanSteam === '') { $scanSteam = trim((string) ($scan['steamId'] ?? '')); }
            $sName = trim((string) ($scan['serverName'] ?? ''));
            $sAddr = trim((string) ($scan['serverAddress'] ?? ''));
        ?>
            <tr>
                <td class="pdf-mono"><?= acp_h((string) ($scan['uploadedAt'] ?? '')) ?></td>
                <td><span class="pdf-vec-badge"><?= acp_h((string) ($scan['status'] ?? '')) ?></span></td>
                <td><?= acp_h((string) ($scan['playerName'] ?? '')) ?></td>
                <td class="pdf-mono"><?= acp_h($scanSteam !== '' ? $scanSteam : '-') ?></td>
                <td class="pdf-mono"><?= acp_h((string) ($scan['maskedIp'] ?? '')) ?></td>
                <td><?= acp_h($sName !== '' || $sAddr !== '' ? trim($sName . ' ' . $sAddr) : 'Not captured') ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php else: ?>
        <div class="empty-state">No previous scans matched this SteamID, IP, or device.</div>
    <?php endif; ?>

    <!-- Confirmed Detections -->
    <div class="section-heading">Confirmed Detections (<?= count($parsedDetections) ?>)</div>
    <?php if (count($parsedDetections) > 0): ?>
        <table class="pdf-table">
            <thead>
                <tr>
                    <th style="width:28px;">#</th>
                    <th style="width:100px;">Type</th>
                    <th style="width:210px;">Cheat Name &amp; Location</th>
                    <th>What It Does (Impact)</th>
                    <th style="width:75px;">Status</th>
                    <th style="width:95px;">Time</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($parsedDetections as $idx => $d): ?>
                    <tr>
                        <td style="text-align:center;color:var(--muted);"><?= $idx + 1 ?></td>
                        <td><span class="pdf-vec-badge <?= acp_h($d['typeBadgeClass']) ?>"><?= acp_h($d['cleanType']) ?></span></td>
                        <td>
                            <div style="font-weight:700;color:var(--text);font-size:11px;"><?= acp_h($d['cleanName']) ?></div>
                            <div style="font-size:9.5px;color:var(--muted);font-family:monospace;margin-top:2px;">
                                <span style="color:var(--muted-deep);">Location:</span> <code style="color:var(--accent);background:var(--bg-2);padding:1px 4px;border-radius:3px;"><?= acp_h($d['cleanLocation']) ?></code>
                            </div>
                        </td>
                        <td>
                            <div style="font-size:11px;color:var(--text-2);line-height:1.4;"><?= acp_h($d['cleanImpact']) ?></div>
                            <?php if (!empty($d['destination'])): ?>
                                <div style="font-size:9.5px;color:var(--danger);font-family:monospace;margin-top:2px;"><?= acp_h($d['destination']) ?></div>
                            <?php endif; ?>
                        </td>
                        <td><span class="pdf-badge-danger"><?= acp_h($d['severity']) ?></span></td>
                        <td>
                            <span style="font-size:10px;color:var(--muted);font-family:monospace;"><?= acp_h($d['cleanTime']) ?></span>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php else: ?>
        <div style="padding:12px;background:var(--surface);border:1px solid var(--line);border-radius:6px;color:var(--muted);font-style:italic;">No confirmed cheat evidence on this machine. Verified clean.</div>
    <?php endif; ?>

    <!-- Review Evidence -->
    <?php if (count($parsedReview) > 0): ?>
        <div class="section-heading">Review Evidence (<?= count($parsedReview) ?> Signal<?= count($parsedReview) === 1 ? '' : 's' ?>)</div>
        <table class="pdf-table">
            <thead>
                <tr>
                    <th style="width:28px;">#</th>
                    <th style="width:130px;">Source Target</th>
                    <th style="width:130px;">Signal Type</th>
                    <th style="width:160px;">Trigger / Alias</th>
                    <th>Referee Analysis</th>
                    <th style="width:80px;">Severity</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($parsedReview as $rIdx => $rf): ?>
                    <tr>
                        <td style="text-align:center;color:var(--muted);"><?= $rIdx + 1 ?></td>
                        <td><span class="pdf-chip chip-purple"><?= acp_h($rf['target']) ?></span></td>
                        <td><span class="pdf-vec-badge" style="color:var(--warn);border-color:var(--warn)40;background:var(--warn)15;"><?= acp_h($rf['vector']) ?></span></td>
                        <td><code class="pdf-mono"><?= acp_h(substr($rf['symbol'], 0, 32)) ?></code></td>
                        <td>
                            <div style="font-size:11px;color:var(--text-2);"><?= acp_h($rf['impact']) ?></div>
                            <div style="font-size:9.5px;color:var(--muted);font-family:monospace;margin-top:2px;"><?= acp_h($rf['rawRule']) ?></div>
                        </td>
                        <td><span class="pdf-badge-warn"><?= acp_h($rf['severity']) ?></span></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>

    <!-- Additional Data (everything captured by the scanner) -->
    <div class="section-heading">Additional Data</div>

    <details class="pdf-acc">
        <summary><span class="acc-title">Scanner Engine Checks</span><span class="acc-chip"><?= count($report['engineChecks'] ?? []) ?> checks</span></summary>
        <div class="inner"><?php pdf_table(array_slice($report['engineChecks'] ?? [], 0, 200), ['Check' => 'name', 'Status' => 'status', 'Detail' => 'detail'], 'No engine checks recorded.'); ?></div>
    </details>

    <details class="pdf-acc">
        <summary><span class="acc-title">Drivers</span><span class="acc-chip"><?= count($report['drivers'] ?? []) ?> loaded</span></summary>
        <div class="inner"><?php pdf_table($pdfDrivers, ['Name' => 'name', 'Display name' => 'displayName', 'Path' => 'path', 'MD5' => 'md5', 'SHA256' => 'sha256', 'Company' => 'company', 'Signer' => 'signer'], 'No driver data.'); ?></div>
    </details>

    <details class="pdf-acc">
        <summary><span class="acc-title">Modules in hl.exe</span><span class="acc-chip"><?= count($report['modules'] ?? []) ?> modules</span></summary>
        <div class="inner"><?php pdf_table($pdfModules, ['Module' => 'name', 'Corpus' => 'corpusState', 'Prevalence' => 'corpusSeen', 'Trusted' => 'trusted', 'Sig valid' => 'signatureValid', 'Path' => 'path', 'Version' => 'fileVersion', 'MD5' => 'md5', 'Company' => 'company', 'Signer' => 'signer'], 'No hl.exe module data.'); ?></div>
    </details>

    <details class="pdf-acc">
        <summary><span class="acc-title">Steam Identity Candidates</span><span class="acc-chip"><?= count($report['steamIdentityCandidates'] ?? []) ?> identified</span></summary>
        <div class="inner"><?php pdf_table(array_slice($report['steamIdentityCandidates'] ?? [], 0, 50), ['Primary' => 'primary', 'SteamID64' => 'steamId', 'Steam2' => 'steamId2', 'Steam3' => 'steamId3', 'Source' => 'source'], 'No Steam identity candidates found.'); ?></div>
    </details>

    <details class="pdf-acc">
        <summary><span class="acc-title">Live In-Game Behavior</span><span class="acc-chip"><?= count($report['liveBehavior'] ?? []) ?> samples</span></summary>
        <div class="inner"><?php pdf_table(array_slice($report['liveBehavior'] ?? [], 0, 20), ['Started' => 'startedAt', 'Duration' => 'durationSeconds', 'Active samples' => 'activeSamples', 'Total samples' => 'totalSamples', 'Attack presses' => 'attackPresses', 'Low-move attacks' => 'lowMoveAttackPresses', 'Snap attacks' => 'snapAttackPresses', 'Strafe alternations' => 'strafeAlternations', 'Output' => 'output'], 'No live in-game behavior captured.'); ?></div>
    </details>

    <details class="pdf-acc">
        <summary><span class="acc-title">Memory Evidence</span><span class="acc-chip"><?= count($report['memoryArtifacts'] ?? []) ?> regions</span></summary>
        <div class="inner"><?php pdf_table(array_slice($report['memoryArtifacts'] ?? [], 0, 200), ['Base' => 'baseAddress', 'Size' => 'regionSize', 'Type' => 'type', 'Protection' => 'protection', 'Known module' => 'inKnownModule', 'MD5 first 4K' => 'md5First4K', 'Strings' => 'strings'], 'No executable memory artifacts found.'); ?></div>
    </details>

    <details class="pdf-acc">
        <summary><span class="acc-title">Processes</span><span class="acc-chip"><?= count($report['processes'] ?? []) ?> processes</span></summary>
        <div class="inner"><?php pdf_table($pdfProcesses, ['PID' => 'pid', 'Name' => 'name', 'Size' => 'bytes', 'MD5' => 'md5', 'SHA256' => 'sha256', 'Path' => 'path'], 'No process data.'); ?></div>
    </details>

    <details class="pdf-acc">
        <summary><span class="acc-title">HL Directory Files</span><span class="acc-chip"><?= count($report['hlFiles'] ?? []) ?> files</span></summary>
        <div class="inner"><?php pdf_table($pdfHlFiles, ['File' => 'relativePath', 'Bytes' => 'bytes', 'MD5' => 'md5', 'SHA256' => 'sha256', 'Company' => 'company', 'Signer' => 'signer'], 'No Half-Life folder files found.'); ?></div>
    </details>

    <div class="pdf-footer">
        <span>ACS Anti-Cheat Scanner &middot; Created by LongHorn</span>
        <span>Report #<?= acp_h($summary['id']) ?> &middot; Generated <?= acp_h(gmdate('Y-m-d H:i:s')) ?> UTC</span>
    </div>
    </div>
</body>
</html>

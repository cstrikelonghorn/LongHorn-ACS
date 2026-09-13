<?php
declare(strict_types=1);

/**
 * Side-by-side report comparison.
 *
 * Compares two scan reports to highlight what changed between them — useful for
 * spotting when a player switched clients, changed IPs, or when new detections
 * appeared.
 *
 * Usage: compare.php?a=<report_id>&b=<report_id>
 */

require __DIR__ . '/config.php';
require __DIR__ . '/theme_bar.php';
require __DIR__ . '/nav.php';

// Comparing two reports means reading two players' identifiers side by side, which is an
// admin action by definition - a per-report share key deliberately does not unlock it.
acp_admin_remember_token($acpConfig);
acp_require_dashboard_access($acpConfig);

$navReports = acp_recent_reports($acpConfig);
$navDownloadHref = 'download.php';

$reportA = null;
$reportB = null;
$error = '';

try {
    $idA = trim((string) ($_GET['a'] ?? ''));
    $idB = trim((string) ($_GET['b'] ?? ''));

    if ($idA === '' || $idB === '') {
        $error = 'Provide two report IDs: compare.php?a=<id1>&b=<id2>';
    } else {
        $reportA = acp_load_report($acpConfig, $idA);
        $reportB = acp_load_report($acpConfig, $idB);

        if ($reportA === null) {
            $error = "Report '{$idA}' not found.";
        } elseif ($reportB === null) {
            $error = "Report '{$idB}' not found.";
        }
    }
} catch (Throwable $e) {
    $error = $e->getMessage();
}

function acp_compare_field(string $label, $valA, $valB, bool $mono = false): void
{
    $a = is_scalar($valA) ? (string) $valA : '';
    $b = is_scalar($valB) ? (string) $valB : '';
    $changed = $a !== $b;
    $cls = $mono ? ' mono' : '';
    $rowCls = $changed ? ' cmp-changed' : '';

    echo '<tr class="' . $rowCls . '">';
    echo '<td class="cmp-label">' . acp_h($label) . '</td>';
    echo '<td class="cmp-val' . $cls . '">' . ($a !== '' ? acp_h($a) : '<span class="dim">—</span>') . '</td>';
    echo '<td class="cmp-val' . $cls . '">' . ($b !== '' ? acp_h($b) : '<span class="dim">—</span>') . '</td>';
    echo '<td class="cmp-status">' . ($changed ? '<span class="cmp-badge changed">CHANGED</span>' : '<span class="cmp-badge same">same</span>') . '</td>';
    echo '</tr>';
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ACP — Compare Reports</title>
    <link rel="stylesheet" href="assets/theme.css">
    <?php uds_theme_head(); ?>
    <link rel="stylesheet" href="assets/acp.css?v=<?= filemtime(__DIR__ . '/assets/acp.css') ?>">
    <style>
        html[data-uds-theme] .cmp-table { width: 100%; border-collapse: separate; border-spacing: 0; }
        html[data-uds-theme] .cmp-table th { padding: 12px 14px; text-align: left; background: var(--surface-2); border-bottom: 1px solid var(--line); font-family: var(--f-mono); font-size: 10.5px; font-weight: 600; letter-spacing: 1.6px; text-transform: uppercase; color: var(--muted); }
        html[data-uds-theme] .cmp-table td { padding: 10px 14px; border-bottom: 1px solid var(--line-soft); vertical-align: top; }
        html[data-uds-theme] .cmp-label { color: var(--muted); font-size: 12.5px; width: 180px; }
        html[data-uds-theme] .cmp-val { color: var(--text-2); font-size: 13px; }
        html[data-uds-theme] .cmp-val.mono { font-family: var(--f-mono); font-size: 12px; }
        html[data-uds-theme] .cmp-val .dim { color: var(--muted-deep); font-style: italic; }
        html[data-uds-theme] .cmp-changed .cmp-val { color: var(--warn); font-weight: 600; }
        html[data-uds-theme] .cmp-status { width: 100px; text-align: right; }
        html[data-uds-theme] .cmp-badge { display: inline-block; padding: 3px 10px; border-radius: 999px; font-family: var(--f-mono); font-size: 9.5px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; }
        html[data-uds-theme] .cmp-badge.changed { background: var(--warn-dim); color: var(--warn); border: 1px solid color-mix(in srgb, var(--warn) 40%, transparent); }
        html[data-uds-theme] .cmp-badge.same { background: var(--surface-2); color: var(--muted-deep); border: 1px solid var(--line-soft); }
        html[data-uds-theme] .cmp-header { display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-4); margin-bottom: var(--sp-5); }
        html[data-uds-theme] .cmp-report-card { padding: var(--sp-4); background: var(--surface-2); border: 1px solid var(--line); border-radius: var(--r); }
        html[data-uds-theme] .cmp-report-card h3 { margin: 0 0 var(--sp-2); font-family: var(--f-display); font-size: 15px; color: var(--text); }
        html[data-uds-theme] .cmp-report-card .meta { color: var(--muted); font-family: var(--f-mono); font-size: 11px; }
        html[data-uds-theme] .cmp-section { margin-bottom: var(--sp-5); }
        html[data-uds-theme] .cmp-section h3 { margin: 0 0 var(--sp-3); padding-bottom: var(--sp-2); border-bottom: 1px solid var(--line-soft); font-family: var(--f-display); font-size: 14px; letter-spacing: 1.2px; text-transform: uppercase; color: var(--text); }
        html[data-uds-theme] .error-box { padding: var(--sp-5); background: var(--danger-dim); border: 1px solid var(--danger); border-radius: var(--r); color: var(--danger); }
    </style>
</head>
<body>
<?php acp_site_nav('home', $navDownloadHref); ?>
<header>
    <div class="wrap topbar">
        <div class="brand">
            <div class="brand-mark" aria-hidden="true">
                <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 3l7 3v5c0 4.6-3 8.4-7 10-4-1.6-7-5.4-7-10V6l7-3z"/>
                    <path d="M9.5 12l2 2 3.5-4"/>
                </svg>
            </div>
            <div>
                <div class="brand-title">ACP <em>Compare</em> Reports</div>
                <div class="brand-sub">Side-by-side diff of two scan reports</div>
            </div>
        </div>
        <div class="topbar-actions">
            <a href="index.php" class="pill">&larr; Back to reports</a>
        </div>
    </div>
</header>

<main class="wrap">
    <?php if ($error !== ''): ?>
        <div class="error-box"><?= acp_h($error) ?></div>
    <?php elseif ($reportA !== null && $reportB !== null): ?>
        <?php
        $sumA = acp_report_summary($reportA);
        $sumB = acp_report_summary($reportB);
        ?>

        <div class="cmp-header">
            <div class="cmp-report-card">
                <h3>Report A: #<?= acp_h($sumA['id']) ?></h3>
                <div class="meta"><?= acp_h($sumA['playerName']) ?> &middot; <?= acp_h(acp_fmt_time($sumA['createdAt'] ?: $sumA['uploadedAt'])) ?></div>
            </div>
            <div class="cmp-report-card">
                <h3>Report B: #<?= acp_h($sumB['id']) ?></h3>
                <div class="meta"><?= acp_h($sumB['playerName']) ?> &middot; <?= acp_h(acp_fmt_time($sumB['createdAt'] ?: $sumB['uploadedAt'])) ?></div>
            </div>
        </div>

        <section class="panel cmp-section">
            <h3>Identity</h3>
            <table class="cmp-table">
                <thead><tr><th>Field</th><th>Report A</th><th>Report B</th><th></th></tr></thead>
                <tbody>
                    <?php acp_compare_field('Player name', $sumA['playerName'], $sumB['playerName']); ?>
                    <?php acp_compare_field('Player ID', $sumA['playerId'], $sumB['playerId'], true); ?>
                    <?php acp_compare_field('Steam ID', $sumA['steamId'], $sumB['steamId'], true); ?>
                    <?php acp_compare_field('Steam2', $sumA['steamId2'], $sumB['steamId2'], true); ?>
                    <?php acp_compare_field('IP address', acp_mask_ip($sumA['ip']), acp_mask_ip($sumB['ip']), true); ?>
                    <?php acp_compare_field('Machine', $sumA['machine'], $sumB['machine']); ?>
                    <?php acp_compare_field('Device fingerprint', $sumA['deviceFingerprint'], $sumB['deviceFingerprint'], true); ?>
                </tbody>
            </table>
        </section>

        <section class="panel cmp-section">
            <h3>Game Environment</h3>
            <table class="cmp-table">
                <thead><tr><th>Field</th><th>Report A</th><th>Report B</th><th></th></tr></thead>
                <tbody>
                    <?php acp_compare_field('Game build', $sumA['gameBuild'], $sumB['gameBuild']); ?>
                    <?php acp_compare_field('Render mode', $sumA['renderMode'], $sumB['renderMode']); ?>
                    <?php acp_compare_field('Window mode', $sumA['gameWindowMode'], $sumB['gameWindowMode']); ?>
                    <?php acp_compare_field('Game directory', $sumA['gameRoot'], $sumB['gameRoot'], true); ?>
                    <?php acp_compare_field('Server address', $sumA['serverAddress'], $sumB['serverAddress'], true); ?>
                    <?php acp_compare_field('Server name', $sumA['serverName'], $sumB['serverName']); ?>
                    <?php acp_compare_field('Server map', acp_clean_map($sumA['serverMap']), acp_clean_map($sumB['serverMap'])); ?>
                </tbody>
            </table>
        </section>

        <section class="panel cmp-section">
            <h3>Scan Results</h3>
            <table class="cmp-table">
                <thead><tr><th>Field</th><th>Report A</th><th>Report B</th><th></th></tr></thead>
                <tbody>
                    <?php acp_compare_field('Status', $sumA['status'], $sumB['status']); ?>
                    <?php acp_compare_field('Detections', $sumA['detected'], $sumB['detected']); ?>
                    <?php acp_compare_field('Warnings', $sumA['warnings'], $sumB['warnings']); ?>
                    <?php acp_compare_field('Scan duration', acp_duration_ms($sumA['scanDurationMs']), acp_duration_ms($sumB['scanDurationMs'])); ?>
                    <?php acp_compare_field('OpenGL hook', $sumA['hooked'] ? 'DETECTED' : 'none', $sumB['hooked'] ? 'DETECTED' : 'none'); ?>
                </tbody>
            </table>
        </section>

        <section class="panel cmp-section">
            <h3>Timing</h3>
            <table class="cmp-table">
                <thead><tr><th>Field</th><th>Report A</th><th>Report B</th><th></th></tr></thead>
                <tbody>
                    <?php acp_compare_field('Report created', acp_fmt_time($sumA['createdAt'] ?: $sumA['uploadedAt']), acp_fmt_time($sumB['createdAt'] ?: $sumB['uploadedAt']), true); ?>
                    <?php acp_compare_field('Game launched', acp_fmt_time($sumA['gameLaunchTime']), acp_fmt_time($sumB['gameLaunchTime']), true); ?>
                    <?php acp_compare_field('Scan started', acp_fmt_time($sumA['scanStartedAt']), acp_fmt_time($sumB['scanStartedAt']), true); ?>
                </tbody>
            </table>
        </section>
    <?php endif; ?>
</main>
<?php uds_theme_footbar(); ?>
</body>
</html>

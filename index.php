<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/theme_bar.php';
require_once __DIR__ . '/nav.php';

$reportId = (string) ($_GET['report'] ?? '');

// Reports carry SteamIDs, IPs and disk serials, so nothing below runs before the viewer
// is established. A share-key viewer gets exactly the one report their key names; only an
// admin (or localhost) sees the list of everyone else's scans.
acp_admin_remember_token($acpConfig);
$isAdminView = acp_admin_authenticated($acpConfig) || acp_is_local_request();

if ($reportId !== '') {
    acp_require_report_access($acpConfig, $reportId);
} else {
    acp_require_dashboard_access($acpConfig);
}

$perPage = 20;
$page = max(1, (int) ($_GET['page'] ?? 1));
$searchQuery = trim((string) ($_GET['q'] ?? ''));
$searchScope = (string) ($_GET['by'] ?? 'all');
if (!in_array($searchScope, ['all', 'name', 'server'], true)) {
    $searchScope = 'all';
}
$isSearch = $isAdminView && $searchQuery !== '';

try {
    acp_ensure_dir($acpConfig['reportsDir']);
    $database = acp_load_database($acpConfig);
    $counts = $database['counts'] ?? [];
    $selectedReport = $reportId !== '' ? acp_load_report($acpConfig, $reportId) : null;
    $reportStats = $isAdminView ? acp_report_status_counts($acpConfig) : ['total' => 0, 'detected' => 0, 'clean' => 0];
    $listTotal = $isSearch ? acp_search_report_count($acpConfig, $searchQuery, $searchScope) : $reportStats['total'];
    $totalPages = max(1, (int) ceil($listTotal / $perPage));
    $page = min($page, $totalPages);
    $recentReports = !$isAdminView
        ? []
        : ($isSearch
            ? acp_search_reports($acpConfig, $searchQuery, $searchScope, $perPage, ($page - 1) * $perPage)
            : acp_recent_reports_page($acpConfig, $perPage, ($page - 1) * $perPage));
} catch (Throwable $e) {
    // The message can carry absolute paths and database internals, so it goes to the log
    // rather than to the browser - the same policy api.php already follows.
    error_log('[ACS] index: ' . $e->getMessage());
    http_response_code(500);
    echo '<h1>ACS error</h1><p>Something went wrong loading this page. Check the server log.</p>';
    exit;
}

// Report export: lets the viewer download the exact report being displayed as JSON.
// This is the single report (already rendered on this page), never the signature database.
if ($selectedReport !== null && (string) ($_GET['download'] ?? '') === 'json') {
    $safeId = preg_replace('/[^a-zA-Z0-9_-]/', '', $reportId) ?: 'report';
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Disposition: attachment; filename="acs-report-' . $safeId . '.json"');
    echo json_encode($selectedReport, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

// Shared navigation shown on every dashboard/report view. Download targets the open
// report, or the newest report when the dashboard is shown.
$summary = $selectedReport !== null ? acp_report_summary($selectedReport) : null;
$navReportId = (string) ($selectedReport['id'] ?? '');
if ($navReportId === '' && $isAdminView) {
    $newestReports = acp_recent_reports($acpConfig, 1);
    $navReportId = (string) ($newestReports[0]['id'] ?? '');
}
$navDownloadHref = 'download.php';

if (!function_exists('acp_items')) {
    function acp_items(array $report, string $key): array
    {
        $items = $report['detectedCheats'][$key] ?? [];
        return is_array($items) ? $items : [];
    }
}

function acp_table(array $rows, array $columns, string $empty, string $wrapClass = ''): void
{
    $cls = 'table-wrap' . ($wrapClass !== '' ? ' ' . $wrapClass : '');
    echo '<div class="' . acp_h($cls) . '"><table><thead><tr>';
    foreach ($columns as $label => $_) {
        echo '<th>' . acp_h((string) $label) . '</th>';
    }
    echo '</tr></thead><tbody>';

    foreach ($rows as $row) {
        echo '<tr>';
        foreach ($columns as $field) {
            $rawValue = is_array($row) ? ($row[$field] ?? '') : '';
            if (is_bool($rawValue)) {
                $value = $rawValue ? 'Yes' : 'No';
            } else {
                $value = (string) $rawValue;
            }

            // Colour-code severity / status cells as badges to match the desktop app.
            if ($field === 'corpusState' && $value !== '') {
                // Mirrors WarGods' three states: a hash is clean, a cheat, or simply Unknown.
                $map = ['cheat' => 'DETECTED', 'unknown' => 'WARNING', 'clean' => 'CLEAN'];
                $cls = $map[$value] ?? 'INFO';
                echo '<td><span class="badge ' . acp_h($cls) . '">' . acp_h(strtoupper($value)) . '</span></td>';
                continue;
            }

            if (($field === 'severity' || $field === 'status') && $value !== '') {
                $cls = strtoupper($value);
                if ($field === 'status' && !in_array($cls, ['DETECTED', 'WARNING', 'CLEAN', 'OK', 'REVIEW', 'INFO'], true)) {
                    $cls = 'INFO';
                }
                if ($cls === 'OK') {
                    $cls = 'CLEAN';
                } elseif ($cls === 'REVIEW') {
                    $cls = 'WARNING';
                }
                echo '<td><span class="badge ' . acp_h($cls) . '">' . acp_h($value) . '</span></td>';
                continue;
            }

            if ($field === 'type' && $value !== '') {
                $badgeCls = 'INFO';
                $badgeText = strtoupper($value);
                if (stripos($value, 'Injected') !== false) {
                    $badgeCls = 'DETECTED';
                    $badgeText = 'INJECTED';
                } elseif (stripos($value, 'Loaded') !== false || stripos($value, 'Game Folder') !== false) {
                    $badgeCls = 'DETECTED';
                    $badgeText = 'LOADED';
                } elseif (stripos($value, 'Resource') !== false || stripos($value, 'Asset') !== false || stripos($value, 'Model') !== false) {
                    $badgeCls = 'DETECTED';
                    $badgeText = 'RESOURCE';
                } elseif (stripos($value, 'Behavior') !== false) {
                    $badgeCls = 'WARNING';
                    $badgeText = 'BEHAVIOR';
                } elseif (stripos($value, 'Environment') !== false || stripos($value, 'Restart') !== false) {
                    $badgeCls = 'WARNING';
                    $badgeText = 'SUSPECT';
                } elseif (stripos($value, 'Previously') !== false) {
                    $badgeCls = 'WARNING';
                    $badgeText = 'LAUNCHED';
                } elseif (stripos($value, 'Installed') !== false) {
                    $badgeCls = 'WARNING';
                    $badgeText = 'ON-DISK';
                } elseif (stripos($value, 'Download') !== false) {
                    $badgeCls = 'INFO';
                    $badgeText = 'DOWNLOAD';
                }
                echo '<td><span class="badge ' . acp_h($badgeCls) . '">' . acp_h($badgeText) . '</span></td>';
                continue;
            }

            if ($field === 'evidence') {
                echo '<td class="mono" style="word-break:break-word;font-size:12px;max-width:340px;">' . acp_h($value) . '</td>';
                continue;
            }

            if ($field === 'cheat') {
                echo '<td><strong style="color:var(--text);font-size:13px;">' . acp_h($value) . '</strong></td>';
                continue;
            }

            if ($field === 'time' && $value !== '') {
                $fmtTime = acp_fmt_time($value);
                echo '<td class="mono" style="font-size:11.5px;white-space:nowrap;">' . acp_h($fmtTime ?: $value) . '</td>';
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

/**
 * Attach the corpus verdict to each inventory row.
 *
 * The corpus summary is stored on the report at upload time, so an old report keeps the
 * classification that was current when it was taken rather than silently changing later.
 */
function acp_with_corpus_state(array $rows, array $report): array
{
    $states = $report['corpus']['states'] ?? [];
    if (!is_array($states)) {
        $states = [];
    }

    foreach ($rows as $i => $row) {
        if (!is_array($row)) {
            continue;
        }

        $sha = strtolower((string) ($row['sha256'] ?? ''));
        $rows[$i]['corpusState'] = $states[$sha]['state'] ?? 'unseen';
        $machines = $states[$sha]['machines'] ?? null;
        $rows[$i]['corpusSeen'] = $machines === null ? '' : ($machines . ' machines');
    }

    return $rows;
}

function acp_field(string $label, string $value, bool $mono = false): void
{
    $empty = trim($value) === '' || $value === 'Not found';
    echo '<div class="spec-row"><div class="spec-key">' . acp_h($label) . '</div>';
    echo '<div class="spec-val' . ($mono ? ' mono' : '') . ($empty ? ' is-empty' : '') . '">' . acp_h($empty ? 'Not found' : $value) . '</div></div>';
}

function acp_field_group(string $label): void
{
    echo '<div class="spec-group">' . acp_h($label) . '</div>';
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ACS — Anti-Cheat Report</title>
    <link rel="stylesheet" href="assets/theme.css">
<?php uds_theme_head(); ?>
    <link rel="stylesheet" href="assets/acp.css?v=<?= filemtime(__DIR__ . '/assets/acp.css') ?>">
</head>
<body>
<?php
// Share link: lets an admin hand an accused player (or another admin) one link to this
// single report, without giving out the admin token and without exposing any other scan.
$acsShareKey = ($isAdminView && $selectedReport !== null)
    ? acp_report_view_key($acpConfig, $reportId)
    : '';
if ($acsShareKey !== ''):
    $acsShareUrl = 'index.php?report=' . rawurlencode($reportId) . '&k=' . $acsShareKey;
?>
<div class="wrap" style="padding-block:10px 0">
    <div style="display:flex;flex-wrap:wrap;align-items:center;gap:10px;font-size:13px;
                border:1px solid var(--line,#232a34);border-radius:6px;padding:8px 12px">
        <strong style="font-weight:600">Share this report</strong>
        <input id="acs-share" readonly value="<?= acp_h($acsShareUrl) ?>"
               style="flex:1 1 320px;min-width:0;font:inherit;font-family:ui-monospace,monospace;
                      background:transparent;color:inherit;border:1px solid var(--line,#232a34);
                      border-radius:4px;padding:5px 8px">
        <button type="button" id="acs-share-copy" style="font:inherit;cursor:pointer;padding:5px 12px;
                border-radius:4px;border:1px solid var(--line,#232a34);background:transparent;color:inherit">Copy</button>
        <span style="opacity:.65">Opens this report only. No admin token needed.</span>
    </div>
</div>
<script>
document.getElementById('acs-share-copy')?.addEventListener('click', function () {
    var field = document.getElementById('acs-share');
    field.select();
    navigator.clipboard?.writeText(field.value).then(
        () => { this.textContent = 'Copied'; setTimeout(() => { this.textContent = 'Copy'; }, 1500); },
        () => { this.textContent = 'Press Ctrl+C'; }
    );
});
</script>
<?php endif; ?>
<header>
    <div class="wrap topbar">
        <div class="brand">
            <div class="brand-mark lh-mark" aria-hidden="true">
                <img class="lh-logo-img" src="images/logo_up.jpg" alt="LongHorn">
            </div>
            <div>
                <div class="brand-title">ACS <em>Anti-Cheat</em> Scanner</div>
                <div class="brand-sub">
                    <span class="cs-pulse-dot" aria-hidden="true"></span>
                    <span class="cs-sub-text">Counter-Strike 1.6 Anti-Cheats Scanner</span>
                </div>
            </div>
        </div>
        <div class="topbar-actions">
            <a class="lh-brand-btn" href="https://www.cslonghorn.com" target="_blank" rel="noopener noreferrer" data-hint="www.cslonghorn.com — LongHorn Protection">
                <span class="lh-brand-dot" aria-hidden="true"></span>
                <span class="lh-brand-text">LongHorn</span>
            </a>
            <?php if ($selectedReport !== null): ?>
                <a href="export_pdf.php?report=<?= rawurlencode($summary['id'] ?? $reportId) ?>" target="_blank" class="report-download-btn">Report Download</a>
            <?php endif; ?>
        </div>
    </div>
</header>
<?php acp_site_nav('home', $navDownloadHref, true); ?>
<main class="wrap">
    <?php if ($selectedReport === null): ?>
    <section class="stats" aria-label="Database counts">
        <div class="stat"><strong><?= (int) ($counts['totalSignatures'] ?? count($database['signatures'] ?? [])) ?></strong><span>integrated signatures</span></div>
        <div class="stat"><strong><?= (int) $reportStats['total'] ?></strong><span>recent scans</span></div>
        <div class="stat s-red"><strong><?= (int) $reportStats['detected'] ?></strong><span>detected reports</span></div>
        <div class="stat s-green"><strong><?= (int) $reportStats['clean'] ?></strong><span>clean reports</span></div>
    </section>
    <?php endif; ?>

    <?php if ($selectedReport !== null): ?>
        <?php
        $summary = acp_report_summary($selectedReport);
        $cc = $summary['categoryCounts'];
        $statusText = $summary['status'] === 'DETECTED' ? 'Cheats detected' : ($summary['status'] === 'WARNING' ? 'Review required' : 'No cheats detected');
        $createdAtRaw = $summary['createdAt'] ?: $summary['uploadedAt'];
        $createdAtFmt = acp_fmt_time($createdAtRaw);
        $createdAtAgo = acp_time_ago($createdAtRaw);
        ?>
        <div id="acpReportContainer" data-view-mode="gamer">
        <?php
        $gaugeItems = [
            'Injected'   => (int) ($cc['injected'] ?? 0),
            'Loaded'     => (int) ($cc['loaded'] ?? 0),
            'Resources'  => (int) ($cc['resources'] ?? 0),
            'Behavior'   => (int) ($cc['behavioral'] ?? 0),
            'Launched'   => (int) ($cc['previouslyLaunched'] ?? 0),
            'Installed'  => (int) ($cc['installedInOs'] ?? 0),
            'Downloaded' => (int) ($cc['downloaded'] ?? 0),
            'Review'     => (int) ($summary['warnings'] ?? 0),
        ];
        $gaugeMax = max(1, max($gaugeItems));
        $threatScore = $summary['status'] === 'DETECTED'
            ? min(99, 80 + (int) $summary['detected'] * 2)
            : ($summary['status'] === 'WARNING' ? 45 + (int) $summary['warnings'] * 3 : 6);
        $threatScore = max(3, min(99, $threatScore));
        $threatFilled = (int) round($threatScore / 10);
        ?>
        <section class="verdict v-<?= acp_h($summary['status']) ?> verdict-compact">
            <div class="verdict-hud" aria-hidden="true">
                <span class="vh-corner vh-tl"></span>
                <span class="vh-corner vh-tr"></span>
                <span class="vh-corner vh-bl"></span>
                <span class="vh-corner vh-br"></span>
            </div>
            <div class="verdict-main">
                <span class="verdict-status-badge"><span class="dot"></span><?= acp_h($summary['status']) ?></span>
                <h1 class="verdict-title" data-text="<?= acp_h($statusText) ?>"><?= acp_h($statusText) ?></h1>
                <span class="verdict-subnote">
                    <?php if ($summary['status'] === 'DETECTED'): ?>
                        <?= (int) ($summary['detected'] ?: array_sum($cc)) ?> confirmed memory tampering <?= ((int) ($summary['detected'] ?: array_sum($cc)) === 1 ? 'anomaly' : 'anomalies') ?> identified in live game process<?php if ((int) $summary['warnings'] > 0): ?> &middot; <?= (int) $summary['warnings'] ?> flagged for review<?php endif; ?>
                    <?php elseif ($summary['status'] === 'WARNING'): ?>
                        <?= (int) ($summary['warnings'] ?: count($parsedReview ?? [])) ?> environment <?= ((int) ($summary['warnings'] ?: count($parsedReview ?? [])) === 1 ? 'signal' : 'signals') ?> flagged for referee review
                    <?php else: ?>
                        Zero integrity anomalies or unauthorized memory modifications detected
                    <?php endif; ?>
                </span>
                <div class="verdict-threat">
                    <span class="vt-label">THREAT</span>
                    <span class="vt-bars" aria-hidden="true">
                        <?php for ($i = 1; $i <= 10; $i++): ?><span class="vt-bar<?= $i <= $threatFilled ? ' on' : '' ?>"></span><?php endfor; ?>
                    </span>
                    <span class="vt-num"><?= (int) $threatScore ?>%</span>
                </div>
            </div>
            <?php
            $activeGauges = array_filter($gaugeItems, static fn($cnt) => $cnt > 0);
            ?>
            <div class="verdict-summary-side">
                <?php if (count($activeGauges) > 0): ?>
                    <div class="v-flagged-container">
                        <span class="v-flagged-label">FLAGGED CATEGORIES</span>
                        <div class="v-flagged-pills">
                            <?php foreach ($activeGauges as $label => $count): ?>
                                <?php
                                $pillCls = ($label === 'Review') ? 'pill-warn' : (in_array($label, ['Injected', 'Loaded', 'Resources', 'Behavior'], true) ? 'pill-danger' : 'pill-suspect');
                                ?>
                                <div class="v-flag-pill <?= $pillCls ?>">
                                    <span class="v-flag-num"><?= $count ?></span>
                                    <span class="v-flag-name"><?= acp_h(strtoupper($label)) ?></span>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php else: ?>
                    <div class="v-clean-badge-box">
                        <div class="v-clean-icon">
                            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
                        </div>
                        <div class="v-clean-text">
                            <span class="v-clean-title">ALL INTEGRITY CHECKS CLEAN</span>
                            <span class="v-clean-sub"><?= (int)$summary['scannedProcesses'] ?> Processes &middot; <?= (int)$summary['scannedModules'] ?> Modules &middot; 0 Flags</span>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </section>

        <?php
        $initials = '?';
        $nameParts = preg_split('/\s+/', trim((string) $summary['playerName'])) ?: [];
        if (($nameParts[0] ?? '') !== '') {
            $initials = strtoupper(substr($nameParts[0], 0, 1) . (($nameParts[1] ?? '') !== '' ? substr($nameParts[1], 0, 1) : ''));
        }

        $totalScans = acp_count_total_scans($acpConfig, $selectedReport);
        $buildBadge = acp_game_build_badge($selectedReport, $summary['gameBuild']);
        $geo = acp_ip_geo($summary['ip']);
        $steamDisplay = $summary['steamId2'] !== '' ? $summary['steamId2'] : ($summary['steamId'] !== '' ? $summary['steamId'] : '');
        // Player's own wall-clock time at scan (client-supplied local time, kept verbatim
        // so the offset in the ISO string does not get re-converted by the server clock).
        $localTimeRaw = trim((string) ($summary['localTime'] ?? ''));
        $localTimeDisplay = $localTimeRaw !== '' ? str_replace('T', ' ', substr($localTimeRaw, 0, 19)) : '';
        $launchFmt = acp_fmt_time($summary['gameLaunchTime']);
        $launchAgo = acp_time_ago($summary['gameLaunchTime']);
        $sessionDelta = acp_session_delta_text((string) $summary['gameLaunchTime'], (string) $createdAtRaw);
        ?>
        <section class="panel basic-data">
            <div class="panel-header-flex">
                <h2>Gaming Telemetry &amp; Basic Data</h2>
            </div>

            <div class="telemetry-grid">
                <!-- Card 1: Player & Steam Profile -->
                <div class="telemetry-card">
                    <div class="t-card-header">
                        <span class="t-card-title">PLAYER IDENTITY</span>
                        <span class="scan-count<?= $totalScans > 1 ? ' multi' : '' ?>" title="Scans recorded for this identity"><?= (int) $totalScans ?> <?= $totalScans === 1 ? 'SCAN' : 'SCANS' ?></span>
                    </div>

                    <div class="player-hero-row">
                        <div class="avatar"><?= acp_h($initials) ?></div>
                        <div class="player-hero-info">
                            <div class="identity-name"><?= acp_h($summary['playerName'] ?: 'Unknown player') ?></div>
                            <div class="player-subid">
                                <span>ID: <code class="mono"><?= acp_h($summary['playerId'] ?: '—') ?></code></span>
                                <span>Report <code class="mono">#<?= acp_h($summary['id']) ?></code></span>
                            </div>
                        </div>
                    </div>

                    <div class="telemetry-rows">
                        <div class="t-row">
                            <span class="t-label">Steam ID (Steam2)</span>
                            <span class="t-value mono copyable" title="Steam2 Identifier">
                                <?= acp_h($summary['steamId2'] !== '' ? $summary['steamId2'] : ($summary['steamId'] !== '' ? $summary['steamId'] : 'Not found')) ?>
                            </span>
                        </div>
                        <div class="t-row">
                            <span class="t-label">Player LocalTime</span>
                            <span class="t-value mono">
                                <?php if ($localTimeDisplay !== ''): ?>
                                    <?= acp_h($localTimeDisplay) ?><?php if ($summary['timeZoneName'] !== ''): ?><span class="tz-name"><?= acp_h($summary['timeZoneName']) ?></span><?php endif; ?>
                                <?php else: ?>
                                    <time class="js-local-time" data-utc="<?= acp_h($createdAtRaw) ?>" datetime="<?= acp_h($createdAtRaw) ?>" title="Converted to your local time (client time zone not recorded)"><?= acp_h(acp_fmt_time($createdAtRaw)) ?></time>
                                <?php endif; ?>
                            </span>
                        </div>
                        <div class="t-row">
                            <span class="t-label">Player IP</span>
                            <span class="t-value mono ip-cell">
                                <?php if ($summary['ip'] !== ''): ?>
                                <?php if ($geo['code'] !== ''): ?>
                                    <img class="flag-inline" src="https://flagcdn.com/w40/<?= acp_h($geo['code']) ?>.png" alt="<?= acp_h(strtoupper($geo['code'])) ?>" title="<?= acp_h($geo['country']) ?>" onerror="this.outerHTML='<span class=\'flag-fallback\' title=\'' + this.title + '\'>' + this.alt + '</span>'">
                                <?php endif; ?>
                                    <?= acp_h(acp_mask_ip($summary['ip'])) ?>
                                    <?php if ($geo['country'] !== ''): ?><span class="geo-country"><?= acp_h($geo['country']) ?></span><?php endif; ?>
                                    <a class="ipinfo-link" href="https://ipinfo.io/<?= acp_h($summary['ip']) ?>" target="_blank" rel="noopener" title="View full IP details on ipinfo.io">IP</a>
                                <?php else: ?>
                                    Not captured
                                <?php endif; ?>
                            </span>
                        </div>
                        <?php if ($geo['isp'] !== '' || $geo['as'] !== ''): ?>
                        <div class="t-row">
                            <span class="t-label">ISP / ASN</span>
                            <span class="t-value">
                                <?php if ($geo['isp'] !== ''): ?><span class="isp-name"><?= acp_h($geo['isp']) ?></span><?php endif; ?>
                                <?php if ($geo['as'] !== ''): ?><span class="asn-badge mono"><?= acp_h($geo['as']) ?></span><?php endif; ?>
                            </span>
                        </div>
                        <?php endif; ?>
                        <div class="t-row">
                            <span class="t-label">Host Machine</span>
                            <span class="t-value"><?= acp_h($summary['machine'] ?: 'Unknown') ?></span>
                        </div>
                    </div>
                </div>

                <!-- Card 2: Game Client & Engine Environment -->
                <div class="telemetry-card">
                    <div class="t-card-header">
                        <span class="t-card-title">GAME CLIENT &amp; ENGINE</span>
                        <span class="build-badge b-<?= acp_h($buildBadge['class']) ?>"><?= acp_h($buildBadge['label']) ?></span>
                    </div>

                    <div class="telemetry-rows">
                        <div class="t-row">
                            <span class="t-label">Distribution</span>
                            <span class="t-value">
                                <span class="client-type-pill <?= $buildBadge['isSteam'] ? 'is-steam' : 'is-nonsteam' ?>">
                                    <?= $buildBadge['isSteam'] ? 'GENUINE STEAM' : 'NON-STEAM CLIENT' ?>
                                </span>
                            </span>
                        </div>
                        <div class="t-row">
                            <span class="t-label">Game Build</span>
                            <span class="t-value highlight-val"><?= acp_h($buildBadge['cleanBuild']) ?></span>
                        </div>
                        <div class="t-row">
                            <span class="t-label">Renderer &amp; Window</span>
                            <span class="t-value">
                                <span class="render-chip"><?= acp_h($summary['renderMode'] ?: 'Unknown') ?></span>
                                <span class="display-mode-chip"><?= acp_h($summary['gameWindowMode'] ?: 'Unknown') ?></span>
                            </span>
                        </div>
                        <div class="t-row">
                            <span class="t-label">Active Server</span>
                            <span class="t-value srv-cell">
                                <?php if ($summary['serverName'] !== '' || $summary['serverAddress'] !== ''): ?>
                                    <div class="srv-name" title="<?= acp_h($summary['serverName']) ?>">
                                        <span class="srv-live-dot"></span>
                                        <?= acp_h($summary['serverName'] ?: 'Game Server') ?>
                                    </div>
                                    <div class="srv-addr mono"><?= acp_h($summary['serverAddress']) ?></div>
                                <?php else: ?>
                                    <span class="dim-text">Standalone / Main Menu</span>
                                <?php endif; ?>
                            </span>
                        </div>
                        <div class="t-row">
                            <span class="t-label">Server Map</span>
                            <span class="t-value">
                                <?php if ($summary['serverMap'] !== ''): ?>
                                    <span class="map-chip"><?= acp_h(acp_clean_map($summary['serverMap'])) ?></span>
                                <?php else: ?>
                                    <span class="dim-text">None (Menu)</span>
                                <?php endif; ?>
                            </span>
                        </div>
                        <div class="t-row">
                            <span class="t-label">HL Executable Path</span>
                            <span class="t-value mono hl-path-val" title="<?= acp_h(acp_sanitize_path($summary['hlPath'])) ?>">
                                <?= acp_h($summary['hlPath'] !== '' ? acp_sanitize_path($summary['hlPath']) : 'Not found') ?>
                            </span>
                        </div>
                    </div>
                </div>

                <!-- Card 3: Security & Integrity Health -->
                <div class="telemetry-card">
                    <div class="t-card-header">
                        <span class="t-card-title">SECURITY &amp; INTEGRITY</span>
                    </div>

                    <div class="telemetry-rows">
                        <div class="t-row">
                            <span class="t-label">Operating System</span>
                            <span class="t-value os-val">
                                <?= acp_h(acp_clean_os($summary['os'])) ?>
                            </span>
                        </div>
                        <div class="t-row">
                            <span class="t-label">OpenGL Inline Hook</span>
                            <span class="t-value">
                                <?php if ($summary['hooked']): ?>
                                    <span class="health-chip danger"><span class="chip-dot"></span>HOOK DETECTED (<?= acp_h($summary['hookedAddr']) ?>)</span>
                                <?php else: ?>
                                    <span class="health-chip ok"><span class="chip-dot"></span>CLEAN (No inline hooks)</span>
                                <?php endif; ?>
                            </span>
                        </div>
                        <div class="t-row">
                            <span class="t-label">Process Memory Code</span>
                            <span class="t-value">
                                <?php if ($cc['injected'] > 0): ?>
                                    <span class="health-chip danger"><span class="chip-dot"></span><?= (int)$cc['injected'] ?> Injected Mod(s)</span>
                                <?php else: ?>
                                    <span class="health-chip ok"><span class="chip-dot"></span>Byte-Exact to Disk</span>
                                <?php endif; ?>
                            </span>
                        </div>
                        <div class="t-row">
                            <span class="t-label">Active Signatures</span>
                            <span class="t-value"><?= (int)($counts['totalSignatures'] ?? count($database['signatures'] ?? [])) ?> Definitions</span>
                        </div>
                        <div class="t-row">
                            <span class="t-label">Cryptographic Integrity</span>
                            <span class="t-value">
                                <?php if (($selectedReport['signatureVerified'] ?? false) === true): ?>
                                    <span class="health-chip ok"><span class="chip-dot"></span>Verified RSA-2048</span>
                                <?php else: ?>
                                    <span class="health-chip neutral">Community / Local build</span>
                                <?php endif; ?>
                            </span>
                        </div>
                    </div>
                </div>

                <!-- Card 4: Session Timeline & Audit -->
                <div class="telemetry-card">
                    <div class="t-card-header">
                        <span class="t-card-title">SESSION TIMELINE AUDIT</span>
                        <span class="attn-legend"><span class="attn-pulse"></span>CROSS-CHECK</span>
                    </div>

                    <div class="telemetry-rows">
                        <div class="t-row attn-row">
                            <span class="t-label">Report Created</span>
                            <div class="t-value">
                                <div class="attn-time mono"><?= acp_h($createdAtFmt ?: 'Unknown') ?></div>
                                <?php if ($createdAtAgo !== ''): ?><div class="attn-ago"><?= acp_h($createdAtAgo) ?></div><?php endif; ?>
                            </div>
                        </div>
                        <div class="t-row attn-row<?= $launchFmt === '' ? ' attn-dim' : '' ?>">
                            <span class="t-label">Game Launched</span>
                            <div class="t-value">
                                <div class="attn-time mono"><?= acp_h($launchFmt ?: 'Not running') ?></div>
                                <?php if ($launchAgo !== ''): ?><div class="attn-ago"><?= acp_h($launchAgo) ?></div><?php endif; ?>
                            </div>
                        </div>
                        <div class="t-row">
                            <span class="t-label">Scan Duration</span>
                            <span class="t-value mono">
                                <?= acp_h(acp_fmt_duration_clean((int) $summary['scanDurationMs'])) ?>
                            </span>
                        </div>
                        <div class="t-row">
                            <span class="t-label">Session Sync Delta</span>
                            <span class="t-value">
                                <span class="session-delta-badge"><?= acp_h($sessionDelta) ?></span>
                            </span>
                        </div>
                    </div>

                    <div class="timeline-hint">
                        Cross-check game launch vs server demo start to verify player did not restart game to unload cheats.
                    </div>
                </div>
            </div>

            <!-- Extended Identity & Installation Details -->
            <details class="bd-more">
                <summary>Extended Hardware &amp; Forensic Identity</summary>
                <div class="inner">
                    <div class="spec">
                        <?php acp_field_group('Hardware & Identity Forensics'); ?>
                        <?php acp_field('Report number', '#' . $summary['id'], true); ?>
                        <?php acp_field('Unique player ID', $summary['playerId'], true); ?>
                        <?php acp_field('Player nickname', $summary['playerName']); ?>
                        <?php acp_field('Machine name', $summary['machine']); ?>
                        <?php acp_field('HDD Serial', acp_mask_hwid($summary['hddSerial']), true); ?>
                        <?php acp_field('Device Fingerprint', $summary['deviceFingerprint'], true); ?>

                        <?php acp_field_group('Steam Identifiers'); ?>
                        <?php acp_field('SteamID64', $summary['steamId'], true); ?>
                        <?php acp_field('Steam2', $summary['steamId2'], true); ?>
                        <?php acp_field('Steam3', $summary['steamId3'], true); ?>
                        <?php acp_field('Steam Account ID', $summary['steamAccountId'], true); ?>
                        <?php acp_field('Identity Source', $summary['steamIdentitySource']); ?>

                        <?php acp_field_group('Installation Paths & Bounds'); ?>
                        <?php acp_field('Game window bounds', trim($summary['gameWindowTitle'] . ' ' . $summary['gameWindowBounds'])); ?>
                        <?php acp_field('Game root directory', acp_sanitize_path($summary['gameRoot']), true); ?>
                        <?php acp_field('Config file', acp_sanitize_path($summary['configPath']), true); ?>
                        <?php acp_field('Steam installation path', acp_sanitize_path($summary['steamPath']), true); ?>
                        <?php acp_field('Signature Database', (string) ((int) ($counts['totalSignatures'] ?? count($database['signatures'] ?? []))) . ' integrated signatures'); ?>
                    </div>
                </div>
            </details>
        </section>

        <section class="panel">
            <h2>Previous Scans For This Player</h2>
            <?php
            $previousScans = $selectedReport['previousScans'] ?? acp_find_related_reports($acpConfig, $selectedReport, 10);
            $previousScans = acp_enrich_previous_scans($acpConfig, $previousScans);
            ?>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Status</th>
                            <th>Nickname</th>
                            <th>Steam ID</th>
                            <th>IP</th>
                            <th>Server Connection History</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($previousScans as $scan): ?>
                            <?php
                            $scanSteam = trim((string) ($scan['steamId2'] ?? ''));
                            if ($scanSteam === '') {
                                $scanSteam = trim((string) ($scan['steamId'] ?? ''));
                            }
                            $scanServerName = trim((string) ($scan['serverName'] ?? ''));
                            $scanServerAddr = trim((string) ($scan['serverAddress'] ?? ''));
                            ?>
                            <tr>
                                <td class="mono"><?= acp_h((string) ($scan['uploadedAt'] ?? '')) ?></td>
                                <td><span class="badge <?= acp_h((string) ($scan['status'] ?? '')) ?>"><?= acp_h((string) ($scan['status'] ?? '')) ?></span></td>
                                <td><?= acp_h((string) ($scan['playerName'] ?? '')) ?></td>
                                <td class="mono"><?= acp_h($scanSteam !== '' ? $scanSteam : '—') ?></td>
                                <td class="mono"><?= acp_h((string) ($scan['maskedIp'] ?? '')) ?></td>
                                <td>
                                    <div class="srv-cell prev-srv">
                                        <?php if ($scanServerName !== '' || $scanServerAddr !== ''): ?>
                                            <span class="srv-name"><?= acp_h($scanServerName !== '' ? $scanServerName : 'Game Server') ?></span>
                                            <?php if ($scanServerAddr !== ''): ?><span class="srv-addr mono"><?= acp_h($scanServerAddr) ?></span><?php endif; ?>
                                        <?php else: ?>
                                            <span class="dim-text">Not captured</span>
                                        <?php endif; ?>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        <?php if (count($previousScans) === 0): ?>
                            <tr><td colspan="6" class="empty-cell">No previous scans matched this SteamID, IP, or device.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </section>

        <section class="panel panel-detections" id="confirmed-detections">
            <div class="panel-header-flex">
                <div class="panel-title-wrap">
                    <h2>Confirmed Detections</h2>
                </div>
                <div class="panel-header-badge badge-status-<?= strtolower($summary['status']) ?>">
                    <?= $summary['status'] === 'DETECTED' ? 'CHEATS DETECTED' : ($summary['status'] === 'WARNING' ? 'SUSPICIOUS' : 'NO DETECTIONS') ?>
                </div>
            </div>

            <?php
            $detectedRows = array_merge(
                acp_items($selectedReport, 'injected'),
                acp_items($selectedReport, 'loaded'),
                acp_items($selectedReport, 'resources'),
                acp_items($selectedReport, 'behavioral'),
                acp_items($selectedReport, 'previouslyLaunched'),
                acp_items($selectedReport, 'installedInOs'),
                acp_items($selectedReport, 'downloaded')
            );
            $parsedDetections = array_map('acp_gamer_detection', $detectedRows);
            $totalDetections = count($parsedDetections);

            // Compute breakdown counts
            $modulesCount = [];
            $categoriesCount = [];
            foreach ($parsedDetections as $dItem) {
                $m = $dItem['module'] ?: 'Other';
                $modulesCount[$m] = ($modulesCount[$m] ?? 0) + 1;
                $cat = $dItem['cleanType'] ?: 'Other';
                $categoriesCount[$cat] = ($categoriesCount[$cat] ?? 0) + 1;
            }
            ?>

            <?php if ($totalDetections > 0): ?>
                <!-- 2026 Security Metrics KPI Ribbon -->
                <div class="metrics-kpi-bar">
                    <div class="metrics-kpi-item">
                        <span class="kpi-label">TOTAL VIOLATIONS</span>
                        <div class="kpi-val-row">
                            <span class="kpi-val val-danger"><?= $totalDetections ?></span>
                            <span class="kpi-badge badge-detected">CONFIRMED</span>
                        </div>
                    </div>
                    <div class="metrics-kpi-divider"></div>
                    <div class="metrics-kpi-item">
                        <span class="kpi-label">DETECTION CATEGORIES</span>
                        <div class="kpi-vector-pills">
                            <?php foreach ($categoriesCount as $cat => $cnt): ?>
                                <span class="kpi-vec-pill"><?= $cnt ?> <?= acp_h($cat) ?></span>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <div class="metrics-kpi-divider"></div>
                    <div class="metrics-kpi-item">
                        <span class="kpi-label">TARGET MODULES</span>
                        <div class="kpi-modules-list">
                            <?php foreach ($modulesCount as $mod => $cnt): ?>
                                <span class="kpi-mod-chip"><code><?= acp_h($mod) ?></code> <span class="mod-cnt"><?= $cnt ?></span></span>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>

                <!-- Modern Metrics Toolbar & Interactive Tabs -->
                <div class="metrics-toolbar">
                    <div class="metrics-tabs" role="tablist">
                        <button type="button" class="metrics-tab active" data-filter="all">All Violations (<?= $totalDetections ?>)</button>
                        <?php foreach ($categoriesCount as $cat => $cnt): ?>
                            <button type="button" class="metrics-tab" data-filter="<?= acp_h($cat) ?>"><?= acp_h($cat) ?> (<?= $cnt ?>)</button>
                        <?php endforeach; ?>
                    </div>
                    <div class="metrics-tools-right">
                        <input type="text" id="detectionFilterInput" class="metrics-search-input" placeholder="Quick filter cheat name, location, impact..." aria-label="Filter detections">
                        <button type="button" id="toggleAllDrawersBtn" class="metrics-action-btn" title="Toggle technical drawer on all rows">Expand All</button>
                    </div>
                </div>

                <!-- High-Density Telemetry Data-Grid Table (8-line scrollable viewport) -->
                <div class="metrics-table-wrap table-scroll-8">
                    <table class="metrics-table" id="detectionsMetricsTable">
                        <thead>
                            <tr>
                                <th class="col-num">#</th>
                                <th class="col-type">Type</th>
                                <th class="col-cheat">Cheat Name &amp; Location</th>
                                <th class="col-impact">What It Does (Impact)</th>
                                <th class="col-status">Status</th>
                                <th class="col-time">Time</th>
                                <th class="col-action">
                                    <button type="button" class="th-forensics-btn" onclick="acpToggleAllDrawers(this)" title="Toggle all forensic drawers">Forensics</button>
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($parsedDetections as $idx => $item): ?>
                                <tr class="metrics-row" data-target="<?= acp_h($item['module']) ?>" data-category="<?= acp_h($item['cleanType']) ?>" data-row-id="<?= $idx ?>" onclick="acpToggleDrawer('forensics-drawer-<?= $idx ?>', this, event)">
                                    <td class="col-num"><?= $idx + 1 ?></td>
                                    <td class="col-type">
                                        <span class="type-badge <?= acp_h($item['typeBadgeClass']) ?>" title="<?= acp_h($item['cleanType']) ?>">
                                            <i class="fa <?= acp_h($item['typeIcon']) ?>" aria-hidden="true"></i>
                                            <span><?= acp_h($item['cleanType']) ?></span>
                                        </span>
                                    </td>
                                    <td class="col-cheat">
                                        <div class="cheat-title-block">
                                            <div class="cheat-main-name"><?= acp_h($item['cleanName']) ?></div>
                                            <div class="cheat-location-sub" title="<?= acp_h($item['cleanLocation']) ?>">
                                                <span class="loc-label">Location:</span>
                                                <code class="loc-val"><?= acp_h($item['cleanLocation']) ?></code>
                                            </div>
                                        </div>
                                    </td>
                                    <td class="col-impact">
                                        <div class="impact-desc"><?= acp_h($item['cleanImpact']) ?></div>
                                    </td>
                                    <td class="col-status">
                                        <span class="status-pill status-<?= strtolower($item['severity']) === 'warning' ? 'warning' : 'detected' ?>"><?= acp_h($item['severity']) ?></span>
                                    </td>
                                    <td class="col-time">
                                        <?php if (!empty($item['time'])): ?>
                                            <span class="time-stamp" title="<?= acp_h($item['time']) ?>"><?= acp_h(acp_fmt_time($item['time']) ?: $item['time']) ?></span>
                                        <?php else: ?>
                                            <span class="time-live" title="Active in running game process"><span class="live-dot"></span> Active in game</span>
                                        <?php endif; ?>
                                    </td>
                                    <td class="col-action">
                                        <button type="button" class="forensics-toggle-btn" aria-expanded="false" aria-controls="forensics-drawer-<?= $idx ?>" onclick="acpToggleDrawer('forensics-drawer-<?= $idx ?>', this, event)">
                                            <span class="btn-text">Forensics</span>
                                        </button>
                                    </td>
                                </tr>
                                <tr class="metrics-drawer-row is-collapsed" id="forensics-drawer-<?= $idx ?>" data-target="<?= acp_h($item['module']) ?>" data-category="<?= acp_h($item['cleanType']) ?>">
                                    <td colspan="7" class="drawer-cell">
                                        <div class="drawer-content">
                                            <div class="drawer-grid">
                                                <div class="drawer-field">
                                                    <span class="drawer-label">Engine Rule / Signature</span>
                                                    <span class="drawer-val"><?= acp_h($item['rawCheat']) ?></span>
                                                </div>
                                                <?php if ($item['cleanLocation'] !== ''): ?>
                                                <div class="drawer-field">
                                                    <span class="drawer-label">Target / Hooked Artifact</span>
                                                    <code class="drawer-val mono"><?= acp_h($item['cleanLocation']) ?></code>
                                                </div>
                                                <?php endif; ?>
                                                <?php if ($item['destination'] !== ''): ?>
                                                <div class="drawer-field">
                                                    <span class="drawer-label">Memory Destination / Offset</span>
                                                    <code class="drawer-val mono"><?= acp_h($item['destination']) ?></code>
                                                </div>
                                                <?php endif; ?>
                                                <?php if ($item['time'] !== ''): ?>
                                                <div class="drawer-field">
                                                    <span class="drawer-label">Detection Timestamp</span>
                                                    <span class="drawer-val mono"><?= acp_h(acp_fmt_time($item['time']) ?: $item['time']) ?></span>
                                                </div>
                                                <?php endif; ?>
                                                <div class="drawer-field full-width">
                                                    <span class="drawer-label">Live Memory Disassembly / Forensic Evidence</span>
                                                    <pre class="drawer-pre"><?= acp_h($item['rawEvidence']) ?></pre>
                                                </div>
                                                <?php if ($item['rawReason'] !== ''): ?>
                                                <div class="drawer-field full-width">
                                                    <span class="drawer-label">Technical Explanation</span>
                                                    <p class="drawer-note"><?= acp_h($item['rawReason']) ?></p>
                                                </div>
                                                <?php endif; ?>
                                            </div>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php else: ?>
                <div class="empty-panel-msg" style="padding:16px;text-align:center;color:var(--muted);font-style:italic;">No confirmed cheat evidence on this machine. Verified clean.</div>
            <?php endif; ?>
        </section>

        <?php
        // Filter review findings to strictly non-detected warnings/anomalies (avoids duplicating confirmed cheats)
        $allReportFindings = acp_report_findings($selectedReport);
        $detectedSubjects = array_fill_keys(array_map(static fn($d) => (string)($d['evidence'] ?? ''), $detectedRows), true);
        $reviewFindings = array_values(array_filter(
            $allReportFindings,
            static function(array $f) use ($detectedSubjects): bool {
                if (strtoupper((string) ($f['severity'] ?? '')) === 'DETECTED') {
                    return false;
                }
                $subj = (string) ($f['subject'] ?? '');
                return !isset($detectedSubjects[$subj]);
            }
        ));
        $parsedReview = array_map('acp_gamer_finding', $reviewFindings);
        ?>
        <section class="panel panel-review" id="review-evidence">
            <div class="panel-header-flex">
                <div class="panel-title-wrap">
                    <h2>Review Evidence</h2>
                </div>
                <span class="panel-header-badge badge-status-warning"><?= count($parsedReview) > 0 ? (count($parsedReview) . ' PENDING REVIEW') : 'CLEAN' ?></span>
            </div>
            <p class="panel-note">Lower-confidence environment flags worth a manual check. These are <strong style="color:var(--warn)">WARNING</strong>-level only and are never counted as a confirmed cheat on their own.</p>

            <?php if (count($parsedReview) > 0): ?>
                <!-- Review KPI Ribbon -->
                <div class="metrics-kpi-bar kpi-bar-review">
                    <div class="metrics-kpi-item">
                        <span class="kpi-label">TOTAL SIGNALS</span>
                        <div class="kpi-val-row">
                            <span class="kpi-val val-warn"><?= count($parsedReview) ?></span>
                            <span class="kpi-badge badge-warning">FLAGGED</span>
                        </div>
                    </div>
                    <div class="metrics-kpi-divider"></div>
                    <div class="metrics-kpi-item">
                        <span class="kpi-label">FLAGGED CATEGORY</span>
                        <span class="kpi-val"><?= acp_h($parsedReview[0]['vector']) ?></span>
                    </div>
                    <div class="metrics-kpi-divider"></div>
                    <div class="metrics-kpi-item">
                        <span class="kpi-label">AFFECTED TARGET</span>
                        <code class="kpi-val-mono"><?= acp_h($parsedReview[0]['target']) ?></code>
                    </div>
                </div>

                <!-- Review Metrics Data-Grid -->
                <div class="metrics-table-wrap">
                    <table class="metrics-table review-metrics-table">
                        <thead>
                            <tr>
                                <th class="col-num">#</th>
                                <th class="col-target">Source / Target</th>
                                <th class="col-vector">Signal Type</th>
                                <th class="col-symbol">Trigger Symbol / Alias</th>
                                <th class="col-impact">Referee Analysis</th>
                                <th class="col-status">Severity</th>
                                <th class="col-action">
                                    <button type="button" class="th-forensics-btn" onclick="acpToggleAllReviewDrawers(this)" title="Toggle all review drawers">Forensics</button>
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($parsedReview as $rIdx => $rf): ?>
                                <tr class="metrics-row" data-row-id="rev-<?= $rIdx ?>" onclick="acpToggleDrawer('review-drawer-<?= $rIdx ?>', this, event)">
                                    <td class="col-num"><?= $rIdx + 1 ?></td>
                                    <td class="col-target"><span class="target-chip chip-config"><code><?= acp_h($rf['target']) ?></code></span></td>
                                    <td class="col-vector"><span class="vector-badge badge-vec-warn"><?= acp_h($rf['vector']) ?></span></td>
                                    <td class="col-symbol"><code class="symbol-mono"><?= acp_h($rf['symbol']) ?></code></td>
                                    <td class="col-impact"><span class="impact-text"><?= acp_h($rf['impact']) ?></span></td>
                                    <td class="col-status"><span class="status-pill status-warning"><?= acp_h($rf['severity']) ?></span></td>
                                    <td class="col-action">
                                        <button type="button" class="forensics-toggle-btn" aria-expanded="false" aria-controls="review-drawer-<?= $rIdx ?>" onclick="acpToggleDrawer('review-drawer-<?= $rIdx ?>', this, event)">
                                            <span class="btn-text">Forensics</span>
                                        </button>
                                    </td>
                                </tr>
                                <tr class="metrics-drawer-row is-collapsed" id="review-drawer-<?= $rIdx ?>">
                                    <td colspan="7" class="drawer-cell">
                                        <div class="drawer-content">
                                            <div class="drawer-grid">
                                                <div class="drawer-field">
                                                    <span class="drawer-label">Engine Rule</span>
                                                    <span class="drawer-val"><?= acp_h($rf['rawRule']) ?></span>
                                                </div>
                                                <div class="drawer-field">
                                                    <span class="drawer-label">Source Subsystem</span>
                                                    <span class="drawer-val mono"><?= acp_h($rf['source'] ?: 'Game Config') ?></span>
                                                </div>
                                                <div class="drawer-field full-width">
                                                    <span class="drawer-label">Full Config Subject &amp; Alias Chain</span>
                                                    <pre class="drawer-pre"><?= acp_h($rf['rawSubject']) ?></pre>
                                                </div>
                                                <?php if ($rf['rawReason'] !== ''): ?>
                                                <div class="drawer-field full-width">
                                                    <span class="drawer-label">Detection Rule Logic</span>
                                                    <p class="drawer-note"><?= acp_h($rf['rawReason']) ?></p>
                                                </div>
                                                <?php endif; ?>
                                            </div>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php else: ?>
                <div class="empty-panel-msg" style="padding:16px;text-align:center;color:var(--muted);font-style:italic;">No review evidence recorded. Verified clean.</div>
            <?php endif; ?>
        </section>

        <section class="panel">
            <h2>Scanner Engine Checks</h2>
            <?php if (!empty($selectedReport['scanStages'])): ?>
                <p>Scan mode: <?= acp_h((string) ($selectedReport['scanMode'] ?? 'unknown')) ?> · <?= ($selectedReport['signatureVerified'] ?? false) ? 'Transport signature verified' : 'Transport signature unverified' ?> · Client observations require review; signing does not attest a cheat-free device.</p>
                <?php acp_table($selectedReport['scanStages'], ['Scan stage' => 'name', 'Duration (ms)' => 'durationMs'], 'Stage timings unavailable.', 'table-scroll-8'); ?>
            <?php endif; ?>
            <?php acp_table($selectedReport['engineChecks'] ?? [], ['Check' => 'name', 'Status' => 'status', 'Detail' => 'detail'], 'No engine checks recorded.', 'table-scroll-8'); ?>
        </section>

        <section class="panel">
            <div class="panel-header-flex">
                <h2>Additional Data</h2>
                <span class="panel-header-badge">FORENSIC ENGINE ARTIFACTS</span>
            </div>
            <p class="panel-note">Deep system diagnostics gathered during scan execution. Click any category to expand full technical inventory.</p>

            <details>
                <summary>
                    <span class="acc-title">Drivers</span>
                    <span class="acc-chip"><?= count($selectedReport['drivers'] ?? []) ?> loaded</span>
                </summary>
                <div class="inner">
                    <div class="acc-gamer-tip">
                        <span><strong>Summary:</strong> Kernel drivers running in the Windows OS kernel. Inspected for known cheat driver signatures and digital signatures.</span>
                    </div>
                    <?php
                    $sanitizedDrivers = array_map(static function($d) {
                        if (is_array($d) && isset($d['path'])) {
                            $d['path'] = acp_sanitize_path((string)$d['path']);
                        }
                        return $d;
                    }, array_slice($selectedReport['drivers'] ?? [], 0, 500));
                    acp_table($sanitizedDrivers, ['Name' => 'name', 'Display name' => 'displayName', 'Path' => 'path', 'MD5' => 'md5', 'SHA256' => 'sha256', 'Company' => 'company', 'Signer' => 'signer'], 'No driver data.');
                    ?>
                </div>
            </details>
            <details>
                <summary>
                    <span class="acc-title">Modules in hl.exe</span>
                    <span class="acc-chip"><?= count($selectedReport['modules'] ?? []) ?> modules</span>
                </summary>
                <div class="inner">
                    <div class="acc-gamer-tip">
                        <span><strong>Summary:</strong> Dynamic link libraries (.dll) mapped into Half-Life game memory. Cross-referenced against the verified clean game corpus.</span>
                    </div>
                    <?php
                    $sanitizedModules = array_map(static function($m) {
                        if (is_array($m) && isset($m['path'])) {
                            $m['path'] = acp_sanitize_path((string)$m['path']);
                        }
                        return $m;
                    }, array_slice($selectedReport['modules'] ?? [], 0, 500));
                    acp_table(acp_with_corpus_state($sanitizedModules, $selectedReport), ['Module' => 'name', 'Corpus' => 'corpusState', 'Prevalence' => 'corpusSeen', 'Trusted' => 'trusted', 'Sig valid' => 'signatureValid', 'Path' => 'path', 'Version' => 'fileVersion', 'MD5' => 'md5', 'Company' => 'company', 'Signer' => 'signer'], 'No hl.exe module data.');
                    ?>
                </div>
            </details>
            <details>
                <summary>
                    <span class="acc-title">Steam identity candidates</span>
                    <span class="acc-chip"><?= count($selectedReport['steamIdentityCandidates'] ?? []) ?> identified</span>
                </summary>
                <div class="inner">
                    <div class="acc-gamer-tip">
                        <span><strong>Summary:</strong> Steam account IDs discovered on this machine from the active Steam process, game registry, and client configurations.</span>
                    </div>
                    <?php acp_table(array_slice($selectedReport['steamIdentityCandidates'] ?? [], 0, 50), ['Primary' => 'primary', 'SteamID64' => 'steamId', 'Steam2' => 'steamId2', 'Steam3' => 'steamId3', 'Source' => 'source'], 'No Steam identity candidates found.'); ?>
                </div>
            </details>
            <details>
                <summary>
                    <span class="acc-title">Live in-game behavior</span>
                    <span class="acc-chip"><?= count($selectedReport['liveBehavior'] ?? []) ?> samples</span>
                </summary>
                <div class="inner">
                    <div class="acc-gamer-tip">
                        <span><strong>Summary:</strong> Real-time combat telemetry checking for snap aimbot jumps, inhuman trigger times, or unnatural recoil compensation.</span>
                    </div>
                    <?php acp_table(array_slice($selectedReport['liveBehavior'] ?? [], 0, 20), ['Started' => 'startedAt', 'Duration' => 'durationSeconds', 'Active samples' => 'activeSamples', 'Total samples' => 'totalSamples', 'Attack presses' => 'attackPresses', 'Low-move attacks' => 'lowMoveAttackPresses', 'Snap attacks' => 'snapAttackPresses', 'Strafe alternations' => 'strafeAlternations', 'Output' => 'output'], 'No live in-game behavior captured.'); ?>
                </div>
            </details>
            <details>
                <summary>
                    <span class="acc-title">Memory evidence</span>
                    <span class="acc-chip"><?= count($selectedReport['memoryArtifacts'] ?? []) ?> regions</span>
                </summary>
                <div class="inner">
                    <div class="acc-gamer-tip">
                        <span><strong>Summary:</strong> Memory pages in hl.exe scanned for hidden shellcode, injected hooks, or unauthorized executable code.</span>
                    </div>
                    <?php acp_table(array_slice($selectedReport['memoryArtifacts'] ?? [], 0, 200), ['Base' => 'baseAddress', 'Size' => 'regionSize', 'Type' => 'type', 'Protection' => 'protection', 'Known module' => 'inKnownModule', 'MD5 first 4K' => 'md5First4K', 'Strings' => 'strings'], 'No executable memory artifacts found.'); ?>
                </div>
            </details>
            <details>
                <summary>
                    <span class="acc-title">Processes</span>
                    <span class="acc-chip"><?= count($selectedReport['processes'] ?? []) ?> processes</span>
                </summary>
                <div class="inner">
                    <div class="acc-gamer-tip">
                        <span><strong>Summary:</strong> All processes running on the user's PC during the match, cross-referenced with cheat signatures and debug utilities. Protected personal applications are shielded.</span>
                    </div>
                    <?php
                    $safeProcesses = acp_sanitize_processes(array_slice($selectedReport['processes'] ?? [], 0, 500));
                    acp_table($safeProcesses, ['PID' => 'pid', 'Name' => 'name', 'Size' => 'bytes', 'MD5' => 'md5', 'SHA256' => 'sha256', 'Path' => 'path'], 'No process data.');
                    ?>
                </div>
            </details>
            <details>
                <summary>
                    <span class="acc-title">HL directory files</span>
                    <span class="acc-chip"><?= count($selectedReport['hlFiles'] ?? []) ?> files</span>
                </summary>
                <div class="inner">
                    <div class="acc-gamer-tip">
                        <span><strong>Summary:</strong> Files in the Counter-Strike folder hashed to detect modified models, sound files, or injected .asi/.dll loader plugins.</span>
                    </div>
                    <?php
                    $sanitizedHlFiles = array_map(static function($f) {
                        if (is_array($f) && isset($f['relativePath'])) {
                            $f['relativePath'] = acp_sanitize_path((string)$f['relativePath']);
                        }
                        return $f;
                    }, array_slice($selectedReport['hlFiles'] ?? [], 0, 500));
                    acp_table($sanitizedHlFiles, ['File' => 'relativePath', 'Bytes' => 'bytes', 'MD5' => 'md5', 'SHA256' => 'sha256', 'Company' => 'company', 'Signer' => 'signer'], 'No Half-Life folder files found.');
                    ?>
                </div>
            </details>
        </section>
        </div><!-- /#acpReportContainer -->

    <?php endif; ?>

    <?php if ($selectedReport === null): ?>
    <section class="panel">
        <div class="panel-header-flex recent-head">
            <h2>Recent Scans</h2>

            <form class="recent-search" method="get" action="index.php" role="search">
                <div class="rs-help-wrap">
                    <button type="button" class="rs-help" id="rsHelpBtn" aria-expanded="false" aria-controls="rsHelpPanel" aria-label="How to search" title="How to search">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9.5"/><path d="M9.4 9.2a2.7 2.7 0 1 1 3.7 2.5c-.75.3-1.1.85-1.1 1.55v.35"/><path d="M12 17.1h.01"/></svg>
                    </button>
                    <div class="rs-help-panel" id="rsHelpPanel" hidden>
                        <div class="rsh-title">Search Reports</div>
                        <ul>
                            <li>Type a <b>player name</b> to list that player's scans.</li>
                            <li>Type a <b>server name or IP</b> to list every scan taken on that server.</li>
                            <li>Pick the scope with the dropdown: <b>All</b>, <b>Player</b> or <b>Server</b>.</li>
                            <li>Click any <b>Server Name / IP</b> in the table to filter to that server only.</li>
                            <li>Press <b>Enter</b> or the orange button to search; <b>&times;</b> clears the filter.</li>
                        </ul>
                    </div>
                </div>
                <label class="rs-input-wrap">
                    <svg class="rs-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
                    <input type="search" name="q" value="<?= acp_h($searchQuery) ?>" placeholder="Search name or server..." aria-label="Search scans">
                </label>
                <select name="by" aria-label="Search scope">
                    <option value="all"<?= $searchScope === 'all' ? ' selected' : '' ?>>All</option>
                    <option value="name"<?= $searchScope === 'name' ? ' selected' : '' ?>>Player</option>
                    <option value="server"<?= $searchScope === 'server' ? ' selected' : '' ?>>Server</option>
                </select>
                <button type="submit" class="rs-btn" aria-label="Search" title="Search">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
                </button>
                <?php if ($isSearch): ?>
                    <a class="rs-clear" href="index.php" aria-label="Clear search" title="Clear search">&times;</a>
                <?php endif; ?>
            </form>
        </div>
        <script>
        (function () {
            var btn = document.getElementById('rsHelpBtn');
            var panel = document.getElementById('rsHelpPanel');
            if (!btn || !panel) { return; }
            function close() { panel.hidden = true; btn.setAttribute('aria-expanded', 'false'); }
            if (window.location.hash === '#search-help') {
                panel.hidden = false;
                btn.setAttribute('aria-expanded', 'true');
            }
            btn.addEventListener('click', function (e) {
                e.stopPropagation();
                var willOpen = panel.hidden;
                panel.hidden = !willOpen;
                btn.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
            });
            document.addEventListener('click', function (e) {
                if (!panel.hidden && !panel.contains(e.target) && e.target !== btn) { close(); }
            });
            document.addEventListener('keydown', function (e) { if (e.key === 'Escape') { close(); } });
        })();
        </script>

        <?php if ($isSearch): ?>
            <p class="recent-note">
                Showing <b><?= (int) $listTotal ?></b> result<?= $listTotal === 1 ? '' : 's' ?>
                for <b><?= acp_h($searchQuery) ?></b>
                (<?= $searchScope === 'server' ? 'server name / IP' : ($searchScope === 'name' ? 'player name' : 'name &amp; server') ?>)
            </p>
        <?php endif; ?>

        <div class="table-wrap">
            <table class="recent-scans-table">
                <thead>
                <tr>
                    <th>Name</th>
                    <th>IP</th>
                    <th>Server Name / IP</th>
                    <th>Status</th>
                    <th>Time</th>
                    <th>Report</th>
                </tr>
                </thead>
                <tbody>
                <?php foreach ($recentReports as $report): ?>
                    <?php
                    $rsServer = trim((string) ($report['serverName'] ?? ''));
                    $rsAddr = trim((string) ($report['serverAddress'] ?? ''));
                    $rsFilter = $rsServer !== '' ? $rsServer : $rsAddr;
                    ?>
                    <tr>
                        <td><a class="name-link" href="?report=<?= rawurlencode($report['id']) ?>" title="Open report #<?= acp_h($report['id']) ?>"><?= acp_h($report['playerName'] ?: 'Unknown') ?></a></td>
                        <td class="mono"><?= acp_h($report['maskedIp'] ?? '') ?></td>
                        <td>
                            <?php if ($rsServer !== '' || $rsAddr !== ''): ?>
                                <a class="recent-srv" href="?by=server&amp;q=<?= rawurlencode($rsFilter) ?>" title="Show every scan on <?= acp_h(trim($rsServer . ' ' . $rsAddr)) ?>">
                                    <span class="rs-name"><?= acp_h($rsServer !== '' ? $rsServer : 'Game Server') ?></span>
                                    <?php if ($rsAddr !== ''): ?><span class="rs-addr mono"><?= acp_h($rsAddr) ?></span><?php endif; ?>
                                </a>
                            <?php else: ?>
                                <span class="dim-text">Not captured</span>
                            <?php endif; ?>
                        </td>
                        <td><span class="badge <?= acp_h($report['status']) ?>"><?= acp_h($report['status']) ?></span></td>
                        <td class="mono"><?= acp_h(acp_short_time((string) $report['uploadedAt'])) ?></td>
                        <td><a href="?report=<?= rawurlencode($report['id']) ?>">View &rarr;</a></td>
                    </tr>
                <?php endforeach; ?>
                <?php if (count($recentReports) === 0): ?>
                    <tr><td colspan="6" class="empty-cell"><?= $isSearch ? 'No scans match your search.' : 'No scans uploaded yet.' ?></td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>

        <?php $pageSuffix = $isSearch ? '&amp;q=' . rawurlencode($searchQuery) . '&amp;by=' . rawurlencode($searchScope) : ''; ?>
        <?php if ($totalPages > 1): ?>
        <nav class="pagination" aria-label="Recent scans pages">
            <?php if ($page > 1): ?>
                <a class="page-btn" href="?page=<?= (int) ($page - 1) ?><?= $pageSuffix ?>" rel="prev">&larr; Prev</a>
            <?php else: ?>
                <span class="page-btn is-disabled">&larr; Prev</span>
            <?php endif; ?>
            <span class="page-info">Page <?= (int) $page ?> / <?= (int) $totalPages ?> <span class="page-total">&middot; <?= (int) $listTotal ?> scans</span></span>
            <?php if ($page < $totalPages): ?>
                <a class="page-btn" href="?page=<?= (int) ($page + 1) ?><?= $pageSuffix ?>" rel="next">Next &rarr;</a>
            <?php else: ?>
                <span class="page-btn is-disabled">Next &rarr;</span>
            <?php endif; ?>
        </nav>
        <?php endif; ?>
    </section>
    <?php endif; ?>

    <footer>
        <span class="lh-powered">
            <span>ACS Anti-Cheat Scanner</span>
            <span class="lh-powered-sep">-</span>
            <span class="powered-text">Powered By</span>
            <a class="valve-logo" href="https://www.cslonghorn.com" target="_blank" rel="noopener" title="cslonghorn.com"><span>LONGHORN</span></a>
        </span>
        <span>Copyright &copy; <?= date('Y') ?> All Rights Reserved.</span>
    </footer>
</main>
<script>
// 2026 Modern Metrics Data-Grid Interactivity
window.acpToggleDrawer = function(drawerId, triggerEl, evt) {
    if (evt) {
        if (evt.target && (evt.target.tagName === 'A' || evt.target.closest('a'))) return;
        evt.stopPropagation();
    }
    var drawer = document.getElementById(drawerId);
    if (!drawer) return;

    var row = triggerEl ? (triggerEl.classList && triggerEl.classList.contains('metrics-row') ? triggerEl : triggerEl.closest('tr')) : null;
    var btn = row ? row.querySelector('.forensics-toggle-btn') : (triggerEl && triggerEl.classList && triggerEl.classList.contains('forensics-toggle-btn') ? triggerEl : null);

    var isCollapsed = drawer.classList.contains('is-collapsed');
    if (isCollapsed) {
        drawer.classList.remove('is-collapsed');
        drawer.classList.add('is-open-user');
        drawer.style.display = 'table-row';
        if (row) row.classList.add('is-expanded');
        if (btn) {
            btn.setAttribute('aria-expanded', 'true');
            var txt = btn.querySelector('.btn-text');
            if (txt) txt.textContent = 'Close';
        }
    } else {
        drawer.classList.add('is-collapsed');
        drawer.classList.remove('is-open-user');
        drawer.style.display = 'none';
        if (row) row.classList.remove('is-expanded');
        if (btn) {
            btn.setAttribute('aria-expanded', 'false');
            var txt = btn.querySelector('.btn-text');
            if (txt) txt.textContent = 'Forensics';
        }
    }
};

window.acpToggleAllDrawers = function(headerBtn) {
    var table = document.getElementById('detectionsMetricsTable');
    if (!table) return;
    var rows = table.querySelectorAll('tbody .metrics-row');
    var toggleBtn = document.getElementById('toggleAllDrawersBtn');

    var hasClosed = false;
    rows.forEach(function(row) {
        if (row.style.display === 'none') return;
        var rId = row.getAttribute('data-row-id');
        var d = document.getElementById('forensics-drawer-' + rId);
        if (d && d.classList.contains('is-collapsed')) {
            hasClosed = true;
        }
    });

    var shouldOpen = hasClosed;
    rows.forEach(function(row) {
        if (row.style.display === 'none') return;
        var rId = row.getAttribute('data-row-id');
        var d = document.getElementById('forensics-drawer-' + rId);
        var b = row.querySelector('.forensics-toggle-btn');
        if (!d) return;

        if (shouldOpen) {
            d.classList.remove('is-collapsed');
            d.classList.add('is-open-user');
            d.style.display = 'table-row';
            row.classList.add('is-expanded');
            if (b) {
                b.setAttribute('aria-expanded', 'true');
                var txt = b.querySelector('.btn-text');
                if (txt) txt.textContent = 'Close';
            }
        } else {
            d.classList.add('is-collapsed');
            d.classList.remove('is-open-user');
            d.style.display = 'none';
            row.classList.remove('is-expanded');
            if (b) {
                b.setAttribute('aria-expanded', 'false');
                var txt = b.querySelector('.btn-text');
                if (txt) txt.textContent = 'Forensics';
            }
        }
    });

    if (toggleBtn) {
        toggleBtn.textContent = shouldOpen ? 'Collapse All' : 'Expand All';
    }
};

window.acpToggleAllReviewDrawers = function(headerBtn) {
    var table = document.querySelector('.review-metrics-table');
    if (!table) return;
    var rows = table.querySelectorAll('tbody .metrics-row');

    var hasClosed = false;
    rows.forEach(function(row) {
        var rId = row.getAttribute('data-row-id');
        var drawerId = rId ? rId.replace('rev-', 'review-drawer-') : '';
        var d = document.getElementById(drawerId);
        if (d && d.classList.contains('is-collapsed')) {
            hasClosed = true;
        }
    });

    var shouldOpen = hasClosed;
    rows.forEach(function(row) {
        var rId = row.getAttribute('data-row-id');
        var drawerId = rId ? rId.replace('rev-', 'review-drawer-') : '';
        var d = document.getElementById(drawerId);
        var b = row.querySelector('.forensics-toggle-btn');
        if (!d) return;

        if (shouldOpen) {
            d.classList.remove('is-collapsed');
            d.classList.add('is-open-user');
            d.style.display = 'table-row';
            row.classList.add('is-expanded');
            if (b) {
                b.setAttribute('aria-expanded', 'true');
                var txt = b.querySelector('.btn-text');
                if (txt) txt.textContent = 'Close';
            }
        } else {
            d.classList.add('is-collapsed');
            d.classList.remove('is-open-user');
            d.style.display = 'none';
            row.classList.remove('is-expanded');
            if (b) {
                b.setAttribute('aria-expanded', 'false');
                var txt = b.querySelector('.btn-text');
                if (txt) txt.textContent = 'Forensics';
            }
        }
    });
};

document.addEventListener('DOMContentLoaded', function() {
    // 1. Module Filter Tabs
    var tabs = document.querySelectorAll('.metrics-tabs .metrics-tab');
    var rows = document.querySelectorAll('#detectionsMetricsTable tbody .metrics-row');
    var searchInput = document.getElementById('detectionFilterInput');
    var toggleAllBtn = document.getElementById('toggleAllDrawersBtn');

    function applyFilter() {
        var activeTab = document.querySelector('.metrics-tabs .metrics-tab.active');
        var filterVal = activeTab ? (activeTab.getAttribute('data-filter') || 'all') : 'all';
        var query = searchInput ? (searchInput.value || '').trim().toLowerCase() : '';

        rows.forEach(function(row) {
            var target = row.getAttribute('data-target') || '';
            var category = row.getAttribute('data-category') || '';
            var rowId = row.getAttribute('data-row-id');
            var drawer = document.getElementById('forensics-drawer-' + rowId);
            var text = row.textContent.toLowerCase();

            var matchesTab = (filterVal === 'all' || 
                              target.toLowerCase() === filterVal.toLowerCase() || 
                              category.toLowerCase() === filterVal.toLowerCase());
            var matchesQuery = (query === '' || text.indexOf(query) !== -1);

            if (matchesTab && matchesQuery) {
                row.style.display = '';
                if (drawer && drawer.classList.contains('is-open-user')) {
                    drawer.style.display = 'table-row';
                }
            } else {
                row.style.display = 'none';
                if (drawer) {
                    drawer.style.display = 'none';
                }
            }
        });
    }

    if (tabs.length > 0) {
        tabs.forEach(function(tab) {
            tab.addEventListener('click', function() {
                tabs.forEach(function(t) { t.classList.remove('active'); });
                tab.classList.add('active');
                applyFilter();
            });
        });
    }

    if (searchInput) {
        searchInput.addEventListener('input', applyFilter);
    }

    if (toggleAllBtn) {
        toggleAllBtn.addEventListener('click', function() {
            window.acpToggleAllDrawers(toggleAllBtn);
        });
    }
});
</script>
<script>
// Reports that predate the client sending its local time fall back to showing the scan
// timestamp in the viewer's own time zone, exact to the second.
(function () {
    var pad = function (n) { return n < 10 ? '0' + n : '' + n; };
    document.querySelectorAll('.js-local-time').forEach(function (el) {
        var iso = el.getAttribute('data-utc');
        if (!iso) return;
        var d = new Date(iso);
        if (isNaN(d.getTime())) return;
        el.textContent = d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate())
            + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
    });
})();
</script>
<?php uds_theme_footbar(); ?>
</body>
</html>

<?php
declare(strict_types=1);

/**
 * Shared theme runtime for the LongHorn ACP front-end.
 *
 * Two themes ship with the application:
 *   - "core"  the Tactical Cyberdeck look (assets/theme.css)
 *   - "lh"    LH Style, a broadcast-grade competitive-gaming skin layered on
 *             top of the same tokens (assets/lh-style.css)
 *
 * Both share one token contract, so a page only has to opt in once:
 *
 *     uds_theme_head();      // immediately before </head>
 *     uds_theme_footbar();   // immediately before </body>
 *
 * The head call must come last in <head> so the LH override sheet wins over
 * any page-level <style> block without needing !important.
 */

if (!defined('UDS_THEME_VERSION')) {
    define('UDS_THEME_VERSION', '2026.2');
}

/**
 * Asset prefix so the include keeps working from any script in the app root.
 */
function uds_theme_asset(string $file): string
{
    return 'assets/' . $file . '?v=' . UDS_THEME_VERSION;
}

/**
 * Visitor counter tracking total visits (humans and bots are recorded separately).
 */
function uds_get_visitor_stats(): array
{
    $file = __DIR__ . '/database/visitor_stats.json';
    // Starts at zero and only ever counts real requests. Every visit is counted,
    // including automated/bot traffic; humans and bots are tracked separately so the
    // total is honest and the breakdown is available on hover.
    $stats = [
        'total'  => 0,
        'bots'   => 0,
        'humans' => 0,
        'updatedAt' => gmdate('Y-m-d\TH:i:s\Z'),
    ];

    if (file_exists($file)) {
        $raw = @file_get_contents($file);
        $decoded = json_decode((string)$raw, true);
        if (is_array($decoded) && isset($decoded['total'])) {
            $stats = array_merge($stats, $decoded);
        }
    }

    static $counted = false;
    if (!$counted) {
        $counted = true;
        $ua = strtolower((string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
        $isBot = (bool)preg_match('/(bot|crawl|spider|slurp|curl|wget|python|headless|scan|agent|google|bing|yahoo|baidu|yandex)/i', $ua);
        $stats['total'] = (int)($stats['total'] ?? 0) + 1;
        if ($isBot) {
            $stats['bots'] = (int)($stats['bots'] ?? 0) + 1;
        } else {
            $stats['humans'] = (int)($stats['humans'] ?? 0) + 1;
        }
        $stats['updatedAt'] = gmdate('Y-m-d\TH:i:s\Z');
        @file_put_contents($file, json_encode($stats, JSON_PRETTY_PRINT));
    }

    return $stats;
}

/**
 * Stylesheets + the pre-paint theme resolver.
 *
 * Defaults to LH Style, with switching supported.
 */
function uds_theme_head(): void
{
    $switchCss = uds_theme_asset('theme-switch.css');
    $lhCss     = uds_theme_asset('lh-style.css');
    ?>
<link rel="stylesheet" href="<?= htmlspecialchars($switchCss, ENT_QUOTES) ?>">
<link rel="stylesheet" href="<?= htmlspecialchars($lhCss, ENT_QUOTES) ?>">
<script>
(function () {
    var STORE = 'uds-theme';
    var VALID = { core: 1, lh: 1 };
    var t;
    try { t = localStorage.getItem(STORE); } catch (e) { t = null; }
    if (!t || !VALID[t]) { t = 'lh'; }
    document.documentElement.setAttribute('data-uds-theme', t);
})();
</script>
    <?php
}

/**
 * The persistent bottom bar: identity, live human visitor count readout,
 * and the theme picker.
 */
function uds_theme_footbar(): void
{
    $switchJs  = uds_theme_asset('theme-switch.js');
    $effectsJs = uds_theme_asset('lh-effects.js');
    $stats     = uds_get_visitor_stats();
    // Total visits, bots included - that is the "real" number the bar reports.
    $visitorCountFmt = number_format((int)$stats['total']);
    $visitorStatusText = $visitorCountFmt . ' visitors';
    ?>
<div class="uds-footbar" id="uds-footbar" role="contentinfo">
    <div class="uds-fb-left">
        <span class="uds-fb-mark" aria-hidden="true"></span>
        <span class="uds-fb-title">ACP Anti-Cheat Scanner</span>
        <span class="uds-fb-status" id="uds-fb-status">
            <span class="uds-fb-dot" aria-hidden="true"></span>
            <span class="uds-fb-status-text" id="uds-fb-status-text" data-visitor-text="<?= htmlspecialchars($visitorStatusText, ENT_QUOTES) ?>" title="<?= (int)$stats['humans'] ?> human visits &middot; <?= (int)$stats['bots'] ?> bot visits"><?= htmlspecialchars($visitorStatusText, ENT_QUOTES) ?></span>
        </span>
    </div>

    <div class="uds-fb-right">
        <a class="uds-fb-link" href="privacy.php">Privacy Policy</a>
        <span class="uds-fb-divider" aria-hidden="true"></span>
        <a class="uds-fb-link" href="terms.php">Terms of Use</a>
        <span class="uds-fb-divider" aria-hidden="true"></span>
        <a class="uds-fb-link" href="license.php">License Agreement</a>
    </div>
</div>
<script src="<?= htmlspecialchars($switchJs, ENT_QUOTES) ?>" defer></script>
<script src="<?= htmlspecialchars($effectsJs, ENT_QUOTES) ?>" defer></script>
    <?php
}

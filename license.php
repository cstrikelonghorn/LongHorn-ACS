<?php
declare(strict_types=1);

require __DIR__ . '/theme_bar.php';
require __DIR__ . '/nav.php';
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>License Agreement — ACS Anti-Cheat Scanner</title>
    <link rel="stylesheet" href="assets/theme.css">
    <?php uds_theme_head(); ?>
    <link rel="stylesheet" href="assets/acp.css?v=<?= filemtime(__DIR__ . '/assets/acp.css') ?>">
</head>
<body>
<header>
    <div class="wrap topbar">
        <div class="brand">
            <a class="brand-mark lh-mark" href="index.php" aria-label="ACS home">
                <img class="lh-logo-img" src="images/logo_up.jpg" alt="LongHorn">
            </a>
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
        </div>
    </div>
</header>
<?php acp_site_nav('faq', 'download.php', true); ?>
<main class="wrap">

    <section class="panel faq-hero">
        <span class="faq-kicker">Legal</span>
        <h1>License Agreement</h1>
        <p>This agreement governs the ACS Anti-Cheat Scanner and the LongHorn ACP dashboard ("ACS"). By installing, running, or deploying any part of it, you accept these terms.</p>
        <p class="legal-updated">Last updated: <span class="mono"><?= date('F j, Y') ?></span></p>
        <div class="faq-toc">
            <a href="#l-accept">Acceptance</a>
            <a href="#l-grant">License grant</a>
            <a href="#l-use">Permitted use</a>
            <a href="#l-restrict">Restrictions</a>
            <a href="#l-data">Data &amp; evidence</a>
            <a href="#l-reports">Reports</a>
            <a href="#l-warranty">No warranty</a>
            <a href="#l-end">Termination</a>
            <a href="#l-contact">Contact</a>
        </div>
    </section>

    <section class="panel faq-section" id="l-accept">
        <h2>1. Acceptance</h2>
        <div class="legal">
            <p>ACS is a Counter-Strike 1.6 anti-cheat evidence tool. It is made of two parts: the Windows desktop scanner (<code>ACPScanner.exe</code>) and the LongHorn ACP web dashboard with its upload API and signature database. Downloading, installing or running the scanner, or deploying the dashboard, means you accept this agreement. If you do not agree, do not use ACS.</p>
        </div>
    </section>

    <section class="panel faq-section" id="l-grant">
        <h2>2. License grant</h2>
        <div class="legal">
            <p>LongHorn grants you a limited, non-exclusive, non-transferable and revocable licence to:</p>
            <ul>
                <li>run the scanner on machines you own or are authorised to test, and let it inspect the running game process;</li>
                <li>deploy the dashboard and its signature database on infrastructure you control, or upload reports to a deployment you are authorised to use;</li>
                <li>use the generated reports for moderation and evidence review.</li>
            </ul>
            <p>ACS is licensed, not sold. LongHorn keeps all rights in the software and its signature database.</p>
        </div>
    </section>

    <section class="panel faq-section" id="l-use">
        <h2>3. Permitted use</h2>
        <div class="legal">
            <p>Use ACS only on hardware you own or have clear permission to scan, and only to detect unauthorised software on game servers you operate. You must not use it to surveil, harass or profile people who have not agreed to be scanned.</p>
        </div>
    </section>

    <section class="panel faq-section" id="l-restrict">
        <h2>4. Restrictions</h2>
        <div class="legal">
            <p>You may not:</p>
            <ul>
                <li>remove, edit or falsify reports, signatures, or the report signature (HMAC) data;</li>
                <li>bypass, disable, or share the upload and admin tokens, or read reports you are not authorised to see;</li>
                <li>rebrand or resell ACS, or present it as your own product;</li>
                <li>reverse-engineer the compiled scanner beyond what the law allows;</li>
                <li>use ACS to attack or scan third-party systems, or for any unlawful purpose.</li>
            </ul>
        </div>
    </section>

    <section class="panel faq-section" id="l-data">
        <h2>5. Data and evidence</h2>
        <div class="legal">
            <p>To produce evidence, the scanner inspects the running <code>hl.exe</code> game process and records the player nickname, SteamID, a masked IP address, the Windows version, and hardware identifiers such as the disk serial and a device fingerprint used to recognise repeat scans. It also hashes and lists loaded modules, active drivers, running processes, game files and executable memory regions, and it checks game module code, imports and exports for hooks. It does not collect passwords, personal documents or browsing history. Full detail is in the <a href="privacy.php">Privacy Policy</a>.</p>
        </div>
    </section>

    <section class="panel faq-section" id="l-reports">
        <h2>6. Reports</h2>
        <div class="legal">
            <p>Reports are stored on the deployment you upload to and are controlled by that operator. Access is limited to the deployment's administrators and to single-report share links. Reports are HMAC-SHA256 signed so they cannot be altered after a scan, and a deployment can reject unsigned or edited reports. Uploading requires the deployment's upload token, and reviewing or classifying artifacts requires a separate admin token. Every hashed artifact in a report is also recorded in the deployment's artifact corpus, which tracks how many distinct machines have carried it so that common legitimate files stop being treated as suspicious.</p>
        </div>
    </section>

    <section class="panel faq-section" id="l-warranty">
        <h2>7. No warranty</h2>
        <div class="legal">
            <p>ACS is provided "as is" and without warranty of any kind. A detection is evidence, not absolute proof, and every finding must be reviewed by a human before any action is taken. To the extent the law allows, LongHorn is not liable for decisions made from a report or for any loss arising from the use of the software.</p>
        </div>
    </section>

    <section class="panel faq-section" id="l-end">
        <h2>8. Termination</h2>
        <div class="legal">
            <p>Your licence ends automatically if you breach this agreement, and you must then stop using ACS and remove your copies. An operator may also suspend access to a deployment at any time.</p>
        </div>
    </section>

    <section class="panel faq-section" id="l-contact">
        <h2>9. Contact</h2>
        <div class="legal">
            <p>Questions about this agreement: <a href="mailto:support@cslonghorn.com">support@cslonghorn.com</a> or through <a href="https://www.cslonghorn.com" target="_blank" rel="noopener noreferrer">cslonghorn.com</a>.</p>
            <p>See also the <a href="privacy.php">Privacy Policy</a>, the <a href="terms.php">Terms of Use</a> and the <a href="faq.php">FAQ</a>.</p>
        </div>
    </section>

</main>
<?php uds_theme_footbar(); ?>
</body>
</html>

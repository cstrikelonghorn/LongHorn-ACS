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
    <title>Terms of Use — ACS Anti-Cheat Scanner</title>
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
        <h1>Terms of Use</h1>
        <p>These terms govern the use of the ACS Anti-Cheat Scanner ("ACS", "the service") — the desktop scanner, the web dashboard and the server-side engine — and of this website.</p>
        <p class="legal-updated">Last updated: <span class="mono"><?= date('F j, Y') ?></span></p>
        <div class="faq-toc">
            <a href="#t-accept">Acceptance</a>
            <a href="#t-service">The service</a>
            <a href="#t-access">Access</a>
            <a href="#t-use">Acceptable use</a>
            <a href="#t-evidence">Evidence &amp; bans</a>
            <a href="#t-availability">Availability</a>
            <a href="#t-liability">Liability</a>
            <a href="#t-data">Data</a>
            <a href="#t-changes">Changes</a>
            <a href="#t-contact">Contact</a>
        </div>
    </section>

    <section class="panel faq-section" id="t-accept">
        <h2>Acceptance</h2>
        <div class="legal">
            <p>By running the scanner, uploading a report, or viewing this website you agree to these terms. If you do not agree, do not use the service.</p>
        </div>
    </section>

    <section class="panel faq-section" id="t-service">
        <h2>The service</h2>
        <div class="legal">
            <p>ACS collects and presents anti-cheat evidence for Counter-Strike 1.6. It inspects a running game process, compares what it finds against signatures and an artifact corpus, and stores the result as a report. It is an evidence tool, not a policing system: it does not ban, kick, or otherwise act on a player by itself.</p>
        </div>
    </section>

    <section class="panel faq-section" id="t-access">
        <h2>Access</h2>
        <div class="legal">
            <ul>
                <li>Uploading reports requires the deployment's upload token. It is a shared secret and you must keep it confidential.</li>
                <li>Viewing the full dashboard, the review queue and report comparison requires the admin token.</li>
                <li>Single-report share links may be handed out by an admin; they grant access to that report only.</li>
                <li>You are responsible for anything done with a token or link issued to you.</li>
            </ul>
        </div>
    </section>

    <section class="panel faq-section" id="t-use">
        <h2>Acceptable use</h2>
        <div class="legal">
            <ul>
                <li>Do not upload fabricated, altered, replayed or tampered reports.</li>
                <li>Do not attempt to access reports, tokens or data you are not authorised to view.</li>
                <li>Do not use the service to harass, dox, defame or unfairly target a player.</li>
                <li>Do not attempt to overload, scrape, or attack the service or the servers hosting it.</li>
                <li>Do not remove or falsify attribution or branding.</li>
            </ul>
            <p>Access may be suspended if these rules are broken.</p>
        </div>
    </section>

    <section class="panel faq-section" id="t-evidence">
        <h2>Evidence and bans</h2>
        <div class="legal">
            <p>Reports, findings, scores and prevalence figures are provided as-is and may contain false positives or false negatives. A "confirmed detection" is strong evidence of a specific observation, not proof of intent or of guilt beyond doubt. Every ban, kick or other sanction is decided by the operator of the individual game server, who is solely responsible for that decision.</p>
        </div>
    </section>

    <section class="panel faq-section" id="t-availability">
        <h2>Availability and changes</h2>
        <div class="legal">
            <p>The service is provided without any warranty of uptime or fitness for a particular purpose. Features, detection rules and interfaces may change, be interrupted or be discontinued at any time.</p>
        </div>
    </section>

    <section class="panel faq-section" id="t-liability">
        <h2>Limitation of liability</h2>
        <div class="legal">
            <p>To the maximum extent permitted by law, LongHorn and the operators of this deployment are not liable for indirect, incidental or consequential damages arising from the use of, or inability to use, the service — including decisions made on the basis of a report. Nothing in these terms limits liability that cannot be limited by law.</p>
        </div>
    </section>

    <section class="panel faq-section" id="t-data">
        <h2>Data</h2>
        <div class="legal">
            <p>Personal data is handled as described in the <a href="privacy.php">Privacy Policy</a>. Reports remain the responsibility of the operator who hosts them; deleting a report is done by that operator.</p>
        </div>
    </section>

    <section class="panel faq-section" id="t-changes">
        <h2>Changes to these terms</h2>
        <div class="legal">
            <p>These terms may be updated. The date at the top of this page shows the current version, and continuing to use the service after a change means you accept the updated terms.</p>
        </div>
    </section>

    <section class="panel faq-section" id="t-contact">
        <h2>Contact</h2>
        <div class="legal">
            <p>Questions about these terms: <a href="mailto:support@cslonghorn.com">support@cslonghorn.com</a> or through <a href="https://www.cslonghorn.com" target="_blank" rel="noopener noreferrer">cslonghorn.com</a>.</p>
            <p>See also the <a href="privacy.php">Privacy Policy</a> and the <a href="faq.php">FAQ</a>.</p>
        </div>
    </section>

</main>
<?php uds_theme_footbar(); ?>
</body>
</html>

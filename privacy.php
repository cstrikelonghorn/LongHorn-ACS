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
    <title>Privacy Policy — ACS Anti-Cheat Scanner</title>
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
        <h1>Privacy Policy</h1>
        <p>This policy explains what the ACS Anti-Cheat Scanner ("ACS", "we") collects when you run a scan or view this site, why we collect it, how it is protected, and the choices you have.</p>
        <p class="legal-updated">Last updated: <span class="mono"><?= date('F j, Y') ?></span></p>
        <div class="faq-toc">
            <a href="#p-overview">Overview</a>
            <a href="#p-collect">What we collect</a>
            <a href="#p-why">Why we collect it</a>
            <a href="#p-basis">Legal basis</a>
            <a href="#p-retention">Retention</a>
            <a href="#p-access">Who can see it</a>
            <a href="#p-sharing">Sharing</a>
            <a href="#p-security">Security</a>
            <a href="#p-rights">Your rights</a>
            <a href="#p-cookies">Visitor counters</a>
            <a href="#p-contact">Contact</a>
        </div>
    </section>

    <section class="panel faq-section" id="p-overview">
        <h2>Overview</h2>
        <div class="legal">
            <p>ACS is an anti-cheat evidence tool for Counter-Strike 1.6. It is made of three parts: a Windows desktop scanner, this web dashboard, and an optional game-server plugin. This policy covers all three, and it applies to players whose machines are scanned as well as to anyone who views this website.</p>
            <p>In short: we collect the minimum needed to produce and review anti-cheat evidence, we mask identifiers wherever we can, and we never sell personal data.</p>
        </div>
    </section>

    <section class="panel faq-section" id="p-collect">
        <h2>What we collect</h2>
        <div class="legal">
            <h3>When you run the desktop scanner</h3>
            <ul>
                <li><strong>Player identity</strong> — nickname, SteamID / Steam2 / Steam account id, and a derived player id.</li>
                <li><strong>Network</strong> — the IP address your machine connects from. It is stored and always displayed with the last octet masked (for example <code>109.187.61.***</code>).</li>
                <li><strong>Device</strong> — Windows version, disk/volume serial and a device fingerprint used to recognise repeat scans.</li>
                <li><strong>Game environment</strong> — the game build and detected client, the folders and files in your <code>cstrike</code> directory, loaded modules, drivers, private memory regions, and the results of the integrity and hook checks.</li>
                <li><strong>Timing</strong> — when the scan ran and your machine's local time, so a report can be matched to a session.</li>
            </ul>
            <h3>When you visit this website</h3>
            <ul>
                <li><strong>Access data</strong> — the server records your IP address and user agent to serve the page and to count visitors. IP addresses are stored masked.</li>
                <li><strong>No advertising or tracking cookies.</strong> The only client-side storage is a small preference entry that remembers your theme choice.</li>
            </ul>
        </div>
    </section>

    <section class="panel faq-section" id="p-why">
        <h2>Why we collect it</h2>
        <div class="legal">
            <ul>
                <li><strong>To produce a report</strong> — the scan data is the report. Without it there is no evidence to review.</li>
                <li><strong>To identify a player correctly</strong> — the SteamID and device fingerprint link scans of the same machine and separate different players.</li>
                <li><strong>To reduce false positives</strong> — hashes are compared against a corpus of artifacts seen across many machines, which is how common legitimate files are learned as clean.</li>
                <li><strong>To keep the service running</strong> — basic visit counts show how many users are online and help us size the deployment.</li>
            </ul>
        </div>
    </section>

    <section class="panel faq-section" id="p-basis">
        <h2>Legal basis</h2>
        <div class="legal">
            <p>We process scan data to pursue the legitimate interest of detecting cheating on the game servers that use ACS. Website access data is processed to operate the site and to keep counts of visitors. Where local law requires consent for any of this, it is obtained by the operator of the deployment you are dealing with.</p>
        </div>
    </section>

    <section class="panel faq-section" id="p-retention">
        <h2>How long we keep it</h2>
        <div class="legal">
            <p>Scan reports are kept until an administrator of the deployment deletes them. Visitor counters are aggregate numbers with no personal detail beyond a masked address. Nothing is kept "forever" by default, and a deleted report is removed from the dashboard's index as well.</p>
        </div>
    </section>

    <section class="panel faq-section" id="p-access">
        <h2>Who can see a report</h2>
        <div class="legal">
            <ul>
                <li><strong>Admins</strong> — holders of the deployment's admin token can see every report and the list of recent scans.</li>
                <li><strong>Share-link holders</strong> — each report has a single-report link whose key is derived from the report id. It opens that one report and nothing else; it never exposes the recent list or comparison view.</li>
                <li><strong>Localhost</strong> — on the host machine itself, local requests are allowed so a local deployment works without configuration.</li>
            </ul>
            <p>Report files are also blocked from direct web access, so a report cannot be fetched just by guessing a URL.</p>
        </div>
    </section>

    <section class="panel faq-section" id="p-sharing">
        <h2>Sharing</h2>
        <div class="legal">
            <p>We do not sell personal data and we do not run advertising. Report data is shared only with the server operators who requested the anti-cheat scan, and with the hosting provider that stores the deployment's files. If the law requires disclosure, we disclose only what is required.</p>
        </div>
    </section>

    <section class="panel faq-section" id="p-security">
        <h2>How it is protected</h2>
        <div class="legal">
            <ul>
                <li><strong>Signed reports</strong> — every report is HMAC-SHA256 signed so its contents cannot be altered after the scan. Deployments can reject unsigned or edited reports outright.</li>
                <li><strong>Separate secrets</strong> — the token that uploads reports is different from the one that classifies artifacts, so a leaked client cannot change verdicts for other players.</li>
                <li><strong>Masking</strong> — IP addresses are displayed masked, and share links never reveal other scans.</li>
                <li><strong>Least privilege</strong> — report storage is kept outside direct web access and non-web folders ship with deny-all rules.</li>
            </ul>
            <p>No system is perfect. If you believe a report about you contains data it should not, contact us and it will be reviewed.</p>
        </div>
    </section>

    <section class="panel faq-section" id="p-rights">
        <h2>Your rights</h2>
        <div class="legal">
            <p>Depending on where you live you may have the right to access, correct, or delete the data held about you, and to object to processing. To exercise any of these, contact the operator of the deployment or the LongHorn team using the details below. We will ask for enough information to locate the correct reports and to confirm you are entitled to act on them.</p>
        </div>
    </section>

    <section class="panel faq-section" id="p-cookies">
        <h2>Visitor counters and cookies</h2>
        <div class="legal">
            <p>This site does not use advertising or analytics cookies. It stores one local preference for your theme and keeps an aggregate count of visitors, including automated traffic, so the footer can show how many users are online. Those counters do not identify you to other visitors.</p>
        </div>
    </section>

    <section class="panel faq-section" id="p-contact">
        <h2>Contact</h2>
        <div class="legal">
            <p>Questions, access requests or complaints: <a href="mailto:support@cslonghorn.com">support@cslonghorn.com</a> or through <a href="https://www.cslonghorn.com" target="_blank" rel="noopener noreferrer">cslonghorn.com</a>.</p>
            <p>See also the <a href="terms.php">Terms of Use</a> and the <a href="faq.php">FAQ</a>.</p>
        </div>
    </section>

</main>
<?php uds_theme_footbar(); ?>
</body>
</html>

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
    <title>FAQ — ACS Anti-Cheat Scanner</title>
    <meta name="description" content="How the ACS Anti-Cheat Scanner works, what it scans, how to run the desktop app and read the web report, and how your data is protected.">
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
        <span class="faq-kicker">Help Center</span>
        <h1>Frequently Asked Questions</h1>
        <p>ACS is an anti-cheat evidence suite for Counter-Strike 1.6: a Windows scanner you run on your PC, a web dashboard that stores and explains the results, and an optional server plugin that watches players in-game. Everything below explains what it does, how to use it, and how your data is handled.</p>
        <div class="faq-toc">
            <a href="#overview">Overview</a>
            <a href="#how-it-works">How it works</a>
            <a href="#verdicts">Report statuses</a>
            <a href="#what-it-scans">What it scans</a>
            <a href="#included">What's included</a>
            <a href="#use-app">Using the app</a>
            <a href="#use-web">Using the web</a>
            <a href="#safety">How safe</a>
            <a href="#tutorials">Tutorials</a>
            <a href="#questions">Questions</a>
        </div>
    </section>

    <section class="panel faq-section" id="overview">
        <h2>Overview</h2>
        <p class="panel-note">What the project is, in one screen.</p>
        <div class="faq-grid">
            <div class="faq-card">
                <span class="faq-card-icon">1</span>
                <h3>Desktop scanner</h3>
                <p>A Windows app that attaches to a running <code>hl.exe</code>, inventories the game, checks it against a signature database and uploads a signed report.</p>
            </div>
            <div class="faq-card">
                <span class="faq-card-icon">2</span>
                <h3>Web dashboard</h3>
                <p>A PHP dashboard that stores reports, shows what was found, ranks review items, and lets admins compare scans or export a PDF.</p>
            </div>
            <div class="faq-card">
                <span class="faq-card-icon">3</span>
                <h3>Server engine</h3>
                <p>An optional ReHLDS plugin that analyses how a player actually moves, aims and fires — without needing any client cooperation.</p>
            </div>
        </div>
        <p>Who is it for? Server owners and their staff who want evidence-backed decisions instead of guesswork, and honest players who want a way to prove their game is clean.</p>
    </section>

    <section class="panel faq-section" id="how-it-works">
        <h2>How it works</h2>
        <p class="panel-note">From launch to verdict in three steps.</p>
        <ol class="faq-steps">
            <li>
                <strong>Scan.</strong> With Counter-Strike running, the desktop app reads the live game process: loaded modules, memory regions, hooks, files, drivers and configuration.
            </li>
            <li>
                <strong>Upload.</strong> The findings are packed into a report with an HMAC-SHA256 integrity check. This detects a changed payload but is not device attestation; a player controls their own client.
            </li>
            <li>
                <strong>Review.</strong> The dashboard stores the report, classifies each artifact, and presents a clear verdict with confirmed detections separated from lower-confidence review items.
            </li>
        </ol>
        <div class="faq-callout">
            <strong>Evidence, not a verdict.</strong> A report is a set of observations. Bans are always a human decision made by the server operator.
        </div>
    </section>

    <section class="panel faq-section" id="verdicts">
        <h2>Report statuses</h2>
        <p class="panel-note">Every scan ends in one of three verdicts.</p>
        <div class="legal">
            <p>The verdict is about <strong>where</strong> the evidence was found, not how many findings there are: to be marked <strong>Detected</strong>, ACS must find an active cheat inside the running game, not only traces left on the disk.</p>
            <ul>
                <li><span class="legal-badge detected">Detected</span> — <strong>Cheats detected.</strong> Code injected into the running game, a cheat module loaded into it, modified game resources, executable memory that belongs to no module, or live behavioural evidence. Shown in red.</li>
                <li><span class="legal-badge warning">Warning</span> — <strong>Review required / suspicious.</strong> No active in-game cheat, but the report holds review evidence: a detection seen only in historical or offline traces (previously launched, installed in the OS, or downloaded) or a warning-level finding such as a suspicious script or config. Shown in amber.</li>
                <li><span class="legal-badge clean">Clean</span> — <strong>No cheats detected.</strong> No detection and no warning findings. Shown in green.</li>
            </ul>
            <p>The same finding only turns a verdict red when it is live in the game process; if it is found only as a historical trace, it contributes to the amber verdict instead.</p>
            <figure class="legal-figure">
                <img src="images/status-levels.png" alt="The three report verdicts: Detected (red), Warning (amber) and Clean (green)" loading="lazy">
                <figcaption>The three report verdicts exactly as they appear on a report.</figcaption>
            </figure>

            <h3>Artifact states and finding severity</h3>
            <p>Separately from the verdict, every file, module and driver hash the scanner sees is kept in the deployment's artifact corpus with one of three states, and every finding is graded with a severity:</p>
            <ul>
                <li><strong>Cheat</strong> — a hash confirmed as a cheat, by a signature match, by prevalence, or by an administrator.</li>
                <li><strong>Unknown</strong> — not classified yet; it waits in the ranked review queue for a human.</li>
                <li><strong>Clean</strong> — seen on enough distinct machines without detections to be treated as legitimate.</li>
            </ul>
            <p>Each finding is graded as <strong>Detected</strong> (strong live evidence, counts toward the red verdict), <strong>Warning</strong> (review evidence only — never a cheat on its own) or <strong>Info</strong> (context with no verdict weight).</p>
            <figure class="legal-figure">
                <img src="images/status-corpus.png" alt="Artifact corpus states: cheat, unknown, clean; and finding severities: detected, warning, info" loading="lazy">
                <figcaption>Corpus states (cheat / unknown / clean) and finding severities (detected / warning / info).</figcaption>
            </figure>
        </div>
    </section>

    <section class="panel faq-section" id="what-it-scans">
        <h2>What it scans</h2>
        <p class="panel-note">Every area the desktop scanner inspects.</p>
        <div class="faq-grid faq-grid-3">
            <div class="faq-card"><h3>Running processes</h3><p>Processes compared against a known cheat/tool list, with paths and hashes recorded.</p></div>
            <div class="faq-card"><h3>Drivers</h3><p>Loaded kernel drivers with MD5/SHA256, publisher and signature state.</p></div>
            <div class="faq-card"><h3>Game modules</h3><p>Every DLL mapped into <code>hl.exe</code>, its path, signer and whether it is trusted.</p></div>
            <div class="faq-card"><h3>Memory regions</h3><p>Private executable memory that does not belong to any file on disk — a manual-map indicator.</p></div>
            <div class="faq-card"><h3>Inline hooks &amp; patches</h3><p>Engine code compared byte-for-byte against the file on disk, catching detours and mid-function patches.</p></div>
            <div class="faq-card"><h3>External readers</h3><p>Other processes holding read/write handles on the game, foreign threads, and overlay windows.</p></div>
            <div class="faq-card"><h3>Scripts &amp; config</h3><p>Alias graphs and control-flow shapes that reveal bunny-hop, rapid-fire and no-recoil scripts regardless of naming.</p></div>
            <div class="faq-card"><h3>Game files</h3><p>The live <code>cstrike</code> folder contents with hashes, so altered sprites and dropped DLLs are visible.</p></div>
            <div class="faq-card"><h3>Game build &amp; client</h3><p>Steam, non-Steam, NextClient, GSClient, RevEmu and other emulators are identified so they are not mistaken for cheats.</p></div>
        </div>
    </section>

    <section class="panel faq-section" id="included">
        <h2>What's included</h2>
        <div class="faq-grid">
            <div class="faq-card"><h3>Unified signature database</h3><p>Hundreds of curated signatures plus a live artifact corpus that learns prevalence across machines.</p></div>
            <div class="faq-card"><h3>Corpus &amp; prevalence</h3><p>Every hash ever seen, classified clean / cheat / unknown, so rare files stand out and common ones stop being false positives.</p></div>
            <div class="faq-card"><h3>Client profiles</h3><p>Known-legitimate CS 1.6 clients and Steam emulators are recognised by name and hash, so their own detours are not treated as cheating.</p></div>
            <div class="faq-card"><h3>Player risk view</h3><p>Server behaviour and client scan results are combined into one explainable risk score per SteamID.</p></div>
            <div class="faq-card"><h3>Compare &amp; export</h3><p>Side-by-side report comparison and a printable PDF export for reports.</p></div>
            <div class="faq-card"><h3>ReChecker feed</h3><p>The signature set can be rendered into a ReChecker <code>resources.ini</code> for server-side enforcement.</p></div>
        </div>
    </section>

    <section class="panel faq-section" id="use-app">
        <h2>Using the desktop app</h2>
        <ol class="faq-steps">
            <li><strong>Configure.</strong> Set <code>apiUrl</code> to your deployed <code>api.php</code> and <code>apiToken</code> to the same value as the server's upload token.</li>
            <li><strong>Launch Counter-Strike.</strong> The scanner only runs while <code>hl.exe</code> / <code>cstrike.exe</code> is already open.</li>
            <li><strong>Start the scan</strong> from the app. It attaches to the game and walks through every check.</li>
            <li><strong>Play normally</strong> while the live behaviour stage captures a short sample window.</li>
            <li><strong>Upload.</strong> The signed report is sent to your dashboard automatically when the scan finishes.</li>
        </ol>
        <div class="faq-callout">
            <strong>Tip.</strong> Run the scanner as administrator for the deepest evidence — some memory and process reads are limited otherwise.
        </div>
    </section>

    <section class="panel faq-section" id="use-web">
        <h2>Using the web dashboard</h2>
        <ol class="faq-steps">
            <li><strong>Dashboard.</strong> The newest scans are listed with name, IP, server, status and time. Use the page buttons to browse older scans.</li>
            <li><strong>Report.</strong> Open a scan to see the verdict, the Basic Data panel (identity, build, server), confirmed detections and review evidence.</li>
            <li><strong>Evidence.</strong> Each detection opens a forensic drawer with the engine rule, hook target, disassembly/byte difference and timestamp.</li>
            <li><strong>History.</strong> Previous scans for the same player and their server connection history are shown on the report.</li>
            <li><strong>Share.</strong> Admins can copy a single-report share link to hand to a player without exposing any other scan.</li>
            <li><strong>Compare / Export.</strong> Compare two reports side by side, or export a clean PDF for records.</li>
        </ol>
    </section>

    <section class="panel faq-section" id="safety">
        <h2>How safe is it?</h2>
        <div class="faq-grid faq-grid-3">
            <div class="faq-card"><h3>The scanner is an evidence tool</h3><p>It collects and explains; it does not ban, punish or modify your game. Nothing is deleted or changed on your PC.</p></div>
            <div class="faq-card"><h3>No account password needed</h3><p>It reads the SteamID the game already exposes and a hardware fingerprint — never your Steam password or login.</p></div>
            <div class="faq-card"><h3>Reports are tamper-evident</h3><p>Each report is HMAC-SHA256 signed. If the server requires signatures, edited reports are rejected outright.</p></div>
            <div class="faq-card"><h3>Your IP is masked</h3><p>Reports display the IP with the last octet hidden (e.g. <code>109.187.61.***</code>) so a public page never narrows you to one host.</p></div>
            <div class="faq-card"><h3>Access is gated</h3><p>Reports are stored outside direct web access, and viewing requires an admin token, a single-report share key, or localhost.</p></div>
            <div class="faq-card"><h3>False-positive resistant</h3><p>Known clients and emulators are recognised, and common files are learned from the corpus instead of being flagged for being unusual.</p></div>
        </div>
        <p>Full details are in the <a href="privacy.php">Privacy Policy</a> and <a href="terms.php">Terms of Use</a>.</p>
    </section>

    <section class="panel faq-section" id="tutorials">
        <h2>Tutorials</h2>
        <p class="panel-note">Short walk-throughs for the common tasks.</p>

        <details>
            <summary>Run your first scan</summary>
            <div class="inner tutorial-body">
                <ol>
                    <li>Open <code>windows/acp-settings.json</code> and set <code>apiUrl</code> and <code>apiToken</code>.</li>
                    <li>Start Counter-Strike 1.6 and join any server (or the main menu).</li>
                    <li>Launch the ACS scanner and press Scan. Keep the game focused while the live-behaviour stage runs.</li>
                    <li>When it finishes, the app confirms the upload and shows the report link.</li>
                </ol>
            </div>
        </details>

        <details>
            <summary>Read a report correctly</summary>
            <div class="inner tutorial-body">
                <ol>
                    <li>Start with the verdict and the metrics circles — they summarise how many confirmed detections exist.</li>
                    <li>Check <strong>Basic Data</strong> for identity, build and server at the time of the scan.</li>
                    <li>Read <strong>Confirmed Detections</strong> as strong evidence; read <strong>Review Evidence</strong> as "worth a look", not a verdict.</li>
                    <li>Open a row's <em>Forensics</em> drawer to see the exact rule and byte difference behind it.</li>
                </ol>
            </div>
        </details>

        <details>
            <summary>Share a clean scan with an admin</summary>
            <div class="inner tutorial-body">
                <ol>
                    <li>When the scan finishes, open <strong>View Evidence</strong> in the app and click the report link to copy it.</li>
                    <li>Send that link to the server admin.</li>
                    <li>Admins open reports with their own access, so the link does not expose the report to anyone else.</li>
                </ol>
            </div>
        </details>

        <details>
            <summary>Review the Unknown bucket (admins)</summary>
            <div class="inner tutorial-body">
                <ol>
                    <li>Open <code>review.php</code> with your admin token.</li>
                    <li>Rows are ranked by suspicion: mapped into the game, unsigned, rare, driver, or concentrated on machines with detections.</li>
                    <li>Use the VirusTotal link, then mark each row <strong>Cheat</strong> or <strong>Clean</strong> — the verdict applies to every future scan.</li>
                </ol>
            </div>
        </details>

        <details>
            <summary>Deploy server-side enforcement</summary>
            <div class="inner tutorial-body">
                <ol>
                    <li>Generate the feed: <code>rechecker.php?action=resources</code>.</li>
                    <li>Save it as <code>cstrike/addons/rechecker/resources.ini</code> on your server.</li>
                    <li>Review the file, then start with <code>amx_kick</code> rather than a ban until you trust the rules.</li>
                </ol>
            </div>
        </details>
    </section>

    <section class="panel faq-section" id="questions">
        <h2>Questions</h2>

        <details>
            <summary>Is the scanner a virus or malware?</summary>
            <div class="inner"><p>No. It is a read-only inspection tool. It opens the game process to read memory, hashes files and uploads a report. It does not inject code, modify the game, or keep running in the background.</p></div>
        </details>

        <details>
            <summary>Why does Windows say “Windows protected your PC”?</summary>
            <div class="inner"><p>That is Microsoft Defender SmartScreen. It warns about every new app that is not code-signed and not yet downloaded by many people — it does not mean a virus was found. The scanner is not code-signed yet. Check that the file's SHA-256 matches the one on the <a href="download.php">Download page</a>, then choose <strong>More info → Run anyway</strong>.</p></div>
        </details>

        <details>
            <summary>Does it ban players automatically?</summary>
            <div class="inner"><p>No. ACS produces evidence. A confirmed detection is strong evidence, and review items are lower-confidence signals — but every ban or kick is a decision made by a human server operator.</p></div>
        </details>

        <details>
            <summary>Will it flag legitimate software like Steam, Discord or MSI Afterburner?</summary>
            <div class="inner"><p>That is exactly what the client profiles and the artifact corpus prevent. Known overlays, injectors and CS 1.6 clients are recognised by name and hash; common files seen on many distinct machines are learned as clean instead of being flagged for rarity.</p></div>
        </details>

        <details>
            <summary>Does it work with non-Steam clients and emulators?</summary>
            <div class="inner"><p>Yes. Steam, non-Steam repacks, NextClient, GSClient, GoldClient, RevEmu/RevCrew, SmartSteamEmu, Goldberg and others are identified so the report shows the real client instead of calling its own detours a cheat.</p></div>
        </details>

        <details>
            <summary>Do I need administrator rights?</summary>
            <div class="inner"><p>The scan runs without elevation, but running as administrator allows deeper memory and process inspection, which produces more complete evidence. Some system processes are simply not readable without it.</p></div>
        </details>

        <details>
            <summary>Does the game have to be running?</summary>
            <div class="inner"><p>Yes. The scanner attaches to a live <code>hl.exe</code>. If the game is not running there is nothing to inspect, so start Counter-Strike first.</p></div>
        </details>

        <details>
            <summary>How long does a scan take?</summary>
            <div class="inner"><p>Typically well under a minute for the static checks, plus a short live-behaviour sample window while you play normally. The exact time depends on how many files and modules are present.</p></div>
        </details>

        <details>
            <summary>What data is stored, and for how long?</summary>
            <div class="inner"><p>Player identity, masked IP, operating system, hardware identifiers, game build and the evidence found. Reports stay on the operator's server until an administrator deletes them. See the <a href="privacy.php">Privacy Policy</a> for the full list.</p></div>
        </details>

        <details>
            <summary>Can a report be faked or edited?</summary>
            <div class="inner"><p>Reports are HMAC-SHA256 signed. When the server enforces signatures, a report whose contents were changed after signing is rejected. The dashboard also never trusts client-side claims for server-side behaviour.</p></div>
        </details>

        <details>
            <summary>Who can see my report?</summary>
            <div class="inner"><p>Admins with the access token, anyone holding a single-report share link you choose to give out, or requests from localhost on the host machine. The recent-scans list and comparison view are admin-only.</p></div>
        </details>

        <details>
            <summary>Is there a way to prove I am clean?</summary>
            <div class="inner"><p>Yes. Run a scan and share the resulting report link with the admin. A clean verdict with no confirmed detections is exactly the proof the system is designed to provide.</p></div>
        </details>

        <details>
            <summary>I found a false positive — what should I do?</summary>
            <div class="inner"><p>Send the report link to support with a note. Legitimate programs are folded into the client profiles or classified as clean in the corpus, which fixes the false positive for every future scan.</p></div>
        </details>
    </section>

    <section class="panel faq-section faq-cta">
        <h2>Still need help?</h2>
        <p>Open the dashboard to view a report, or reach the LongHorn team directly.</p>
        <div class="faq-cta-actions">
            <a class="lh-brand-btn" href="index.php"><span class="lh-brand-text">Open Dashboard</span></a>
            <a class="lh-brand-btn" href="mailto:support@cslonghorn.com"><span class="lh-brand-text">Contact Support</span></a>
            <a class="lh-brand-btn" href="https://www.cslonghorn.com" target="_blank" rel="noopener noreferrer"><span class="lh-brand-text">cslonghorn.com</span></a>
        </div>
    </section>

</main>
<?php uds_theme_footbar(); ?>
</body>
</html>

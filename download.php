<?php
declare(strict_types=1);

require __DIR__ . '/config.php';
require __DIR__ . '/theme_bar.php';
require __DIR__ . '/nav.php';

// Auto-sync app artwork into web-accessible images directory if present
$copyMap = [
    __DIR__ . '/windows/Assets/acs-hero.png' => __DIR__ . '/images/acs-hero.png',
    __DIR__ . '/windows/Assets/acs-logo.png' => __DIR__ . '/images/acs-logo.png',
];
foreach ($copyMap as $src => $dst) {
    if (file_exists($src) && (!file_exists($dst) || filesize($dst) === 0)) {
        @copy($src, $dst);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Handle Download Action
// ─────────────────────────────────────────────────────────────────────────────
// The app ships as one self-contained executable - no archive, no Assets folder, no settings.
$exePath = __DIR__ . '/windows/release/ACPScanner.exe';   // `dotnet publish` writes here
$targetFile = file_exists($exePath) ? $exePath : null;

$action = (string) ($_GET['action'] ?? '');

// Direct file download endpoint
if ($action === 'download' || $action === 'file') {
    if ($targetFile && file_exists($targetFile)) {
        $downloadName = 'ACS-Scanner-' . acs_release_version() . '-windows.exe';
        $mime = 'application/octet-stream';

        header('Content-Description: File Transfer');
        header('Content-Type: ' . $mime);
        header('Content-Disposition: attachment; filename="' . $downloadName . '"');
        header('Content-Transfer-Encoding: binary');
        header('Expires: 0');
        header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
        header('Pragma: public');
        header('Content-Length: ' . (string) filesize($targetFile));
        readfile($targetFile);
        exit;
    } else {
        http_response_code(404);
        echo 'Target release package not found on server.';
        exit;
    }
}

// Release package metadata for display
$primarySha256 = $targetFile !== null ? acs_release_hash($targetFile, 'sha256') : '';
$displaySha256 = $primarySha256;
$displayMd5 = $targetFile !== null ? acs_release_hash($targetFile, 'md5') : '';
$displaySize = $targetFile !== null ? round(filesize($targetFile) / (1024 * 1024), 1) . ' MB' : 'unavailable';
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Download ACS Desktop Scanner v<?= htmlspecialchars(acs_release_version(), ENT_QUOTES) ?> — Official Forensic Suite for Counter-Strike 1.6</title>
    <meta name="description" content="ACS Desktop Scanner v<?= htmlspecialchars(acs_release_version(), ENT_QUOTES) ?> — a free cheat scanner for Counter-Strike 1.6. Reads-only, safe, no install. Ask suspicious players to run a scan and verify their report on our website.">
    <link rel="stylesheet" href="assets/theme.css">
    <?php uds_theme_head(); ?>
    <link rel="stylesheet" href="assets/acp.css?v=<?= filemtime(__DIR__ . '/assets/acp.css') ?>">
    <link rel="stylesheet" href="assets/theme-switch.css?v=<?= filemtime(__DIR__ . '/assets/theme-switch.css') ?>">
    <style>
        /* ════════════════════════════════════════════════════════════════════════════
           ACS DESKTOP v1.0 — REFINED BROADCAST & FORENSIC SUITE
           ════════════════════════════════════════════════════════════════════════════ */

        /* Hero Container */
        .dl-hero {
            position: relative;
            padding: var(--sp-6) var(--sp-5);
            background: linear-gradient(135deg, rgba(11, 17, 32, 0.97) 0%, rgba(7, 10, 18, 0.99) 100%), var(--surface);
            border: 1px solid var(--line-strong);
            border-radius: var(--r);
            box-shadow: 0 16px 50px rgba(0, 0, 0, 0.7), 0 0 30px rgba(0, 229, 255, 0.08);
            margin-bottom: var(--sp-6);
            overflow: hidden;
        }

        .dl-hero::before {
            content: "";
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 2px;
            background: linear-gradient(90deg, #f0ad3a 0%, #5ad6ff 50%, #e24b3c 85%, transparent);
            box-shadow: 0 0 12px rgba(90, 214, 255, 0.4);
        }

        .dl-hero-grid {
            display: grid;
            grid-template-columns: 1.25fr 1fr;
            gap: var(--sp-6);
            align-items: center;
        }

        @media (max-width: 980px) {
            .dl-hero-grid { grid-template-columns: 1fr; gap: var(--sp-5); }
        }

        .dl-hero h1 {
            font-family: var(--f-display);
            font-size: 38px;
            font-weight: 700;
            line-height: 1.15;
            letter-spacing: 0.8px;
            margin: 0 0 var(--sp-3);
            color: var(--text);
            text-transform: uppercase;
        }

        .dl-hero h1 em {
            font-style: normal;
            color: #f0ad3a;
            text-shadow: 0 0 16px rgba(240, 173, 58, 0.4);
        }

        .dl-hero-sub {
            font-family: var(--f-mono);
            font-size: 11px;
            letter-spacing: 3px;
            text-transform: uppercase;
            color: var(--muted);
            margin: -6px 0 var(--sp-3);
            opacity: 0.85;
            animation: subHint 4s ease-in-out infinite;
        }

        @keyframes subHint {
            0%, 100% { opacity: 0.55; }
            50% { opacity: 0.95; text-shadow: 0 0 8px rgba(90, 214, 255, 0.25); }
        }

        .sim-example-watermark {
            position: absolute;
            inset: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            pointer-events: none;
            z-index: 5;
            overflow: hidden;
        }

        .sim-example-watermark span {
            font-family: var(--f-display);
            font-size: clamp(48px, 9vw, 110px);
            font-weight: 800;
            letter-spacing: 14px;
            text-transform: uppercase;
            color: rgba(255, 255, 255, 0.045);
            border: 4px solid rgba(255, 255, 255, 0.045);
            border-radius: 10px;
            padding: 8px 34px;
            transform: rotate(-14deg);
            user-select: none;
            white-space: nowrap;
        }

        .dl-hero-lead {
            font-size: 15px;
            line-height: 1.65;
            color: var(--text-2);
            margin-bottom: var(--sp-5);
            max-width: 660px;
        }

        .dl-hero-lead code {
            font-family: var(--f-mono);
            color: #5ad6ff;
            background: rgba(90, 214, 255, 0.08);
            padding: 2px 6px;
            border-radius: 3px;
            border: 1px solid rgba(90, 214, 255, 0.2);
        }

        .dl-action-row {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 16px;
            margin-bottom: var(--sp-4);
        }

        /* -----------------------------------------------------------------
           TACTICAL FORENSIC DOWNLOAD BUTTON & HERO MATRIX (NON-GENERIC AI)
           ----------------------------------------------------------------- */
        .dl-badge-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 5px 12px;
            background: rgba(240, 173, 58, 0.08);
            border: 1px solid rgba(240, 173, 58, 0.25);
            border-radius: 3px;
            font-family: var(--f-mono);
            font-size: 11px;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            color: #ffc966;
            margin-bottom: var(--sp-3);
        }

        .dl-badge-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: #4fd08c;
            box-shadow: 0 0 8px #4fd08c;
            animation: pulseGreen 2s ease-in-out infinite;
        }

        @keyframes pulseGreen {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.5; transform: scale(0.85); }
        }

        .dl-badge-sep {
            color: rgba(255, 255, 255, 0.2);
        }

        .dl-badge-channel {
            color: #5ad6ff;
            font-weight: 600;
        }

        /* Tactical Master Download Button */
        .dl-tactical-download {
            display: inline-flex;
            align-items: stretch;
            background: #080c12;
            border: 1px solid #f0ad3a;
            border-radius: 4px;
            text-decoration: none;
            cursor: pointer;
            position: relative;
            overflow: hidden;
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.6), 0 0 18px rgba(240, 173, 58, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.15);
            transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
            user-select: none;
        }

        .dl-tactical-download::before {
            content: "";
            position: absolute;
            inset: 0;
            background: linear-gradient(135deg, rgba(240, 173, 58, 0.14) 0%, transparent 60%);
            pointer-events: none;
            transition: opacity 0.25s;
        }

        .dl-tactical-download::after {
            content: "";
            position: absolute;
            top: 0; left: -100%; width: 60%; height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 201, 102, 0.25), transparent);
            transform: skewX(-25deg);
            transition: none;
        }

        .dl-tactical-download:hover::after {
            left: 140%;
            transition: left 0.75s ease-in-out;
        }

        .dl-tactical-download:hover {
            border-color: #ffc966;
            transform: translateY(-2px);
            box-shadow: 0 14px 40px rgba(0, 0, 0, 0.7), 0 0 28px rgba(240, 173, 58, 0.45), inset 0 1px 0 rgba(255, 255, 255, 0.3);
        }

        .dl-tactical-download:active {
            transform: translateY(0);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.8), 0 0 12px rgba(240, 173, 58, 0.3);
        }

        /* Left Icon Block */
        .dl-btn-icon-block {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 0 18px;
            background: linear-gradient(180deg, #f0ad3a 0%, #c48318 100%);
            color: #07090d;
            border-right: 1px solid rgba(0, 0, 0, 0.25);
            transition: background 0.2s;
        }

        .dl-tactical-download:hover .dl-btn-icon-block {
            background: linear-gradient(180deg, #ffbe4d 0%, #db951f 100%);
        }

        .dl-btn-svg {
            width: 22px;
            height: 22px;
            stroke-width: 2.4;
            transition: transform 0.25s cubic-bezier(0.34, 1.56, 0.64, 1);
        }

        .dl-tactical-download:hover .dl-btn-svg {
            transform: translateY(2px);
        }

        /* Center Command Bay */
        .dl-btn-text-block {
            display: flex;
            flex-direction: column;
            justify-content: center;
            padding: 13px 22px 13px 18px;
            text-align: left;
        }

        .dl-btn-title {
            font-family: var(--f-display);
            font-size: 17px;
            font-weight: 700;
            letter-spacing: 1.2px;
            text-transform: uppercase;
            color: #ece8e0;
            line-height: 1.15;
            transition: color 0.2s;
        }

        .dl-tactical-download:hover .dl-btn-title {
            color: #ffc966;
            text-shadow: 0 0 10px rgba(240, 173, 58, 0.3);
        }

        .dl-btn-subtitle {
            font-family: var(--f-mono);
            font-size: 10.5px;
            letter-spacing: 0.8px;
            color: #7b8896;
            margin-top: 3px;
            text-transform: uppercase;
        }

        /* Right Telemetry Badge */
        .dl-btn-badge-block {
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: flex-end;
            padding: 10px 18px;
            background: rgba(255, 255, 255, 0.025);
            border-left: 1px solid rgba(255, 255, 255, 0.08);
            font-family: var(--f-mono);
        }

        .dl-badge-version {
            font-size: 12px;
            font-weight: 700;
            color: #5ad6ff;
            letter-spacing: 0.5px;
        }

        .dl-badge-size {
            font-size: 10px;
            color: #94a2b0;
            margin-top: 3px;
            letter-spacing: 0.3px;
        }

        /* Responsive tactical download button */
        @media (max-width: 580px) {
            .dl-tactical-download {
                width: 100%;
                flex-wrap: wrap;
            }
            .dl-btn-badge-block {
                width: 100%;
                flex-direction: row;
                justify-content: space-between;
                align-items: center;
                border-left: none;
                border-top: 1px solid rgba(255, 255, 255, 0.08);
                padding: 6px 14px;
            }
        }

        /* Tactical Specs Matrix */
        .dl-hero-specs-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 10px;
            margin-top: var(--sp-4);
            max-width: 680px;
        }

        .dl-spec-card {
            display: flex;
            align-items: center;
            gap: 10px;
            background: rgba(12, 17, 24, 0.7);
            border: 1px solid #1c2633;
            border-radius: 4px;
            padding: 9px 12px;
            box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);
            transition: border-color 0.2s;
        }

        .dl-spec-card:hover {
            border-color: rgba(90, 214, 255, 0.35);
        }

        .dl-spec-icon {
            width: 26px;
            height: 26px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #f0ad3a;
            flex-shrink: 0;
        }

        .dl-spec-icon svg {
            width: 16px;
            height: 16px;
        }

        .dl-spec-content {
            display: flex;
            flex-direction: column;
            line-height: 1.2;
        }

        .dl-spec-label {
            font-family: var(--f-mono);
            font-size: 9.5px;
            letter-spacing: 1px;
            color: #606c7a;
            text-transform: uppercase;
            margin-bottom: 2px;
        }

        .dl-spec-value {
            font-family: var(--f-ui);
            font-size: 12px;
            font-weight: 600;
            color: #d1d8e0;
            white-space: nowrap;
        }



        /* ----------------------- 1:1 REALISTIC APP SIMULATOR ----------------------- */
        .app-window-frame {
            width: 100%;
            background: #07090d;
            border: 1px solid #2c3744;
            border-radius: 4px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.85), 0 0 30px rgba(0, 0, 0, 0.5);
            position: relative;
            overflow: hidden;
            user-select: none;
        }

        .app-window-frame::after {
            content: "";
            position: absolute;
            bottom: 0; left: 0; right: 0;
            height: 2px;
            background: linear-gradient(90deg, transparent 5%, #e24b3c 50%, transparent 95%);
            box-shadow: 0 0 10px #e24b3c;
        }

        /* App Title Bar */
        .app-titlebar {
            height: 38px;
            background: rgba(7, 9, 13, 0.95);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 14px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }

        .app-title-left {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .app-brand-soldier {
            width: 16px;
            height: 16px;
            color: #f0ad3a;
            flex: none;
        }

        .app-title-text {
            font-family: var(--f-display);
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 1.2px;
            color: #ece8e0;
            text-transform: uppercase;
        }

        .app-title-text em {
            font-style: normal;
            color: #f0ad3a;
            margin-right: 4px;
        }

        .app-title-pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 3px 10px;
            border-radius: 12px;
            border: 1px solid #f0ad3a;
            background: rgba(240, 173, 58, 0.06);
            font-family: var(--f-mono);
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.8px;
            color: #f0ad3a;
            text-transform: uppercase;
        }

        .app-title-pill.scanning { border-color: #5ad6ff; color: #5ad6ff; background: rgba(90, 214, 255, 0.08); }
        .app-title-pill.clean { border-color: #4fd08c; color: #4fd08c; background: rgba(79, 208, 140, 0.08); }
        .app-title-pill.detected { border-color: #e24b3c; color: #e24b3c; background: rgba(226, 75, 60, 0.08); }

        .app-title-pill .pill-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: currentColor;
            box-shadow: 0 0 6px currentColor;
        }

        .app-window-controls {
            display: flex;
            align-items: center;
            gap: 12px;
            color: #606c7a;
            font-size: 12px;
        }

        /* App Body Layout */
        .app-main-body {
            display: grid;
            grid-template-columns: 1.15fr 1fr;
            min-height: 440px;
            position: relative;
            background: #07090d;
        }

        @media (max-width: 820px) {
            .app-main-body { grid-template-columns: 1fr; }
        }

        .app-left-panel {
            padding: 24px 22px 16px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            position: relative;
            z-index: 2;
        }

        .app-eyebrow {
            font-family: var(--f-display);
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 1.5px;
            color: #f0ad3a;
            text-transform: uppercase;
            margin-bottom: 2px;
        }

        .app-verdict-large {
            font-family: 'Bahnschrift', var(--f-display);
            font-size: 42px;
            font-weight: 700;
            line-height: 1;
            letter-spacing: 1px;
            color: #ffc966;
            text-transform: uppercase;
            margin-bottom: 6px;
            transition: color 0.3s ease;
        }

        .app-verdict-note {
            font-family: var(--f-mono);
            font-size: 10.5px;
            letter-spacing: 0.6px;
            color: #94a2b0;
            text-transform: uppercase;
            margin-bottom: 22px;
            min-height: 16px;
        }

        /* Metric Counters */
        .app-stats-row {
            display: flex;
            gap: 28px;
            margin-bottom: 24px;
        }

        .app-stat-col {
            display: flex;
            flex-direction: column;
        }

        .app-stat-number {
            font-family: 'Bahnschrift', var(--f-display);
            font-size: 26px;
            font-weight: 700;
            line-height: 1;
            color: #ece8e0;
            margin-bottom: 4px;
        }

        .app-stat-label {
            font-family: var(--f-display);
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 1.2px;
            color: #606c7a;
            text-transform: uppercase;
        }

        /* State Line */
        .app-state-box {
            margin-bottom: 22px;
        }

        .app-state-title {
            font-family: var(--f-display);
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 1.2px;
            color: #f0ad3a;
            text-transform: uppercase;
            margin-bottom: 6px;
        }

        .app-state-divider {
            width: 100%;
            height: 1px;
            background: rgba(255, 255, 255, 0.1);
            margin-bottom: 8px;
        }

        .app-status-log {
            font-family: var(--f-mono);
            font-size: 12px;
            color: #94a2b0;
            min-height: 18px;
        }

        /* App Action Buttons */
        .app-buttons-row {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 20px;
        }

        .app-btn-start {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 18px;
            background: linear-gradient(180deg, rgba(240, 173, 58, 0.22) 0%, rgba(240, 173, 58, 0.08) 100%);
            border: 1px solid #f0ad3a;
            border-radius: 4px;
            color: #ffc966;
            font-family: var(--f-display);
            font-size: 13px;
            font-weight: 700;
            letter-spacing: 1.2px;
            text-transform: uppercase;
            cursor: pointer;
            position: relative;
            overflow: hidden;
            transition: all 0.2s ease;
        }

        .app-btn-start:hover {
            background: linear-gradient(180deg, rgba(240, 173, 58, 0.35) 0%, rgba(240, 173, 58, 0.16) 100%);
            box-shadow: 0 0 16px rgba(240, 173, 58, 0.4);
            color: #ffffff;
        }

        .app-btn-cancel {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 10px 16px;
            background: rgba(16, 20, 28, 0.6);
            border: 1px solid #2c3744;
            border-radius: 4px;
            color: #606c7a;
            font-family: var(--f-display);
            font-size: 13px;
            font-weight: 700;
            letter-spacing: 1.2px;
            text-transform: uppercase;
            cursor: not-allowed;
            transition: all 0.2s;
        }

        .app-btn-cancel.is-active {
            color: #ece8e0;
            border-color: #e24b3c;
            cursor: pointer;
        }

        .app-btn-cancel.is-active:hover {
            background: rgba(226, 75, 60, 0.15);
        }

        .app-btn-evidence {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 10px 16px;
            background: rgba(16, 20, 28, 0.6);
            border: 1px solid #2c4766;
            border-radius: 4px;
            color: #5ad6ff;
            font-family: var(--f-display);
            font-size: 13px;
            font-weight: 700;
            letter-spacing: 1.2px;
            text-transform: uppercase;
            cursor: pointer;
            transition: all 0.2s;
        }

        .app-btn-evidence:hover {
            border-color: #5ad6ff;
            box-shadow: 0 0 14px rgba(90, 214, 255, 0.35);
        }

        /* App Footer Notice */
        .app-footer-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 11px;
            color: #606c7a;
            font-family: var(--f-mono);
            padding-top: 10px;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
        }

        .app-powered-pill {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            font-size: 10px;
            color: #94a2b0;
        }

        .app-lh-tag {
            background: #8e1f18;
            color: #ffffff;
            padding: 1px 6px;
            border-radius: 3px;
            font-weight: 800;
            letter-spacing: 0.6px;
        }

        /* Right Panel: CS Hero Artwork & Reticle */
        .app-right-panel {
            position: relative;
            background-color: #05070a;
            background-image: url('images/acs-hero.png'), url('images/acs-app-screenshot.jpg');
            background-size: cover;
            background-position: right center;
            background-repeat: no-repeat;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
        }

        .app-right-scrim {
            position: absolute;
            inset: 0;
            background: linear-gradient(90deg, #07090d 0%, rgba(7, 9, 13, 0.6) 30%, transparent 80%);
            pointer-events: none;
        }

        /* Radar Reticle */
        .app-reticle-wrap {
            position: relative;
            width: 220px;
            height: 220px;
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 2;
        }

        .reticle-corner {
            position: absolute;
            width: 14px;
            height: 14px;
            border: 2px solid #f0ad3a;
            pointer-events: none;
        }

        .reticle-corner.tl { top: 0; left: 0; border-right: 0; border-bottom: 0; }
        .reticle-corner.tr { top: 0; right: 0; border-left: 0; border-bottom: 0; }
        .reticle-corner.bl { bottom: 0; left: 0; border-right: 0; border-top: 0; }
        .reticle-corner.br { bottom: 0; right: 0; border-left: 0; border-top: 0; }

        .reticle-ring-outer {
            position: absolute;
            width: 180px;
            height: 180px;
            border-radius: 50%;
            border: 1px dashed #f0ad3a;
            opacity: 0.6;
            animation: reticleSpin 12s linear infinite;
        }

        .reticle-ring-outer.scanning {
            border-color: #5ad6ff;
            animation-duration: 3s;
            opacity: 0.9;
        }

        @keyframes reticleSpin {
            100% { transform: rotate(360deg); }
        }

        .reticle-ring-inner {
            position: absolute;
            width: 140px;
            height: 140px;
            border-radius: 50%;
            border: 2px solid rgba(240, 173, 58, 0.4);
        }

        .reticle-center-badge {
            position: relative;
            z-index: 3;
            text-align: center;
        }

        .reticle-state {
            font-family: 'Bahnschrift', var(--f-display);
            font-size: 24px;
            font-weight: 700;
            letter-spacing: 1px;
            color: #f0ad3a;
            text-transform: uppercase;
        }

        .reticle-sub {
            font-family: var(--f-mono);
            font-size: 9.5px;
            letter-spacing: 1.5px;
            color: #94a2b0;
            text-transform: uppercase;
            margin-top: 2px;
        }

        /* Simulator Test Bench Controls */
        .sim-testbench-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 10px;
            background: var(--surface);
            border: 1px solid var(--line);
            border-radius: 6px;
            padding: 12px 18px;
            margin-bottom: var(--sp-6);
        }

        .sim-testbench-bar span {
            font-family: var(--f-mono);
            font-size: 11.5px;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }

        .sim-testbench-btns {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        .sim-test-btn {
            background: var(--surface-2);
            border: 1px solid var(--line);
            color: var(--text-2);
            padding: 6px 14px;
            border-radius: 4px;
            font-family: var(--f-display);
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.6px;
            text-transform: uppercase;
            cursor: pointer;
            transition: all 0.2s;
        }

        .sim-test-btn:hover { color: var(--text); border-color: var(--accent); }
        .sim-test-btn.clean { border-color: rgba(79, 208, 140, 0.4); color: #4fd08c; }
        .sim-test-btn.clean:hover { background: rgba(79, 208, 140, 0.1); border-color: #4fd08c; }
        .sim-test-btn.warning { border-color: rgba(240, 166, 58, 0.4); color: #f0a63a; }
        .sim-test-btn.warning:hover { background: rgba(240, 166, 58, 0.1); border-color: #f0a63a; }
        .sim-test-btn.detected { border-color: rgba(226, 75, 60, 0.4); color: #e24b3c; }
        .sim-test-btn.detected:hover { background: rgba(226, 75, 60, 0.1); border-color: #e24b3c; }

        /* Evidence Drawer Modal (Authentic in-app log viewer) */
        .evidence-modal-backdrop {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(4, 6, 11, 0.85);
            backdrop-filter: blur(8px);
            z-index: 99999;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .evidence-modal-backdrop.is-active { display: flex; }

        .evidence-modal-box {
            width: min(840px, 96vw);
            max-height: 85vh;
            background: #07090d;
            border: 1px solid #2c3744;
            border-radius: 6px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.9);
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        .evidence-modal-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 14px 20px;
            background: #0c1017;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        }

        .evidence-modal-title {
            font-family: var(--f-display);
            font-size: 14px;
            font-weight: 700;
            letter-spacing: 1px;
            color: #5ad6ff;
            text-transform: uppercase;
        }

        .evidence-modal-close {
            background: none;
            border: 1px solid #2c3744;
            color: #94a2b0;
            width: 28px;
            height: 28px;
            border-radius: 4px;
            cursor: pointer;
        }

        .evidence-modal-body {
            padding: 20px;
            overflow-y: auto;
            font-family: var(--f-mono);
            font-size: 12px;
            line-height: 1.6;
            color: #ece8e0;
            background: #040508;
        }

        /* ----------------------- REAL ARCHITECTURAL CODE TABS ----------------------- */
        .code-showcase-box {
            background: #06090e;
            border: 1px solid var(--line-strong);
            border-radius: 8px;
            padding: 22px;
            margin-bottom: var(--sp-6);
        }

        .code-tab-nav {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--line);
        }

        .code-tab-btn {
            background: var(--surface-2);
            border: 1px solid var(--line);
            color: var(--muted);
            padding: 6px 14px;
            border-radius: 4px;
            font-family: var(--f-mono);
            font-size: 11px;
            cursor: pointer;
            transition: all 0.2s;
        }

        .code-tab-btn.is-active {
            background: rgba(90, 214, 255, 0.12);
            border-color: #5ad6ff;
            color: #5ad6ff;
            font-weight: 700;
        }

        .code-tab-view { display: none; }
        .code-tab-view.is-active { display: block; }

        .code-real-pre {
            margin: 0;
            padding: 16px;
            background: #030407;
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 6px;
            font-family: var(--f-mono);
            font-size: 12px;
            line-height: 1.65;
            color: #d1d5db;
            overflow-x: auto;
        }

        .code-hl-kw { color: #ff7b72; font-weight: 600; }
        .code-hl-type { color: #79c0ff; }
        .code-hl-str { color: #a5d6ff; }
        .code-hl-fn { color: #d2a8ff; }
        .code-hl-com { color: #6b7280; font-style: italic; }
        .code-hl-num { color: #f2cc60; }

        /* ----------------------- VERDICTS & STATUS CARDS ----------------------- */
        .verdict-tri-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: var(--sp-4);
            margin-bottom: var(--sp-6);
        }

        @media (max-width: 1040px) {
            .verdict-tri-grid { grid-template-columns: 1fr; }
        }

        .v-card {
            background: var(--surface);
            border: 1px solid var(--line);
            border-radius: 6px;
            padding: 20px;
            display: flex;
            flex-direction: column;
        }

        .v-card.clean { border-color: rgba(79, 208, 140, 0.4); }
        .v-card.warning { border-color: rgba(240, 166, 58, 0.4); }
        .v-card.detected { border-color: rgba(226, 75, 60, 0.4); }

        .v-badge-pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 10px;
            border-radius: 4px;
            font-family: var(--f-display);
            font-size: 13px;
            font-weight: 700;
            letter-spacing: 0.8px;
            text-transform: uppercase;
            margin-bottom: 12px;
        }

        .v-badge-pill.clean { background: rgba(79, 208, 140, 0.12); color: #4fd08c; border: 1px solid #4fd08c; }
        .v-badge-pill.warning { background: rgba(240, 166, 58, 0.12); color: #f0a63a; border: 1px solid #f0a63a; }
        .v-badge-pill.detected { background: rgba(226, 75, 60, 0.12); color: #e24b3c; border: 1px solid #e24b3c; }

        .v-card h3 {
            font-family: var(--f-display);
            font-size: 18px;
            margin: 0 0 6px;
            color: var(--text);
            text-transform: uppercase;
        }

        .v-card p {
            font-size: 13px;
            color: var(--text-2);
            line-height: 1.55;
            margin: 0 0 14px;
            flex: 1;
        }

        .v-mock-box {
            background: #04060a;
            border: 1px solid var(--line-soft);
            border-radius: 4px;
            padding: 10px 12px;
            font-family: var(--f-mono);
            font-size: 11px;
        }

        .v-mock-row {
            display: flex;
            justify-content: space-between;
            padding: 3px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
        }

        .v-mock-row:last-child { border-bottom: none; }
    </style>
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

<?php acp_site_nav('download', 'download.php', true); ?>

<main class="wrap">

    <!-- ═══════════════════════════════════════════════════════════════════════
         1. HERO SECTION & APPLICATION DOWNLOAD ACTION
         ═══════════════════════════════════════════════════════════════════════ -->
    <section class="dl-hero">
        <div class="dl-hero-grid">
            <div>
                <div class="dl-badge-pill">
                    <span class="dl-badge-dot"></span>
                    <span>OFFICIAL GOLDSRC FORENSIC SUITE</span>
                    <span class="dl-badge-sep">/</span>
                    <span class="dl-badge-channel">v<?= htmlspecialchars(acs_release_version(), ENT_QUOTES) ?> STABLE</span>
                </div>
                <h1>ACS Desktop Scanner <em>v<?= htmlspecialchars(acs_release_version(), ENT_QUOTES) ?></em></h1>
                <div class="dl-hero-sub">Counter-Strike 1.6 Anti-Cheat Forensic Suite</div>
                <p class="dl-hero-lead">
                    A lightweight forensic cheat scanner engineered specifically for Counter-Strike 1.6. It performs non-invasive memory and filesystem verification to detect unauthorized hooks, injected DLLs, and aim/trigger/ESP modifications in real time. It operates <em>read-only</em> during live gameplay — zero driver requirements, zero system modifications, and zero game alteration. Reports are cryptographically signed with HMAC-SHA256 and verified instantly via web telemetry.
                </p>

                <div class="dl-action-row">
                    <a href="download.php?action=download" class="dl-tactical-download" id="btnStartDownload">
                        <div class="dl-btn-icon-block">
                            <svg class="dl-btn-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="square" stroke-linejoin="miter">
                                <path d="M12 3v13m0 0l-5-5m5 5l5-5"/>
                                <path d="M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2"/>
                            </svg>
                        </div>
                        <div class="dl-btn-text-block">
                            <span class="dl-btn-title">DOWNLOAD ACS SCANNER</span>
                            <span class="dl-btn-subtitle">OFFICIAL STANDALONE CLIENT · NO SETUP REQUIRED</span>
                        </div>
                        <div class="dl-btn-badge-block">
                            <span class="dl-badge-version">v<?= htmlspecialchars(acs_release_version(), ENT_QUOTES) ?></span>
                            <span class="dl-badge-size"><?= htmlspecialchars($displaySize, ENT_QUOTES) ?></span>
                        </div>
                    </a>
                </div>

                <div class="dl-hero-specs-grid">
                    <div class="dl-spec-card">
                        <div class="dl-spec-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/></svg>
                        </div>
                        <div class="dl-spec-content">
                            <span class="dl-spec-label">PLATFORM</span>
                            <span class="dl-spec-value">Windows 10 / 11 (x86 &amp; x64)</span>
                        </div>
                    </div>
                    <div class="dl-spec-card">
                        <div class="dl-spec-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
                        </div>
                        <div class="dl-spec-content">
                            <span class="dl-spec-label">DEPLOYMENT</span>
                            <span class="dl-spec-value">Portable EXE · <?= htmlspecialchars($displaySize, ENT_QUOTES) ?></span>
                        </div>
                    </div>
                    <div class="dl-spec-card">
                        <div class="dl-spec-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                        </div>
                        <div class="dl-spec-content">
                            <span class="dl-spec-label">INTEGRITY &amp; SAFETY</span>
                            <span class="dl-spec-value">Read-Only · Zero Driver</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Authentic Screenshot / App Interface Preview -->
            <div style="position: relative;">
                <div class="app-window-frame">
                    <div class="app-titlebar">
                        <div class="app-title-left">
                            <svg class="app-brand-soldier" viewBox="0 0 24 24" fill="currentColor">
                                <path d="M12 2a3 3 0 1 0 0 6 3 3 0 0 0 0-6zm-4 8c-1.1 0-2 .9-2 2v6h2v4h4v-4h2v-6c0-1.1-.9-2-2-2H8z"/>
                            </svg>
                            <span class="app-title-text"><em>ACS</em> Anti-Cheat Scanner</span>
                        </div>
                        <div class="app-title-pill">
                            <span class="pill-dot"></span>
                            <span>STANDBY</span>
                        </div>
                        <div class="app-window-controls">
                            <span>_</span>
                            <span>✕</span>
                        </div>
                    </div>
                    <img src="images/acs-app-screenshot.jpg" alt="ACS Desktop Scanner Interface" style="width: 100%; display: block;" onerror="this.onerror=null; this.src='images/appUI.png';">
                </div>
            </div>
        </div>
    </section>

    <!-- ═══════════════════════════════════════════════════════════════════════
         2. INTERACTIVE 1:1 DESKTOP APP SIMULATOR (MATCHING SCREENSHOT)
         ═══════════════════════════════════════════════════════════════════════ -->
    <div style="margin-bottom: var(--sp-3);">
        <span style="font-family: var(--f-mono); font-size: 11px; letter-spacing: 1.5px; color: #f0ad3a; text-transform: uppercase; font-weight: 700;">Diagnostic Console Simulation</span>
        <h2 style="font-family: var(--f-display); font-size: 26px; font-weight: 700; text-transform: uppercase; margin: 4px 0 6px; color: var(--text);">
            ACS Desktop App v<?= htmlspecialchars(acs_release_version(), ENT_QUOTES) ?> — Live Interactive Terminal
        </h2>
        <p style="color: var(--muted); font-size: 14px; margin: 0 0 var(--sp-4);">
            Experience the internal diagnostics and HUD telemetry of the Windows client. Run real-time simulation sequences to evaluate clean match scans, offline configuration warnings, or active memory detours.
        </p>
    </div>

    <!-- Simulator Test Bench Bar -->
    <div class="sim-testbench-bar">
        <span>Test Diagnostics Engine:</span>
        <div class="sim-testbench-btns">
            <button type="button" class="sim-test-btn clean" id="simActionClean">▶ Simulate Clean Match Scan</button>
            <button type="button" class="sim-test-btn warning" id="simActionWarn">⚠ Simulate Warning State</button>
            <button type="button" class="sim-test-btn detected" id="simActionCheat">✖ Simulate Cheat Hook Detected</button>
            <button type="button" class="sim-test-btn" id="simActionReset">↺ Reset Standby</button>
        </div>
    </div>

    <!-- The 1:1 Replicated Desktop App Window -->
    <div class="app-window-frame" style="margin-bottom: var(--sp-6);">
        <!-- Title bar -->
        <div class="app-titlebar">
            <div class="app-title-left">
                <svg class="app-brand-soldier" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 2a3 3 0 1 0 0 6 3 3 0 0 0 0-6zm-4 8c-1.1 0-2 .9-2 2v6h2v4h4v-4h2v-6c0-1.1-.9-2-2-2H8z"/>
                </svg>
                <div class="app-title-text">
                    <em>ACS</em> ANTI-CHEAT SCANNER &nbsp;·&nbsp; COUNTER-STRIKE 1.6
                </div>
            </div>
            <div class="app-title-pill" id="simTitlePill">
                <span class="pill-dot"></span>
                <span id="simTitlePillText">STANDBY</span>
            </div>
            <div class="app-window-controls">
                <span>_</span>
                <span>✕</span>
            </div>
        </div>

        <!-- Example Watermark (simulated demo output) -->
        <div class="sim-example-watermark" aria-hidden="true">
            <span>Example</span>
        </div>

        <!-- Main Body -->
        <div class="app-main-body">
            <!-- Left Panel -->
            <div class="app-left-panel">
                <div>
                    <div class="app-eyebrow">EVIDENCE SCANNER</div>
                    <div class="app-verdict-large" id="simVerdictLarge">READY</div>
                    <div class="app-verdict-note" id="simVerdictNote">LAUNCH COUNTER-STRIKE, THEN START THE SCAN</div>

                    <!-- 3 Stats -->
                    <div class="app-stats-row">
                        <div class="app-stat-col">
                            <div class="app-stat-number" id="simCheatsCount">0</div>
                            <div class="app-stat-label">CHEATS</div>
                        </div>
                        <div class="app-stat-col">
                            <div class="app-stat-number" id="simWarningsCount">0</div>
                            <div class="app-stat-label">WARNINGS</div>
                        </div>
                        <div class="app-stat-col">
                            <div class="app-stat-number" id="simElapsed">00:00</div>
                            <div class="app-stat-label">ELAPSED</div>
                        </div>
                    </div>

                    <!-- State Line -->
                    <div class="app-state-box">
                        <div class="app-state-title" id="simStage">IDLE</div>
                        <div class="app-state-divider"></div>
                        <div class="app-status-log" id="simStatusLog">Waiting to start</div>
                    </div>
                </div>

                <div>
                    <!-- Action Buttons -->
                    <div class="app-buttons-row">
                        <button type="button" class="app-btn-start" id="simBtnStart">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/></svg>
                            <span>START SCAN</span>
                        </button>
                        <button type="button" class="app-btn-cancel" id="simBtnCancel">
                            <span>■ CANCEL</span>
                        </button>
                        <button type="button" class="app-btn-evidence" id="simBtnEvidence">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="6" x2="20" y2="6"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="18" x2="20" y2="18"/></svg>
                            <span>VIEW EVIDENCE</span>
                        </button>
                    </div>

                    <!-- Footer -->
                    <div class="app-footer-bar">
                        <span id="simHintLine">ⓘ Counter-Strike must be running before you scan.</span>
                        <span class="app-powered-pill">Powered By <span class="app-lh-tag">LONGHORN</span></span>
                    </div>
                </div>
            </div>

            <!-- Right Panel: CS Operator Art + Iris Reticle -->
            <div class="app-right-panel">
                <div class="app-right-scrim"></div>
                <div class="app-reticle-wrap">
                    <div class="reticle-corner tl"></div>
                    <div class="reticle-corner tr"></div>
                    <div class="reticle-corner bl"></div>
                    <div class="reticle-corner br"></div>
                    <div class="reticle-ring-outer" id="simReticleOuter"></div>
                    <div class="reticle-ring-inner"></div>
                    <div class="reticle-center-badge">
                        <div class="reticle-state" id="simReticleState">STANDBY</div>
                        <div class="reticle-sub" id="simReticleSub">INTEGRITY SCAN</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- ═══════════════════════════════════════════════════════════════════════
         3. SCANNED STATUS BREAKDOWN & VERDICTS
         ═══════════════════════════════════════════════════════════════════════ -->
    <div style="margin-bottom: var(--sp-4);">
        <span style="font-family: var(--f-mono); font-size: 11px; letter-spacing: 1.5px; color: #f0ad3a; text-transform: uppercase; font-weight: 700;">Forensic Classification</span>
        <h2 style="font-family: var(--f-display); font-size: 26px; font-weight: 700; text-transform: uppercase; margin: 4px 0 6px; color: var(--text);">
            Scanned Status Breakdown
        </h2>
        <p style="color: var(--muted); font-size: 14px; margin: 0;">
            Every scan report terminates in one of three definitive verdicts based on the physical location and execution state of the evidence.
        </p>
    </div>

    <div class="verdict-tri-grid">
        <!-- 1. CLEAN -->
        <div class="v-card clean">
            <div class="v-badge-pill clean">Clean · No Cheats</div>
            <h3>Verdict: Clean</h3>
            <p>
                All mapped executable modules compare byte-identical to legitimate files on disk. Zero detached executable memory allocations, zero alias loops, and whitelisted client hash.
            </p>
            <div class="v-mock-box">
                <div class="v-mock-row"><span>hw.dll .text section:</span><strong style="color: #4fd08c;">Byte-Identical</strong></div>
                <div class="v-mock-row"><span>client.dll exports:</span><strong style="color: #4fd08c;">Zero Detours</strong></div>
                <div class="v-mock-row"><span>Script alias graph:</span><strong style="color: #4fd08c;">Legitimate Binds</strong></div>
                <div class="v-mock-row"><span>Client Distribution:</span><strong style="color: #4fd08c;">Steam Build 8684</strong></div>
            </div>
        </div>

        <!-- 2. WARNING -->
        <div class="v-card warning">
            <div class="v-badge-pill warning">Warning · Review Required</div>
            <h3>Verdict: Warning</h3>
            <p>
                No active cheat hook is executed inside the live game process, but suspicious review items exist: unclassified modules in the game folder or historical offline tool traces.
            </p>
            <div class="v-mock-box">
                <div class="v-mock-row"><span>Live Memory:</span><strong style="color: #4fd08c;">No Active Injections</strong></div>
                <div class="v-mock-row"><span>Directory Scan:</span><strong style="color: #f0a63a;">Unseen Module Hash</strong></div>
                <div class="v-mock-row"><span>Script Parsing:</span><strong style="color: #f0a63a;">Dense Alias Chain</strong></div>
                <div class="v-mock-row"><span>Operator Action:</span><strong style="color: #f0a63a;">Admin Review Queue</strong></div>
            </div>
        </div>

        <!-- 3. DETECTED -->
        <div class="v-card detected">
            <div class="v-badge-pill detected">Detected · Cheats Active</div>
            <h3>Verdict: Detected</h3>
            <p>
                High-confidence forensic proof of live tampering: inline trampoline JMP hooks inside <code>hw.dll</code> / <code>client.dll</code>, unauthorized foreign threads, or recursive jump scripts.
            </p>
            <div class="v-mock-box">
                <div class="v-mock-row"><span>Target Hook:</span><strong style="color: #e24b3c;">hw.dll!CL_CreateMove</strong></div>
                <div class="v-mock-row"><span>Disassembly:</span><strong style="color: #e24b3c;">E9 4A 12 00 00 (JMP)</strong></div>
                <div class="v-mock-row"><span>Rule Trigger:</span><strong style="color: #e24b3c;">acp-hook-cl-createmove</strong></div>
                <div class="v-mock-row"><span>Evidence Integrity:</span><strong style="color: #4fd08c;">HMAC-SHA256 Sealed</strong></div>
            </div>
        </div>
    </div>

    <!-- Official UI Status Levels Visual -->
    <div style="background: var(--surface); border: 1px solid var(--line); border-radius: 6px; padding: 20px; margin-bottom: var(--sp-6);">
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; align-items: center;">
            <figure style="margin: 0;">
                <img src="images/status-levels.png" alt="Report Verdict Status Levels" style="width: 100%; border-radius: 4px; border: 1px solid var(--line-soft);" loading="lazy">
                <figcaption style="font-size: 11.5px; color: var(--muted); margin-top: 6px; font-family: var(--f-mono);">Official Verdict Status Badges (Detected, Warning, Clean)</figcaption>
            </figure>
            <figure style="margin: 0;">
                <img src="images/status-corpus.png" alt="Artifact Corpus Classification" style="width: 100%; border-radius: 4px; border: 1px solid var(--line-soft);" loading="lazy">
                <figcaption style="font-size: 11.5px; color: var(--muted); margin-top: 6px; font-family: var(--f-mono);">Artifact Corpus Prevalence (Cheat, Unknown, Clean)</figcaption>
            </figure>
        </div>
    </div>

    <!-- ═══════════════════════════════════════════════════════════════════════
         4. REAL EDUCATIONAL ENGINE ARCHITECTURE & CODE EXPLANATION
         ═══════════════════════════════════════════════════════════════════════ -->
    <div class="code-showcase-box">
        <div style="margin-bottom: var(--sp-3);">
            <span style="font-family: var(--f-mono); font-size: 11px; letter-spacing: 1.5px; color: #5ad6ff; text-transform: uppercase; font-weight: 700;">Engineering Principles</span>
            <h3 style="font-family: var(--f-display); font-size: 22px; font-weight: 700; color: var(--text); text-transform: uppercase; margin: 4px 0;">
                Educational Engine Architecture &amp; Logic
            </h3>
            <p style="color: var(--muted); font-size: 13.5px; margin: 0;">
                Transparent architectural insights into how the C# detection engine verifies memory integrity, resolves obfuscated alias graphs, and generates tamper-evident signatures without weaponizable reverse-engineering details.
            </p>
        </div>

        <div class="code-tab-nav">
            <button type="button" class="code-tab-btn is-active" data-view="code-pe">PE Module Relocation Normalizer</button>
            <button type="button" class="code-tab-btn" data-view="code-ast">Script Alias Graph DAG Analyzer</button>
            <button type="button" class="code-tab-btn" data-view="code-probe">Cross-Process Memory Probes</button>
            <button type="button" class="code-tab-btn" data-view="code-hmac">Cryptographic HMAC-SHA256 Envelope</button>
        </div>

        <!-- Tab 1: Module Integrity & Relocations -->
        <div class="code-tab-view is-active" id="code-pe">
            <pre class="code-real-pre"><code><span class="code-hl-com">// ModuleIntegrity.cs — Relocation-Aware .text Section Comparison</span>
<span class="code-hl-kw">internal static class</span> <span class="code-hl-type">ModuleIntegrity</span>
{
    <span class="code-hl-com">// Compares live memory .text bytes against disk copy with ASLR relocations applied</span>
    <span class="code-hl-kw">internal static</span> <span class="code-hl-type">Result</span> <span class="code-hl-fn">Verify</span>(<span class="code-hl-type">IntPtr</span> hProcess, <span class="code-hl-type">string</span> diskPath, <span class="code-hl-type">IntPtr</span> loadAddress)
    {
        <span class="code-hl-kw">byte</span>[] diskBytes = <span class="code-hl-type">File</span>.<span class="code-hl-fn">ReadAllBytes</span>(diskPath);
        <span class="code-hl-kw">var</span> pe = <span class="code-hl-type">PeHeaders</span>.<span class="code-hl-fn">Parse</span>(diskBytes);
        <span class="code-hl-kw">var</span> textSection = pe.Sections.<span class="code-hl-fn">First</span>(s => s.Name == <span class="code-hl-str">".text"</span>);

        <span class="code-hl-com">// Calculate relocation delta: (Actual ImageBase - Preferred ImageBase)</span>
        <span class="code-hl-kw">long</span> delta = loadAddress.ToInt64() - pe.OptionalHeader.ImageBase;
        <span class="code-hl-kw">byte</span>[] normalizedDisk = <span class="code-hl-fn">ApplyBaseRelocations</span>(diskBytes, textSection, delta);

        <span class="code-hl-com">// Read in-memory section via Windows standard debugging API</span>
        <span class="code-hl-kw">byte</span>[] memBytes = <span class="code-hl-kw">new byte</span>[textSection.VirtualSize];
        <span class="code-hl-type">NativeMethods</span>.<span class="code-hl-fn">ReadProcessMemory</span>(hProcess, loadAddress + textSection.VirtualAddress, memBytes, memBytes.Length, <span class="code-hl-kw">out</span> _);

        <span class="code-hl-com">// Identify byte mismatches that exceed single-byte benign hotpatch thresholds</span>
        <span class="code-hl-kw">var</span> patchSites = <span class="code-hl-fn">FindDiscrepancies</span>(normalizedDisk, memBytes, minPatchBytes: <span class="code-hl-num">2</span>);
        <span class="code-hl-kw">return</span> patchSites.Count > <span class="code-hl-num">0</span> ? <span class="code-hl-type">Result</span>.<span class="code-hl-fn">Patched</span>(patchSites) : <span class="code-hl-type">Result</span>.<span class="code-hl-fn">Clean</span>();
    }
}</code></pre>
        </div>

        <!-- Tab 2: Alias Graph AST -->
        <div class="code-tab-view" id="code-ast">
            <pre class="code-real-pre"><code><span class="code-hl-com">// ConfigAnalyzer.cs — Resolved Control-Flow Script Graph Analysis</span>
<span class="code-hl-kw">internal static class</span> <span class="code-hl-type">ConfigAnalyzer</span>
{
    <span class="code-hl-com">// Scripts hide behind nested alias indirection across multiple .cfg files.</span>
    <span class="code-hl-com">// ACS resolves the full alias AST to match control-flow shapes rather than names.</span>
    <span class="code-hl-kw">internal static</span> <span class="code-hl-type">List</span>&lt;<span class="code-hl-type">Finding</span>&gt; <span class="code-hl-fn">Analyze</span>(<span class="code-hl-type">IReadOnlyDictionary</span>&lt;<span class="code-hl-type">string</span>, <span class="code-hl-type">string</span>&gt; files)
    {
        <span class="code-hl-kw">var</span> aliases = <span class="code-hl-kw">new</span> <span class="code-hl-type">Dictionary</span>&lt;<span class="code-hl-type">string</span>, <span class="code-hl-type">List</span>&lt;<span class="code-hl-type">Command</span>&gt;&gt;(<span class="code-hl-type">StringComparer</span>.OrdinalIgnoreCase);
        <span class="code-hl-kw">foreach</span> (<span class="code-hl-kw">var</span> (path, content) <span class="code-hl-kw">in</span> files)
        {
            <span class="code-hl-kw">foreach</span> (<span class="code-hl-kw">var</span> cmd <span class="code-hl-kw">in</span> <span class="code-hl-fn">Tokenize</span>(content))
                <span class="code-hl-kw">if</span> (cmd.Name == <span class="code-hl-str">"alias"</span>) aliases[cmd.<span class="code-hl-fn">Arg</span>(<span class="code-hl-num">0</span>)] = cmd.Body;
        }

        <span class="code-hl-com">// Detect wait-driven cyclic loops toggling movement tokens (+jump / -jump)</span>
        <span class="code-hl-kw">foreach</span> (<span class="code-hl-kw">var</span> loop <span class="code-hl-kw">in</span> <span class="code-hl-fn">TraverseAliasCycles</span>(aliases))
        {
            <span class="code-hl-kw">if</span> (loop.<span class="code-hl-fn">HasTokens</span>(<span class="code-hl-str">"+jump"</span>, <span class="code-hl-str">"-jump"</span>, <span class="code-hl-str">"wait"</span>))
                <span class="code-hl-kw">return new</span> <span class="code-hl-type">Finding</span>(<span class="code-hl-str">"acp-script-bunnyhop"</span>, Severity.Detected, loop.Trace);
        }
        <span class="code-hl-kw">return</span> <span class="code-hl-type">Finding</span>.Empty;
    }
}</code></pre>
        </div>

        <!-- Tab 3: Cross-Process Probes -->
        <div class="code-tab-view" id="code-probe">
            <pre class="code-real-pre"><code><span class="code-hl-com">// SystemProbe.cs — External Reader Handles & Thread Boundary Validation</span>
<span class="code-hl-kw">internal static class</span> <span class="code-hl-type">SystemProbe</span>
{
    <span class="code-hl-com">// Flags foreign processes holding write access or injected threads inside hl.exe</span>
    <span class="code-hl-kw">internal static</span> <span class="code-hl-type">ProbeResult</span> <span class="code-hl-fn">InspectHandlesAndThreads</span>(<span class="code-hl-type">int</span> hlProcessId)
    {
        <span class="code-hl-kw">var</span> moduleRanges = <span class="code-hl-fn">GetLegitimateModuleMemoryRanges</span>(hlProcessId);

        <span class="code-hl-kw">foreach</span> (<span class="code-hl-kw">var</span> thread <span class="code-hl-kw">in</span> <span class="code-hl-fn">EnumerateThreads</span>(hlProcessId))
        {
            <span class="code-hl-type">IntPtr</span> startAddress = <span class="code-hl-fn">QueryThreadStartAddress</span>(thread.Id);
            <span class="code-hl-com">// A thread entrypoint outside any loaded PE module indicates a manual-mapped injector</span>
            <span class="code-hl-kw">if</span> (!moduleRanges.<span class="code-hl-fn">Any</span>(range => range.<span class="code-hl-fn">Contains</span>(startAddress)))
            {
                <span class="code-hl-kw">return new</span> <span class="code-hl-type">ProbeResult</span>(Severity.Detected, <span class="code-hl-str">"Foreign thread detected in unbacked memory"</span>);
            }
        }
        <span class="code-hl-kw">return</span> <span class="code-hl-type">ProbeResult</span>.Clean;
    }
}</code></pre>
        </div>

        <!-- Tab 4: HMAC Envelope -->
        <div class="code-tab-view" id="code-hmac">
            <pre class="code-real-pre"><code><span class="code-hl-com">// ScanUploadResult.cs — Tamper-Evident Report Envelope Signing</span>
<span class="code-hl-kw">internal static class</span> <span class="code-hl-type">ReportSigner</span>
{
    <span class="code-hl-com">// Signs the serialized JSON report using HMAC-SHA256 with the shared API secret</span>
    <span class="code-hl-kw">internal static</span> <span class="code-hl-type">string</span> <span class="code-hl-fn">ComputeSignature</span>(<span class="code-hl-type">string</span> jsonBody, <span class="code-hl-type">string</span> secret)
    {
        <span class="code-hl-kw">using var</span> hmac = <span class="code-hl-kw">new</span> <span class="code-hl-type">HMACSHA256</span>(<span class="code-hl-type">Encoding</span>.UTF8.<span class="code-hl-fn">GetBytes</span>(secret));
        <span class="code-hl-kw">byte</span>[] hash = hmac.<span class="code-hl-fn">ComputeHash</span>(<span class="code-hl-type">Encoding</span>.UTF8.<span class="code-hl-fn">GetBytes</span>(jsonBody));
        <span class="code-hl-kw">return</span> <span class="code-hl-type">Convert</span>.<span class="code-hl-fn">ToHexString</span>(hash).<span class="code-hl-fn">ToLowerInvariant</span>();
    }
}</code></pre>
        </div>

        <div style="margin-top: 14px; padding: 10px 14px; background: rgba(90, 214, 255, 0.05); border-left: 3px solid #5ad6ff; font-size: 12px; color: var(--text-2); font-family: var(--f-ui);">
            <strong>Architectural Disclosure Boundary:</strong> The C# structures above illustrate non-weaponizable engineering concepts including ASLR relocation normalization, AST alias graph cycle reduction, thread start-address bounds validation, and cryptographic HMAC-SHA256 sealing. Proprietary signature databases, internal byte pattern tables, and private client tokens remain secure and protected.
        </div>
    </div>

    <!-- ═══════════════════════════════════════════════════════════════════════
         5. PACKAGE CHECKSUM & SYSTEM REQUIREMENTS
         ═══════════════════════════════════════════════════════════════════════ -->
    <div style="background: var(--surface); border: 1px solid var(--line); border-radius: 6px; padding: 20px; margin-bottom: var(--sp-6);">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px; margin-bottom: 14px;">
            <h3 style="margin: 0; font-family: var(--f-display); font-size: 18px; text-transform: uppercase; color: var(--text);">
                Cryptographic Checksums &amp; Verification
            </h3>
            <div style="display: flex; gap: 8px;">
                <button type="button" class="sim-test-btn" id="btnCopySha" style="font-family: var(--f-mono); font-size: 11px;">
                    Copy SHA-256
                </button>
            </div>
        </div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; font-family: var(--f-mono); font-size: 11.5px; margin-bottom: 16px;">
            <div style="background: #05070a; border: 1px solid var(--line-soft); border-radius: 4px; padding: 10px 12px;">
                <span style="color: var(--muted); display: block; margin-bottom: 2px;">FILE NAME</span>
                <span style="color: var(--text);">ACS-Scanner-<?= htmlspecialchars(acs_release_version(), ENT_QUOTES) ?>-windows.exe</span>
            </div>
            <div style="background: #05070a; border: 1px solid var(--line-soft); border-radius: 4px; padding: 10px 12px;">
                <span style="color: var(--muted); display: block; margin-bottom: 2px;">FILE SIZE</span>
                <span style="color: var(--text);"><?= htmlspecialchars($displaySize, ENT_QUOTES) ?></span>
            </div>
            <div style="background: #05070a; border: 1px solid var(--line-soft); border-radius: 4px; padding: 10px 12px;">
                <span style="color: var(--muted); display: block; margin-bottom: 2px;">MD5 CHECKSUM</span>
                <span style="color: #ffc966;"><?= htmlspecialchars($displayMd5, ENT_QUOTES) ?></span>
            </div>
            <div style="background: #05070a; border: 1px solid var(--line-soft); border-radius: 4px; padding: 10px 12px; grid-column: 1 / -1;">
                <span style="color: var(--muted); display: block; margin-bottom: 2px;">SHA-256 CRYPTOGRAPHIC CHECKSUM</span>
                <span style="color: #5ad6ff; word-break: break-all;" id="valSha256"><?= htmlspecialchars($displaySha256, ENT_QUOTES) ?></span>
            </div>
        </div>

        <div style="padding: 16px 18px; background: rgba(90, 214, 255, 0.04); border: 1px solid rgba(90, 214, 255, 0.2); border-radius: 4px; font-size: 12.5px; color: var(--text-2); font-family: var(--f-ui); line-height: 1.6;">
            <div style="display: flex; align-items: center; gap: 8px; color: #5ad6ff; font-weight: 700; text-transform: uppercase; font-size: 12px; letter-spacing: 0.8px; margin-bottom: 6px;">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                Cryptographic Binary Integrity Verification
            </div>
            <p style="margin: 0 0 10px;">
                Every official ACS release binary is verified against the cryptographic hash computed directly on this deployment server. Validate your local package integrity at any time via PowerShell:
            </p>
            <div style="font-size: 12px; color: var(--text); font-family: var(--f-mono); background: #05070a; padding: 9px 12px; border: 1px solid var(--line-soft); border-radius: 4px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px;">
                <code><span style="color: #ffc966;">Get-FileHash</span> .\ACS-Scanner-<?= htmlspecialchars(acs_release_version(), ENT_QUOTES) ?>-windows.exe <span style="color: #5ad6ff;">-Algorithm SHA256</span></code>
                <span style="color: #4fd08c; font-size: 11px; font-weight: 600;">✓ SECURE PIPELINE BUILD</span>
            </div>
        </div>
    </div>

</main>

<!-- In-App Evidence Viewer Modal (Replicating LogForm.cs) -->
<div class="evidence-modal-backdrop" id="evidenceModal">
    <div class="evidence-modal-box">
        <div class="evidence-modal-header">
            <span class="evidence-modal-title">ACS Evidence Log — In-App Forensic Diagnostics</span>
            <button type="button" class="evidence-modal-close" id="btnCloseEvidence">&times;</button>
        </div>
        <div class="evidence-modal-body" id="evidenceModalContent">
            <div style="color: #5ad6ff; margin-bottom: 8px;">[LOG] Initializing ACS Forensic Log Viewer...</div>
            <div style="color: #94a2b0;">Target: hl.exe (PID: 7428) · GoldSrc Engine 8684</div>
            <div style="color: #4fd08c; margin-top: 6px;">hw.dll .text section (Size: 0x001B4000) verified clean.</div>
            <div style="color: #4fd08c;">client.dll .text section (Size: 0x000E2000) verified clean.</div>
            <div style="color: #4fd08c;">opengl32.dll exports verified clean.</div>
            <div style="color: #94a2b0; margin-top: 6px;">Report Envelope: HMAC-SHA256 signature verified.</div>
        </div>
    </div>
</div>

<script>
(function () {
    // 1. Code Architecture Tab Switcher
    var codeButtons = document.querySelectorAll('.code-tab-btn');
    codeButtons.forEach(function (btn) {
        btn.addEventListener('click', function () {
            codeButtons.forEach(function (b) { b.classList.remove('is-active'); });
            document.querySelectorAll('.code-tab-view').forEach(function (v) { v.classList.remove('is-active'); });
            btn.classList.add('is-active');
            var viewId = btn.getAttribute('data-view');
            var targetView = document.getElementById(viewId);
            if (targetView) { targetView.classList.add('is-active'); }
        });
    });

    // 2. 1:1 Realistic Desktop App v1.0 Simulator Logic
    var simVerdictLarge = document.getElementById('simVerdictLarge');
    var simVerdictNote = document.getElementById('simVerdictNote');
    var simCheatsCount = document.getElementById('simCheatsCount');
    var simWarningsCount = document.getElementById('simWarningsCount');
    var simElapsed = document.getElementById('simElapsed');
    var simStage = document.getElementById('simStage');
    var simStatusLog = document.getElementById('simStatusLog');
    var simTitlePill = document.getElementById('simTitlePill');
    var simTitlePillText = document.getElementById('simTitlePillText');
    var simReticleOuter = document.getElementById('simReticleOuter');
    var simReticleState = document.getElementById('simReticleState');
    var simReticleSub = document.getElementById('simReticleSub');
    var simBtnStart = document.getElementById('simBtnStart');
    var simBtnCancel = document.getElementById('simBtnCancel');
    var simBtnEvidence = document.getElementById('simBtnEvidence');
    var evidenceModal = document.getElementById('evidenceModal');
    var btnCloseEvidence = document.getElementById('btnCloseEvidence');
    var evidenceContent = document.getElementById('evidenceModalContent');

    var simTimer = null;
    var clockTimer = null;
    var elapsedSec = 0;

    function formatTime(s) {
        var m = Math.floor(s / 60);
        var rem = s % 60;
        return (m < 10 ? '0' + m : m) + ':' + (rem < 10 ? '0' + rem : rem);
    }

    function resetAppToIdle() {
        if (simTimer) clearInterval(simTimer);
        if (clockTimer) clearInterval(clockTimer);
        simTimer = null; clockTimer = null; elapsedSec = 0;

        simVerdictLarge.textContent = 'READY';
        simVerdictLarge.style.color = '#ffc966';
        simVerdictNote.textContent = 'LAUNCH COUNTER-STRIKE, THEN START THE SCAN';
        simCheatsCount.textContent = '0';
        simCheatsCount.style.color = '#ece8e0';
        simWarningsCount.textContent = '0';
        simWarningsCount.style.color = '#ece8e0';
        simElapsed.textContent = '00:00';
        simStage.textContent = 'IDLE';
        simStatusLog.textContent = 'Waiting to start';

        simTitlePill.className = 'app-title-pill';
        simTitlePillText.textContent = 'STANDBY';

        simReticleOuter.className = 'reticle-ring-outer';
        simReticleState.textContent = 'STANDBY';
        simReticleState.style.color = '#f0ad3a';
        simReticleSub.textContent = 'INTEGRITY SCAN';

        simBtnCancel.classList.remove('is-active');
        simBtnStart.style.opacity = '1';
    }

    function startLiveScanSequence(outcomeType) {
        resetAppToIdle();

        simVerdictLarge.textContent = 'SCANNING';
        simVerdictLarge.style.color = '#5ad6ff';
        simVerdictNote.textContent = 'KEEP COUNTER-STRIKE FOCUSED WHILE SCANNING';

        simTitlePill.className = 'app-title-pill scanning';
        simTitlePillText.textContent = 'SCANNING';

        simReticleOuter.className = 'reticle-ring-outer scanning';
        simReticleState.textContent = 'SCANNING';
        simReticleState.style.color = '#5ad6ff';
        simReticleSub.textContent = 'PE INTEGRITY';

        simBtnCancel.classList.add('is-active');
        simBtnStart.style.opacity = '0.5';

        clockTimer = setInterval(function () {
            elapsedSec++;
            simElapsed.textContent = formatTime(elapsedSec);
        }, 1000);

        var stages = [
            { stage: 'PROCESS', log: 'Attaching to running hl.exe (PID: 7428)...', sec: 1 },
            { stage: 'MODULES', log: 'Comparing hw.dll .text section against disk PE binary...', sec: 3 },
            { stage: 'IAT / EAT', log: 'Verifying client.dll and opengl32.dll export tables...', sec: 6 },
            { stage: 'SCRIPTS', log: 'Tokenizing config alias DAGs for wait-driven loops...', sec: 9 },
            { stage: 'PROBES', log: 'Enumerating cross-process read/write handles and foreign threads...', sec: 12 },
            { stage: 'SIGNING', log: 'Generating HMAC-SHA256 tamper-evident evidence envelope...', sec: 14 }
        ];

        var step = 0;
        simTimer = setInterval(function () {
            if (step < stages.length) {
                simStage.textContent = stages[step].stage;
                simStatusLog.textContent = stages[step].log;
                step++;
            } else {
                clearInterval(simTimer);
                clearInterval(clockTimer);
                simTimer = null; clockTimer = null;
                simBtnCancel.classList.remove('is-active');
                simBtnStart.style.opacity = '1';
                concludeScan(outcomeType);
            }
        }, 750);
    }

    function concludeScan(outcome) {
        if (outcome === 'clean') {
            simVerdictLarge.textContent = 'CLEAN';
            simVerdictLarge.style.color = '#4fd08c';
            simVerdictNote.textContent = 'NO CHEATS DETECTED — 100% BYTE IDENTICAL';
            simCheatsCount.textContent = '0';
            simWarningsCount.textContent = '0';
            simStage.textContent = 'COMPLETE';
            simStatusLog.textContent = 'Uploaded signed report: index.php?report=01a79b0f332f9011';

            simTitlePill.className = 'app-title-pill clean';
            simTitlePillText.textContent = 'CLEAN';

            simReticleOuter.className = 'reticle-ring-outer';
            simReticleState.textContent = 'CLEAN';
            simReticleState.style.color = '#4fd08c';
            simReticleSub.textContent = 'VERIFIED SAFE';

            evidenceContent.innerHTML = '<div style="color: #4fd08c; font-weight: 700;">[VERDICT: CLEAN] Report #01a79b0f332f9011</div>' +
                '<div style="color: #94a2b0; margin-top: 6px;">Target: hl.exe (PID: 7428) · Steam Build 8684</div>' +
                '<div style="color: #4fd08c; margin-top: 4px;">✓ hw.dll .text section (0x001B4000 bytes) byte-identical.</div>' +
                '<div style="color: #4fd08c;">✓ client.dll .text section (0x000E2000 bytes) byte-identical.</div>' +
                '<div style="color: #4fd08c;">✓ opengl32.dll export trampolines: 0 hooks found.</div>' +
                '<div style="color: #4fd08c;">✓ Config alias graph: 14 .cfg files parsed, 0 cyclic jump loops.</div>' +
                '<div style="color: #4fd08c;">✓ Injected threads: 0 unauthorized threads detected.</div>' +
                '<div style="color: #5ad6ff; margin-top: 8px;">HMAC-SHA256 Signature: 8f4b1e9c2a7d4e3f... [AUTHENTIC]</div>';
        } else if (outcome === 'warn') {
            simVerdictLarge.textContent = 'WARNING';
            simVerdictLarge.style.color = '#f0a63a';
            simVerdictNote.textContent = 'REVIEW REQUIRED — OFFLINE SUSPICIOUS ARTIFACTS';
            simCheatsCount.textContent = '0';
            simWarningsCount.textContent = '2';
            simWarningsCount.style.color = '#f0a63a';
            simStage.textContent = 'REVIEW';
            simStatusLog.textContent = 'Report uploaded with 2 review items for admin review';

            simTitlePill.className = 'app-title-pill';
            simTitlePillText.textContent = 'WARNING';

            simReticleOuter.className = 'reticle-ring-outer';
            simReticleState.textContent = 'WARNING';
            simReticleState.style.color = '#f0a63a';
            simReticleSub.textContent = 'REVIEW QUEUE';

            evidenceContent.innerHTML = '<div style="color: #f0a63a; font-weight: 700;">[VERDICT: WARNING] Report #01a79b0f332f9011</div>' +
                '<div style="color: #94a2b0; margin-top: 6px;">Live game memory is clean, but offline review traces were flagged:</div>' +
                '<div style="color: #f0a63a; margin-top: 4px;">! Warning: cstrike/userconfig.cfg line 42 has complex alias chain.</div>' +
                '<div style="color: #f0a63a;">! Warning: Unseen custom module helper.dll present in root directory.</div>' +
                '<div style="color: #4fd08c;">✓ hw.dll & client.dll memory .text sections verified clean.</div>' +
                '<div style="color: #5ad6ff; margin-top: 8px;">HMAC-SHA256 Signature: 3a7c8f9b5e1d4a2e... [AUTHENTIC]</div>';
        } else if (outcome === 'cheat') {
            simVerdictLarge.textContent = 'DETECTED';
            simVerdictLarge.style.color = '#e24b3c';
            simVerdictNote.textContent = 'ACTIVE IN-MEMORY DETOUR HOOK IDENTIFIED';
            simCheatsCount.textContent = '1';
            simCheatsCount.style.color = '#e24b3c';
            simWarningsCount.textContent = '0';
            simStage.textContent = 'DETECTION';
            simStatusLog.textContent = 'hw.dll!CL_CreateMove modified by inline detour JMP';

            simTitlePill.className = 'app-title-pill detected';
            simTitlePillText.textContent = 'DETECTED';

            simReticleOuter.className = 'reticle-ring-outer';
            simReticleState.textContent = 'DETECTED';
            simReticleState.style.color = '#e24b3c';
            simReticleSub.textContent = 'HOOK FOUND';

            evidenceContent.innerHTML = '<div style="color: #e24b3c; font-weight: 700;">[VERDICT: DETECTED] Report #01a79b0f332f9011</div>' +
                '<div style="color: #e24b3c; margin-top: 6px;">x Rule Triggered: acp-hook-cl-createmove (Severity: DETECTED, Confidence: HIGH)</div>' +
                '<div style="color: #e24b3c;">x Target: hw.dll .text section offset RVA 0x0002A140</div>' +
                '<div style="color: #94a2b0;">Expected bytes on disk: 55 8B EC 83 EC 08 (Standard Prologue)</div>' +
                '<div style="color: #e24b3c;">Live bytes in memory:   E9 4A 12 00 00 90 (Inline Trampoline Detour JMP)</div>' +
                '<div style="color: #5ad6ff; margin-top: 8px;">HMAC-SHA256 Forensic Sealed: 9b4d8a2f1c5e7b3a... [TAMPER PROOF]</div>';
        }
    }

    document.getElementById('simActionClean').addEventListener('click', function () { startLiveScanSequence('clean'); });
    document.getElementById('simActionWarn').addEventListener('click', function () { startLiveScanSequence('warn'); });
    document.getElementById('simActionCheat').addEventListener('click', function () { startLiveScanSequence('cheat'); });
    document.getElementById('simActionReset').addEventListener('click', resetAppToIdle);
    document.getElementById('simBtnStart').addEventListener('click', function () { startLiveScanSequence('clean'); });
    document.getElementById('simBtnCancel').addEventListener('click', resetAppToIdle);

    document.getElementById('simBtnEvidence').addEventListener('click', function () {
        evidenceModal.classList.add('is-active');
    });
    btnCloseEvidence.addEventListener('click', function () {
        evidenceModal.classList.remove('is-active');
    });
    evidenceModal.addEventListener('click', function (e) {
        if (e.target === evidenceModal) evidenceModal.classList.remove('is-active');
    });

    // 3. Copy SHA-256 Checksum Button
    var btnCopySha = document.getElementById('btnCopySha');
    if (btnCopySha) {
        btnCopySha.addEventListener('click', function () {
            var hashText = document.getElementById('valSha256').textContent.trim();
            navigator.clipboard.writeText(hashText).then(function () {
                btnCopySha.textContent = 'Copied ✓';
                setTimeout(function () { btnCopySha.textContent = 'Copy SHA-256'; }, 2000);
            });
        });
    }

    // 4. Rotating Hints
    var hints = [
        "Counter-Strike must be running before you scan.",
        "The report link opens in your browser and can be shared with an admin.",
        "A scan result is evidence for review, not proof of a cheat-free device.",
        "Scanning reads your game's files and memory. Nothing is changed."
    ];
    var hintIdx = 0;
    var hintEl = document.getElementById('simHintLine');
    setInterval(function () {
        hintIdx = (hintIdx + 1) % hints.length;
        if (hintEl) hintEl.textContent = 'ⓘ ' + hints[hintIdx];
    }, 7000);
})();
</script>

<?php uds_theme_footbar(); ?>
</body>
</html>

<?php
declare(strict_types=1);

// Player risk dashboard: the correlated view across the ReHLDS behavioural engine and the
// desktop scanner.
//
// Like review.php, the admin token is entered in the browser and sent per request rather
// than held in a session - the data behind it names people, and a page that stays
// authenticated in a shared browser tab is how that leaks.

require __DIR__ . '/config.php';
require __DIR__ . '/theme_bar.php';
require __DIR__ . '/nav.php';

$navReports = acp_recent_reports($acpConfig);
$navDownloadHref = 'download.php';

$stats = ['players' => 0, 'cheats' => 0, 'review' => 0, 'sessions' => 0, 'evidence' => 0, 'servers' => 0];
try {
    $stats = acp_behavior_stats(acp_behavior_open($acpConfig)) + $stats;
} catch (Throwable $e) {
    // An unreadable telemetry database must not take the page down; the counts simply
    // stay at zero and the table reports the error when it loads.
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ACS — Player Risk</title>
    <link rel="stylesheet" href="assets/theme.css">
<?php uds_theme_head(); ?>
    <link rel="stylesheet" href="assets/acp.css?v=<?= filemtime(__DIR__ . '/assets/acp.css') ?>">
    <style>
        .riskbar { position: relative; height: 8px; border-radius: 4px; background: rgba(127,127,127,.22);
                   overflow: hidden; min-width: 110px; }
        .riskbar i { position: absolute; inset: 0 auto 0 0; border-radius: 4px; display: block; }
        .r-cheat  i { background: #e5484d; }
        .r-review i { background: #f5a524; }
        .r-clean  i { background: #30a46c; }
        .verdict { font-size: 11px; font-weight: 700; letter-spacing: .04em; text-transform: uppercase;
                   padding: 2px 8px; border-radius: 999px; white-space: nowrap; }
        .v-cheat  { background: rgba(229,72,77,.16);  color: #e5484d; }
        .v-review { background: rgba(245,165,36,.16); color: #c98a12; }
        .v-clean  { background: rgba(48,164,108,.16); color: #30a46c; }
        table.players { width: 100%; border-collapse: collapse; }
        table.players th { text-align: left; font-size: 12px; opacity: .65; padding: 8px 10px;
                           border-bottom: 1px solid rgba(127,127,127,.25); }
        table.players td { padding: 9px 10px; border-bottom: 1px solid rgba(127,127,127,.12);
                           vertical-align: middle; }
        table.players tr.p-row { cursor: pointer; }
        table.players tr.p-row:hover td { background: rgba(127,127,127,.07); }
        .detail { padding: 0; }
        .detail-inner { padding: 12px 14px 18px; }
        .ev { border-left: 3px solid rgba(127,127,127,.3); padding: 6px 0 6px 10px; margin: 8px 0; }
        .ev.sev-DETECTED { border-left-color: #e5484d; }
        .ev.sev-WARNING  { border-left-color: #f5a524; }
        .ev-head { font-weight: 600; }
        .ev-meta { font-size: 12px; opacity: .7; }
        .ev-reason { font-size: 12.5px; opacity: .85; margin-top: 3px; max-width: 78ch; }
        .num { font-variant-numeric: tabular-nums; }
        .muted { opacity: .6; }
    </style>
</head>
<body>
<?php acp_site_nav('home', $navDownloadHref); ?>
<header>
    <div class="wrap topbar">
        <div>
            <div class="brand">ACS <em>Player Risk</em></div>
            <div class="sub">server behaviour and client scans, correlated &middot; highest risk first</div>
        </div>
        <div class="bar" style="margin:0">
            <input type="password" id="token" placeholder="admin token" size="26" autocomplete="off">
            <select id="verdict">
                <option value="">All</option>
                <option value="cheat">Cheat</option>
                <option value="review">Review</option>
                <option value="clean">Clean</option>
            </select>
            <button class="primary" id="load">Load</button>
        </div>
    </div>
</header>

<main class="wrap">
    <section class="stats" aria-label="Telemetry scale">
        <div class="stat"><strong><?= (int) $stats['players'] ?></strong><span>players tracked</span></div>
        <div class="stat s-red"><strong><?= (int) $stats['cheats'] ?></strong><span>cheat verdicts</span></div>
        <div class="stat"><strong><?= (int) $stats['review'] ?></strong><span>need review</span></div>
        <div class="stat"><strong><?= (int) $stats['sessions'] ?></strong><span>sessions</span></div>
        <div class="stat"><strong><?= (int) $stats['evidence'] ?></strong><span>evidence rows</span></div>
        <div class="stat"><strong><?= (int) $stats['servers'] ?></strong><span>game servers</span></div>
    </section>

    <section>
        <p id="status" class="muted">Enter the admin token and press Load.</p>
        <table class="players" id="table" hidden>
            <thead>
                <tr>
                    <th>Player</th>
                    <th>Verdict</th>
                    <th style="width:150px">Risk</th>
                    <th class="num">Server</th>
                    <th class="num">Client</th>
                    <th class="num">Detected</th>
                    <th class="num">Sessions</th>
                    <th>Last seen</th>
                </tr>
            </thead>
            <tbody id="rows"></tbody>
        </table>
    </section>
</main>

<script>
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => (
    {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function token() { return $('token').value.trim(); }

async function api(action, params = {}) {
    const q = new URLSearchParams({ action, ...params });
    const res = await fetch('api.php?' + q.toString(), {
        headers: { 'X-ACS-Token': token() }
    });
    const body = await res.json().catch(() => ({ ok: false, error: 'Bad JSON from server' }));
    if (!res.ok || !body.ok) throw new Error(body.error || ('HTTP ' + res.status));
    return body;
}

function riskCell(p) {
    const v = p.verdict || 'clean';
    const pct = Math.max(0, Math.min(100, Number(p.risk) || 0));
    return `<div class="riskbar r-${esc(v)}"><i style="width:${pct}%"></i></div>
            <span class="num" style="font-size:12px">${pct.toFixed(1)}</span>`;
}

function renderRows(players) {
    if (!players.length) {
        $('rows').innerHTML = '<tr><td colspan="8" class="muted">No players match that filter.</td></tr>';
        return;
    }
    $('rows').innerHTML = players.map(p => `
        <tr class="p-row" data-steam="${esc(p.steam64)}">
            <td>
                <div>${esc(p.name || '(unknown)')}</div>
                <div class="ev-meta mono">${esc(p.auth_id || p.steam64)}</div>
            </td>
            <td><span class="verdict v-${esc(p.verdict)}">${esc(p.verdict)}</span></td>
            <td>${riskCell(p)}</td>
            <td class="num">${(Number(p.server_risk) || 0).toFixed(1)}</td>
            <td class="num">${(Number(p.client_risk) || 0).toFixed(1)}</td>
            <td class="num">${p.detected ?? 0}</td>
            <td class="num">${p.sessions ?? 0}</td>
            <td class="ev-meta">${esc((p.last_seen || '').replace('T', ' ').replace('Z', ''))}</td>
        </tr>
        <tr class="detail" id="d-${esc(p.steam64)}" hidden><td colspan="8"></td></tr>
    `).join('');

    document.querySelectorAll('tr.p-row').forEach(tr => {
        tr.addEventListener('click', () => toggle(tr.dataset.steam));
    });
}

async function toggle(steam64) {
    const row = $('d-' + steam64);
    if (!row) return;
    if (!row.hidden) { row.hidden = true; return; }

    const cell = row.firstElementChild;
    cell.innerHTML = '<div class="detail-inner muted">Loading…</div>';
    row.hidden = false;

    try {
        const body = await api('player', { steam64 });
        const p = body.player;
        const s = body.scoring || {};

        const rules = (s.rules || []).map(r => `
            <div class="ev sev-${esc(r.severity)}">
                <div class="ev-head">${esc(r.name || r.rule)}
                    <span class="ev-meta">— contributes ${(Number(r.score) || 0).toFixed(1)}</span></div>
                <div class="ev-meta">${esc(r.category)} · ${r.hits} hit(s) across
                    ${r.session_count ?? 1} session(s) · last ${esc((r.last || '').replace('T', ' ').replace('Z', ''))}</div>
                <div class="ev-reason mono">${esc(r.subject)}</div>
            </div>`).join('') || '<p class="muted">No server-side evidence.</p>';

        const recent = (p.evidence || []).slice(0, 25).map(e => `
            <div class="ev sev-${esc(e.severity)}">
                <div class="ev-head">${esc(e.rule_name)}
                    <span class="ev-meta">${esc(e.severity)} · ${esc(e.category)}</span></div>
                <div class="ev-reason mono">${esc(e.subject)}</div>
                <div class="ev-reason">${esc(e.reason)}</div>
                <div class="ev-meta">${esc((e.created || '').replace('T', ' ').replace('Z', ''))}
                    · server ${esc(e.server_id)}</div>
            </div>`).join('') || '<p class="muted">Nothing recorded.</p>';

        const client = s.clientReport
            ? `<a href="index.php?report=${encodeURIComponent(s.clientReport)}">open scanner report</a>`
            : '<span class="muted">no desktop scan on file for this SteamID</span>';

        cell.innerHTML = `<div class="detail-inner">
            <p><strong>Score</strong> — server ${(Number(s.serverRisk)||0).toFixed(1)},
               client ${(Number(s.clientRisk)||0).toFixed(1)},
               combined <strong>${(Number(s.risk)||0).toFixed(1)}</strong>
               (${esc(s.verdict)}). Categories: ${esc((s.categories || []).join(', ') || 'none')}.</p>
            <p>${client}</p>
            <h4>What is driving the score</h4>${rules}
            <h4>Recent evidence</h4>${recent}
        </div>`;
    } catch (err) {
        cell.innerHTML = `<div class="detail-inner" style="color:#e5484d">${esc(err.message)}</div>`;
    }
}

async function load() {
    if (!token()) { $('status').textContent = 'An admin token is required.'; return; }
    $('status').textContent = 'Loading…';
    try {
        const body = await api('players', { verdict: $('verdict').value, limit: 200 });
        renderRows(body.players || []);
        $('table').hidden = false;
        $('status').textContent = `${(body.players || []).length} player(s).`;
    } catch (err) {
        $('table').hidden = true;
        $('status').textContent = err.message;
    }
}

$('load').addEventListener('click', load);
$('token').addEventListener('keydown', (e) => { if (e.key === 'Enter') load(); });
</script>
<?php uds_theme_footbar(); ?>
</body>
</html>

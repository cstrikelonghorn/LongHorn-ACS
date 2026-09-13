<?php
declare(strict_types=1);

/**
 * Corpus review queue.
 *
 * WarGods classifies its Unknown bucket by hand, through forum threads. This does the same job
 * as a ranked worklist: the scoring already pushed the interesting rows to the top, so a
 * reviewer works down the list instead of hunting through millions of records.
 *
 * The page holds no secrets. It is a shell that talks to api.php with an admin token the
 * reviewer pastes in, kept in sessionStorage so it dies with the tab.
 */

require __DIR__ . '/config.php';
require __DIR__ . '/theme_bar.php';
require __DIR__ . '/nav.php';

$navReports = acp_recent_reports($acpConfig);
$navDownloadHref = 'download.php';
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ACS — Corpus Review</title>
    <link rel="stylesheet" href="assets/theme.css">
<?php uds_theme_head(); ?>
    <link rel="stylesheet" href="assets/acp.css?v=<?= filemtime(__DIR__ . '/assets/acp.css') ?>">
</head>
<body>
<?php acp_site_nav('home', $navDownloadHref); ?>
<header>
    <div class="wrap topbar">
        <div>
            <div class="brand">ACS <em>Corpus Review</em></div>
            <div class="sub">unknown artifacts, most suspicious first</div>
        </div>
        <div class="bar" style="margin:0">
            <input type="password" id="token" placeholder="admin token" size="26" autocomplete="off">
            <select id="state">
                <option value="unknown">Unknown</option>
                <option value="cheat">Cheat</option>
                <option value="clean">Clean</option>
            </select>
            <button class="primary" id="load">Load</button>
        </div>
    </div>
</header>

<div class="wrap">
    <dl class="stats" id="stats"></dl>
    <div id="out"><div class="msg">Paste the admin token (<code>ACP_ADMIN_TOKEN</code>) and press Load.</div></div>
    <footer>
        Prevalence auto-clears common binaries on every upload. Anything left here is rare,
        unsigned, mapped into the game, or concentrated on machines that produced detections.
    </footer>
</div>

<script>
const $ = (id) => document.getElementById(id);
const tokenBox = $('token');
tokenBox.value = sessionStorage.getItem('acpAdminToken') || '';

async function api(action, opts = {}) {
    const token = tokenBox.value.trim();
    const res = await fetch(`api.php?action=${action}${opts.query || ''}`, {
        method: opts.method || 'GET',
        headers: { 'Authorization': `Bearer ${token}`, ...(opts.body ? { 'Content-Type': 'application/json' } : {}) },
        body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    const json = await res.json().catch(() => ({ ok: false, error: `HTTP ${res.status}` }));
    if (!res.ok && !json.error) { json.error = `HTTP ${res.status}`; }
    return json;
}

function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function loadStats() {
    const r = await fetch('api.php?action=corpus').then(x => x.json()).catch(() => null);
    if (!r || !r.corpus) { return; }
    const c = r.corpus;
    $('stats').innerHTML = [
        ['Artifacts', c.artifacts, ''], ['Unknown', c.unknown, 'unknown'],
        ['Clean', c.clean, 'clean'], ['Cheat', c.cheat, 'cheat'],
        ['Reports', c.reports, ''], ['Machines', c.machines, ''],
    ].map(([k, v, cls]) => `<div class="stat"><dt>${k}</dt><dd class="${cls}">${Number(v).toLocaleString()}</dd></div>`).join('');
}

function scoreClass(n) { return n >= 8 ? 'hot' : n >= 4 ? 'warm' : 'cold'; }

async function load() {
    sessionStorage.setItem('acpAdminToken', tokenBox.value.trim());
    $('out').innerHTML = '<div class="msg">Loading…</div>';
    await loadStats();

    const r = await api('queue', { query: `&state=${encodeURIComponent($('state').value)}&limit=200` });
    if (!r.ok) {
        $('out').innerHTML = `<div class="msg err">${esc(r.error || 'Request failed')}</div>`;
        return;
    }
    if (!r.items.length) {
        $('out').innerHTML = '<div class="msg">Nothing in this bucket.</div>';
        return;
    }

    const rows = r.items.map(it => `
        <tr data-sha="${esc(it.sha256)}">
            <td class="num score ${scoreClass(it.score)}">${it.score}</td>
            <td>
                <div class="name">${esc(it.name || '(unnamed)')}</div>
                <div class="path">${esc(it.path_sample || '')}</div>
            </td>
            <td><span class="tag">${esc(it.kind)}</span>
                ${it.loaded_in_game > 0 ? '<span class="tag ingame">in game</span>' : ''}
                ${Number(it.signed) ? '' : '<span class="tag unsigned">unsigned</span>'}</td>
            <td class="num">${it.machines}</td>
            <td class="num">${it.dirty_machines}</td>
            <td class="num">${it.times_seen}</td>
            <td>${esc(it.signer || '—')}</td>
            <td>
                <div class="hash">${esc(it.sha256.slice(0, 24))}…</div>
                <a class="vt" href="https://www.virustotal.com/gui/file/${esc(it.sha256)}" target="_blank" rel="noopener noreferrer">VirusTotal ↗</a>
            </td>
            <td>
                <button class="cheat" data-act="cheat">Cheat</button>
                <button class="clean" data-act="clean">Clean</button>
            </td>
        </tr>`).join('');

    $('out').innerHTML = `<div class="table-wrap"><table>
        <thead><tr>
            <th>Score</th><th>Artifact</th><th>Flags</th>
            <th>Machines</th><th>Dirty</th><th>Seen</th><th>Signer</th><th>Hash</th><th>Classify</th>
        </tr></thead><tbody>${rows}</tbody></table></div>`;
}

$('out').addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-act]');
    if (!btn) { return; }

    const tr = btn.closest('tr');
    const sha = tr.dataset.sha;
    tr.querySelectorAll('button').forEach(b => b.disabled = true);

    const r = await api('classify', {
        method: 'POST',
        body: { sha256: sha, state: btn.dataset.act, note: 'classified from review queue' },
    });

    if (r.ok) {
        tr.remove();
        loadStats();
    } else {
        tr.querySelectorAll('button').forEach(b => b.disabled = false);
        alert(r.error || 'Classification failed');
    }
});

$('load').addEventListener('click', load);
tokenBox.addEventListener('keydown', e => { if (e.key === 'Enter') { load(); } });
loadStats();
</script>
<?php uds_theme_footbar(); ?>
</body>
</html>

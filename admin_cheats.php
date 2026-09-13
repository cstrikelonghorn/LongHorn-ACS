<?php
declare(strict_types=1);

/**
 * Admin Cheats Database Manager.
 *
 * A professional web UI for managing the ACS cheat signature database:
 *   - Browse, search, enable/disable, and delete signatures
 *   - Add new cheats with a visual wizard (auto-generates ID, scopes, match rules)
 *   - Test a filename, hash, or string against all rules (dry-run sandbox)
 *   - Bulk-import SHA-256 / MD5 hash lists in one click
 *   - Promote unknown corpus artifacts directly into named cheat signatures
 *
 * Authentication: uses the same ACP_ADMIN_TOKEN as corpus review.
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
    <title>ACS — Cheats Database Manager</title>
    <link rel="stylesheet" href="assets/theme.css">
<?php uds_theme_head(); ?>
    <link rel="stylesheet" href="assets/acp.css?v=<?= filemtime(__DIR__ . '/assets/acp.css') ?>">
</head>
<body>
<?php acp_site_nav('cheats', $navDownloadHref); ?>
<header>
    <div class="wrap topbar">
        <div>
            <div class="brand">ACS <em>Cheats Database</em></div>
            <div class="sub">manage signatures, test rules, import hashes</div>
        </div>
        <div class="bar" style="margin:0">
            <button class="primary" id="btnLock" title="Lock the Cheats DB and forget the saved password">&#128274; Lock</button>
        </div>
    </div>
</header>

<!-- Stats Dashboard -->
<div class="wrap">
    <dl class="acm-stats" id="acmStats"></dl>
    <div id="acmDiag" style="font-family:monospace;font-size:11.5px;color:#8b949e;padding:4px 0 0;white-space:pre-wrap;word-break:break-word;"></div>
</div>

<!-- Tab Navigation -->
<div class="wrap">
    <div class="acm-tabs" id="acmTabs">
        <button class="acm-tab is-active" data-tab="signatures">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6h16M4 12h10M4 18h14"/></svg>
            Signatures
        </button>
        <button class="acm-tab" data-tab="add">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v8M8 12h8"/></svg>
            Add New
        </button>
        <button class="acm-tab" data-tab="tester">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 3h6l3 6-6 12-6-12z"/><path d="M12 9v6"/></svg>
            Tester
        </button>
        <button class="acm-tab" data-tab="import">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12M7 11l5 5 5-5"/><path d="M4 21h16"/></svg>
            Bulk Import
        </button>
    </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════════════
     TAB 1: SIGNATURES TABLE
     ═══════════════════════════════════════════════════════════════════════ -->
<div class="wrap acm-panel" id="panel-signatures">
    <div class="acm-toolbar">
        <input type="text" id="sigSearch" placeholder="Search by name, ID, description…" class="acm-search">
        <select id="sigFilter" class="acm-filter">
            <option value="">All Severities</option>
            <option value="DETECTED">DETECTED</option>
            <option value="WARNING">WARNING</option>
            <option value="INFO">INFO</option>
        </select>
        <select id="sigScopeFilter" class="acm-filter">
            <option value="">All Scopes</option>
            <option value="demo-file">Demo File</option>
            <option value="process">Process</option>
            <option value="module">Module/DLL</option>
            <option value="driver">Driver</option>
            <option value="memory">Memory</option>
            <option value="hl-file">Game File</option>
            <option value="hl-config">Config</option>
            <option value="execution-trace">Exec Trace</option>
            <option value="download-trace">Download Trace</option>
        </select>
    </div>
    <div id="sigTable"><div class="acm-msg">Connect with your admin token to load signatures.</div></div>
</div>

<!-- ═══════════════════════════════════════════════════════════════════════
     TAB 2: ADD NEW CHEAT
     ═══════════════════════════════════════════════════════════════════════ -->
<div class="wrap acm-panel" id="panel-add" hidden>
    <div class="acm-card">
        <h3 class="acm-card-title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v8M8 12h8"/></svg>
            Add New Cheat Signature
        </h3>

        <div class="acm-form-grid">
            <div class="acm-field">
                <label for="addName">Cheat Name <span class="req">*</span></label>
                <input type="text" id="addName" placeholder="e.g. Vermillion D3D Multihack">
            </div>
            <div class="acm-field">
                <label for="addSeverity">Severity</label>
                <select id="addSeverity">
                    <option value="DETECTED" selected>🔴 DETECTED (confirmed cheat)</option>
                    <option value="WARNING">🟡 WARNING (suspicious, needs review)</option>
                    <option value="INFO">🔵 INFO (informational only)</option>
                </select>
            </div>
            <div class="acm-field">
                <label for="addConfidence">Confidence</label>
                <select id="addConfidence">
                    <option value="high" selected>High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
            </div>
            <div class="acm-field">
                <label for="addType">Detection Type</label>
                <select id="addType">
                    <option value="injected-dll">💉 Injected DLL (module hook)</option>
                    <option value="process">⚙️ Running Process</option>
                    <option value="driver">🔧 Kernel Driver</option>
                    <option value="game-file">📁 Game File (model, sprite, WAD)</option>
                    <option value="config">📝 Config Script (.cfg)</option>
                    <option value="exec-trace">🕐 Execution Trace (Prefetch/UserAssist)</option>
                    <option value="download">⬇️ Download Trace</option>
                    <option value="memory">🧠 Memory Pattern</option>
                    <option value="demo">🎬 Demo File Behavior</option>
                </select>
            </div>
            <div class="acm-field">
                <label for="addMatchType">Match Method</label>
                <select id="addMatchType">
                    <option value="path_regex">📂 File/Process Name (auto-regex)</option>
                    <option value="sha256">🔐 SHA-256 Hash</option>
                    <option value="md5">🔑 MD5 Hash</option>
                    <option value="file_contains">📄 File Contains String</option>
                    <option value="output_regex">📊 Scanner Output Regex</option>
                    <option value="report_regex">📋 Report Regex</option>
                    <option value="config_regex">📝 Config Regex</option>
                    <option value="driver_regex">🔧 Driver Regex</option>
                </select>
            </div>
            <div class="acm-field acm-field-wide">
                <label for="addMatchValue">Match Target <span class="req">*</span></label>
                <textarea id="addMatchValue" rows="3" placeholder="e.g. vermillion.dll  or  /(?i)hpp\\s*v[0-9]/  or a SHA-256 hash"></textarea>
                <div class="acm-hint" id="addMatchHint">Type a filename or process name — it will be auto-wrapped into a regex.</div>
            </div>
            <div class="acm-field acm-field-wide">
                <label for="addDesc">Description / Impact</label>
                <textarea id="addDesc" rows="2" placeholder="e.g. Silent aimbot and ESP wallhack overlay for CS 1.6"></textarea>
            </div>
            <div class="acm-field">
                <label for="addSourceGroup">Source Group</label>
                <input type="text" id="addSourceGroup" value="admin-panel" placeholder="e.g. admin-panel">
            </div>
        </div>

        <div class="acm-actions">
            <button class="acm-btn acm-btn-primary" id="btnAddSave">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12l5 5L19 7"/></svg>
                Save Signature
            </button>
            <button class="acm-btn" id="btnAddClear">Clear Form</button>
        </div>
        <div id="addResult"></div>
    </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════════════
     TAB 3: SIGNATURE TESTER
     ═══════════════════════════════════════════════════════════════════════ -->
<div class="wrap acm-panel" id="panel-tester" hidden>
    <div class="acm-card">
        <h3 class="acm-card-title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 3h6l3 6-6 12-6-12z"/><path d="M12 9v6"/></svg>
            Signature Tester (Dry-Run Sandbox)
        </h3>
        <p class="acm-hint">Paste a filename, process name, DLL name, hash, or any text to test which rules would match it. Nothing is saved.</p>

        <div class="acm-field acm-field-wide">
            <label for="testInput">Test Input</label>
            <textarea id="testInput" rows="3" placeholder="e.g.  vermillion.dll  or  C:\Users\Player\Downloads\hpp_v6.exe  or  a SHA-256 hash"></textarea>
        </div>

        <div class="acm-actions">
            <button class="acm-btn acm-btn-primary" id="btnTest">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 3h6l3 6-6 12-6-12z"/></svg>
                Run Test
            </button>
        </div>
        <div id="testResult"></div>
    </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════════════
     TAB 4: BULK IMPORT
     ═══════════════════════════════════════════════════════════════════════ -->
<div class="wrap acm-panel" id="panel-import" hidden>
    <div class="acm-card">
        <h3 class="acm-card-title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12M7 11l5 5 5-5"/><path d="M4 21h16"/></svg>
            Bulk Hash Import
        </h3>
        <p class="acm-hint">Paste one hash per line (SHA-256 or MD5). Duplicates are automatically skipped.</p>

        <div class="acm-form-grid">
            <div class="acm-field">
                <label for="impName">Cheat Name</label>
                <input type="text" id="impName" placeholder="e.g. Known Cheat DLL" value="Imported Cheat Hash">
            </div>
            <div class="acm-field">
                <label for="impHashType">Hash Type</label>
                <select id="impHashType">
                    <option value="sha256" selected>SHA-256 (64 chars)</option>
                    <option value="md5">MD5 (32 chars)</option>
                </select>
            </div>
            <div class="acm-field">
                <label for="impSeverity">Severity</label>
                <select id="impSeverity">
                    <option value="DETECTED" selected>🔴 DETECTED</option>
                    <option value="WARNING">🟡 WARNING</option>
                </select>
            </div>
            <div class="acm-field acm-field-wide">
                <label for="impDesc">Description</label>
                <input type="text" id="impDesc" value="Bulk-imported cheat file hash." placeholder="Optional description">
            </div>
            <div class="acm-field acm-field-wide">
                <label for="impHashes">Hash List <span class="req">*</span></label>
                <textarea id="impHashes" rows="8" placeholder="Paste hashes here, one per line…
e.g.
a1b2c3d4e5f6...  (64 hex chars for SHA-256)
abcdef123456...  (32 hex chars for MD5)"></textarea>
                <div class="acm-hint" id="impCount">0 valid hashes detected</div>
            </div>
        </div>

        <div class="acm-actions">
            <button class="acm-btn acm-btn-primary" id="btnImport">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12M7 11l5 5 5-5"/><path d="M4 21h16"/></svg>
                Import Hashes
            </button>
        </div>
        <div id="importResult"></div>
    </div>
</div>

<!-- Unlock Popup -->
<div class="acm-modal-backdrop" id="pwModal" hidden>
    <div class="acm-modal" style="max-width:400px;">
        <div class="acm-modal-header">
            <h3>&#128274; Cheats DB — Access</h3>
        </div>
        <div class="acm-modal-body">
            <div class="acm-field">
                <label for="pwInput">Password</label>
                <input type="password" id="pwInput" autocomplete="off" placeholder="Enter password">
            </div>
            <div id="pwError" style="color:#f85149;font-size:12.5px;min-height:18px;"></div>
        </div>
        <div class="acm-modal-footer">
            <button class="acm-btn acm-btn-primary" id="pwSubmit">Unlock</button>
        </div>
    </div>
</div>

<!-- Edit Modal -->
<div class="acm-modal-backdrop" id="editModal" hidden>
    <div class="acm-modal">
        <div class="acm-modal-header">
            <h3>Edit Signature</h3>
            <button class="acm-modal-close" id="editClose">&times;</button>
        </div>
        <div class="acm-modal-body">
            <input type="hidden" id="editId">
            <div class="acm-form-grid">
                <div class="acm-field acm-field-wide">
                    <label for="editName">Cheat Name</label>
                    <input type="text" id="editName">
                </div>
                <div class="acm-field">
                    <label for="editSeverity">Severity</label>
                    <select id="editSeverity">
                        <option value="DETECTED">DETECTED</option>
                        <option value="WARNING">WARNING</option>
                        <option value="INFO">INFO</option>
                    </select>
                </div>
                <div class="acm-field">
                    <label for="editConfidence">Confidence</label>
                    <select id="editConfidence">
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                </div>
                <div class="acm-field acm-field-wide">
                    <label for="editDesc">Description</label>
                    <textarea id="editDesc" rows="2"></textarea>
                </div>
                <div class="acm-field">
                    <label for="editEnabled">Enabled</label>
                    <select id="editEnabled">
                        <option value="true">Yes</option>
                        <option value="false">No</option>
                    </select>
                </div>
                <div class="acm-field">
                    <label for="editSourceGroup">Source Group</label>
                    <input type="text" id="editSourceGroup">
                </div>
            </div>
        </div>
        <div class="acm-modal-footer">
            <button class="acm-btn acm-btn-primary" id="editSave">Save Changes</button>
            <button class="acm-btn" id="editCancel">Cancel</button>
        </div>
    </div>
</div>

<footer class="wrap" style="padding:32px 0 60px;text-align:center;opacity:.5;font-size:13px">
    Admin Cheats Manager &mdash; signatures are live-served to all scanners on next sync.
</footer>

<script>
/* ═══════════════════════════════════════════════════════════════════════════
   Admin Cheats Manager — Client-Side Logic
   ═══════════════════════════════════════════════════════════════════════════ */
const $ = (id) => document.getElementById(id);

/* ── Self-diagnostics: every JS error and API result is shown on the page ── */
function acmDiag(html) {
    const d = $('acmDiag');
    if (d) d.innerHTML = html;
}
window.addEventListener('error', function (e) {
    acmDiag('<span style="color:#f85149">JS ERROR: ' + esc(String(e.message || e.type)) + ' @ line ' + e.lineno + '</span>');
});
window.addEventListener('unhandledrejection', function (e) {
    acmDiag('<span style="color:#f85149">PROMISE ERROR: ' + esc(String(e.reason && e.reason.message ? e.reason.message : e.reason)) + '</span>');
});

let adminPassword = sessionStorage.getItem('acpAdminPassword') || '';

let allSignatures = [];
let connected = false;

function showPwModal(message) {
    $('pwError').textContent = message || '';
    $('pwModal').hidden = false;
    setTimeout(() => $('pwInput').focus(), 30);
}

function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

async function api(action, opts = {}) {
    let res;
    try {
        res = await fetch(`api.php?action=${action}${opts.query || ''}`, {
            method: opts.method || 'GET',
            headers: { 'Authorization': `Bearer ${adminPassword}`, ...(opts.body ? {'Content-Type':'application/json'} : {}) },
            body: opts.body ? JSON.stringify(opts.body) : undefined,
        });
    } catch (err) {
        acmDiag('<span style="color:#f85149">NETWORK ERROR on ' + esc(action) + ': ' + esc(String(err && err.message ? err.message : err)) + '</span>'
            + '\nIs the PHP server running and is this page opened via http:// (not file://)?');
        return { ok: false, error: 'Network error - see the status line above the stats.' };
    }
    const json = await res.json().catch(() => ({ ok: false, error: `HTTP ${res.status}` }));
    json.httpStatus = res.status;
    if (!res.ok && !json.error) json.error = `HTTP ${res.status}`;
    if (!res.ok) {
        acmDiag('<span style="color:#f85149">' + esc(action) + ' → HTTP ' + res.status + ': ' + esc(json.error || '') + '</span>'
            + (res.status === 401 ? '\nWrong or missing password - unlock again.' : '')
            + (res.status === 503 ? '\nThe server has no password configured (set adminPassword in config.php).' : ''));
        if (res.status === 401) {
            adminPassword = '';
            sessionStorage.removeItem('acpAdminPassword');
            showPwModal(json.error || 'Wrong password');
        }
    } else {
        acmDiag('');
    }
    return json;
}

/* ──────── Stats Dashboard ──────── */
function renderStats(counts) {
    if (!counts) return;
    const items = [
        ['Total', counts.totalSignatures, ''],
        ['Enabled', counts.enabled, 'ok'],
        ['Client Live', counts.clientLive, 'accent'],
        ['Demo File', counts.demoFile, ''],
        ['Config', counts.config, ''],
        ['Client Report', counts.clientReport, ''],
    ];
    $('acmStats').innerHTML = items.map(([k,v,c]) =>
        `<div class="acm-stat"><dt>${k}</dt><dd class="${c}">${Number(v).toLocaleString()}</dd></div>`
    ).join('');
}

/* ──────── Tab Switching ──────── */
$('acmTabs').addEventListener('click', e => {
    const btn = e.target.closest('.acm-tab');
    if (!btn) return;
    document.querySelectorAll('.acm-tab').forEach(t => t.classList.remove('is-active'));
    btn.classList.add('is-active');
    document.querySelectorAll('.acm-panel').forEach(p => p.hidden = true);
    const panel = $('panel-' + btn.dataset.tab);
    if (panel) panel.hidden = false;
});

/* ──────── Signature Table ──────── */
function severityBadge(sev) {
    const cls = sev === 'DETECTED' ? 'acm-sev-detected' : sev === 'WARNING' ? 'acm-sev-warning' : 'acm-sev-info';
    return `<span class="acm-sev ${cls}">${esc(sev)}</span>`;
}

function scopeBadges(scopes) {
    if (!Array.isArray(scopes) || scopes.length === 0) return '<span class="acm-scope">all</span>';
    return scopes.map(s => `<span class="acm-scope">${esc(s)}</span>`).join(' ');
}

function matchSummary(match) {
    if (!match) return '—';
    const keys = Object.keys(match);
    return keys.map(k => {
        const v = match[k];
        const val = Array.isArray(v) ? (v.length > 2 ? `[${v.length} values]` : v.join(', ')) : String(v);
        const short = val.length > 60 ? val.substring(0, 57) + '…' : val;
        return `<span class="acm-match-key">${esc(k)}</span> <code class="acm-match-val">${esc(short)}</code>`;
    }).join('<br>');
}

function renderSignatures() {
    const search = ($('sigSearch').value || '').toLowerCase();
    const sevFilter = $('sigFilter').value;
    const scopeFilter = $('sigScopeFilter').value;

    let filtered = allSignatures.filter(s => {
        if (sevFilter && (s.severity || '').toUpperCase() !== sevFilter) return false;
        if (scopeFilter && !(s.scopes || []).includes(scopeFilter)) return false;
        if (search) {
            const hay = ((s.id || '') + ' ' + (s.name || '') + ' ' + (s.description || '')).toLowerCase();
            if (!hay.includes(search)) return false;
        }
        return true;
    });

    if (filtered.length === 0) {
        $('sigTable').innerHTML = '<div class="acm-msg">No signatures match your filters.</div>';
        return;
    }

    const rows = filtered.map((s, i) => `
        <tr class="${s.enabled === false ? 'acm-disabled' : ''}" data-id="${esc(s.id)}">
            <td class="num">${i + 1}</td>
            <td>${severityBadge((s.severity || 'WARNING').toUpperCase())}</td>
            <td>
                <div class="acm-sig-name">${esc(s.name || s.id)}</div>
                <div class="acm-sig-id">${esc(s.id)}</div>
            </td>
            <td>${scopeBadges(s.scopes)}</td>
            <td>${matchSummary(s.match)}</td>
            <td class="acm-sig-actions">
                <button class="acm-btn-icon acm-toggle" title="${s.enabled === false ? 'Enable' : 'Disable'}" data-id="${esc(s.id)}" data-enabled="${s.enabled === false ? 'false' : 'true'}">
                    ${s.enabled === false ? '⏸' : '✅'}
                </button>
                <button class="acm-btn-icon acm-edit" title="Edit" data-id="${esc(s.id)}">✏️</button>
                <button class="acm-btn-icon acm-delete" title="Delete" data-id="${esc(s.id)}">🗑️</button>
            </td>
        </tr>
    `).join('');

    $('sigTable').innerHTML = `
        <div class="acm-table-info">${filtered.length} of ${allSignatures.length} signatures</div>
        <div class="table-wrap"><table class="acm-sigs-table">
            <thead><tr>
                <th>#</th><th>Severity</th><th>Name</th><th>Scopes</th><th>Match</th><th>Actions</th>
            </tr></thead>
            <tbody>${rows}</tbody>
        </table></div>`;
}

$('sigSearch').addEventListener('input', renderSignatures);
$('sigFilter').addEventListener('change', renderSignatures);
$('sigScopeFilter').addEventListener('change', renderSignatures);

/* ──────── Signature Actions (Toggle, Edit, Delete) ──────── */
$('sigTable').addEventListener('click', async e => {
    const toggle = e.target.closest('.acm-toggle');
    const del = e.target.closest('.acm-delete');
    const edit = e.target.closest('.acm-edit');

    if (toggle) {
        const id = toggle.dataset.id;
        const newEnabled = toggle.dataset.enabled === 'true' ? false : true;
        toggle.disabled = true;
        const r = await api('signature_edit', { method: 'POST', body: { id, enabled: newEnabled } });
        if (r.ok) { await loadSignatures(); } else { alert(r.error || 'Failed'); }
        toggle.disabled = false;
    }

    if (del) {
        const id = del.dataset.id;
        const sig = allSignatures.find(s => s.id === id);
        if (!confirm(`Delete signature "${sig?.name || id}"?\n\nThis removes it permanently from the database.`)) return;
        del.disabled = true;
        const r = await api('signature_delete', { method: 'POST', body: { id } });
        if (r.ok) { await loadSignatures(); } else { alert(r.error || 'Failed'); del.disabled = false; }
    }

    if (edit) {
        const id = edit.dataset.id;
        const sig = allSignatures.find(s => s.id === id);
        if (!sig) return;
        $('editId').value = sig.id;
        $('editName').value = sig.name || '';
        $('editSeverity').value = (sig.severity || 'WARNING').toUpperCase();
        $('editConfidence').value = sig.confidence || 'medium';
        $('editDesc').value = sig.description || '';
        $('editEnabled').value = sig.enabled === false ? 'false' : 'true';
        $('editSourceGroup').value = sig.sourceGroup || '';
        $('editModal').hidden = false;
    }
});

/* ──────── Edit Modal ──────── */
$('editClose').addEventListener('click', () => $('editModal').hidden = true);
$('editCancel').addEventListener('click', () => $('editModal').hidden = true);
$('editModal').addEventListener('click', e => { if (e.target === $('editModal')) $('editModal').hidden = true; });

$('editSave').addEventListener('click', async () => {
    $('editSave').disabled = true;
    const r = await api('signature_edit', { method: 'POST', body: {
        id: $('editId').value,
        name: $('editName').value,
        severity: $('editSeverity').value,
        confidence: $('editConfidence').value,
        description: $('editDesc').value,
        enabled: $('editEnabled').value !== 'false',
        sourceGroup: $('editSourceGroup').value,
    }});
    $('editSave').disabled = false;
    if (r.ok) {
        $('editModal').hidden = true;
        await loadSignatures();
    } else {
        alert(r.error || 'Failed to save');
    }
});

/* ──────── Add New ──────── */
$('addMatchType').addEventListener('change', () => {
    const t = $('addMatchType').value;
    const hints = {
        'path_regex': 'Type a filename or process name — it will be auto-wrapped into a regex.',
        'sha256': 'Paste one or more SHA-256 hashes (64 hex chars), one per line.',
        'md5': 'Paste one or more MD5 hashes (32 hex chars), one per line.',
        'file_contains': 'A literal string to search inside game files.',
        'output_regex': 'A PHP/PCRE regex to match scanner output text.',
        'report_regex': 'A PHP/PCRE regex to match client report text.',
        'config_regex': 'A PHP/PCRE regex to match game config lines.',
        'driver_regex': 'A PHP/PCRE regex to match loaded driver names.',
    };
    $('addMatchHint').textContent = hints[t] || '';
});

$('btnAddSave').addEventListener('click', async () => {
    const body = {
        name: $('addName').value,
        severity: $('addSeverity').value,
        confidence: $('addConfidence').value,
        detectionType: $('addType').value,
        matchType: $('addMatchType').value,
        matchValue: $('addMatchValue').value,
        description: $('addDesc').value,
        sourceGroup: $('addSourceGroup').value,
    };

    $('btnAddSave').disabled = true;
    const r = await api('signature_add', { method: 'POST', body });
    $('btnAddSave').disabled = false;

    if (r.ok) {
        $('addResult').innerHTML = `<div class="acm-success">✅ Signature <strong>${esc(r.signature?.name)}</strong> added (ID: <code>${esc(r.signature?.id)}</code>). Total: ${r.total}</div>`;
        $('addName').value = '';
        $('addMatchValue').value = '';
        $('addDesc').value = '';
        await loadSignatures();
    } else {
        $('addResult').innerHTML = `<div class="acm-error">❌ ${esc(r.error || 'Failed')}</div>`;
    }
});

$('btnAddClear').addEventListener('click', () => {
    ['addName','addMatchValue','addDesc'].forEach(id => $(id).value = '');
    $('addResult').innerHTML = '';
});

/* ──────── Tester ──────── */
$('btnTest').addEventListener('click', async () => {
    const input = $('testInput').value.trim();
    if (!input) { $('testResult').innerHTML = '<div class="acm-error">Enter something to test.</div>'; return; }

    $('btnTest').disabled = true;
    const r = await api('signature_test', { method: 'POST', body: { input } });
    $('btnTest').disabled = false;

    if (!r.ok) {
        $('testResult').innerHTML = `<div class="acm-error">❌ ${esc(r.error)}</div>`;
        return;
    }

    if (r.matches === 0) {
        $('testResult').innerHTML = `<div class="acm-info">🔍 No rules matched "<code>${esc(input.substring(0,80))}</code>"</div>`;
        return;
    }

    const rows = r.hits.map(h => `
        <tr>
            <td>${severityBadge(h.severity)}</td>
            <td><strong>${esc(h.name)}</strong><br><small>${esc(h.id)}</small></td>
            <td>${esc(h.matchedBy)}</td>
            <td>${esc(h.confidence)}</td>
            <td>${esc(h.description || '—')}</td>
        </tr>`).join('');

    $('testResult').innerHTML = `
        <div class="acm-success">🎯 <strong>${r.matches}</strong> rule(s) matched</div>
        <div class="table-wrap"><table class="acm-sigs-table">
            <thead><tr><th>Severity</th><th>Rule</th><th>Matched By</th><th>Confidence</th><th>Description</th></tr></thead>
            <tbody>${rows}</tbody>
        </table></div>`;
});

/* ──────── Bulk Import ──────── */
$('impHashes').addEventListener('input', () => {
    const text = $('impHashes').value;
    const type = $('impHashType').value;
    const regex = type === 'sha256' ? /^[0-9a-f]{64}$/i : /^[0-9a-f]{32}$/i;
    const lines = text.split(/[\r\n,;\s]+/).filter(l => regex.test(l.trim()));
    const unique = new Set(lines.map(l => l.trim().toLowerCase()));
    $('impCount').textContent = `${unique.size} valid unique hash(es) detected`;
});

$('btnImport').addEventListener('click', async () => {
    const body = {
        name: $('impName').value,
        hashType: $('impHashType').value,
        severity: $('impSeverity').value,
        description: $('impDesc').value,
        hashes: $('impHashes').value,
    };

    $('btnImport').disabled = true;
    const r = await api('signature_import', { method: 'POST', body });
    $('btnImport').disabled = false;

    if (r.ok) {
        $('importResult').innerHTML = `<div class="acm-success">✅ <strong>${r.added}</strong> signature(s) added, <strong>${r.skipped}</strong> skipped (duplicates). Total: ${r.total}</div>`;
        $('impHashes').value = '';
        $('impCount').textContent = '0 valid hashes detected';
        await loadSignatures();
    } else {
        $('importResult').innerHTML = `<div class="acm-error">❌ ${esc(r.error || 'Failed')}</div>`;
    }
});

/* ──────── Load & Unlock ──────── */
function adminErrorHtml(message) {
    if (/disabled until/i.test(message || '')) {
        return `<div class="acm-error">❌ ${esc(message)}</div>`
            + `<div class="acm-msg" style="margin-top:10px; line-height:1.6;">`
            + `<strong>Setup required:</strong> the server has no password configured. `
            + `Set <code>adminPassword</code> in <code>config.php</code> (or the <code>ACS_ADMIN_PASSWORD</code> environment variable).</div>`;
    }
    return `<div class="acm-error">❌ ${esc(message || 'Failed to load')}</div>`;
}

async function loadSignatures() {
    const r = await api('signatures');
    if (!r.ok) {
        if (r.httpStatus !== 401) {
            $('sigTable').innerHTML = adminErrorHtml(r.error);
        }
        return;
    }
    allSignatures = r.signatures || [];
    renderStats(r.counts);
    renderSignatures();
    connected = true;
}

async function tryUnlock() {
    const pw = $('pwInput').value.trim();
    if (!pw) { $('pwError').textContent = 'Enter the password.'; return; }
    $('pwSubmit').disabled = true;
    adminPassword = pw;
    const r = await api('signatures');
    $('pwSubmit').disabled = false;
    if (r.ok) {
        sessionStorage.setItem('acpAdminPassword', adminPassword);
        $('pwModal').hidden = true;
        $('pwError').textContent = '';
        $('pwInput').value = '';
        $('sigTable').innerHTML = '<div class="acm-msg">Loading…</div>';
        allSignatures = r.signatures || [];
        renderStats(r.counts);
        renderSignatures();
        connected = true;
        acmDiag('');
    } else if (r.httpStatus !== 401) {
        $('pwError').textContent = r.error || 'Access denied.';
    }
}

$('pwSubmit').addEventListener('click', tryUnlock);
$('pwInput').addEventListener('keydown', e => { if (e.key === 'Enter') tryUnlock(); });

$('btnLock').addEventListener('click', () => {
    sessionStorage.removeItem('acpAdminPassword');
    adminPassword = '';
    allSignatures = [];
    connected = false;
    showPwModal('');
});

// Unlock automatically with the remembered password, otherwise show the popup
if (adminPassword) {
    $('sigTable').innerHTML = '<div class="acm-msg">Loading…</div>';
    loadSignatures();
} else {
    showPwModal('');
    acmDiag('locked · enter the Cheats DB password to continue');
}
</script>
<?php uds_theme_footbar(); ?>
</body>
</html>

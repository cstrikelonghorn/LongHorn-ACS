<?php
declare(strict_types=1);

/**
 * Shared left navigation drawer.
 *
 * One definition, used by every page so the menu is identical everywhere:
 *
 *     require __DIR__ . '/nav.php';          // with the other requires
 *     ...
 *     <body>
 *     <?php acp_site_nav('home', $downloadHref); ?>
 *
 * Behaviour:
 *   - desktop (>= 1024px): pinned open by default, pushes the page content;
 *     the toggle collapses it back off the left edge.
 *   - tablet / phone: off-canvas, closed by default, opens over the content with
 *     a tap-to-close backdrop.
 *   - the open/closed choice is remembered per browser in localStorage.
 */

if (!function_exists('acp_nav_icon')) {
    function acp_nav_icon(string $name): string
    {
        $paths = [
            'home'     => '<path d="M3 10.5 12 3l9 7.5"/><path d="M5 9.5V21h14V9.5"/>',
            'download' => '<path d="M12 3v12"/><path d="M7 11l5 5 5-5"/><path d="M4 21h16"/>',
            'support'  => '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3.5"/><path d="M12 3v2.5M12 18.5V21M3 12h2.5M18.5 12H21"/>',
            'help'     => '<circle cx="12" cy="12" r="9"/><path d="M9.3 9.2a2.8 2.8 0 1 1 3.7 2.6c-.7.3-1 .8-1 1.5v.3"/><path d="M12 17h.01"/>',
            'cheats'   => '<path d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7z"/><path d="M9 12l2 2 4-4"/>',
        ];

        return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" '
            . 'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            . ($paths[$name] ?? '') . '</svg>';
    }
}

if (!function_exists('acp_report_nav')) {
    function acp_report_nav(string $downloadHref = 'download.php'): void
    {
        $targetHref = ($downloadHref === '#' || $downloadHref === '') ? 'download.php' : $downloadHref;
        $items = [
            ['label' => 'Home',     'href' => 'index.php',  'icon' => 'home'],
            ['label' => 'Download', 'href' => $targetHref,   'icon' => 'download'],
            ['label' => 'Support',  'href' => 'mailto:support@cslonghorn.com', 'icon' => 'support'],
            ['label' => 'FAQ',      'href' => 'faq.php', 'icon' => 'help'],
        ];
        ?>
        <nav class="report-nav" aria-label="Report menu">
            <?php foreach ($items as $item): ?>
            <a class="report-nav-item" href="<?= htmlspecialchars((string) $item['href'], ENT_QUOTES) ?>"<?= !empty($item['external']) ? ' target="_blank" rel="noopener noreferrer"' : '' ?>>
                <?= acp_nav_icon($item['icon']) ?>
                <span><?= htmlspecialchars((string) $item['label'], ENT_QUOTES) ?></span>
            </a>
            <?php endforeach; ?>
        </nav>
        <?php
    }
}

if (!function_exists('acp_site_nav')) {
    /**
     * @param bool $pinned  Report views pass true: the pill is rendered already open and
     *                      stays docked under the sticky header, with no Menu button to click.
     */
    function acp_site_nav(string $active = 'home', string $downloadHref = 'download.php', bool $pinned = false): void
    {
        $targetHref = ($downloadHref === '#' || $downloadHref === '') ? 'download.php' : $downloadHref;
        $items = [
            ['key' => 'home',     'label' => 'Home',     'href' => 'index.php',  'icon' => 'home'],
            ['key' => 'cheats',   'label' => 'Cheats DB', 'href' => 'admin_cheats.php', 'icon' => 'cheats'],
            ['key' => 'download', 'label' => 'Download', 'href' => $targetHref,   'icon' => 'download'],
            ['key' => 'support',  'label' => 'Support',  'href' => 'mailto:support@cslonghorn.com', 'icon' => 'support'],
            ['key' => 'faq',      'label' => 'FAQ',      'href' => 'faq.php', 'icon' => 'help'],
        ];

        // Report views: the pill is rendered server-side, in normal flow under the header,
        // so it is always visible without a click but scrolls away with the page.
        if ($pinned) {
            ?>
<div class="acp-pinned-menu" id="acpPinnedMenu">
    <div class="acp-pinned-inner">
        <nav class="report-nav" aria-label="Site menu">
            <?php foreach ($items as $item): ?>
            <a class="report-nav-item<?= $active === $item['key'] ? ' is-active' : '' ?>"
               href="<?= htmlspecialchars((string) $item['href'], ENT_QUOTES) ?>"<?= !empty($item['external']) ? ' target="_blank" rel="noopener noreferrer"' : '' ?>>
                <?= acp_nav_icon($item['icon']) ?>
                <span><?= htmlspecialchars((string) $item['label'], ENT_QUOTES) ?></span>
            </a>
            <?php endforeach; ?>
        </nav>
    </div>
</div>
            <?php
            return;
        }
        ?>
<div class="acp-menu-source" id="acpMenuSource" hidden>
    <nav class="report-nav" aria-label="Site menu">
        <?php foreach ($items as $item): ?>
        <a class="report-nav-item<?= $active === $item['key'] ? ' is-active' : '' ?>"
           href="<?= htmlspecialchars((string) $item['href'], ENT_QUOTES) ?>"<?= !empty($item['external']) ? ' target="_blank" rel="noopener noreferrer"' : '' ?>>
            <?= acp_nav_icon($item['icon']) ?>
            <span><?= htmlspecialchars((string) $item['label'], ENT_QUOTES) ?></span>
        </a>
        <?php endforeach; ?>
    </nav>
</div>
<script>
(function () {
    function mount() {
        var source = document.getElementById('acpMenuSource');
        if (!source) { return; }
        var bar = source.querySelector('.report-nav');
        if (!bar) { return; }

        var pinned = source.getAttribute('data-pinned') === '1';
        var anchor = document.querySelector('.wrap.topbar') || document.querySelector('.topbar') || document.querySelector('header');
        var header = document.querySelector('header');

        var menu = document.createElement('div');
        menu.className = 'acp-menu';

        var toggle = document.createElement('button');
        toggle.type = 'button';
        toggle.className = 'acp-nav-btn';
        toggle.setAttribute('aria-expanded', 'false');
        toggle.setAttribute('aria-label', 'Toggle navigation menu');
        toggle.innerHTML = '<svg class="acp-nav-ico-open" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg>'
            + '<svg class="acp-nav-ico-close" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 6l-6 6 6 6"/></svg>'
            + '<span class="acp-nav-btn-label">Menu</span>';

        // Report views are "pinned": no Menu button, the pill is always docked.
        if (!pinned) {
            menu.appendChild(toggle);
        } else {
            document.documentElement.classList.add('acp-menu-pinned');
        }

        // The exact report-page pill, moved into an integrated strip that slides
        // open in the page flow (it pushes the content down, not over it).
        var panel = document.createElement('div');
        panel.className = 'acp-menu-panel' + (pinned ? ' is-open is-pinned' : '');
        panel.id = 'acpMenuPanel';
        var inner = document.createElement('div');
        inner.className = 'acp-menu-panel-inner';
        inner.appendChild(bar);
        panel.appendChild(inner);

        source.remove();
        if (!pinned && anchor) { anchor.insertBefore(menu, anchor.firstChild); }

        // The panel stays OUTSIDE the header (so it keeps its transparent look),
        // but is made sticky below the header so it is visible at any scroll.
        if (header && header.parentNode) {
            header.parentNode.insertBefore(panel, header.nextSibling);
        } else {
            document.body.insertBefore(panel, document.body.firstChild);
        }

        function syncHeaderHeight() {
            if (header) {
                document.documentElement.style.setProperty('--acp-header-h', header.offsetHeight + 'px');
            }
        }
        syncHeaderHeight();
        window.addEventListener('resize', syncHeaderHeight);
        window.addEventListener('orientationchange', syncHeaderHeight);
        window.addEventListener('load', syncHeaderHeight);

        // Pinned menu is position:fixed, so measure its real height and reserve that
        // much space at the top of the page content.
        function syncMenuHeight() {
            if (!pinned) { return; }
            document.documentElement.style.setProperty('--acp-menu-h', panel.offsetHeight + 'px');
        }
        syncMenuHeight();
        window.addEventListener('resize', syncMenuHeight);
        window.addEventListener('load', syncMenuHeight);
        setTimeout(syncMenuHeight, 60);

        function setOpen(open) {
            if (pinned) { open = true; }
            menu.classList.toggle('is-open', open);
            panel.classList.toggle('is-open', open);
            toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        }

        toggle.addEventListener('click', function (e) {
            e.stopPropagation();
            setOpen(!panel.classList.contains('is-open'));
        });
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') { setOpen(false); }
        });
        bar.querySelectorAll('a').forEach(function (a) {
            a.addEventListener('click', function () { setOpen(false); });
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', mount);
    } else {
        mount();
    }
})();
</script>
        <?php
    }
}

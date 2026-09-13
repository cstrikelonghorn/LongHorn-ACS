/* ============================================================================
   UDS THEME SWITCH
   ----------------------------------------------------------------------------
   Owns the footbar picker and the persisted choice. The theme attribute is
   already set pre-paint by the inline snippet in theme_bar.php; this file only
   handles interaction, so a slow network never leaves the page unthemed.

   Other scripts listen for the "uds:themechange" event rather than polling
   the attribute.
   ========================================================================== */
(function () {
    'use strict';

    var STORE = 'uds-theme';
    var DEFAULT = 'lh';

    var root = document.documentElement;

    function readStored() {
        try {
            return localStorage.getItem(STORE);
        } catch (e) {
            return null;
        }
    }

    function writeStored(theme) {
        try {
            localStorage.setItem(STORE, theme);
        } catch (e) {
            /* Private mode or blocked storage */
        }
    }

    function current() {
        var v = root.getAttribute('data-uds-theme');
        return (v && THEMES[v]) ? v : DEFAULT;
    }

    /* ------------------------------------------------------------ switcher */
    var bar = document.getElementById('uds-footbar');
    if (!bar) { return; }

    var opts = Array.prototype.slice.call(bar.querySelectorAll('[data-uds-set-theme]'));
    var thumb = bar.querySelector('.uds-theme-thumb');
    var statusText = bar.querySelector('.uds-fb-status-text');
    var visitorStatus = (statusText && statusText.getAttribute('data-visitor-text')) || (statusText && statusText.textContent.trim()) || '0 visitors';
    var THEMES = {
        core: { label: 'Default',  status: 'Cyberdeck interface active' },
        lh:   { label: 'LH Style', status: visitorStatus }
    };

    /* The highlight is positioned from the live button box so it stays correct
       across font loading, zoom and the mobile layout change.

       The thumb is inset by the track's own padding (CSS `left`), and
       offsetLeft is measured from the same padding edge, so the inset has to
       be subtracted back out. That value is read from the stylesheet rather
       than hardcoded -- it was a literal 3 until the track padding changed to
       2px, which left the highlight a pixel off. */
    function thumbInset() {
        var v = parseFloat(window.getComputedStyle(thumb).left);
        return isFinite(v) ? v : 0;
    }

    function moveThumb(animate) {
        if (!thumb) { return; }
        var active = opts.filter(function (b) {
            return b.getAttribute('data-uds-set-theme') === current();
        })[0];
        if (!active) { return; }

        if (!animate) { thumb.style.transition = 'none'; }
        thumb.style.width = active.offsetWidth + 'px';
        thumb.style.transform = 'translateX(' + (active.offsetLeft - thumbInset()) + 'px)';
        if (!animate) {
            /* Force a reflow so the suppressed transition cannot be coalesced
               with the restore below. */
            void thumb.offsetWidth;
            thumb.style.transition = '';
        }
    }

    /* Each theme brings its own type, so the option boxes resize when the new
       face finishes loading. Re-measure once that settles, or the highlight
       keeps the width it had under the fallback font. */
    function moveThumbAfterFonts() {
        if (document.fonts && document.fonts.ready) {
            document.fonts.ready.then(function () { moveThumb(false); });
        }
    }

    function syncUi() {
        var c = current();
        opts.forEach(function (b) {
            var active = b.getAttribute('data-uds-set-theme') === c;
            b.setAttribute('aria-checked', active ? 'true' : 'false');
            b.removeAttribute('disabled');
            b.setAttribute('aria-disabled', 'false');
            b.classList.remove('is-disabled');
            b.tabIndex = active ? 0 : -1;
        });
        if (statusText && THEMES[c]) {
            statusText.textContent = THEMES[c].status;
        }
    }

    function apply(theme, persist) {
        if (!THEMES[theme] || theme === current()) { return; }
        root.setAttribute('data-uds-theme', theme);
        if (persist) { writeStored(theme); }
        syncUi();
        moveThumb(true);
        moveThumbAfterFonts();
        document.dispatchEvent(new CustomEvent('uds:themechange', { detail: { theme: theme } }));
    }

    opts.forEach(function (b) {
        b.addEventListener('click', function () {
            apply(b.getAttribute('data-uds-set-theme'), true);
        });

        /* Arrow keys step through the radiogroup like native radio buttons. */
        b.addEventListener('keydown', function (ev) {
            var idx = opts.indexOf(b);
            var next = -1;
            if (ev.key === 'ArrowRight' || ev.key === 'ArrowDown') {
                next = (idx + 1) % opts.length;
            } else if (ev.key === 'ArrowLeft' || ev.key === 'ArrowUp') {
                next = (idx - 1 + opts.length) % opts.length;
            }
            if (next >= 0) {
                ev.preventDefault();
                opts[next].focus();
                apply(opts[next].getAttribute('data-uds-set-theme'), true);
            }
        });
    });

    /* A choice made in another tab should follow here too. */
    window.addEventListener('storage', function (ev) {
        if (ev.key === STORE && ev.newValue && THEMES[ev.newValue]) {
            apply(ev.newValue, false);
        }
    });

    window.addEventListener('resize', function () { moveThumb(false); });

    /* Web fonts change the button widths after first paint. */
    moveThumbAfterFonts();

    /* Reconcile once in case the stored value and the pre-paint attribute ever
       disagree (for example after a theme is renamed). */
    var stored = readStored();
    if (stored && stored !== current() && THEMES[stored]) {
        root.setAttribute('data-uds-theme', stored);
    }

    syncUi();
    moveThumb(false);

    /* Expose a tiny surface for other page scripts. */
    window.udsTheme = {
        get: current,
        set: function (t) { apply(t, true); }
    };
}());

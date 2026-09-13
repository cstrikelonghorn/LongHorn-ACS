/* ============================================================================
   LH STYLE — REPORT EFFECTS
   ----------------------------------------------------------------------------
   The motion layer for the LH theme. Three behaviours, each tied to something
   the report actually means:

     STAMP    the verdict headline resolves into focus, so the eye lands on the
              conclusion before the evidence.
     ROLL-UP  counts climb from zero, which makes a jump from 0 to 7 threats
              legible as a quantity rather than a static glyph.
     SEQUENCE evidence cards arrive in order instead of as one block, so the
              list reads as a sequence of findings.

   SAFETY RULE: this file hides real report content in order to animate it in.
   A scan verdict must never be lost to a decoration, so every hide is paired
   with a timer that reveals it regardless of what else happens -- a throttled
   background tab, a thrown error, a browser that never fires the next frame.
   requestAnimationFrame drives the nice path; setTimeout guarantees the floor.
   ========================================================================== */
(function () {
    'use strict';

    var root = document.documentElement;
    var reduced = window.matchMedia
        && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    function isLh() {
        return root.getAttribute('data-uds-theme') === 'lh';
    }

    function all(sel) {
        return Array.prototype.slice.call(document.querySelectorAll(sel));
    }

    /* ------------------------------------------------------------- roll-up */
    /* Counts up to the value already rendered in the DOM, so the settled state
       is byte-identical to the server-rendered markup. */
    function rollUp(el) {
        var raw = (el.textContent || '').trim();
        var match = raw.match(/^(\d+)(.*)$/);
        if (!match) { return; }

        var target = parseInt(match[1], 10);
        var suffix = match[2] || '';
        if (!isFinite(target) || target <= 0) { return; }

        var duration = Math.min(900, 320 + target * 22);
        var start = null;
        var settled = false;

        el.classList.add('lh-counting');

        function settle() {
            if (settled) { return; }
            settled = true;
            el.textContent = target + suffix;
        }

        /* The number must end correct even if frames stop arriving. */
        var guard = setTimeout(settle, duration + 700);

        function step(ts) {
            if (settled) { return; }
            if (start === null) { start = ts; }
            var p = Math.min(1, (ts - start) / duration);
            /* Ease out so the figure decelerates onto its final value. */
            var eased = 1 - Math.pow(1 - p, 3);
            el.textContent = Math.round(target * eased) + suffix;
            if (p < 1) {
                requestAnimationFrame(step);
            } else {
                clearTimeout(guard);
                settle();
            }
        }
        requestAnimationFrame(step);
    }

    /* ------------------------------------------------------------- reveals */
    function sequence(nodes, baseDelay, stepDelay) {
        if (!nodes.length) { return; }

        nodes.forEach(function (el, i) {
            el.classList.add('lh-reveal');
            el.style.setProperty('--lh-delay', (baseDelay + i * stepDelay) + 'ms');
        });

        var revealed = false;
        function reveal() {
            if (revealed) { return; }
            revealed = true;
            nodes.forEach(function (el) { el.classList.add('lh-in'); });
        }

        /* Two frames: the first commits the hidden state, the second starts the
           transition. Without the gap the browser coalesces both and nothing
           animates. */
        requestAnimationFrame(function () {
            requestAnimationFrame(reveal);
        });

        /* Floor: content becomes visible on a timer no matter what. */
        setTimeout(reveal, 400);

        /* Once the sequence has played out, drop the animation classes so the
           content is left in a plain, un-styled state. */
        var total = baseDelay + nodes.length * stepDelay + 1400;
        setTimeout(function () {
            nodes.forEach(function (el) {
                el.classList.remove('lh-reveal');
                el.style.removeProperty('--lh-delay');
            });
        }, total);
    }

    /* ------------------------------------------------------------- footbar */
    /* Mirror the report verdict in the persistent status readout. */
    function syncStatus() {
        var status = document.getElementById('uds-fb-status');
        if (!status) { return; }

        var hero = document.querySelector('.result-hero');
        status.classList.remove('is-busy', 'is-alert');
        if (!hero) { return; }

        var text = status.querySelector('.uds-fb-status-text');
        var confirmed = document.querySelector('.metric-confirmed strong');
        var n = confirmed ? parseInt((confirmed.textContent || '0').trim(), 10) : 0;

        if (hero.classList.contains('detected')) {
            status.classList.add('is-alert');
            if (text) {
                text.textContent = n > 0
                    ? n + (n === 1 ? ' confirmed detection' : ' confirmed detections')
                    : 'Detections confirmed';
            }
        } else if (hero.classList.contains('warning')) {
            status.classList.add('is-busy');
            if (text) { text.textContent = 'Review required'; }
        } else if (text) {
            text.textContent = 'Scan complete: no signature matched';
        }
    }

    /* ---------------------------------------------------------------- boot */
    var ran = false;

    function run() {
        if (ran || !isLh()) { return; }
        ran = true;

        /* Read the counts before any roll-up starts rewriting them. */
        syncStatus();
        if (reduced) { return; }

        /* Verdict headline. The stamp starts from transparent, and this line is
           the single most important sentence on the page, so the class is
           dropped on a timer once the animation has had time to land. Nothing
           about the verdict then depends on an animation having run. */
        var title = document.querySelector('.result-title, .verdict-title');
        if (title) {
            title.classList.add('lh-stamp');
            setTimeout(function () { title.classList.remove('lh-stamp'); }, 1200);
        }

        /* Counts: dashboard tiles and the report metric row. */
        all('.stats-dashboard .sc-value, .result-metric strong').forEach(rollUp);

        /* The threat index is the headline figure, so it rolls after the stamp
           has landed rather than competing with it. Its element mixes a text
           node with a <small> suffix, so the digits are wrapped first. */
        var score = document.querySelector('.threat-score > strong');
        if (score && score.firstChild && score.firstChild.nodeType === 3) {
            var digits = score.firstChild;
            var wrap = document.createElement('span');
            wrap.textContent = (digits.textContent || '').trim();
            score.replaceChild(wrap, digits);
            setTimeout(function () { rollUp(wrap); }, 260);
        }

        /* Evidence, in document order (already sorted by severity server-side). */
        sequence(all('.finding-list .finding-card'), 340, 62);
        sequence(all('.result-intel-grid .intel'), 220, 45);
    }

    /* Any failure here must leave the page readable rather than half-hidden. */
    function safeRun() {
        try {
            run();
        } catch (e) {
            all('.lh-reveal').forEach(function (el) {
                el.classList.remove('lh-reveal');
            });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', safeRun);
    } else {
        safeRun();
    }

    /* Switching into LH mid-session plays the sequence once, so the change
       actually demonstrates itself. */
    document.addEventListener('uds:themechange', function (ev) {
        if (ev.detail && ev.detail.theme === 'lh') {
            safeRun();
        } else {
            syncStatus();
        }
    });
}());

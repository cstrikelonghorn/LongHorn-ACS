// ACS recoil engine.
//
// This is the strongest server-side detector available in CS 1.6, and the reason is a
// specific property of the game: punchangle is authoritative. CBasePlayer fires along
// pev->v_angle + pev->punchangle, server-side. A client-side "no recoil" that merely
// stops the view from shaking does not move the player's bullets back onto the target -
// it only hides the kick.
//
// So anything that actually *controls* recoil has to steer the mouse, and steering the
// mouse means the viewangles in the usercmd stream must cancel the punchangle. That
// cancellation is visible to the server with no client cooperation at all.
//
// The test therefore is not "is this player accurate" but "does this player's pitch input
// cancel the punch they are receiving, tick for tick, more precisely than a hand can".

#include "acs.h"

// Bursts end when the player stops shooting for this long, or switches weapon.
static const double kBurstGap = 0.35;
static const size_t kBurstCap = 128;

// Pearson correlation between a[i] and b[i + lag].
//
// The zero-variance guard matters: a player who does not compensate at all produces a
// constant-zero dview, which has no variance. Returning 0 there is what stops "did
// nothing" from being scored as "perfectly correlated".
static double Pearson(const std::vector<float>& a, const std::vector<float>& b, size_t lag)
{
    if (a.size() <= lag) return 0.0;
    size_t n = a.size() - lag;
    if (n < 4) return 0.0;

    double sa = 0, sb = 0, saa = 0, sbb = 0, sab = 0;
    for (size_t i = 0; i < n; ++i)
    {
        double x = a[i], y = b[i + lag];
        sa += x; sb += y; saa += x * x; sbb += y * y; sab += x * y;
    }
    double dn  = (double)n;
    double num = dn * sab - sa * sb;
    double da  = dn * saa - sa * sa;
    double db  = dn * sbb - sb * sb;
    if (da <= 1e-9 || db <= 1e-9) return 0.0;
    return num / sqrt(da * db);
}

static void ClearBurst(RecoilState& r)
{
    r.dview.clear();
    r.dpunch.clear();
}

static void FinishBurst(PlayerState& p)
{
    RecoilState& r = p.recoil;
    size_t n = r.dview.size();
    if (n < (size_t)g_cfg.recoil_min_shots) { ClearBurst(r); return; }

    // Same-tick: the player is reacting to the kick as it lands.
    double r_same = Pearson(r.dview, r.dpunch, 0);
    // One tick ahead: the player's correction arrives *before* the kick it cancels. A hand
    // cannot do this, because there is nothing yet to react to. A script replaying a known
    // recoil pattern can, and usually does, because it compensates on the shot rather than
    // on the resulting punch.
    double r_lead = Pearson(r.dview, r.dpunch, 1);

    // How completely the punch was cancelled. Perfect compensation means
    // dview == -dpunch on every tick, i.e. this goes to zero.
    double ss = 0.0;
    for (size_t i = 0; i < n; ++i)
    {
        double e = (double)r.dview[i] + (double)r.dpunch[i];
        ss += e * e;
    }
    double rms = sqrt(ss / (double)n);

    r.bursts_analysed++;
    r.sum_residual += rms;
    r.residual_n++;
    if (r_same < r.best_r) r.best_r = r_same;
    if (r.best_residual <= 0.0 || rms < r.best_residual) r.best_residual = rms;

    bool compensated = (r_same <= -(double)g_cfg.recoil_r) && (rms <= (double)g_cfg.recoil_residual);
    if (compensated) r.bursts_compensated++;

    // Predictive only counts when leading beats following by a clear margin - otherwise
    // autocorrelation in the punch decay curve can make the two look similar.
    bool predictive = (n >= 12) && (r_lead <= -0.85) && (r_lead < r_same - 0.10);
    if (predictive) r.predictive_bursts++;

    if (r.bursts_compensated == g_cfg.recoil_report_at ||
        (r.bursts_compensated > g_cfg.recoil_report_at &&
         ((r.bursts_compensated - g_cfg.recoil_report_at) % 5) == 0))
    {
        EvidenceRaise(p, "acs-recoil-compensation", "Mechanical recoil compensation",
            "DETECTED", "recoil",
            AcsFormat("%d/%d bursts at r=%.3f, residual %.3f deg/tick (best r=%.3f, best residual=%.3f)",
                       r.bursts_compensated, r.bursts_analysed, r_same, rms, r.best_r, r.best_residual),
            "Pitch input cancelled the server-side punchangle tick for tick across a full burst. "
            "CS 1.6 fires along v_angle + punchangle, so recoil can only be controlled by moving "
            "the mouse - and a hand cannot cancel it this precisely or this repeatably.",
            60.0);
    }

    if (r.predictive_bursts == 2 ||
        (r.predictive_bursts > 2 && (r.predictive_bursts % 3) == 0))
    {
        EvidenceRaise(p, "acs-recoil-predictive", "Recoil compensation precedes the kick",
            "DETECTED", "recoil",
            AcsFormat("%d bursts with lead correlation %.3f vs same-tick %.3f over %d ticks",
                       r.predictive_bursts, r_lead, r_same, (int)n),
            "The pitch correction arrived one tick before the punchangle it cancels. Reaction "
            "cannot precede its stimulus, so the correction was replayed from a known recoil "
            "pattern rather than produced in response to the view.",
            70.0);
    }

    ClearBurst(r);
}

void RecoilOnTick(PlayerState& p, const TickSample& t)
{
    RecoilState& r = p.recoil;

    if (!t.alive)
    {
        ClearBurst(r);
        r.have_prev_punch = false;
        return;
    }

    float dpunch = 0.0f;
    if (r.have_prev_punch) dpunch = t.punch_pitch - r.prev_punch_pitch;
    r.prev_punch_pitch = t.punch_pitch;
    r.have_prev_punch  = true;

    bool firing = t.attack_down();
    if (firing) r.last_fire_time = t.time;

    if (r.dview.empty())
    {
        // Knives and grenades have no punchangle to compensate, so a burst only starts on
        // a weapon that actually kicks. weapon_id 0 means we have not seen a CurWeapon
        // message yet; allow it rather than dropping the first burst of a life.
        if (!t.attack_pressed()) return;
        r.burst_weapon  = t.weapon_id;
        r.burst_started = t.time;
    }
    else
    {
        if (t.weapon_id != r.burst_weapon || (t.time - r.last_fire_time) > kBurstGap)
        {
            FinishBurst(p);
            return;
        }
    }

    // Only ticks with something to compensate carry information. Including idle ticks
    // would dilute both the correlation and the residual toward "clean" for everyone.
    if (firing || fabsf(dpunch) > 0.01f)
    {
        if (r.dview.size() < kBurstCap)
        {
            r.dview.push_back(t.dpitch);
            r.dpunch.push_back(dpunch);
        }
        else
        {
            FinishBurst(p);
        }
    }
}

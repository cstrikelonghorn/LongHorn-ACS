// ACS behavioural engine.
//
// The other three engines look at mechanics over milliseconds. This one looks at outcomes
// over a session, which is a different kind of evidence: weaker per observation, but it
// accumulates, and it does not care how the cheat is implemented.
//
// Outcome statistics are the easiest place in an anti-cheat to produce false positives,
// because the distribution of honest skill has a long tail and server rules move the mean
// around - a headshot-only server, an AWP map, or a stacked scrim all shift these numbers
// without anyone cheating. So the rules here demand large samples, and most of them top
// out at WARNING. They are intended to raise a player's risk in combination with the
// mechanical engines, not to convict on their own.

#include "acs.h"

// A view has to physically travel between two targets. Kills closer together than this,
// repeatedly, mean it did not have to.
static const double kMultiKillWindow = 0.30;
static const int    kMinKillsForRate = 25;

void BehaviorOnKill(PlayerState& killer, PlayerState* victim, const char* weapon, bool headshot)
{
    BehaviorState& b = killer.behavior;
    std::string w = (weapon && *weapon) ? weapon : "unknown";

    b.kills++;
    b.kills_by_weapon[w]++;
    if (headshot)
    {
        b.headshots++;
        b.hs_by_weapon[w]++;
    }

    double now = gpGlobals->time;
    if (b.last_kill_time > 0.0)
    {
        double gap = now - b.last_kill_time;
        if (gap >= 0.0 && (b.fastest_interval <= 0.0 || gap < b.fastest_interval))
            b.fastest_interval = gap;

        if (gap > 0.0 && gap < kMultiKillWindow)
        {
            b.fast_multikills++;
            if (b.fast_multikills == 5 ||
                (b.fast_multikills > 5 && (b.fast_multikills % 5) == 0))
            {
                EvidenceRaise(killer, "acs-multikill-speed", "Kills chained faster than the view can travel",
                    b.fast_multikills >= 10 ? "DETECTED" : "WARNING", "behavior",
                    AcsFormat("%d kill pairs under %.0f ms, fastest %.0f ms",
                               b.fast_multikills, kMultiKillWindow * 1000.0, b.fastest_interval * 1000.0),
                    "Separate targets killed in immediate succession, repeatedly. Switching targets "
                    "requires moving the view and reacquiring; doing it this fast this often means "
                    "the second target was acquired without being looked for.",
                    b.fast_multikills >= 10 ? 40.0 : 18.0);
            }
        }
    }
    b.last_kill_time = now;

    // Headshot rate. Checked on a cadence rather than every kill so the threshold is not
    // re-tested (and re-raised) on a sample that has barely moved.
    if (b.kills >= kMinKillsForRate && (b.kills % 10) == 0)
    {
        double ratio = (double)b.headshots / (double)b.kills;
        if (ratio >= 0.65)
        {
            bool hard = (ratio >= 0.80 && b.kills >= 40);
            EvidenceRaise(killer, "acs-headshot-rate", "Headshot rate far above distribution",
                hard ? "DETECTED" : "WARNING", "behavior",
                AcsFormat("%d/%d headshots (%.0f%%) over %d kills", b.headshots, b.kills, ratio * 100.0, b.kills),
                "Sustained headshot proportion well outside the honest distribution for this sample "
                "size. Confirm the server is not headshot-only and the weapon mix is not "
                "pistol-heavy before acting on this alone.",
                hard ? 30.0 : 12.0);
        }
    }

    if (victim) victim->behavior.deaths++;
}

// Serialises everything the session learned. This is what the backend correlates against
// the desktop scanner's report for the same player.
void BehaviorSessionSummary(PlayerState& p, std::string& out_json)
{
    const AimState&      a = p.aim;
    const RecoilState&   r = p.recoil;
    const MovementState& m = p.move;
    const CmdState&      c = p.cmd;
    const BehaviorState& b = p.behavior;

    double reaction_mean = a.reaction_n ? (a.reaction_sum / a.reaction_n) : 0.0;
    double quant         = a.quant_n ? (a.quant_residual_sum / a.quant_n) : -1.0;
    double residual_mean = r.residual_n ? (r.sum_residual / r.residual_n) : -1.0;
    float  sync          = m.strafe_ticks ? ((float)m.sync_ticks / (float)m.strafe_ticks) : -1.0f;
    double hs_ratio      = b.kills ? ((double)b.headshots / (double)b.kills) : 0.0;

    std::string s = "{";
    s += "\"type\":\"session_stats\"";
    s += ",\"sessionId\":\"" + AcsJsonEscape(p.session_id) + "\"";
    s += ",\"authId\":\"" + AcsJsonEscape(p.authid) + "\"";
    s += ",\"name\":\"" + AcsJsonEscape(p.name) + "\"";
    s += AcsFormat(",\"durationSec\":%.1f", gpGlobals->time - p.connect_time);
    s += AcsFormat(",\"ticks\":%u", p.ring_total);
    s += AcsFormat(",\"risk\":%.1f", p.risk);

    s += ",\"aim\":{";
    s += AcsFormat("\"snapEvents\":%d", a.snap_events);
    s += AcsFormat(",\"instantSnaps\":%d", a.instant_snaps);
    s += AcsFormat(",\"linearSnaps\":%d", a.linear_snaps);
    s += AcsFormat(",\"trackLocks\":%d", a.track_locks);
    s += AcsFormat(",\"reactionMeanMs\":%.1f", reaction_mean * 1000.0);
    s += AcsFormat(",\"reactionMinMs\":%.1f", a.reaction_min * 1000.0);
    s += AcsFormat(",\"quantStep\":%.4f", a.quant_step);
    s += AcsFormat(",\"quantResidual\":%.4f", quant);
    s += AcsFormat(",\"quantSamples\":%d", a.quant_n);
    s += "}";

    s += ",\"recoil\":{";
    s += AcsFormat("\"bursts\":%d", r.bursts_analysed);
    s += AcsFormat(",\"compensated\":%d", r.bursts_compensated);
    s += AcsFormat(",\"predictive\":%d", r.predictive_bursts);
    s += AcsFormat(",\"bestR\":%.4f", r.best_r);
    s += AcsFormat(",\"bestResidual\":%.4f", r.best_residual);
    s += AcsFormat(",\"meanResidual\":%.4f", residual_mean);
    s += "}";

    s += ",\"movement\":{";
    s += AcsFormat("\"jumps\":%d", m.jumps);
    s += AcsFormat(",\"perfectJumps\":%d", m.perfect_jumps);
    s += AcsFormat(",\"bestStreak\":%d", m.best_perfect_streak);
    s += AcsFormat(",\"strafeTicks\":%d", m.strafe_ticks);
    s += AcsFormat(",\"syncRatio\":%.4f", sync);
    s += AcsFormat(",\"maxSpeed\":%.1f", m.max_speed_seen);
    s += AcsFormat(",\"duckToggles\":%d", m.duck_toggles);
    s += "}";

    s += ",\"usercmd\":{";
    s += AcsFormat("\"worstTimeRatio\":%.4f", c.worst_ratio);
    s += AcsFormat(",\"overspeedWindows\":%d", c.overspeed_windows);
    s += AcsFormat(",\"zeroMsec\":%d", c.zero_msec);
    s += AcsFormat(",\"oversizeMsec\":%d", c.oversize_msec);
    s += AcsFormat(",\"badLerp\":%d", c.bad_lerp);
    s += AcsFormat(",\"impossibleMove\":%d", c.impossible_move);
    s += AcsFormat(",\"longestRepeatRun\":%d", c.duplicate_cmds);
    s += AcsFormat(",\"impulses\":%d", c.impulse_spam);
    s += "}";

    s += ",\"behavior\":{";
    s += AcsFormat("\"kills\":%d", b.kills);
    s += AcsFormat(",\"headshots\":%d", b.headshots);
    s += AcsFormat(",\"deaths\":%d", b.deaths);
    s += AcsFormat(",\"headshotRatio\":%.4f", hs_ratio);
    s += AcsFormat(",\"fastMultikills\":%d", b.fast_multikills);
    s += AcsFormat(",\"fastestKillGapMs\":%.0f", b.fastest_interval * 1000.0);
    s += ",\"killsByWeapon\":{";
    bool first = true;
    for (std::map<std::string, int>::const_iterator it = b.kills_by_weapon.begin();
         it != b.kills_by_weapon.end(); ++it)
    {
        if (!first) s += ",";
        first = false;
        std::map<std::string, int>::const_iterator hs = b.hs_by_weapon.find(it->first);
        int hsn = (hs == b.hs_by_weapon.end()) ? 0 : hs->second;
        s += "\"" + AcsJsonEscape(it->first) + "\":[" + AcsFormat("%d,%d", it->second, hsn) + "]";
    }
    s += "}}";

    s += "}";
    out_json = s;
}

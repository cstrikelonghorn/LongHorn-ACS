// ACS movement engine.
//
// Two things make movement scriptable in GoldSrc, and both leave a signature in the
// usercmd stream.
//
// Bunny-hopping: PM_Jump refuses to re-jump while IN_JUMP is still held
// (`if (pmove->oldbuttons & IN_JUMP) return;`), so chaining hops requires releasing and
// re-pressing the key on the exact tick you touch the ground. A human with the jump key
// on the scroll wheel lands some of those; a script lands all of them.
//
// Air-strafing: gaining speed means turning the view in the same direction as the strafe
// key you are holding, and swapping both together. Humans do this with a phase error that
// shows up as desynchronised ticks. A strafe bot derives the yaw from the key, so the two
// never disagree.

#include "acs.h"

// Ground ticks between landing and the next jump that still counts as frame-perfect. One
// tick of slack, because the landing tick itself may be consumed by the engine.
static const int   kPerfectGroundTicks = 1;
// Air-strafe ticks needed before the sync ratio means anything. Below this the ratio is
// noise - a couple of clean hops would read as 100%.
static const int   kMinStrafeTicks     = 200;
// Ground speed no stock CS 1.6 movement produces while standing on the floor. The knife
// caps at 250; this leaves headroom for the landing tick and map boosts.
static const float kGroundSpeedCeiling = 330.0f;
static const int   kOverspeedRun       = 8;

static bool AtThreshold(int count, int threshold, int repeat)
{
    if (count < threshold) return false;
    return ((count - threshold) % repeat) == 0;
}

void MovementOnTick(PlayerState& p, const TickSample& t)
{
    MovementState& m = p.move;

    if (!t.alive)
    {
        m.ground_ticks   = 0;
        m.perfect_streak = 0;
        return;
    }

    // --- bunny hop timing -----------------------------------------------------
    if (t.jump_pressed() && t.on_ground)
    {
        m.jumps++;
        if (m.ground_ticks <= kPerfectGroundTicks)
        {
            m.perfect_jumps++;
            m.perfect_streak++;
            if (m.perfect_streak > m.best_perfect_streak) m.best_perfect_streak = m.perfect_streak;

            if (AtThreshold(m.perfect_streak, g_cfg.bhop_streak, 4))
            {
                // A long streak is scripted; a shorter one is reported for review because
                // a wheel-bound jump can produce short streaks legitimately, and whether
                // that is allowed is a server policy question rather than a cheat question.
                bool hard = m.perfect_streak >= g_cfg.bhop_streak * 2;
                EvidenceRaise(p, "acs-bhop-script", "Frame-perfect jump chaining",
                    hard ? "DETECTED" : "WARNING", "movement",
                    AcsFormat("streak of %d, %d/%d jumps frame-perfect this session",
                               m.perfect_streak, m.perfect_jumps, m.jumps),
                    "Every jump in the chain was issued within one tick of landing. PM_Jump blocks "
                    "re-jumping while IN_JUMP is held, so each hop needed a separate release and "
                    "press timed to the landing tick.",
                    hard ? 40.0 : 15.0);
            }
        }
        else
        {
            m.perfect_streak = 0;
        }
        m.ground_ticks = 0;
    }

    if (t.on_ground)
    {
        m.ground_ticks++;
        // Landing without jumping again quickly ends the chain.
        if (m.ground_ticks > 12) m.perfect_streak = 0;
    }
    else
    {
        m.ground_ticks = 0;
        m.air_ticks++;

        // --- air-strafe synchronisation ---------------------------------------
        // Only ticks with a strafe key held and the view actually turning carry
        // information about whether the two are being driven from the same source.
        bool  strafing = fabsf(t.sidemove) > 1.0f;
        float dyaw     = t.dyaw;
        if (strafing && fabsf(dyaw) > 0.02f)
        {
            m.strafe_ticks++;
            // +moveright is a negative sidemove in GoldSrc, and gaining speed means
            // turning toward the held key: yaw decreases when strafing right.
            bool right   = (t.sidemove < 0.0f);
            bool yaw_neg = (dyaw < 0.0f);
            if (right == yaw_neg) m.sync_ticks++;
        }

        if (m.strafe_ticks >= kMinStrafeTicks && (m.strafe_ticks % 100) == 0)
        {
            float ratio = (float)m.sync_ticks / (float)m.strafe_ticks;
            if (ratio >= g_cfg.sync_ratio)
            {
                EvidenceRaise(p, "acs-strafe-bot", "Air-strafe synchronisation without error",
                    ratio >= 0.995f ? "DETECTED" : "WARNING", "movement",
                    AcsFormat("%.1f%% sync over %d strafing air ticks", ratio * 100.0f, m.strafe_ticks),
                    "View direction and strafe key agreed on essentially every air tick. Human "
                    "strafing carries a phase error between hand and key; agreement this complete "
                    "means the yaw is being derived from the key rather than aimed.",
                    ratio >= 0.995f ? 40.0 : 15.0);
            }
        }
    }

    // --- speed ----------------------------------------------------------------
    float speed = t.speed2d();
    if (speed > m.max_speed_seen) m.max_speed_seen = speed;

    if (t.on_ground && speed > kGroundSpeedCeiling)
    {
        m.overspeed_ticks++;
        if (m.overspeed_ticks == kOverspeedRun ||
            (m.overspeed_ticks > kOverspeedRun && (m.overspeed_ticks % 40) == 0))
        {
            EvidenceRaise(p, "acs-ground-overspeed", "Ground speed above engine maximum",
                "WARNING", "movement",
                AcsFormat("%.0f u/s on the ground, peak %.0f u/s, %d ticks",
                           speed, m.max_speed_seen, m.overspeed_ticks),
                "Horizontal speed while standing on the floor exceeded what PM_WalkMove produces "
                "for any CS 1.6 weapon. Check for a speed hack, though map boosts and conveyor "
                "entities can also produce this.",
                20.0);
        }
    }
    else if (t.on_ground)
    {
        if (m.overspeed_ticks > 0) m.overspeed_ticks--;
    }

    // --- duck spam ------------------------------------------------------------
    uint16_t duck = (uint16_t)((t.buttons & IN_DUCK) ? 1 : 0);
    if (duck != m.last_duck_state)
    {
        m.duck_toggles++;
        m.last_duck_state = duck;
    }
}

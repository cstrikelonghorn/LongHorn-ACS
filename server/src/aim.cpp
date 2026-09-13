// ACS aim engine.
//
// What the server actually has is a stream of viewangles, one per usercmd. It does not
// have the screen, the targets, or the mouse. So every rule here is a statement about the
// *shape* of that angle stream rather than about where the player was looking.
//
// The distinction that does most of the work: a human aims with a hand, and a hand has
// momentum and error. It accelerates into a movement, overshoots the target, and corrects
// back. An aimbot computes a destination angle and goes there. That difference survives
// smoothing, humanisation and randomisation, because those features change the *speed* of
// the movement without restoring the overshoot-and-correct structure.

#include "acs.h"

// A snap can only be judged from ticks that come after it, so candidates wait this long
// before being resolved. 12 ticks is ~120ms at cl_cmdrate 100.
static const uint32_t kResolveLag  = 12;
static const int      kPreWindow   = 6;   // ticks of run-up that must be quiet
static const int      kPostWindow  = 5;   // ticks that must settle afterwards
static const int      kTrackWindow = 12;  // ticks examined for post-snap tracking
static const float    kMoveFloor   = 0.6f; // deg/tick that counts as the view moving
static const int      kMaxRunSpan  = 5;   // longer than this is a swing, not a snap

// Mean angular speed across an inclusive seq range. Ticks that have aged out of the ring
// are skipped rather than counted as zero, which would fake quiet where we simply have no
// data.
static float MeanSpeedSeq(const PlayerState& p, uint32_t first, uint32_t last)
{
    if (last < first) return 0.0f;
    float sum = 0.0f;
    int   n   = 0;
    for (uint32_t s = first; s <= last; ++s)
    {
        const TickSample* t = p.BySeq(s);
        if (!t) continue;
        sum += t->angular_speed();
        n++;
    }
    return n ? (sum / n) : 0.0f;
}

// Shape of the movement, as two numbers.
//
// mag_cv  - coefficient of variation of the per-tick step sizes. A hand accelerates into
//           a movement and decelerates out of it, so the steps form a bell and the
//           variation is large. Linear interpolation between two computed angles moves
//           the same distance every tick, so the variation collapses to zero.
//
// dir_dev - RMS wobble of each step's direction around the movement's mean direction. A
//           wrist rotating through an arc changes the yaw/pitch ratio as it goes; a
//           computed path holds it fixed.
//
// Both are needed. Direction alone does not separate the two cases, because a fast human
// flick is also nearly one-directional - that was measured against a simulated
// flick-shooter and it scored as straight as the bot did. It is the *speed profile* that
// a hand cannot make uniform.
static void RunShape(const AimState& a, float& mag_cv, float& dir_dev)
{
    mag_cv  = 1.0f;   // fail-safe defaults: "looks human" when there is nothing to judge
    dir_dev = 1.0f;

    int n = a.run_span;
    if (n < 3 || n > ACS_RUN_MAX) return;

    float mag[ACS_RUN_MAX];
    double sum = 0.0, sy = 0.0, sp = 0.0;
    for (int i = 0; i < n; ++i)
    {
        mag[i] = AcsHypot(a.run_dy[i], a.run_dp[i]);
        sum += mag[i];
        sy  += a.run_dy[i];
        sp  += a.run_dp[i];
    }
    if (sum <= 1e-6) return;

    double mean = sum / n;
    double var  = 0.0;
    for (int i = 0; i < n; ++i) { double d = mag[i] - mean; var += d * d; }
    mag_cv = (float)(sqrt(var / n) / mean);

    if (fabs(sy) < 1e-9 && fabs(sp) < 1e-9) return;
    double mean_dir = atan2(sp, sy);
    double dvar = 0.0;
    int    dn   = 0;
    for (int i = 0; i < n; ++i)
    {
        if (mag[i] < mean * 0.15) continue;          // too short to carry a direction
        double d = atan2(a.run_dp[i], a.run_dy[i]) - mean_dir;
        while (d >  3.14159265) d -= 6.28318531;
        while (d < -3.14159265) d += 6.28318531;
        dvar += d * d;
        dn++;
    }
    dir_dev = dn ? (float)sqrt(dvar / dn) : 1.0f;
}

// Mouse input is quantised: the client turns an integer count of mouse counts into an
// angle, so every delta a human produces is an integer multiple of
// (sensitivity * m_yaw). An aimbot writes an arbitrary float.
//
// This is reported as a metric and never on its own as a verdict, for one specific
// reason: GoldSrc delta-encodes usercmd viewangles at 16-bit precision (~0.0055 deg), so
// what reaches the server is already re-quantised onto a different grid than the client
// produced. For common sensitivities the mouse step is ~10x the network step and the
// structure survives, but at very high sensitivity or very low DPI the two grids alias
// and the residual stops being meaningful.
static void UpdateQuantisation(AimState& a, const TickSample& t)
{
    float ady = fabsf(t.dyaw);
    if (ady <= 0.011f || ady >= 2.0f) return;  // below the network grid, or a real swing

    if (a.quant_step <= 0.0f || ady < a.quant_step)
    {
        // A smaller step invalidates residuals measured against the old one.
        if (a.quant_step > 0.0f && ady < a.quant_step * 0.8f)
        {
            a.quant_residual_sum = 0.0;
            a.quant_n = 0;
        }
        a.quant_step = ady;
        return;
    }

    float k = ady / a.quant_step;
    float r = fabsf(k - floorf(k + 0.5f));
    a.quant_residual_sum += r;
    a.quant_n++;
}

// A completed angular run becomes a snap candidate if it covered enough ground, did it
// fast enough, and came out of a quiet view.
static void EndRun(PlayerState& p, const TickSample& t)
{
    AimState& a = p.aim;
    a.run_active = false;

    if (a.run_span <= 0 || a.run_span > kMaxRunSpan) return;
    if (a.run_mag < g_cfg.snap_min_deg) return;
    if (a.run_pre_quiet > g_cfg.snap_quiet_deg) return;

    AimState::Candidate c;
    c.seq       = (t.seq > 0) ? t.seq - 1 : 0;   // last tick that was part of the run
    c.magnitude = a.run_mag;
    c.pre_quiet = a.run_pre_quiet;
    c.span      = a.run_span;
    RunShape(a, c.mag_cv, c.dir_dev);
    a.pending.push_back(c);
}

// Counts yaw direction reversals after a snap.
//
// This is the overshoot test. A human who snaps onto a target passes it and comes back,
// producing at least one sign change; a human tracking a moving target produces several.
// An aimbot that recomputes the angle every tick approaches from one side and never
// crosses over. Sustained movement with zero reversals is the signature.
static bool IsTrackLock(const PlayerState& p, uint32_t from_seq)
{
    int   reversals = 0;
    int   moving    = 0;
    float sum       = 0.0f;
    int   last_sign = 0;

    for (uint32_t s = from_seq + 1; s <= from_seq + (uint32_t)kTrackWindow; ++s)
    {
        const TickSample* t = p.BySeq(s);
        if (!t) return false;                   // incomplete window, do not guess
        sum += t->angular_speed();
        if (fabsf(t->dyaw) <= 0.02f) continue;  // too small to carry a direction
        moving++;
        int sign = (t->dyaw > 0.0f) ? 1 : -1;
        if (last_sign != 0 && sign != last_sign) reversals++;
        last_sign = sign;
    }

    float mean = sum / (float)kTrackWindow;
    // Needs to be actually tracking: not frozen (a player who simply stopped moving the
    // mouse also has zero reversals, and that is not evidence of anything), and not
    // making a fresh large movement.
    if (moving < 6) return false;
    if (mean < 0.05f || mean > 2.0f) return false;
    return reversals == 0;
}

// Raises evidence the first time a counter reaches its threshold and then on every
// `repeat` further hits, so a long session escalates instead of reporting once and going
// quiet.
static bool AtThreshold(int count, int threshold, int repeat)
{
    if (count < threshold) return false;
    return ((count - threshold) % repeat) == 0;
}

static void ResolveCandidate(PlayerState& p, const AimState::Candidate& c)
{
    AimState& a = p.aim;

    // Did the view lock after the movement, or keep wandering? A swing that keeps going
    // is someone turning around, not an aimbot arriving somewhere.
    float settle = MeanSpeedSeq(p, c.seq + 1, c.seq + (uint32_t)kPostWindow);
    if (settle > g_cfg.snap_settle_deg) return;

    // Did a shot follow? Without one, a fast settled movement is just a flick - common,
    // and not evidence. The snap has to be aimed at something.
    const TickSample* fired = NULL;
    for (uint32_t s = c.seq; s <= c.seq + (uint32_t)g_cfg.snap_fire_ticks; ++s)
    {
        const TickSample* t = p.BySeq(s);
        if (t && t->attack_pressed()) { fired = t; break; }
    }
    if (!fired) return;

    a.snap_events++;

    const TickSample* snap_tick = p.BySeq(c.seq);
    if (snap_tick)
    {
        double dt = fired->time - snap_tick->time;
        if (dt >= 0.0 && dt < 1.0)
        {
            a.reaction_sum += dt;
            a.reaction_n++;
            if (a.reaction_min <= 0.0f || (float)dt < a.reaction_min) a.reaction_min = (float)dt;
        }
    }

    if (c.span <= 2) a.instant_snaps++;
    // Uniform step size AND fixed direction together mean the path was computed.
    if (c.span >= 3 && c.mag_cv <= 0.12f && c.dir_dev <= 0.030f) a.linear_snaps++;
    if (IsTrackLock(p, c.seq)) a.track_locks++;

    // --- verdicts -------------------------------------------------------------

    // A fast, settled, shot-at movement on its own is NOT enough for a verdict. An
    // aggressive flick-shooter produces exactly that shape: quiet, a ~50 ms sweep onto
    // the target, and a pre-committed click on arrival. Testing against a simulated
    // flick-shooter profile produced a snap on essentially every engagement.
    //
    // So the bare pattern is reported as WARNING only, and conviction requires one of the
    // two things a hand cannot also do: arriving in <= 2 ticks, or travelling in a
    // straight line.
    if (AtThreshold(a.snap_events, g_cfg.snap_report_at, 10))
    {
        EvidenceRaise(p, "acs-aim-snap", "Snap-to-target aim pattern",
            "WARNING", "aim",
            AcsFormat("%d snap-fire events (%d instant, %d straight), last %.1f deg in %d tick(s)",
                       a.snap_events, a.instant_snaps, a.linear_snaps, c.magnitude, c.span),
            "View left a still position, covered a large angle quickly, settled, and a shot "
            "followed. Fast flick-shooting produces the same shape, so on its own this raises "
            "risk rather than convicting - see the instant/straight rules for the parts that "
            "a hand cannot reproduce.",
            15.0);
    }

    if (AtThreshold(a.instant_snaps, 5, 8))
    {
        EvidenceRaise(p, "acs-aim-instant", "Aim arrives faster than a hand can move it",
            "DETECTED", "aim",
            AcsFormat("%d snaps completed within 2 ticks, last %.1f deg in %d tick(s)",
                       a.instant_snaps, c.magnitude, c.span),
            "A large angle was crossed inside one or two usercmds (~10-20 ms). Mouse input is "
            "accumulated per frame, so a physical flick of this size is spread across several "
            "commands as the hand accelerates. Arriving in one is a written angle, not an aimed "
            "one.",
            50.0);
    }

    if (AtThreshold(a.linear_snaps, 3, 5))
    {
        EvidenceRaise(p, "acs-aim-linear", "Straight-line interpolation in aim path",
            "DETECTED", "aim",
            AcsFormat("%d snaps with uniform step size and fixed direction (cv %.3f, wobble %.3f rad)",
                       a.linear_snaps, c.mag_cv, c.dir_dev),
            "The view covered the same distance on every tick of the movement, in an unchanging "
            "direction. A hand accelerates into a flick and decelerates out of it, and the wrist "
            "changes the yaw/pitch ratio as it rotates. A constant-speed, fixed-direction path is "
            "interpolation between a computed origin and a computed destination - which is what a "
            "smoothed or humanised aimbot is still doing underneath the smoothing.",
            50.0);
    }

    if (AtThreshold(a.track_locks, 5, 10))
    {
        EvidenceRaise(p, "acs-aim-tracklock", "Target tracking without correction",
            "WARNING", "aim",
            AcsFormat("%d post-snap windows with sustained movement and zero direction reversals",
                       a.track_locks),
            "After snapping, the view kept adjusting but never once reversed direction. Human "
            "tracking overshoots and corrects back; a per-tick computed angle approaches from one "
            "side only.",
            25.0);
    }

    // Trigger latency after the view arrives.
    //
    // This deliberately tops out at WARNING, because the obvious stronger reading of it is
    // wrong. It is tempting to argue that a click under ~100 ms after the view lands
    // cannot be a human reaction - but a flick shot is not a reaction. The player commits
    // to the click while the flick is still travelling, so the press lands on arrival by
    // design. Simulating a flick-shooter produced a ~20 ms mean, which is exactly what an
    // aimbot looks like by this measure.
    //
    // What the number is genuinely good for is corroboration: combined with an instant or
    // interpolated arrival it says the whole engagement was machine-timed. On its own it
    // says the player flicks and pre-fires.
    if (a.reaction_n >= 6)
    {
        double mean = a.reaction_sum / a.reaction_n;
        if (mean < 0.060 && AtThreshold(a.reaction_n, 6, 12))
        {
            EvidenceRaise(p, "acs-aim-reaction", "Trigger fires as the view arrives",
                "WARNING", "aim",
                AcsFormat("mean %.0f ms over %d snaps, fastest %.0f ms",
                           mean * 1000.0, a.reaction_n, a.reaction_min * 1000.0),
                "The shot consistently lands within a few milliseconds of the view reaching its "
                "destination. Pre-committed flick shots do this legitimately, so this raises risk "
                "rather than convicting - it is meaningful in combination with an instant or "
                "interpolated arrival, not by itself.",
                12.0);
        }
    }
}

void AimOnTick(PlayerState& p, const TickSample& t)
{
    AimState& a = p.aim;

    if (!t.alive) { a.run_active = false; return; }

    UpdateQuantisation(a, t);

    // --- angular run tracking -------------------------------------------------
    float sp = t.angular_speed();

    if (!a.run_active && sp >= kMoveFloor)
    {
        uint32_t last  = (t.seq >= 1) ? t.seq - 1 : 0;
        uint32_t first = (t.seq >= (uint32_t)kPreWindow) ? t.seq - kPreWindow : 0;
        a.run_pre_quiet = (t.seq >= 1) ? MeanSpeedSeq(p, first, last) : 999.0f;
        a.run_active    = true;
        a.run_start_seq = t.seq;
        a.run_mag       = 0.0f;
        a.run_span      = 0;

    }

    if (a.run_active)
    {
        // Hysteresis: a run continues while the view is still clearly moving, so a single
        // slow tick in the middle of a snap does not split it into two short runs.
        if (sp >= kMoveFloor * 0.5f)
        {
            a.run_mag  += sp;
            a.run_span += 1;
            if (a.run_span <= ACS_RUN_MAX)
            {
                a.run_dy[a.run_span - 1] = t.dyaw;
                a.run_dp[a.run_span - 1] = t.dpitch;
            }

            if (a.run_span > kMaxRunSpan + 3) a.run_active = false;  // a swing, abandon it
        }
        else
        {
            EndRun(p, t);
        }
    }

    // --- resolve candidates that now have enough future ------------------------
    if (!a.pending.empty())
    {
        std::vector<AimState::Candidate> keep;
        keep.reserve(a.pending.size());
        for (size_t i = 0; i < a.pending.size(); ++i)
        {
            const AimState::Candidate& c = a.pending[i];
            if (t.seq >= c.seq + kResolveLag)
                ResolveCandidate(p, c);
            else
                keep.push_back(c);
        }
        a.pending.swap(keep);
    }
}

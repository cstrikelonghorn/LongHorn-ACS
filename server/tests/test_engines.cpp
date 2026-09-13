// ACS engine behaviour tests.
//
// Drives synthetic usercmd streams through the real engines and asserts both directions:
// the cheat-shaped stream must raise the rule, and the human-shaped stream must not. The
// second half is the one that matters - a detector that fires on everything is worse than
// no detector.

#include "acs.h"
#include <stdio.h>
#include <string>
#include <vector>

// --- boundary stubs --------------------------------------------------------
static std::vector<std::string> g_raised;

void EvidenceRaise(PlayerState& p, const char* rule_id, const char* /*rule_name*/,
                   const char* severity, const char* /*category*/,
                   const std::string& subject, const std::string& /*reason*/, double weight)
{
    g_raised.push_back(std::string(rule_id) + "|" + severity + "|" + subject);
    p.risk += weight;
}
void UplinkQueue(const std::string&) {}
void UplinkInit() {}
void UplinkShutdown() {}
void UplinkFlush() {}

// --- engine globals --------------------------------------------------------
enginefuncs_t g_engfuncs;
static globalvars_t g_gv;
globalvars_t* gpGlobals = &g_gv;

static void StubPrint(const char* s) { fputs(s, stdout); }
static const char* StubAuth(edict_t*) { return "STEAM_0:1:99999"; }
static edict_t* StubIndexEnt(int) { return NULL; }
static int StubEntIndex(const edict_t*) { return 1; }

// --- harness ---------------------------------------------------------------
static unsigned int g_seed = 12345;
static double Rand01()
{
    g_seed = g_seed * 1103515245u + 12345u;
    return (double)((g_seed >> 16) & 0x7fff) / 32767.0;
}
static double Noise(double amp) { return (Rand01() * 2.0 - 1.0) * amp; }

struct Sim
{
    PlayerState* p;
    double time;
    float  yaw, pitch;
    float  punch;
    bool   on_ground;
    int    tick;

    void Begin()
    {
        p = AcsPlayer(1);
        p->Reset();
        p->in_use   = true;
        p->entindex = 1;
        p->authid   = "STEAM_0:1:99999";
        p->name     = "test";
        p->session_id = "test";
        p->reported_start = true;
        time = 100.0; yaw = 0.0f; pitch = 0.0f; punch = 0.0f;
        on_ground = true; tick = 0;
        g_raised.clear();
    }

    void Push(unsigned short buttons, int msec = 10, float fwd = 0.0f, float side = 0.0f)
    {
        g_gv.time = (float)time;
        TickSample t;
        memset(&t, 0, sizeof(t));
        t.time = time; t.realtime = time;
        t.msec = (unsigned char)msec; t.lerp_msec = 50;
        t.yaw = yaw; t.pitch = pitch; t.roll = 0.0f;
        t.forwardmove = fwd; t.sidemove = side; t.upmove = 0.0f;
        t.buttons = buttons;
        t.punch_pitch = punch;
        t.vel_x = 200.0f; t.vel_y = 0.0f;
        t.flags = on_ground ? FL_ONGROUND : 0;
        t.on_ground = on_ground;
        t.alive = true; t.health = 100; t.weapon_id = 7;
        AcsPlayerTick(*p, t);
        time += msec / 1000.0;
        tick++;
    }
};

static bool Raised(const char* rule)
{
    for (size_t i = 0; i < g_raised.size(); ++i)
        if (g_raised[i].compare(0, strlen(rule), rule) == 0) return true;
    return false;
}

static bool Raised2(const char* rule, const char* sev)
{
    for (size_t i = 0; i < g_raised.size(); ++i)
        if (g_raised[i].compare(0, strlen(rule), rule) == 0 &&
            g_raised[i].find(std::string("|") + sev + "|") != std::string::npos) return true;
    return false;
}

static int g_pass = 0, g_fail = 0;
static void Expect(const char* what, bool cond)
{
    printf("  %-52s %s\n", what, cond ? "PASS" : "*** FAIL ***");
    if (cond) g_pass++; else g_fail++;
}
static void DumpRaised()
{
    for (size_t i = 0; i < g_raised.size(); ++i)
        printf("      raised: %s\n", g_raised[i].c_str());
}

// Mouse input is quantised to an integer number of counts.
static float Quantise(float deg, float step)
{
    float k = deg / step;
    k = (k < 0) ? -floorf(-k + 0.5f) : floorf(k + 0.5f);
    return k * step;
}

// ---------------------------------------------------------------------------
// Aim
// ---------------------------------------------------------------------------

// A human flick: accelerates, overshoots, corrects back, settles, then fires after a
// visual reaction delay. Takes 8-12 ticks, which is what a hand actually needs.
static void HumanAim(Sim& s)
{
    const float step = 0.044f;   // sensitivity 2.0 * m_yaw 0.022
    for (int rep = 0; rep < 30; ++rep)
    {
        for (int i = 0; i < 90; ++i)            // idle: small drift
        {
            s.yaw += Quantise((float)Noise(0.05), step);
            s.Push(0);
        }

        float total = 25.0f + (float)Rand01() * 20.0f;
        int   span  = 8 + (int)(Rand01() * 4);
        float over  = total * 1.08f;
        for (int i = 0; i < span; ++i)          // bell-shaped acceleration, with overshoot
        {
            float x = (float)(i + 1) / (float)span;
            float w = sinf(x * 3.14159f) * 1.6f / (float)span;
            s.yaw += Quantise(over * w, step);
            s.pitch += Quantise(over * w * 0.15f, step);
            s.Push(0);
        }
        for (int i = 0; i < 4; ++i)             // correct back onto the target
        {
            s.yaw -= Quantise(total * 0.02f, step);
            s.Push(0);
        }
        for (int i = 0; i < 18; ++i)            // reaction delay, then fire
        {
            s.yaw += Quantise((float)Noise(0.03), step);
            s.Push(i == 17 ? IN_ATTACK : 0);
        }
    }
}

// An aimbot: quiet, one or two ticks of travel, locked, shot.
static void BotAim(Sim& s)
{
    for (int rep = 0; rep < 30; ++rep)
    {
        for (int i = 0; i < 90; ++i) { s.yaw += (float)Noise(0.04); s.Push(0); }

        float total = 30.0f + (float)Rand01() * 25.0f;
        s.yaw   += total * 0.5f;  s.pitch += total * 0.5f * 0.22f; s.Push(0);
        s.yaw   += total * 0.5f;  s.pitch += total * 0.5f * 0.22f; s.Push(0);

        s.Push(0);
        s.Push(IN_ATTACK);                      // fire 2 ticks after arrival
        for (int i = 0; i < 14; ++i) { s.yaw += 0.15f; s.Push(0); }  // no-overshoot tracking
    }
}

// A "smoothed"/"humanised" aimbot: same destination, reached over 4 ticks by linear
// interpolation. This is what defeats a naive one-tick-snap detector, and what the
// linearity test exists for.
static void SmoothBotAim(Sim& s)
{
    for (int rep = 0; rep < 30; ++rep)
    {
        for (int i = 0; i < 90; ++i) { s.yaw += (float)Noise(0.04); s.Push(0); }

        float total = 30.0f + (float)Rand01() * 25.0f;
        float ratio = 0.22f;
        for (int i = 0; i < 4; ++i)
        {
            s.yaw   += total * 0.25f;
            s.pitch += total * 0.25f * ratio;   // fixed proportion = straight line
            s.Push(0);
        }
        s.Push(0);
        s.Push(IN_ATTACK);
        for (int i = 0; i < 14; ++i) { s.yaw += (float)Noise(0.03); s.Push(0); }
    }
}

// An aggressive human flick-shooter: fast (5-6 ticks) and fires soon after arriving.
// This is the closest honest behaviour to a snap, so it is the false-positive boundary.
static void FlickHuman(Sim& s)
{
    const float step = 0.044f;
    for (int rep = 0; rep < 30; ++rep)
    {
        for (int i = 0; i < 90; ++i) { s.yaw += Quantise((float)Noise(0.05), step); s.Push(0); }

        float total = 28.0f + (float)Rand01() * 18.0f;
        int   span  = 5 + (int)(Rand01() * 2);
        float over  = total * 1.10f;
        for (int i = 0; i < span; ++i)
        {
            float x = (float)(i + 1) / (float)span;
            float w = sinf(x * 3.14159f) * 1.6f / (float)span;
            s.yaw   += Quantise(over * w, step);
            s.pitch += Quantise(over * w * (0.10f + (float)Noise(0.05)), step);
            s.Push(0);
        }
        s.yaw -= Quantise(total * 0.03f, step);      // correct back off the overshoot
        s.Push(0);
        s.Push(IN_ATTACK);                            // fires quickly after settling
        for (int i = 0; i < 20; ++i) { s.yaw += Quantise((float)Noise(0.04), step); s.Push(0); }
    }
}

// ---------------------------------------------------------------------------
// Recoil
// ---------------------------------------------------------------------------
// factor 1.0 with tiny noise is a cheat; a partial, lagged, noisy pull is a human.
static void Spray(Sim& s, double factor, double noise, bool lag)
{
    for (int burst = 0; burst < 6; ++burst)
    {
        s.punch = 0.0f;
        float prev_punch = 0.0f;
        float last_dpunch = 0.0f;

        for (int i = 0; i < 96; ++i)
        {
            s.punch *= 0.90f;                       // engine decay
            if (i % 6 == 0) s.punch -= 0.85f;       // kick on the shot tick

            float dpunch = s.punch - prev_punch;
            prev_punch   = s.punch;

            float src = lag ? last_dpunch : dpunch;
            s.pitch += (float)(-src * factor + Noise(noise));
            last_dpunch = dpunch;

            s.Push(IN_ATTACK);
        }
        for (int i = 0; i < 60; ++i) { s.punch *= 0.9f; s.Push(0); }   // gap between bursts
    }
}

// ---------------------------------------------------------------------------
// Movement
// ---------------------------------------------------------------------------
static void Hop(Sim& s, int ground_ticks_min, int ground_ticks_max, int hops)
{
    for (int h = 0; h < hops; ++h)
    {
        int g = ground_ticks_min + (int)(Rand01() * (ground_ticks_max - ground_ticks_min + 1));
        s.on_ground = true;
        for (int i = 0; i < g; ++i) s.Push(0, 10, 400.0f);      // on ground, jump released
        s.Push(IN_JUMP, 10, 400.0f);                            // press on the landing tick
        s.on_ground = false;
        for (int i = 0; i < 22; ++i) s.Push(IN_JUMP, 10, 400.0f);
        s.Push(0, 10, 400.0f);                                  // release before landing
    }
}

int main()
{
    memset(&g_engfuncs, 0, sizeof(g_engfuncs));
    g_engfuncs.pfnServerPrint       = StubPrint;
    g_engfuncs.pfnGetPlayerAuthId   = StubAuth;
    g_engfuncs.pfnPEntityOfEntIndex = StubIndexEnt;
    g_engfuncs.pfnIndexOfEdict      = StubEntIndex;
    g_gv.time = 100.0f;
    g_cfg.LoadDefaults();

    Sim s;

    printf("\nAIM\n");
    s.Begin(); HumanAim(s);
    printf("    human: %d snaps, %d linear, %d locks\n",
           s.p->aim.snap_events, s.p->aim.linear_snaps, s.p->aim.track_locks);
    Expect("human flicking raises no aim evidence", !Raised("acs-aim"));
    if (Raised("acs-aim")) DumpRaised();

    s.Begin(); BotAim(s);
    printf("    bot:   %d snaps, %d linear, %d locks, reaction %.0fms\n",
           s.p->aim.snap_events, s.p->aim.linear_snaps, s.p->aim.track_locks,
           s.p->aim.reaction_n ? (s.p->aim.reaction_sum / s.p->aim.reaction_n) * 1000.0 : 0.0);
    Expect("aimbot snap pattern is detected", Raised("acs-aim-snap"));
    Expect("one-tick arrival is DETECTED", Raised2("acs-aim-instant", "DETECTED"));

    s.Begin(); SmoothBotAim(s);
    printf("    smooth bot: %d snaps, %d linear, %d locks\n",
           s.p->aim.snap_events, s.p->aim.linear_snaps, s.p->aim.track_locks);
    Expect("4-tick interpolated aimbot is detected", Raised("acs-aim-snap"));
    Expect("its straight-line path is identified", Raised("acs-aim-linear"));

    s.Begin(); FlickHuman(s);
    printf("    flick human: %d snaps, %d instant, %d linear  [boundary case]\n",
           s.p->aim.snap_events, s.p->aim.linear_snaps, s.p->aim.track_locks);
    Expect("fast human flicking is not called linear", !Raised("acs-aim-linear"));
    Expect("fast human flicking is not called instant", !Raised("acs-aim-instant"));
    Expect("fast human flicking is never DETECTED", !Raised2("acs-aim", "DETECTED"));

    printf("\nRECOIL\n");
    s.Begin(); Spray(s, 0.50, 0.16, true);
    printf("    human: %d bursts, %d flagged, best r=%.3f, best residual=%.3f\n",
           s.p->recoil.bursts_analysed, s.p->recoil.bursts_compensated,
           s.p->recoil.best_r, s.p->recoil.best_residual);
    Expect("partial lagged compensation raises nothing", !Raised("acs-recoil"));
    if (Raised("acs-recoil")) DumpRaised();

    s.Begin(); Spray(s, 0.80, 0.09, true);
    printf("    skilled: %d bursts, %d flagged, best r=%.3f, best residual=%.3f\n",
           s.p->recoil.bursts_analysed, s.p->recoil.bursts_compensated,
           s.p->recoil.best_r, s.p->recoil.best_residual);
    Expect("skilled human compensation raises nothing", !Raised("acs-recoil"));
    if (Raised("acs-recoil")) DumpRaised();

    s.Begin(); Spray(s, 1.00, 0.01, false);
    printf("    cheat: %d bursts, %d flagged, best r=%.3f, best residual=%.3f\n",
           s.p->recoil.bursts_analysed, s.p->recoil.bursts_compensated,
           s.p->recoil.best_r, s.p->recoil.best_residual);
    Expect("exact recoil cancellation is detected", Raised("acs-recoil-compensation"));

    printf("\nMOVEMENT\n");
    s.Begin(); Hop(s, 0, 4, 40);
    printf("    human: %d/%d perfect, best streak %d\n",
           s.p->move.perfect_jumps, s.p->move.jumps, s.p->move.best_perfect_streak);
    Expect("inconsistent hop timing raises nothing", !Raised("acs-bhop"));
    if (Raised("acs-bhop")) DumpRaised();

    s.Begin(); Hop(s, 0, 1, 40);
    printf("    script: %d/%d perfect, best streak %d\n",
           s.p->move.perfect_jumps, s.p->move.jumps, s.p->move.best_perfect_streak);
    Expect("frame-perfect hop chaining is detected", Raised("acs-bhop-script"));

    printf("\nUSERCMD\n");
    s.Begin();
    for (int i = 0; i < 4000; ++i) s.Push(0, 10);          // honest: msec matches elapsed
    printf("    honest: worst time ratio %.3f\n", s.p->cmd.worst_ratio);
    Expect("matching msec and elapsed time raises nothing", !Raised("acs-speedhack"));

    // Speed hack: claims 13ms of simulation per 10ms of real time.
    s.Begin();
    for (int i = 0; i < 4000; ++i)
    {
        g_gv.time = (float)s.time;
        TickSample t; memset(&t, 0, sizeof(t));
        t.time = s.time; t.msec = 13; t.lerp_msec = 50;
        t.yaw = s.yaw; t.pitch = s.pitch; t.alive = true; t.health = 100;
        t.on_ground = true; t.flags = FL_ONGROUND;
        AcsPlayerTick(*s.p, t);
        s.time += 0.010;                                   // but only 10ms actually passed
    }
    printf("    hacked: worst time ratio %.3f, %d bad windows\n",
           s.p->cmd.worst_ratio, s.p->cmd.overspeed_windows);
    Expect("inflated msec is detected as a speed hack", Raised("acs-speedhack"));

    s.Begin();
    for (int i = 0; i < 300; ++i)
    {
        g_gv.time = (float)s.time;
        TickSample t; memset(&t, 0, sizeof(t));
        t.time = s.time; t.msec = 10; t.lerp_msec = 50;
        t.forwardmove = 2000.0f;                           // far above cl_forwardspeed
        t.alive = true; t.health = 100; t.on_ground = true; t.flags = FL_ONGROUND;
        AcsPlayerTick(*s.p, t);
        s.time += 0.010;
    }
    Expect("out-of-range movement request is detected", Raised("acs-impossible-move"));

    printf("\n%d passed, %d failed\n\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}

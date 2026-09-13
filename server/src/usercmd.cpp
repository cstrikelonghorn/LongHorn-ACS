// ACS usercmd engine.
//
// This engine does not look at what the player did - it looks at whether the packets
// describing it could have come from a stock client at all. Everything here is a
// structural claim about the command stream: how much time it claims to cover, how fast
// it arrives, and whether its fields are inside the range the retail client can produce.
//
// A note on what is deliberately *not* a verdict here. Byte-identical consecutive
// commands look like a replayed macro and are tempting to flag, but a player running in a
// straight line at a stable framerate emits exactly that: same angles, same buttons, same
// forwardmove, same msec. The longest repeat run is therefore recorded as telemetry and
// left for the correlation engine to weigh against other signals, rather than raised as
// evidence on its own.

#include "acs.h"

static const double kWindow          = 5.0;   // seconds of game time per measurement window
static const double kMinWindowSpan   = 3.0;   // do not judge a window shorter than this
static const float  kCmdRateCeiling  = 160.0f; // cmds/sec no stock client sustains
static const int    kBadWindowReport = 3;

static uint32_t HashCmd(const TickSample& t)
{
    // FNV-1a over the fields a client controls.
    uint32_t h = 2166136261u;
    const float f[6] = { t.yaw, t.pitch, t.forwardmove, t.sidemove, t.upmove, (float)t.msec };
    const unsigned char* raw = (const unsigned char*)f;
    for (size_t i = 0; i < sizeof(f); ++i) { h ^= raw[i]; h *= 16777619u; }
    h ^= t.buttons; h *= 16777619u;
    h ^= t.impulse; h *= 16777619u;
    return h;
}

static void CloseWindow(PlayerState& p, const TickSample& t)
{
    CmdState& c = p.cmd;
    double span = t.time - c.window_started;
    if (span < kMinWindowSpan) return;

    // The client tells us how long each command covered. Summed over a window, that has
    // to track the server's own clock. A client running the engine faster than real time
    // inflates the total - it is claiming more simulated time than actually elapsed.
    double claimed = (double)c.window_msec / 1000.0;
    double ratio   = claimed / span;
    if (ratio > c.worst_ratio) c.worst_ratio = ratio;

    float rate = (float)c.window_cmds / (float)span;

    if (ratio > (double)g_cfg.speed_ratio)
    {
        c.overspeed_windows++;
        if (c.overspeed_windows == kBadWindowReport ||
            (c.overspeed_windows > kBadWindowReport && (c.overspeed_windows % 3) == 0))
        {
            EvidenceRaise(p, "acs-speedhack", "Client claims more time than elapsed",
                "DETECTED", "usercmd",
                AcsFormat("msec sum %.2fs over %.2fs of server time (ratio %.3f, worst %.3f), %d windows",
                           claimed, span, ratio, c.worst_ratio, c.overspeed_windows),
                "Summed usercmd durations exceeded real elapsed time across repeated windows. The "
                "client is asking the server to simulate more movement time than has passed, which "
                "is what a speed hack does.",
                55.0);
        }
    }
    else if (c.overspeed_windows > 0)
    {
        c.overspeed_windows--;   // decay, so a single lag artefact does not accumulate
    }

    if (rate > kCmdRateCeiling)
    {
        EvidenceRaise(p, "acs-cmd-flood", "Command rate above client maximum",
            "WARNING", "usercmd",
            AcsFormat("%.0f cmds/sec sustained over %.1fs", rate, span),
            "Sustained usercmd rate is well above what cl_cmdrate permits on a retail client.",
            25.0);
    }

    c.window_started = t.time;
    c.window_msec    = 0;
    c.window_cmds    = 0;
}

void CmdOnTick(PlayerState& p, const TickSample& t)
{
    CmdState& c = p.cmd;

    if (c.window_started <= 0.0) c.window_started = t.time;

    c.window_msec += t.msec;
    c.window_cmds++;

    if (t.msec == 0)   c.zero_msec++;
    if (t.msec > 100)  c.oversize_msec++;

    // lerp_msec is the client's interpolation amount. The retail client clamps it into
    // [0, 100]; anything outside means the struct was written by something else.
    if (t.lerp_msec < 0 || t.lerp_msec > 100)
    {
        c.bad_lerp++;
        if (c.bad_lerp == 5 || (c.bad_lerp > 5 && (c.bad_lerp % 50) == 0))
        {
            EvidenceRaise(p, "acs-bad-lerp", "usercmd lerp_msec outside client range",
                "WARNING", "usercmd",
                AcsFormat("lerp_msec=%d seen %d times", (int)t.lerp_msec, c.bad_lerp),
                "The retail client clamps lerp_msec to 0..100. Values outside that range indicate "
                "the usercmd was constructed rather than produced by the stock client.",
                30.0);
        }
    }

    // cl_forwardspeed and cl_sidespeed top out at 400 on the retail client, and the value
    // is what the client *asks* for - the server clamps the resulting velocity, but a
    // request above 400 still tells us the client is not stock.
    float worst = fabsf(t.forwardmove);
    if (fabsf(t.sidemove) > worst) worst = fabsf(t.sidemove);
    if (worst > g_cfg.max_move + 0.5f)
    {
        c.impossible_move++;
        if (c.impossible_move == 3 || (c.impossible_move > 3 && (c.impossible_move % 50) == 0))
        {
            EvidenceRaise(p, "acs-impossible-move", "Movement request above client maximum",
                "DETECTED", "usercmd",
                AcsFormat("move request %.1f (limit %.0f), %d times", worst, g_cfg.max_move, c.impossible_move),
                "forwardmove/sidemove exceeded what cl_forwardspeed and cl_sidespeed can produce on "
                "a retail client. The usercmd was written by modified code.",
                50.0);
        }
    }

    // Telemetry only - see the note at the top of this file.
    uint32_t h = HashCmd(t);
    bool active = (t.buttons != 0) || fabsf(t.forwardmove) > 1.0f || fabsf(t.sidemove) > 1.0f;
    if (active && h == c.last_hash)
    {
        c.repeat_run++;
        if (c.repeat_run > c.duplicate_cmds) c.duplicate_cmds = c.repeat_run;
    }
    else
    {
        c.repeat_run = 0;
    }
    c.last_hash = h;

    if (t.impulse != 0) c.impulse_spam++;

    if (t.time - c.window_started >= kWindow) CloseWindow(p, t);
}

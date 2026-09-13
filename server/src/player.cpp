// ACS player lifecycle and tick fan-out.

#include "acs.h"
#include <string.h>

PlayerState g_players[ACS_MAX_PLAYERS];
AcsConfig  g_cfg;

// std::string / std::vector / std::map members mean this cannot be a memset. Every field
// is cleared explicitly, which also makes it obvious when a new field is added to one of
// the engine structs and not reset here.
void PlayerState::Reset()
{
    in_use   = false;
    entindex = 0;
    name.clear();
    authid.clear();
    ip.clear();
    session_id.clear();
    connect_time   = 0.0;
    reported_start = false;
    current_weapon = 0;
    current_clip   = 0;

    ring_head  = 0;
    ring_total = 0;
    memset(ring, 0, sizeof(ring));   // TickSample is POD, so this one is fine

    aim.pending.clear();
    aim.run_active = false;
    aim.run_start_seq = 0;
    aim.run_mag = 0.0f;
    aim.run_span = 0;
    aim.run_pre_quiet = 0.0f;
    memset(aim.run_dy, 0, sizeof(aim.run_dy));
    memset(aim.run_dp, 0, sizeof(aim.run_dp));
    aim.snap_events = 0;
    aim.instant_snaps = 0;
    aim.linear_snaps = 0;
    aim.track_locks = 0;
    aim.reaction_sum = 0.0;
    aim.reaction_n = 0;
    aim.reaction_min = 0.0f;
    aim.quant_residual_sum = 0.0;
    aim.quant_n = 0;
    aim.quant_step = 0.0f;

    recoil.burst_weapon = 0;
    recoil.burst_started = 0.0;
    recoil.last_fire_time = 0.0;
    recoil.prev_punch_pitch = 0.0f;
    recoil.have_prev_punch = false;
    recoil.dview.clear();
    recoil.dpunch.clear();
    recoil.bursts_analysed = 0;
    recoil.bursts_compensated = 0;
    recoil.predictive_bursts = 0;
    recoil.best_r = 0.0;
    recoil.best_residual = 0.0;
    recoil.sum_residual = 0.0;
    recoil.residual_n = 0;

    move.ground_ticks = 0;
    move.jumps = 0;
    move.perfect_jumps = 0;
    move.perfect_streak = 0;
    move.best_perfect_streak = 0;
    move.air_ticks = 0;
    move.sync_ticks = 0;
    move.strafe_ticks = 0;
    move.max_speed_seen = 0.0f;
    move.overspeed_ticks = 0;
    move.duck_toggles = 0;
    move.last_duck_state = 0;

    cmd.window_started = 0.0;
    cmd.window_realtime_started = 0.0;
    cmd.window_msec = 0;
    cmd.window_cmds = 0;
    cmd.worst_ratio = 0.0;
    cmd.overspeed_windows = 0;
    cmd.zero_msec = 0;
    cmd.oversize_msec = 0;
    cmd.bad_lerp = 0;
    cmd.impossible_move = 0;
    cmd.duplicate_cmds = 0;
    cmd.impulse_spam = 0;
    cmd.last_hash = 0;
    cmd.repeat_run = 0;

    behavior.kills = 0;
    behavior.headshots = 0;
    behavior.deaths = 0;
    behavior.shots = 0;
    behavior.kills_by_weapon.clear();
    behavior.hs_by_weapon.clear();
    behavior.last_kill_time = 0.0;
    behavior.fast_multikills = 0;
    behavior.fastest_interval = 0.0;

    evidence_counts.clear();
    evidence_last.clear();
    risk = 0.0;
}

PlayerState* AcsPlayer(int entindex)
{
    if (entindex < 1 || entindex >= ACS_MAX_PLAYERS) return NULL;
    return &g_players[entindex];
}

PlayerState* AcsPlayerByEdict(const edict_t* e)
{
    if (!e) return NULL;
    int idx = ENTINDEX((edict_t*)e);
    return AcsPlayer(idx);
}

void AcsPlayerConnect(int entindex, edict_t* e, const char* name, const char* ip)
{
    PlayerState* p = AcsPlayer(entindex);
    if (!p) return;

    p->Reset();
    p->in_use       = true;
    p->entindex     = entindex;
    p->name         = name ? name : "";
    p->ip           = ip ? ip : "";
    p->connect_time = gpGlobals->time;
    p->session_id   = AcsRandomId(8);

    // At ClientConnect the auth id is usually still STEAM_ID_PENDING. The real one is
    // picked up lazily on the first tick, which is also where the session_start event is
    // emitted - there is no value in telling the backend about a session we cannot name.
    const char* auth = GETPLAYERAUTHID(e);
    p->authid = auth ? auth : "";
}

void AcsPlayerDisconnect(int entindex)
{
    PlayerState* p = AcsPlayer(entindex);
    if (!p || !p->in_use) return;

    if (p->reported_start)
    {
        std::string summary;
        BehaviorSessionSummary(*p, summary);
        UplinkQueue(summary);
    }

    p->Reset();
}

static bool AuthResolved(const std::string& id)
{
    if (id.empty()) return false;
    if (id == "STEAM_ID_PENDING") return false;
    return true;
}

static void EmitSessionStart(PlayerState& p)
{
    std::string ev = "{";
    ev += "\"type\":\"session_start\"";
    ev += ",\"source\":\"rehlds\"";
    ev += ",\"sessionId\":\"" + AcsJsonEscape(p.session_id) + "\"";
    ev += ",\"authId\":\""    + AcsJsonEscape(p.authid)     + "\"";
    ev += ",\"name\":\""      + AcsJsonEscape(p.name)       + "\"";
    ev += ",\"ip\":\""        + AcsJsonEscape(p.ip)         + "\"";
    ev += "}";
    UplinkQueue(ev);
    p.reported_start = true;
}

void AcsPlayerTick(PlayerState& p, const TickSample& in)
{
    if (!g_cfg.enabled || !p.in_use) return;

    TickSample t = in;
    t.seq = p.ring_total;

    // Deltas are computed here rather than at the call site so that every consumer sees
    // wrap-corrected values. The very first tick of a session has no predecessor and is
    // recorded with zero deltas rather than a spurious jump from 0.
    const TickSample* prev = p.At(0);
    if (prev && p.ring_total > 0)
    {
        t.dyaw         = AcsAngleDelta(t.yaw,   prev->yaw);
        t.dpitch       = AcsAngleDelta(t.pitch, prev->pitch);
        t.buttons_prev = prev->buttons;
    }
    else
    {
        t.dyaw = t.dpitch = 0.0f;
        t.buttons_prev = t.buttons;
    }

    p.ring[p.ring_head] = t;
    p.ring_head = (p.ring_head + 1) % ACS_TICK_RING;
    p.ring_total++;

    if (!p.reported_start)
    {
        if (!AuthResolved(p.authid))
        {
            edict_t* e = INDEXENT(p.entindex);
            if (e)
            {
                const char* auth = GETPLAYERAUTHID(e);
                if (auth) p.authid = auth;
            }
        }
        if (AuthResolved(p.authid) || p.ring_total > 600)
            EmitSessionStart(p);
    }

    if (t.attack_pressed()) p.behavior.shots++;

    AimOnTick(p, t);
    RecoilOnTick(p, t);
    MovementOnTick(p, t);
    CmdOnTick(p, t);
}

// ACS - ReHLDS server-side behavioural engine.
//
// Tier 3 of the ACS stack: the viewpoint that does not depend on the player running
// anything. Everything here is derived from data the server already receives - the
// usercmd stream, the player entity state, and the engine messages the game DLL emits.
//
// The design constraint that shapes this file: GoldSrc gives us ~100 usercmds per second
// per player and nothing else. All detection is therefore built out of the shape of that
// stream over time, not out of any single packet.
#ifndef ACS_H
#define ACS_H

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#include <extdll.h>
#include <dllapi.h>
#include <meta_api.h>

// extdll.h drags in windows.h, whose min/max macros break <algorithm> and <limits>.
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

#include <stdint.h>
#include <math.h>
#include <string>
#include <vector>
#include <map>

#define ACS_NAME     "ACS"
#define ACS_VERSION  "1.0.0"

// Slot 0 is unused; GoldSrc entity indices for players are 1..maxplayers.
#define ACS_MAX_PLAYERS 33

// ~5 seconds of history at cl_cmdrate 101. Every window used by the engines below must
// fit inside this, because anything older is gone.
#define ACS_TICK_RING 512

// Longest angular run kept for shape analysis. Anything longer is a swing, not a snap.
#define ACS_RUN_MAX 12

// ---------------------------------------------------------------------------
// Angle helpers
// ---------------------------------------------------------------------------

// Shortest signed distance from b to a, in degrees. Every angular comparison in this
// plugin goes through here - a raw subtraction produces a 359-degree "snap" every time
// a player crosses the yaw wrap point, which would otherwise be the single largest
// source of false positives in the aim engine.
static inline float AcsAngleDelta(float a, float b)
{
    float d = a - b;
    while (d > 180.0f)  d -= 360.0f;
    while (d < -180.0f) d += 360.0f;
    return d;
}

static inline float AcsHypot(float a, float b)
{
    return sqrtf(a * a + b * b);
}

// ---------------------------------------------------------------------------
// One usercmd, plus the entity state that was true when it arrived
// ---------------------------------------------------------------------------
struct TickSample
{
    double   time;            // gpGlobals->time when the cmd was processed
    double   realtime;        // wall clock, for the msec/time consistency check
    uint32_t seq;             // monotonic per player

    uint8_t  msec;            // cmd duration the client claims
    int16_t  lerp_msec;

    float    yaw, pitch, roll;      // cmd viewangles as sent
    float    dyaw, dpitch;          // deltas against the previous cmd

    float    forwardmove, sidemove, upmove;
    uint16_t buttons;
    uint16_t buttons_prev;
    uint8_t  impulse;
    uint8_t  weaponselect;

    // Sampled from pev at CmdStart, i.e. the state the cmd is about to act on.
    float    punch_pitch, punch_yaw;
    float    vel_x, vel_y, vel_z;
    float    origin_z;
    int      flags;
    bool     on_ground;
    bool     ducking;
    bool     alive;
    int      health;
    int      weapon_id;

    bool attack_down()      const { return (buttons & IN_ATTACK) != 0; }
    bool attack_pressed()   const { return (buttons & IN_ATTACK) && !(buttons_prev & IN_ATTACK); }
    bool jump_pressed()     const { return (buttons & IN_JUMP)   && !(buttons_prev & IN_JUMP); }
    float speed2d()         const { return AcsHypot(vel_x, vel_y); }
    float angular_speed()   const { return AcsHypot(dyaw, dpitch); }
};

// ---------------------------------------------------------------------------
// Per-engine state
// ---------------------------------------------------------------------------

struct AimState
{
    // A snap cannot be judged at the tick it happens - whether the view settled, and
    // whether a shot followed, are only knowable a few ticks later. Candidates therefore
    // sit here until enough future ticks exist to resolve them.
    struct Candidate
    {
        uint32_t seq;           // seq of the tick holding the snap
        float    magnitude;     // total angular distance covered
        float    pre_quiet;     // mean angular speed of the run-up
        int      span;          // how many ticks the movement took
        float    mag_cv;        // variation in per-tick step size; a hand accelerates, code does not
        float    dir_dev;       // RMS wobble of step direction, radians
    };
    std::vector<Candidate> pending;

    // A snap is a run of consecutive moving ticks bounded by quiet on both sides, so the
    // run has to be accumulated as it happens and only judged once it ends.
    bool     run_active;
    uint32_t run_start_seq;
    float    run_mag;
    int      run_span;
    float    run_pre_quiet;
    // Individual steps of the run. Runs are bounded to a handful of ticks, so keeping
    // them lets the shape tests below work on the profile rather than on summary sums.
    float    run_dy[ACS_RUN_MAX];
    float    run_dp[ACS_RUN_MAX];

    int      snap_events;           // confirmed snap-then-fire events this session
    int      instant_snaps;         // of those, ones that arrived in <= 2 ticks
    int      linear_snaps;          // of those, ones that travelled in a straight angular line
    int      track_locks;           // post-snap tracking with no human overshoot/correction
    double   reaction_sum;          // seconds from snap to trigger, for the mean
    int      reaction_n;
    float    reaction_min;

    // Mouse-quantisation estimate. See aim.cpp for why this is telemetry and not a verdict.
    double   quant_residual_sum;
    int      quant_n;
    float    quant_step;
};

struct RecoilState
{
    // A burst is a run of consecutive firing ticks with one weapon. Recoil compensation
    // is only measurable inside one, and bursts are short, so the samples are kept as
    // plain arrays - that makes the lagged correlation below trivial to compute.
    int      burst_weapon;
    double   burst_started;
    double   last_fire_time;
    float    prev_punch_pitch;
    bool     have_prev_punch;

    std::vector<float> dview;       // per-tick view pitch delta
    std::vector<float> dpunch;      // per-tick punchangle pitch delta

    int      bursts_analysed;
    int      bursts_compensated;    // correlation and residual both passed
    int      predictive_bursts;     // compensation that led the kick instead of following it
    double   best_r;
    double   best_residual;
    double   sum_residual;
    int      residual_n;
};

struct MovementState
{
    int      ground_ticks;          // consecutive ticks on the ground right now
    int      jumps;
    int      perfect_jumps;         // jump issued within one tick of landing
    int      perfect_streak;
    int      best_perfect_streak;

    int      air_ticks;
    int      sync_ticks;            // air ticks where strafe key and yaw direction agree
    int      strafe_ticks;          // air ticks with a strafe key held at all

    float    max_speed_seen;
    int      overspeed_ticks;

    int      duck_toggles;
    uint16_t last_duck_state;
};

struct CmdState
{
    // Speed-hack detection: the client tells us how long each cmd lasted. Summed, that
    // must track the wall clock. A client running the engine fast inflates it.
    double   window_started;
    double   window_realtime_started;
    uint32_t window_msec;
    int      window_cmds;
    double   worst_ratio;
    int      overspeed_windows;

    int      zero_msec;
    int      oversize_msec;
    int      bad_lerp;
    int      impossible_move;       // forwardmove/sidemove beyond what any stock client sends
    int      duplicate_cmds;        // byte-identical consecutive cmds, i.e. a replayed macro
    int      impulse_spam;

    uint32_t last_hash;
    int      repeat_run;
};

struct BehaviorState
{
    int      kills;
    int      headshots;
    int      deaths;
    int      shots;                 // attack rising edges
    std::map<std::string, int> kills_by_weapon;
    std::map<std::string, int> hs_by_weapon;
    double   last_kill_time;
    int      fast_multikills;       // kills chained faster than a view can travel between targets
    double   fastest_interval;
};

// ---------------------------------------------------------------------------
// Player
// ---------------------------------------------------------------------------
struct PlayerState
{
    bool        in_use;
    int         entindex;
    std::string name;
    std::string authid;
    std::string ip;
    std::string session_id;
    double      connect_time;
    bool        reported_start;

    // Set from the CurWeapon engine message, which is the only portable way to know what
    // a player is actually holding without linking against game-DLL internals.
    int         current_weapon;
    int         current_clip;

    TickSample  ring[ACS_TICK_RING];
    uint32_t    ring_head;          // index of the next write
    uint32_t    ring_total;         // total ticks ever, also the next seq

    AimState      aim;
    RecoilState   recoil;
    MovementState move;
    CmdState      cmd;
    BehaviorState behavior;

    std::map<std::string, int>    evidence_counts;
    std::map<std::string, double> evidence_last;
    double      risk;

    void Reset();

    // back == 0 is the most recent tick. Returns NULL once back runs past what we hold.
    const TickSample* At(uint32_t back) const
    {
        if (back >= ring_total || back >= ACS_TICK_RING) return NULL;
        uint32_t idx = (ring_head + ACS_TICK_RING - 1 - back) % ACS_TICK_RING;
        return &ring[idx];
    }

    // Locates a tick by its sequence number, or NULL if it has aged out of the ring.
    const TickSample* BySeq(uint32_t seq) const
    {
        if (seq >= ring_total) return NULL;
        return At(ring_total - 1 - seq);
    }
};

// ---------------------------------------------------------------------------
// Configuration, read from cfg/acs.cfg - deliberately not from cvars, so the
// uplink secret never becomes something rcon or cvarlist can read back.
// ---------------------------------------------------------------------------
struct AcsConfig
{
    bool        enabled;
    std::string endpoint;
    std::string secret;
    std::string server_id;
    bool        log_to_console;

    // Aim
    float       snap_min_deg;        // angular distance that counts as a snap
    float       snap_quiet_deg;      // mean speed of the run-up that must precede it
    float       snap_settle_deg;     // mean speed after it that counts as "locked"
    int         snap_fire_ticks;     // shot must land within this many ticks of the snap
    int         snap_report_at;      // confirmed snaps before evidence is raised

    // Recoil
    float       recoil_r;            // correlation past which compensation stops looking human
    float       recoil_residual;     // per-shot RMS compensation error, degrees
    int         recoil_min_shots;
    int         recoil_report_at;

    // Movement
    int         bhop_streak;         // consecutive frame-perfect jumps before reporting
    float       sync_ratio;          // air-strafe sync ratio past which it is scripted

    // Usercmd
    float       speed_ratio;         // claimed-time / real-time before it is a speed hack
    float       max_move;            // largest |forwardmove| a stock client emits

    void LoadDefaults();
    bool LoadFile(const char* path);
};

extern AcsConfig    g_cfg;
extern PlayerState   g_players[ACS_MAX_PLAYERS];

// ---------------------------------------------------------------------------
// Module entry points
// ---------------------------------------------------------------------------
PlayerState* AcsPlayer(int entindex);
PlayerState* AcsPlayerByEdict(const edict_t* e);

void AcsPlayerConnect(int entindex, edict_t* e, const char* name, const char* ip);
void AcsPlayerDisconnect(int entindex);
void AcsPlayerTick(PlayerState& p, const TickSample& t);

void AimOnTick(PlayerState& p, const TickSample& t);
void RecoilOnTick(PlayerState& p, const TickSample& t);
void MovementOnTick(PlayerState& p, const TickSample& t);
void CmdOnTick(PlayerState& p, const TickSample& t);

void BehaviorOnKill(PlayerState& killer, PlayerState* victim, const char* weapon, bool headshot);
void BehaviorSessionSummary(PlayerState& p, std::string& out_json);

void EvidenceRaise(PlayerState& p,
                   const char* rule_id, const char* rule_name,
                   const char* severity, const char* category,
                   const std::string& subject, const std::string& reason,
                   double weight);

void UplinkInit();
void UplinkShutdown();
void UplinkQueue(const std::string& json_event);
void UplinkFlush();

void AcsLog(const char* fmt, ...);
std::string AcsJsonEscape(const std::string& in);
std::string AcsFormat(const char* fmt, ...);
std::string AcsHmacSha256Hex(const std::string& key, const std::string& data);
std::string AcsRandomId(int bytes);

#endif // ACS_H

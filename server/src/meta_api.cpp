// ACS - Metamod entry points and engine hooks for ReHLDS / HLDS.
//
// Three hook groups, and each exists for a specific reason:
//
//   pfnCmdStart      the usercmd stream. This is the whole input side of the game and
//                    the source for the aim, recoil, movement and usercmd engines. It is
//                    hooked pre-game-DLL so the command is seen exactly as the client
//                    sent it.
//
//   pfnRegUserMsg    the game DLL registers its network messages by name at startup and
//                    gets back an integer id. Hooking this is the only portable way to
//                    learn which id means DeathMsg and which means CurWeapon, without
//                    hardcoding numbers that differ between mod builds.
//
//   Message*         DeathMsg gives kills and headshots; CurWeapon gives the weapon a
//                    player is actually holding. Neither is reachable from the entity API
//                    without linking against game-DLL internals.

#include "acs.h"
#include <string.h>
#include <stdio.h>

// Meta_Attach installs these into the META_FUNCTIONS table before they are defined.
C_DLLEXPORT int GetEntityAPI2(DLL_FUNCTIONS* pFunctionTable, int* interfaceVersion);
C_DLLEXPORT int GetEntityAPI2_Post(DLL_FUNCTIONS* pFunctionTable, int* interfaceVersion);
C_DLLEXPORT int GetEngineFunctions(enginefuncs_t* pengfuncsFromEngine, int* interfaceVersion);
C_DLLEXPORT int GetEngineFunctions_Post(enginefuncs_t* pengfuncsFromEngine, int* interfaceVersion);

// Metamod / HLSDK globals that every plugin must provide.
enginefuncs_t   g_engfuncs;
globalvars_t*   gpGlobals       = NULL;
meta_globals_t* gpMetaGlobals   = NULL;
gamedll_funcs_t* gpGamedllFuncs = NULL;
mutil_funcs_t*  gpMetaUtilFuncs = NULL;

static DLL_FUNCTIONS  gFunctionTable;
static enginefuncs_t  gEngineTable;
static META_FUNCTIONS gMetaFunctionTable;

plugin_info_t Plugin_info = {
    META_INTERFACE_VERSION,
    ACS_NAME,
    ACS_VERSION,
    "2026",
    "ACS",
    "https://github.com/acs",
    "ACS",
    PT_STARTUP,     // must load at startup to see RegUserMsg
    PT_ANYPAUSE,    // unloadable once paused; the uplink thread is joined on detach
};

C_DLLEXPORT void WINAPI GiveFnptrsToDll(enginefuncs_t* pengfuncsFromEngine, globalvars_t* pGlobals)
{
    memcpy(&g_engfuncs, pengfuncsFromEngine, sizeof(enginefuncs_t));
    gpGlobals = pGlobals;
}

// ---------------------------------------------------------------------------
// Network message interception
// ---------------------------------------------------------------------------

static int g_msgDeathMsg  = 0;
static int g_msgCurWeapon = 0;

namespace {

struct MsgCapture
{
    bool         active;
    int          type;
    edict_t*     dest;
    int          bytes[8];
    int          nbytes;
    std::string  str;
    bool         has_str;

    void Reset() { active = false; type = 0; dest = NULL; nbytes = 0; str.clear(); has_str = false; }
};

MsgCapture g_msg;

void HandleDeathMsg()
{
    // CS 1.6: killer index, victim index, headshot flag, weapon name. Older HL builds
    // omit the headshot byte, so the flag is only read when a third byte was present.
    if (g_msg.nbytes < 2) return;

    int killer_idx = g_msg.bytes[0];
    int victim_idx = g_msg.bytes[1];
    bool headshot  = (g_msg.nbytes >= 3) && (g_msg.bytes[2] != 0);
    const char* weapon = g_msg.has_str ? g_msg.str.c_str() : "";

    PlayerState* killer = AcsPlayer(killer_idx);
    PlayerState* victim = AcsPlayer(victim_idx);

    // Suicides and world kills carry the victim as the killer, or index 0. Neither is
    // aim evidence.
    if (!killer || !killer->in_use) return;
    if (killer_idx == victim_idx) return;

    BehaviorOnKill(*killer, (victim && victim->in_use) ? victim : NULL, weapon, headshot);
}

void HandleCurWeapon()
{
    if (g_msg.nbytes < 2 || !g_msg.dest) return;
    // state 1 means this is the active weapon; state 0 is an inventory update.
    if (g_msg.bytes[0] != 1) return;

    PlayerState* p = AcsPlayerByEdict(g_msg.dest);
    if (!p || !p->in_use) return;

    p->current_weapon = g_msg.bytes[1];
    if (g_msg.nbytes >= 3) p->current_clip = g_msg.bytes[2];
}

} // namespace

static int RegUserMsg_Post(const char* pszName, int iSize)
{
    int id = META_RESULT_ORIG_RET(int);
    if (pszName)
    {
        if      (strcmp(pszName, "DeathMsg")  == 0) g_msgDeathMsg  = id;
        else if (strcmp(pszName, "CurWeapon") == 0) g_msgCurWeapon = id;
    }
    RETURN_META_VALUE(MRES_IGNORED, id);
}

static void MessageBegin_Pre(int msg_dest, int msg_type, const float* pOrigin, edict_t* ed)
{
    g_msg.Reset();
    if (msg_type != 0 && (msg_type == g_msgDeathMsg || msg_type == g_msgCurWeapon))
    {
        g_msg.active = true;
        g_msg.type   = msg_type;
        g_msg.dest   = ed;
    }
    RETURN_META(MRES_IGNORED);
}

static void WriteByte_Pre(int iValue)
{
    if (g_msg.active && g_msg.nbytes < (int)(sizeof(g_msg.bytes) / sizeof(g_msg.bytes[0])))
        g_msg.bytes[g_msg.nbytes++] = iValue;
    RETURN_META(MRES_IGNORED);
}

static void WriteString_Pre(const char* sz)
{
    if (g_msg.active && !g_msg.has_str)
    {
        g_msg.str = sz ? sz : "";
        g_msg.has_str = true;
    }
    RETURN_META(MRES_IGNORED);
}

static void MessageEnd_Pre(void)
{
    if (g_msg.active)
    {
        if      (g_msg.type == g_msgDeathMsg)  HandleDeathMsg();
        else if (g_msg.type == g_msgCurWeapon) HandleCurWeapon();
        g_msg.Reset();
    }
    RETURN_META(MRES_IGNORED);
}

// ---------------------------------------------------------------------------
// Entity API hooks
// ---------------------------------------------------------------------------

static qboolean ClientConnect_Post(edict_t* pEntity, const char* pszName,
                                   const char* pszAddress, char szRejectReason[128])
{
    AcsPlayerConnect(ENTINDEX(pEntity), pEntity, pszName, pszAddress);
    RETURN_META_VALUE(MRES_IGNORED, TRUE);
}

static void ClientDisconnect_Pre(edict_t* pEntity)
{
    AcsPlayerDisconnect(ENTINDEX(pEntity));
    RETURN_META(MRES_IGNORED);
}

static void ClientPutInServer_Post(edict_t* pEntity)
{
    // The auth id is usually resolved by now even though it was not at ClientConnect.
    PlayerState* p = AcsPlayerByEdict(pEntity);
    if (p && p->in_use)
    {
        const char* auth = GETPLAYERAUTHID(pEntity);
        if (auth && *auth) p->authid = auth;
        const char* name = STRING(pEntity->v.netname);
        if (name && *name) p->name = name;
    }
    RETURN_META(MRES_IGNORED);
}

static void CmdStart_Pre(const edict_t* player, const struct usercmd_s* cmd, unsigned int random_seed)
{
    if (!g_cfg.enabled || !player || !cmd) RETURN_META(MRES_IGNORED);

    PlayerState* p = AcsPlayerByEdict(player);
    if (!p || !p->in_use) RETURN_META(MRES_IGNORED);

    const entvars_t& v = player->v;

    TickSample t;
    memset(&t, 0, sizeof(t));
    t.time        = gpGlobals->time;
    t.realtime    = gpGlobals->time;
    t.msec        = cmd->msec;
    t.lerp_msec   = cmd->lerp_msec;
    t.pitch       = cmd->viewangles[PITCH];
    t.yaw         = cmd->viewangles[YAW];
    t.roll        = cmd->viewangles[ROLL];
    t.forwardmove = cmd->forwardmove;
    t.sidemove    = cmd->sidemove;
    t.upmove      = cmd->upmove;
    t.buttons     = cmd->buttons;
    t.impulse     = cmd->impulse;
    t.weaponselect= cmd->weaponselect;

    t.punch_pitch = v.punchangle[PITCH];
    t.punch_yaw   = v.punchangle[YAW];
    t.vel_x       = v.velocity[0];
    t.vel_y       = v.velocity[1];
    t.vel_z       = v.velocity[2];
    t.origin_z    = v.origin[2];
    t.flags       = v.flags;
    t.on_ground   = (v.flags & FL_ONGROUND) != 0;
    t.ducking     = (v.flags & FL_DUCKING) != 0;
    t.alive       = (v.deadflag == DEAD_NO) && (v.health > 0);
    t.health      = (int)v.health;
    t.weapon_id   = p->current_weapon;

    AcsPlayerTick(*p, t);

    RETURN_META(MRES_IGNORED);
}

static void ServerDeactivate_Pre(void)
{
    // Map change: every session ends here, so summaries are emitted before the slots are
    // recycled. Without this a player who is connected across a map change never produces
    // one for the map they just played.
    for (int i = 1; i < ACS_MAX_PLAYERS; ++i)
        if (g_players[i].in_use) AcsPlayerDisconnect(i);

    UplinkFlush();
    RETURN_META(MRES_IGNORED);
}

// ---------------------------------------------------------------------------
// Metamod plumbing
// ---------------------------------------------------------------------------

C_DLLEXPORT int Meta_Query(char* ifvers, plugin_info_t** pPlugInfo, mutil_funcs_t* pMetaUtilFuncs)
{
    gpMetaUtilFuncs = pMetaUtilFuncs;
    *pPlugInfo = &Plugin_info;

    if (strcmp(ifvers, Plugin_info.ifvers) != 0)
    {
        int mmajor = 0, mminor = 0, pmajor = 0, pminor = 0;
        sscanf(ifvers, "%d:%d", &mmajor, &mminor);
        sscanf(META_INTERFACE_VERSION, "%d:%d", &pmajor, &pminor);
        if (pmajor != mmajor) return FALSE;   // incompatible major
    }
    return TRUE;
}

C_DLLEXPORT int Meta_Attach(PLUG_LOADTIME /*now*/, META_FUNCTIONS* pFunctionTable,
                            meta_globals_t* pMGlobals, gamedll_funcs_t* pGamedllFuncs)
{
    if (!pMGlobals || !pFunctionTable) return FALSE;

    gpMetaGlobals  = pMGlobals;
    gpGamedllFuncs = pGamedllFuncs;

    memset(&gFunctionTable, 0, sizeof(gFunctionTable));
    memset(&gEngineTable,   0, sizeof(gEngineTable));
    memset(&gMetaFunctionTable, 0, sizeof(gMetaFunctionTable));

    gMetaFunctionTable.pfnGetEntityAPI2        = GetEntityAPI2;
    gMetaFunctionTable.pfnGetEntityAPI2_Post   = GetEntityAPI2_Post;
    gMetaFunctionTable.pfnGetEngineFunctions   = GetEngineFunctions;
    gMetaFunctionTable.pfnGetEngineFunctions_Post = GetEngineFunctions_Post;
    memcpy(pFunctionTable, &gMetaFunctionTable, sizeof(META_FUNCTIONS));

    for (int i = 0; i < ACS_MAX_PLAYERS; ++i) g_players[i].Reset();

    g_cfg.LoadDefaults();

    char gamedir[256];
    gamedir[0] = '\0';
    GET_GAME_DIR(gamedir);
    std::string cfgpath = std::string(gamedir[0] ? gamedir : "cstrike") + "/addons/acs/acs.cfg";
    if (!g_cfg.LoadFile(cfgpath.c_str()))
        AcsLog("no config at %s - using defaults", cfgpath.c_str());

    UplinkInit();
    AcsLog("%s %s attached (snap>=%.0fdeg, recoil r<=-%.2f, bhop streak %d)",
            ACS_NAME, ACS_VERSION, g_cfg.snap_min_deg, g_cfg.recoil_r, g_cfg.bhop_streak);
    return TRUE;
}

C_DLLEXPORT int Meta_Detach(PLUG_LOADTIME /*now*/, PL_UNLOAD_REASON /*reason*/)
{
    for (int i = 1; i < ACS_MAX_PLAYERS; ++i)
        if (g_players[i].in_use) AcsPlayerDisconnect(i);

    UplinkShutdown();
    return TRUE;
}

C_DLLEXPORT int GetEntityAPI2(DLL_FUNCTIONS* pFunctionTable, int* interfaceVersion)
{
    if (*interfaceVersion != INTERFACE_VERSION)
    {
        *interfaceVersion = INTERFACE_VERSION;
        return FALSE;
    }
    memset(&gFunctionTable, 0, sizeof(gFunctionTable));
    gFunctionTable.pfnClientDisconnect = ClientDisconnect_Pre;
    gFunctionTable.pfnCmdStart         = CmdStart_Pre;
    gFunctionTable.pfnServerDeactivate = ServerDeactivate_Pre;
    memcpy(pFunctionTable, &gFunctionTable, sizeof(DLL_FUNCTIONS));
    return TRUE;
}

C_DLLEXPORT int GetEntityAPI2_Post(DLL_FUNCTIONS* pFunctionTable, int* interfaceVersion)
{
    if (*interfaceVersion != INTERFACE_VERSION)
    {
        *interfaceVersion = INTERFACE_VERSION;
        return FALSE;
    }
    static DLL_FUNCTIONS post;
    memset(&post, 0, sizeof(post));
    post.pfnClientConnect     = ClientConnect_Post;
    post.pfnClientPutInServer = ClientPutInServer_Post;
    memcpy(pFunctionTable, &post, sizeof(DLL_FUNCTIONS));
    return TRUE;
}

C_DLLEXPORT int GetEngineFunctions(enginefuncs_t* pengfuncsFromEngine, int* interfaceVersion)
{
    if (*interfaceVersion != ENGINE_INTERFACE_VERSION)
    {
        *interfaceVersion = ENGINE_INTERFACE_VERSION;
        return FALSE;
    }
    memset(&gEngineTable, 0, sizeof(gEngineTable));
    gEngineTable.pfnMessageBegin = MessageBegin_Pre;
    gEngineTable.pfnWriteByte    = WriteByte_Pre;
    gEngineTable.pfnWriteString  = WriteString_Pre;
    gEngineTable.pfnMessageEnd   = MessageEnd_Pre;
    memcpy(pengfuncsFromEngine, &gEngineTable, sizeof(enginefuncs_t));
    return TRUE;
}

C_DLLEXPORT int GetEngineFunctions_Post(enginefuncs_t* pengfuncsFromEngine, int* interfaceVersion)
{
    if (*interfaceVersion != ENGINE_INTERFACE_VERSION)
    {
        *interfaceVersion = ENGINE_INTERFACE_VERSION;
        return FALSE;
    }
    static enginefuncs_t post;
    memset(&post, 0, sizeof(post));
    post.pfnRegUserMsg = RegUserMsg_Post;
    memcpy(pengfuncsFromEngine, &post, sizeof(enginefuncs_t));
    return TRUE;
}

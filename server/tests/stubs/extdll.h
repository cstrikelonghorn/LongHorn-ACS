// TYPECHECK STUB - not the real HLSDK. Exists only so the ACS sources can be compiled
// for diagnostics on a machine without HLSDK/Metamod checked out. Declares just the
// surface ACS touches, with the real signatures.
#ifndef STUB_EXTDLL_H
#define STUB_EXTDLL_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef int   qboolean;
typedef float vec_t;
typedef vec_t vec3_t[3];
typedef int   string_t;

#define TRUE  1
#define FALSE 0

#define PITCH 0
#define YAW   1
#define ROLL  2

#define IN_ATTACK    (1 << 0)
#define IN_JUMP      (1 << 1)
#define IN_DUCK      (1 << 2)
#define IN_FORWARD   (1 << 3)
#define IN_BACK      (1 << 4)
#define IN_MOVELEFT  (1 << 9)
#define IN_MOVERIGHT (1 << 10)
#define IN_ATTACK2   (1 << 11)

#define FL_ONGROUND  (1 << 9)
#define FL_DUCKING   (1 << 14)

#define DEAD_NO 0

#ifdef _WIN32
  #define C_DLLEXPORT extern "C" __declspec(dllexport)
  #ifndef WINAPI
  #define WINAPI __stdcall
  #endif
#else
  #define C_DLLEXPORT extern "C" __attribute__((visibility("default")))
  #define WINAPI
#endif

struct entvars_s
{
    string_t classname;
    string_t netname;
    vec3_t   origin;
    vec3_t   velocity;
    vec3_t   angles;
    vec3_t   v_angle;
    vec3_t   punchangle;
    int      flags;
    int      deadflag;
    float    health;
    int      button;
    int      oldbuttons;
};
typedef struct entvars_s entvars_t;

struct edict_s
{
    int       free;
    int       serialnumber;
    entvars_t v;
};
typedef struct edict_s edict_t;

struct usercmd_s
{
    short  lerp_msec;
    unsigned char msec;
    vec3_t viewangles;
    float  forwardmove;
    float  sidemove;
    float  upmove;
    unsigned char lightlevel;
    unsigned short buttons;
    unsigned char impulse;
    unsigned char weaponselect;
    int    impact_index;
    vec3_t impact_position;
};
typedef struct usercmd_s usercmd_t;

struct globalvars_s
{
    float time;
    float frametime;
    int   maxClients;
};
typedef struct globalvars_s globalvars_t;

typedef struct enginefuncs_s
{
    int   (*pfnPrecacheModel)(const char*);
    void  (*pfnServerPrint)(const char*);
    void  (*pfnMessageBegin)(int msg_dest, int msg_type, const float* pOrigin, edict_t* ed);
    void  (*pfnMessageEnd)(void);
    void  (*pfnWriteByte)(int iValue);
    void  (*pfnWriteChar)(int iValue);
    void  (*pfnWriteShort)(int iValue);
    void  (*pfnWriteLong)(int iValue);
    void  (*pfnWriteString)(const char* sz);
    void  (*pfnWriteEntity)(int iValue);
    int   (*pfnRegUserMsg)(const char* pszName, int iSize);
    void  (*pfnGetGameDir)(char* szGetGameDir);
    const char* (*pfnGetPlayerAuthId)(edict_t* e);
    edict_t* (*pfnPEntityOfEntIndex)(int iEntIndex);
    int   (*pfnIndexOfEdict)(const edict_t* pEdict);
    const char* (*pfnSzFromIndex)(int iString);
    void  (*pfnAlertMessage)(int atype, const char* szFmt, ...);
} enginefuncs_t;

extern enginefuncs_t g_engfuncs;
extern globalvars_t* gpGlobals;

#define SERVER_PRINT      (*g_engfuncs.pfnServerPrint)
#define GET_GAME_DIR      (*g_engfuncs.pfnGetGameDir)
#define GETPLAYERAUTHID   (*g_engfuncs.pfnGetPlayerAuthId)
#define INDEXENT          (*g_engfuncs.pfnPEntityOfEntIndex)
#define ENTINDEX          (*g_engfuncs.pfnIndexOfEdict)
#define STRING(offset)    ((const char*)(gpGlobals ? "" : ""))

#endif

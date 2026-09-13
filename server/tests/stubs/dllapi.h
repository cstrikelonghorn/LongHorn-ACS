// TYPECHECK STUB - not the real HLSDK.
#ifndef STUB_DLLAPI_H
#define STUB_DLLAPI_H
#include "extdll.h"

typedef struct DLL_FUNCTIONS_s
{
    void     (*pfnGameInit)(void);
    void     (*pfnServerActivate)(edict_t* pEdictList, int edictCount, int clientMax);
    void     (*pfnServerDeactivate)(void);
    qboolean (*pfnClientConnect)(edict_t* pEntity, const char* pszName,
                                 const char* pszAddress, char szRejectReason[128]);
    void     (*pfnClientDisconnect)(edict_t* pEntity);
    void     (*pfnClientPutInServer)(edict_t* pEntity);
    void     (*pfnClientCommand)(edict_t* pEntity);
    void     (*pfnPlayerPreThink)(edict_t* pEntity);
    void     (*pfnPlayerPostThink)(edict_t* pEntity);
    void     (*pfnCmdStart)(const edict_t* player, const struct usercmd_s* cmd,
                            unsigned int random_seed);
    void     (*pfnCmdEnd)(const edict_t* player);
} DLL_FUNCTIONS;

#define INTERFACE_VERSION        140
#define ENGINE_INTERFACE_VERSION 138

typedef struct gamedll_funcs_s
{
    DLL_FUNCTIONS* dllapi_table;
} gamedll_funcs_t;

#endif

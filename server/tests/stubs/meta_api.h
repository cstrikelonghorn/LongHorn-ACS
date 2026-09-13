// TYPECHECK STUB - not the real Metamod SDK.
#ifndef STUB_META_API_H
#define STUB_META_API_H
#include "extdll.h"
#include "dllapi.h"

#define META_INTERFACE_VERSION "5:13"

typedef enum { MRES_UNSET = 0, MRES_IGNORED, MRES_HANDLED, MRES_OVERRIDE, MRES_SUPERCEDE } META_RES;
typedef enum { PT_NEVER = 0, PT_STARTUP, PT_CHANGELEVEL, PT_ANYTIME, PT_ANYPAUSE } PLUG_LOADTIME;
typedef enum { PNL_NULL = 0, PNL_INI_DELETED, PNL_FILE_NEWER, PNL_COMMAND } PL_UNLOAD_REASON;

typedef struct
{
    const char*   ifvers;
    const char*   name;
    const char*   version;
    const char*   date;
    const char*   author;
    const char*   url;
    const char*   logtag;
    PLUG_LOADTIME loadable;
    PLUG_LOADTIME unloadable;
} plugin_info_t;

typedef struct meta_globals_s
{
    META_RES mres;
    META_RES prev_mres;
    META_RES status;
    void*    orig_ret;
    void*    override_ret;
} meta_globals_t;

typedef struct
{
    int (*pfnGetEntityAPI2)(DLL_FUNCTIONS* pFunctionTable, int* interfaceVersion);
    int (*pfnGetEntityAPI2_Post)(DLL_FUNCTIONS* pFunctionTable, int* interfaceVersion);
    int (*pfnGetEngineFunctions)(enginefuncs_t* pengfuncsFromEngine, int* interfaceVersion);
    int (*pfnGetEngineFunctions_Post)(enginefuncs_t* pengfuncsFromEngine, int* interfaceVersion);
} META_FUNCTIONS;

typedef struct
{
    void (*pfnLogConsole)(plugin_info_t* plid, const char* fmt, ...);
} mutil_funcs_t;

extern meta_globals_t*  gpMetaGlobals;
extern gamedll_funcs_t* gpGamedllFuncs;
extern mutil_funcs_t*   gpMetaUtilFuncs;

#define SET_META_RESULT(result) gpMetaGlobals->mres = (result)
#define RETURN_META(result)             do { gpMetaGlobals->mres = (result); return; } while (0)
#define RETURN_META_VALUE(result, value) do { gpMetaGlobals->mres = (result); return (value); } while (0)
#define META_RESULT_ORIG_RET(type)      (*(type*)gpMetaGlobals->orig_ret)

#endif

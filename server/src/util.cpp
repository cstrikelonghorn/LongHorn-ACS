// ACS configuration and small utilities.

#include "acs.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#include <unistd.h>
#endif

void AcsLog(const char* fmt, ...)
{
    char body[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);

    char line[1100];
    snprintf(line, sizeof(line), "[%s] %s\n", ACS_NAME, body);
    SERVER_PRINT(line);
}

std::string AcsFormat(const char* fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    buf[sizeof(buf) - 1] = '\0';
    return std::string(buf);
}

std::string AcsJsonEscape(const std::string& in)
{
    std::string out;
    out.reserve(in.size() + 8);
    for (size_t i = 0; i < in.size(); ++i)
    {
        unsigned char c = (unsigned char)in[i];
        switch (c)
        {
            case '"':  out += "\\\"";  break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                // Player names arrive as raw bytes in whatever encoding the client sent,
                // so anything below 0x20 is escaped and anything above 0x7f is dropped
                // rather than emitted as invalid UTF-8 the backend would reject.
                if (c < 0x20)      { char e[8]; snprintf(e, sizeof(e), "\\u%04x", c); out += e; }
                else if (c < 0x7f) { out += (char)c; }
                break;
        }
    }
    return out;
}

std::string AcsRandomId(int bytes)
{
    static bool seeded = false;
    if (!seeded)
    {
        unsigned int s = (unsigned int)time(NULL);
#ifndef _WIN32
        s ^= (unsigned int)getpid() << 16;
#endif
        srand(s);
        seeded = true;
    }

    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes * 2);
    for (int i = 0; i < bytes * 2; ++i) out += hex[rand() & 0x0f];
    return out;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

void AcsConfig::LoadDefaults()
{
    enabled        = true;
    endpoint.clear();
    secret.clear();
    server_id.clear();
    log_to_console = true;

    // Aim. snap_min_deg is the main sensitivity dial: lowering it finds more, and finds
    // more flick-shooting honest players along with it.
    snap_min_deg    = 18.0f;
    snap_quiet_deg  = 1.5f;
    snap_settle_deg = 1.5f;
    snap_fire_ticks = 4;
    snap_report_at  = 6;

    // Recoil. 0.90 correlation with a sub-0.35-degree residual is well outside what hand
    // compensation produces; good players sit around 0.4-0.6 with residuals several times
    // larger.
    recoil_r         = 0.90f;
    recoil_residual  = 0.35f;
    recoil_min_shots = 10;
    recoil_report_at = 3;

    bhop_streak = 8;
    sync_ratio  = 0.98f;

    speed_ratio = 1.05f;
    max_move    = 400.0f;
}

static void Trim(std::string& s)
{
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) { s.clear(); return; }
    size_t b = s.find_last_not_of(" \t\r\n");
    s = s.substr(a, b - a + 1);
}

bool AcsConfig::LoadFile(const char* path)
{
    FILE* f = fopen(path, "r");
    if (!f) return false;

    char line[1024];
    while (fgets(line, sizeof(line), f))
    {
        std::string s(line);
        size_t hash = s.find('#');
        if (hash != std::string::npos) s = s.substr(0, hash);
        Trim(s);
        if (s.empty()) continue;

        size_t sp = s.find_first_of(" \t");
        if (sp == std::string::npos) continue;
        std::string key = s.substr(0, sp);
        std::string val = s.substr(sp + 1);
        Trim(val);
        if (val.empty()) continue;

        if      (key == "enabled")          enabled = (atoi(val.c_str()) != 0);
        else if (key == "endpoint")         endpoint = val;
        else if (key == "secret")           secret = val;
        else if (key == "server_id")        server_id = val;
        else if (key == "log_to_console")   log_to_console = (atoi(val.c_str()) != 0);
        else if (key == "snap_min_deg")     snap_min_deg = (float)atof(val.c_str());
        else if (key == "snap_quiet_deg")   snap_quiet_deg = (float)atof(val.c_str());
        else if (key == "snap_settle_deg")  snap_settle_deg = (float)atof(val.c_str());
        else if (key == "snap_fire_ticks")  snap_fire_ticks = atoi(val.c_str());
        else if (key == "snap_report_at")   snap_report_at = atoi(val.c_str());
        else if (key == "recoil_r")         recoil_r = (float)atof(val.c_str());
        else if (key == "recoil_residual")  recoil_residual = (float)atof(val.c_str());
        else if (key == "recoil_min_shots") recoil_min_shots = atoi(val.c_str());
        else if (key == "recoil_report_at") recoil_report_at = atoi(val.c_str());
        else if (key == "bhop_streak")      bhop_streak = atoi(val.c_str());
        else if (key == "sync_ratio")       sync_ratio = (float)atof(val.c_str());
        else if (key == "speed_ratio")      speed_ratio = (float)atof(val.c_str());
        else if (key == "max_move")         max_move = (float)atof(val.c_str());
    }

    fclose(f);

    // Environment wins over the file, so a shared config can be committed and the secret
    // supplied per host.
    const char* env_ep = getenv("ACS_ENDPOINT");
    const char* env_sk = getenv("ACS_SECRET");
    const char* env_id = getenv("ACS_SERVER_ID");
    if (env_ep && *env_ep) endpoint  = env_ep;
    if (env_sk && *env_sk) secret    = env_sk;
    if (env_id && *env_id) server_id = env_id;

    // Guard rails: a misconfigured threshold that disables a detector silently is worse
    // than one that is obviously wrong, so clamp rather than accept.
    if (snap_min_deg    < 5.0f)  snap_min_deg = 5.0f;
    if (snap_fire_ticks < 1)     snap_fire_ticks = 1;
    if (snap_fire_ticks > 20)    snap_fire_ticks = 20;
    if (snap_report_at  < 1)     snap_report_at = 1;
    if (recoil_r        > 0.999f) recoil_r = 0.999f;
    if (recoil_r        < 0.5f)  recoil_r = 0.5f;
    if (recoil_min_shots < 5)    recoil_min_shots = 5;
    if (bhop_streak     < 3)     bhop_streak = 3;
    if (sync_ratio      > 1.0f)  sync_ratio = 1.0f;
    if (sync_ratio      < 0.8f)  sync_ratio = 0.8f;
    if (speed_ratio     < 1.01f) speed_ratio = 1.01f;
    if (max_move        < 100.0f) max_move = 100.0f;

    return true;
}

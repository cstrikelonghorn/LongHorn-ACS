// ACS evidence emitter.
//
// Every rule in the four engines funnels through here. The job of this file is to stop a
// detector from turning into a firehose: a player who trips a rule once will usually trip
// it again within seconds, and a backend that receives four hundred copies of the same
// finding learns nothing more than one that receives three.
//
// The vocabulary (severity / confidence / category / ruleId / subject / reason) is the
// same one the desktop scanner emits, so the backend can score both feeds through one
// code path rather than special-casing the source.

#include "acs.h"
#include <string.h>
#include <time.h>

static const double kRuleCooldown = 60.0;  // seconds between repeats of one rule
static const int    kRuleCap      = 25;    // hard stop per rule per session

static std::string IsoNow()
{
    time_t now = time(NULL);
    struct tm t;
#ifdef _WIN32
    gmtime_s(&t, &now);
#else
    gmtime_r(&now, &t);
#endif
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &t);
    return std::string(buf);
}

void EvidenceRaise(PlayerState& p,
                   const char* rule_id, const char* rule_name,
                   const char* severity, const char* category,
                   const std::string& subject, const std::string& reason,
                   double weight)
{
    if (!g_cfg.enabled) return;

    double now = gpGlobals->time;
    int&    count = p.evidence_counts[rule_id];
    double& last  = p.evidence_last[rule_id];

    if (count >= kRuleCap) return;
    if (count > 0 && (now - last) < kRuleCooldown) return;

    last = now;
    count++;

    // Repeats are worth less than the first observation. Twenty snaps is stronger evidence
    // than one, but it is not twenty times stronger - the same underlying cause produced
    // all of them.
    double add = (count == 1) ? weight : weight * 0.35;
    p.risk += add;
    if (p.risk > 100.0) p.risk = 100.0;

    const char* confidence = "medium";
    if (strcmp(severity, "DETECTED") == 0) confidence = "high";
    else if (strcmp(severity, "INFO") == 0) confidence = "low";

    std::string ev = "{";
    ev += "\"type\":\"evidence\"";
    ev += ",\"source\":\"rehlds\"";
    ev += ",\"sessionId\":\"" + AcsJsonEscape(p.session_id) + "\"";
    ev += ",\"authId\":\""    + AcsJsonEscape(p.authid)     + "\"";
    ev += ",\"name\":\""      + AcsJsonEscape(p.name)       + "\"";
    ev += ",\"ip\":\""        + AcsJsonEscape(p.ip)         + "\"";
    ev += ",\"ruleId\":\""    + AcsJsonEscape(rule_id)      + "\"";
    ev += ",\"ruleName\":\""  + AcsJsonEscape(rule_name)    + "\"";
    ev += ",\"severity\":\""  + AcsJsonEscape(severity)     + "\"";
    ev += ",\"confidence\":\"" + std::string(confidence)     + "\"";
    ev += ",\"category\":\""  + AcsJsonEscape(category)     + "\"";
    ev += ",\"subject\":\""   + AcsJsonEscape(subject)      + "\"";
    ev += ",\"reason\":\""    + AcsJsonEscape(reason)       + "\"";
    ev += ",\"time\":\""      + IsoNow()                     + "\"";
    ev += AcsFormat(",\"occurrence\":%d", count);
    ev += AcsFormat(",\"weight\":%.1f", add);
    ev += AcsFormat(",\"risk\":%.1f", p.risk);
    ev += AcsFormat(",\"gameTime\":%.1f", now);
    ev += "}";

    UplinkQueue(ev);

    if (g_cfg.log_to_console)
    {
        AcsLog("[%s] %s <%s> %s - %s (risk %.0f)",
                severity, p.name.c_str(), p.authid.c_str(), rule_name, subject.c_str(), p.risk);
    }
}

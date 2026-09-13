// ACS telemetry uplink.
//
// Evidence is produced on the game thread, which is the same thread that simulates the
// server. Blocking it on a socket would turn a slow backend into server lag, so
// everything here runs on a worker: the game thread only appends a string to a queue.
//
// Two consequences of that split are load-bearing:
//
//   * The worker must never call an engine function. GoldSrc is single-threaded and none
//     of its API is safe to touch from here, so worker-side diagnostics go to stderr,
//     never through AcsLog.
//   * The queue is bounded. A backend that is down must cost a fixed amount of memory,
//     not an unbounded one, so the oldest events are dropped once the cap is reached.
//
// Transport is plain HTTP with an HMAC-SHA256 signature over the body. The signature is
// what authenticates the server and protects the events from being edited in transit;
// it does not make them secret. Run the backend behind a TLS-terminating proxy, or keep
// the link on a private network, if the telemetry itself is sensitive.

#include "acs.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <chrono>
#include <deque>
#include <thread>
#include <mutex>
#include <condition_variable>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET acs_socket_t;
  #define ACS_INVALID_SOCKET INVALID_SOCKET
  #define acs_close closesocket
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <errno.h>
  typedef int acs_socket_t;
  #define ACS_INVALID_SOCKET (-1)
  #define acs_close close
#endif

static const size_t kQueueCap   = 5000;
static const size_t kBatchMax   = 64;
static const int    kFlushEvery = 2;   // seconds

namespace {

std::deque<std::string> g_queue;
std::mutex              g_mutex;
std::condition_variable g_cv;
std::thread             g_worker;
bool                    g_running = false;
bool                    g_started = false;
size_t                  g_dropped = 0;

struct Endpoint
{
    std::string host;
    std::string path;
    int         port;
    bool        valid;
    Endpoint() : port(80), valid(false) {}
};

Endpoint g_endpoint;

Endpoint ParseEndpoint(const std::string& url)
{
    Endpoint e;
    std::string rest;

    if (url.compare(0, 7, "http://") == 0)
    {
        rest = url.substr(7);
    }
    else if (url.compare(0, 8, "https://") == 0)
    {
        // No TLS in-process, by choice - see the header comment.
        fprintf(stderr, "[%s] endpoint is https:// but this build has no TLS. "
                        "Point it at a local http:// proxy that terminates TLS.\n", ACS_NAME);
        return e;
    }
    else
    {
        fprintf(stderr, "[%s] endpoint must start with http://\n", ACS_NAME);
        return e;
    }

    size_t slash = rest.find('/');
    std::string hostport = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    e.path = (slash == std::string::npos) ? "/" : rest.substr(slash);

    size_t colon = hostport.rfind(':');
    if (colon != std::string::npos)
    {
        e.host = hostport.substr(0, colon);
        e.port = atoi(hostport.c_str() + colon + 1);
        if (e.port <= 0 || e.port > 65535) e.port = 80;
    }
    else
    {
        e.host = hostport;
        e.port = 80;
    }

    e.valid = !e.host.empty();
    return e;
}

bool SendAll(acs_socket_t s, const char* data, size_t len)
{
    size_t sent = 0;
    while (sent < len)
    {
        int n = (int)send(s, data + sent, (int)(len - sent), 0);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

// Fire-and-check POST. Returns the HTTP status, or 0 if the request never completed.
int PostBody(const Endpoint& ep, const std::string& body, const std::string& signature)
{
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", ep.port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res = NULL;
    if (getaddrinfo(ep.host.c_str(), portbuf, &hints, &res) != 0 || !res) return 0;

    acs_socket_t s = ACS_INVALID_SOCKET;
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next)
    {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == ACS_INVALID_SOCKET) continue;

#ifndef _WIN32
        struct timeval tv; tv.tv_sec = 8; tv.tv_usec = 0;
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#else
        DWORD tv = 8000;
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif
        if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0) break;
        acs_close(s);
        s = ACS_INVALID_SOCKET;
    }
    freeaddrinfo(res);
    if (s == ACS_INVALID_SOCKET) return 0;

    std::string req;
    req  = "POST " + ep.path + " HTTP/1.1\r\n";
    req += "Host: " + ep.host + "\r\n";
    req += "User-Agent: " ACS_NAME "/" ACS_VERSION "\r\n";
    req += "Content-Type: application/json\r\n";
    req += "X-ACS-Signature: " + signature + "\r\n";
    req += "X-ACS-Server: " + g_cfg.server_id + "\r\n";
    req += "Connection: close\r\n";
    req += AcsFormat("Content-Length: %u\r\n\r\n", (unsigned)body.size());

    int status = 0;
    if (SendAll(s, req.data(), req.size()) && SendAll(s, body.data(), body.size()))
    {
        char buf[512];
        int n = (int)recv(s, buf, sizeof(buf) - 1, 0);
        if (n > 0)
        {
            buf[n] = '\0';
            // "HTTP/1.1 200 OK"
            const char* sp = strchr(buf, ' ');
            if (sp) status = atoi(sp + 1);
        }
    }

    acs_close(s);
    return status;
}

std::string BuildBody(const std::vector<std::string>& events)
{
    std::string body = "{";
    body += "\"source\":\"rehlds\"";
    body += ",\"version\":\"" ACS_VERSION "\"";
    body += ",\"serverId\":\"" + AcsJsonEscape(g_cfg.server_id) + "\"";
    body += AcsFormat(",\"sentAt\":%ld", (long)time(NULL));
    body += ",\"events\":[";
    for (size_t i = 0; i < events.size(); ++i)
    {
        if (i) body += ",";
        body += events[i];
    }
    body += "]}";
    return body;
}

void WorkerMain()
{
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    while (true)
    {
        std::vector<std::string> batch;
        {
            std::unique_lock<std::mutex> lock(g_mutex);
            if (g_queue.empty() && g_running)
                g_cv.wait_for(lock, std::chrono::seconds(kFlushEvery));

            if (!g_running && g_queue.empty()) break;

            while (!g_queue.empty() && batch.size() < kBatchMax)
            {
                batch.push_back(g_queue.front());
                g_queue.pop_front();
            }
        }

        if (batch.empty()) continue;

        std::string body = BuildBody(batch);
        std::string sig  = AcsHmacSha256Hex(g_cfg.secret, body);
        int status = PostBody(g_endpoint, body, sig);

        if (status < 200 || status >= 300)
        {
            // Events are not requeued. A backend that rejects a batch will reject the
            // retry too, and a backend that is down would otherwise collect an ever
            // growing replay that floods it the moment it comes back.
            fprintf(stderr, "[%s] uplink: %u event(s) dropped, HTTP %d\n",
                    ACS_NAME, (unsigned)batch.size(), status);
        }
    }

#ifdef _WIN32
    WSACleanup();
#endif
}

} // namespace

void UplinkInit()
{
    if (g_started) return;
    if (g_cfg.endpoint.empty())
    {
        AcsLog("no endpoint configured - running in local/console mode, nothing is uploaded");
        return;
    }

    g_endpoint = ParseEndpoint(g_cfg.endpoint);
    if (!g_endpoint.valid)
    {
        AcsLog("endpoint '%s' could not be parsed - uplink disabled", g_cfg.endpoint.c_str());
        return;
    }

    if (g_cfg.secret.empty())
    {
        // Refusing here rather than sending unsigned is deliberate: an unauthenticated
        // telemetry endpoint lets anyone attribute fabricated evidence to a real player.
        AcsLog("no secret configured - uplink disabled, evidence would be unauthenticated");
        return;
    }

    g_running = true;
    g_started = true;
    g_worker  = std::thread(WorkerMain);
    AcsLog("uplink to %s:%d%s", g_endpoint.host.c_str(), g_endpoint.port, g_endpoint.path.c_str());
}

void UplinkShutdown()
{
    if (!g_started) return;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_running = false;
    }
    g_cv.notify_all();
    if (g_worker.joinable()) g_worker.join();
    g_started = false;
    if (g_dropped) AcsLog("%u event(s) were dropped by the queue cap", (unsigned)g_dropped);
}

void UplinkQueue(const std::string& json_event)
{
    if (!g_started) return;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_queue.size() >= kQueueCap)
        {
            g_queue.pop_front();
            g_dropped++;
        }
        g_queue.push_back(json_event);
    }
    g_cv.notify_one();
}

void UplinkFlush()
{
    g_cv.notify_one();
}

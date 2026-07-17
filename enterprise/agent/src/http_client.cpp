// HTTP/1.1 client built on raw sockets (no libcurl dependency).
//
// A "high-performance lightweight agent" should not drag in libcurl just to
// exchange small JSON payloads every 5 seconds. This implements the minimal
// HTTP/1.1 subset the agent needs: GET/POST with a JSON body, an optional
// X-Agent-Secret auth header, Content-Length response framing, and
// connect/send/recv timeouts — all through the platform socket API (BSD
// sockets on POSIX, Winsock2 on Windows).
//
// TLS is intentionally out of scope here: the agent talks to the AutoSOC
// server over plain HTTP on a trusted management network / VPN, with TLS
// terminated by a reverse proxy in front of the server (see enterprise/README
// "Security notes"). This keeps the agent's dependency footprint at just the
// C++ standard library + OS sockets.
#include "http_client.hpp"

#include <cerrno>
#include <cstring>
#include <sstream>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using socket_t = SOCKET;
static constexpr socket_t kInvalidSocket = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
using socket_t = int;
static constexpr socket_t kInvalidSocket = -1;
#endif

namespace autosoc {

namespace {

struct ParsedUrl {
    std::string scheme;
    std::string host;
    std::string port = "80";
    std::string path = "/";
    bool valid = false;
};

// Minimal "scheme://host[:port][/path]" parser — enough for our own config.
ParsedUrl parse_url(const std::string& url) {
    ParsedUrl u;
    size_t scheme_end = url.find("://");
    if (scheme_end == std::string::npos) return u;
    u.scheme = url.substr(0, scheme_end);
    size_t host_start = scheme_end + 3;
    size_t path_start = url.find('/', host_start);
    std::string authority = (path_start == std::string::npos)
        ? url.substr(host_start)
        : url.substr(host_start, path_start - host_start);
    u.path = (path_start == std::string::npos) ? "/" : url.substr(path_start);

    size_t colon = authority.rfind(':');
    if (colon != std::string::npos) {
        u.host = authority.substr(0, colon);
        u.port = authority.substr(colon + 1);
    } else {
        u.host = authority;
        u.port = (u.scheme == "https") ? "443" : "80";
    }
    u.valid = !u.host.empty();
    return u;
}

void close_socket(socket_t s) {
#if defined(_WIN32)
    closesocket(s);
#else
    ::close(s);
#endif
}

void set_timeout(socket_t s, long timeout_ms) {
#if defined(_WIN32)
    DWORD tv = static_cast<DWORD>(timeout_ms);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

bool send_all(socket_t s, const std::string& data) {
    size_t sent = 0;
    while (sent < data.size()) {
#if defined(_WIN32)
        int n = send(s, data.data() + sent, static_cast<int>(data.size() - sent), 0);
#else
        ssize_t n = send(s, data.data() + sent, data.size() - sent, 0);
#endif
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

// Reads the whole HTTP response (headers + body) honoring Content-Length.
bool recv_response(socket_t s, std::string& out) {
    char buf[8192];
    out.clear();
    size_t header_end = std::string::npos;
    long content_length = -1;

    for (;;) {
#if defined(_WIN32)
        int n = recv(s, buf, sizeof(buf), 0);
#else
        ssize_t n = recv(s, buf, sizeof(buf), 0);
#endif
        if (n < 0) return !out.empty();  // timeout/error: return what we have
        if (n == 0) break;               // peer closed
        out.append(buf, static_cast<size_t>(n));

        if (header_end == std::string::npos) {
            header_end = out.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                std::string headers = out.substr(0, header_end);
                size_t cl = headers.find("Content-Length:");
                if (cl == std::string::npos) cl = headers.find("content-length:");
                if (cl != std::string::npos) {
                    content_length = std::strtol(headers.c_str() + cl + 16, nullptr, 10);
                }
            }
        }
        if (header_end != std::string::npos && content_length >= 0) {
            size_t body_have = out.size() - (header_end + 4);
            if (body_have >= static_cast<size_t>(content_length)) break;
        }
    }
    return true;
}

}  // namespace

HttpResponse ServerFailover::do_request(Method method, const std::string& base, const std::string& path,
                                        const std::string& json_body, const std::string& secret) {
    HttpResponse r;
    r.server = base;

    ParsedUrl url = parse_url(base);
    if (!url.valid) {
        r.error = "invalid server URL: " + base;
        return r;
    }
    url.path = path;  // the API path (e.g. /agents/heartbeat) overrides the base URL's path
    if (url.scheme == "https") {
        r.error = "TLS not supported by the built-in client; terminate TLS at a reverse proxy "
                  "and configure the agent with an http:// address (see README).";
        return r;
    }

#if defined(_WIN32)
    static bool wsa_ready = false;
    if (!wsa_ready) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        wsa_ready = true;
    }
#endif

    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    int gai = getaddrinfo(url.host.c_str(), url.port.c_str(), &hints, &res);
    if (gai != 0 || res == nullptr) {
        r.error = "DNS/connect resolution failed for " + url.host + ":" + url.port;
        return r;
    }

    socket_t sock = kInvalidSocket;
    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == kInvalidSocket) continue;
        set_timeout(sock, cfg_.http_timeout_ms);
        if (connect(sock, p->ai_addr, static_cast<int>(p->ai_addrlen)) == 0) break;
        close_socket(sock);
        sock = kInvalidSocket;
    }
    freeaddrinfo(res);

    if (sock == kInvalidSocket) {
        r.error = "connect() failed to " + url.host + ":" + url.port + " (" + std::strerror(errno) + ")";
        return r;
    }

    std::ostringstream req;
    const char* verb = (method == Method::kPost) ? "POST" : "GET";
    req << verb << " " << url.path << " HTTP/1.1\r\n"
        << "Host: " << url.host << "\r\n";
    if (!secret.empty()) req << "X-Agent-Secret: " << secret << "\r\n";
    if (method == Method::kPost) {
        req << "Content-Type: application/json\r\n"
            << "Content-Length: " << json_body.size() << "\r\n"
            << "Connection: close\r\n\r\n"
            << json_body;
    } else {
        req << "Connection: close\r\n\r\n";
    }

    if (!send_all(sock, req.str())) {
        r.error = "send() failed writing the request";
        close_socket(sock);
        return r;
    }

    std::string raw_response;
    bool got_data = recv_response(sock, raw_response);
    close_socket(sock);

    if (!got_data || raw_response.empty()) {
        r.error = "no response received (timeout or connection reset)";
        return r;
    }

    // Parse the status line: "HTTP/1.1 200 OK".
    size_t line_end = raw_response.find("\r\n");
    if (line_end == std::string::npos) {
        r.error = "malformed HTTP response (no status line)";
        return r;
    }
    std::string status_line = raw_response.substr(0, line_end);
    size_t first_space = status_line.find(' ');
    if (first_space != std::string::npos) {
        r.status = std::strtol(status_line.c_str() + first_space + 1, nullptr, 10);
    }

    size_t header_end = raw_response.find("\r\n\r\n");
    r.body = (header_end != std::string::npos) ? raw_response.substr(header_end + 4) : "";
    r.ok = r.status > 0 && r.status < 400;
    if (!r.ok) r.error = "HTTP " + std::to_string(r.status);
    return r;
}

void ServerFailover::advance() {
    std::lock_guard<std::mutex> lock(mu_);
    if (!cfg_.servers.empty()) active_ = (active_ + 1) % cfg_.servers.size();
}

HttpResponse ServerFailover::request_with_failover(Method method, const std::string& path,
                                                    const std::string& json_body, const std::string& secret) {
    if (cfg_.servers.empty()) {
        HttpResponse r;
        r.error = "no servers configured";
        return r;
    }
    // Try every server once, starting from the active one; a transport-level
    // failure (connect/send/recv) triggers failover to the next backup.
    for (size_t attempt = 0; attempt < cfg_.servers.size(); ++attempt) {
        std::string base;
        {
            std::lock_guard<std::mutex> lock(mu_);
            base = cfg_.servers[active_];
        }
        HttpResponse r = do_request(method, base, path, json_body, secret);
        if (r.status != 0 || r.ok) return r;  // got a real HTTP status → done
        advance();                             // transport failure → try next server
    }
    HttpResponse r;
    r.error = "all servers unreachable";
    return r;
}

HttpResponse ServerFailover::post_json(const std::string& path, const std::string& json_body,
                                       const std::string& secret) {
    return request_with_failover(Method::kPost, path, json_body, secret);
}

HttpResponse ServerFailover::get_json(const std::string& path, const std::string& secret) {
    return request_with_failover(Method::kGet, path, "", secret);
}

}  // namespace autosoc

// HTTP client with dynamic primary/backup server failover (module 5).
//
// Each request tries the currently-active server; on a network failure it
// rotates to the next server in the list and retries, so the agent keeps
// reporting through an outage of the primary. The active index is
// mutex-guarded because several worker threads may post concurrently.
//
// Authentication: once enrolled, the agent attaches its per-agent secret as
// an X-Agent-Secret header on every call (see main.cpp) — the server refuses
// heartbeats/commands without it, so a caller cannot forge telemetry for an
// agent_uid it does not control.
#pragma once

#include "config.hpp"

#include <mutex>
#include <string>

namespace autosoc {

struct HttpResponse {
    bool ok = false;         // transport succeeded and status < 400
    long status = 0;
    std::string body;
    std::string server;      // which server answered
    std::string error;
};

class ServerFailover {
public:
    explicit ServerFailover(AgentConfig cfg) : cfg_(std::move(cfg)) {}

    // POST/GET a JSON body to `path` on the active server, failing over on
    // transport error. `secret`, when non-empty, is sent as X-Agent-Secret.
    HttpResponse post_json(const std::string& path, const std::string& json_body,
                           const std::string& secret = "");
    HttpResponse get_json(const std::string& path, const std::string& secret = "");

    std::string active_server() {
        std::lock_guard<std::mutex> lock(mu_);
        return cfg_.servers.empty() ? "" : cfg_.servers[active_];
    }

private:
    enum class Method { kPost, kGet };
    HttpResponse do_request(Method method, const std::string& base, const std::string& path,
                            const std::string& json_body, const std::string& secret);
    HttpResponse request_with_failover(Method method, const std::string& path,
                                       const std::string& json_body, const std::string& secret);
    void advance();

    AgentConfig cfg_;
    std::mutex mu_;
    size_t active_ = 0;
};

}  // namespace autosoc

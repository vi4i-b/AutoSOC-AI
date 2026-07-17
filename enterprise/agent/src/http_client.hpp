// HTTP client with dynamic primary/backup server failover (module 5).
//
// Each POST tries the currently-active server; on a network failure it rotates
// to the next server in the list and retries, so the agent keeps reporting
// through an outage of the primary. The active index is mutex-guarded because
// several worker threads may post concurrently.
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

    // POST a JSON body to `path` on the active server, failing over on error.
    HttpResponse post_json(const std::string& path, const std::string& json_body);

    std::string active_server() {
        std::lock_guard<std::mutex> lock(mu_);
        return cfg_.servers.empty() ? "" : cfg_.servers[active_];
    }

private:
    HttpResponse do_post(const std::string& base, const std::string& path,
                         const std::string& json_body);
    void advance();

    AgentConfig cfg_;
    std::mutex mu_;
    size_t active_ = 0;
};

}  // namespace autosoc

// AutoSOC EDR agent — configuration.
//
// All settings come from the environment or CLI so the same binary ships to
// every host. A primary and any number of backup servers enable dynamic
// failover (module 5).
#pragma once

#include <string>
#include <vector>
#include <cstdlib>

namespace autosoc {

struct AgentConfig {
    std::vector<std::string> servers;   // primary first, then backups
    std::string enrollment_token;
    std::string agent_uid;
    std::string hostname;
    int heartbeat_interval_s = 5;
    long http_timeout_ms = 8000;

    static std::string env(const char* key, const std::string& def = "") {
        const char* v = std::getenv(key);
        return v ? std::string(v) : def;
    }

    // AUTOSOC_SERVERS is a comma-separated list: "https://a:8443,https://b:8443".
    static AgentConfig load() {
        AgentConfig c;
        std::string raw = env("AUTOSOC_SERVERS", "http://127.0.0.1:8000");
        size_t start = 0;
        while (start <= raw.size()) {
            size_t comma = raw.find(',', start);
            std::string item = raw.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
            if (!item.empty()) c.servers.push_back(item);
            if (comma == std::string::npos) break;
            start = comma + 1;
        }
        c.enrollment_token = env("AUTOSOC_ENROLLMENT_TOKEN");
        c.hostname = env("AUTOSOC_HOSTNAME", detect_hostname());
        c.agent_uid = env("AUTOSOC_AGENT_UID", "agent-" + c.hostname);
        return c;
    }

    static std::string detect_hostname();
};

}  // namespace autosoc

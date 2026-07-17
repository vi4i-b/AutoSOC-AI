// AutoSOC EDR agent — entry point.
//
// Lifecycle:  harden (anti-tamper) → enroll → heartbeat loop (every 5s, with
// process tree + failover). A clean shutdown sends shutdown=true so the server
// does NOT raise a compromise alarm; a hard kill stops the heartbeat and the
// server detects the silence.
#include "anti_tamper.hpp"
#include "config.hpp"
#include "http_client.hpp"
#include "process_tree.hpp"

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <thread>

using nlohmann::json;
using namespace autosoc;

static std::atomic<bool> g_running{true};

static void request_shutdown(int) {
    // Developer convenience: Ctrl-C authorizes a clean shutdown.
    g_shutdown_authorized.store(true);
    g_running.store(false);
}

static bool enroll(ServerFailover& net, const AgentConfig& cfg) {
    json body = {
        {"enrollment_token", cfg.enrollment_token},
        {"agent_uid", cfg.agent_uid},
        {"hostname", cfg.hostname},
        {"platform",
#if defined(_WIN32)
         "Windows"
#else
         "Linux"
#endif
        },
    };
    for (int attempt = 0; attempt < 5 && g_running.load(); ++attempt) {
        HttpResponse r = net.post_json("/agents/enroll", body.dump());
        if (r.ok) {
            std::cout << "[agent] enrolled via " << r.server << "\n";
            return true;
        }
        std::cerr << "[agent] enroll failed (" << r.error << "), retrying...\n";
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    return false;
}

static void send_heartbeat(ServerFailover& net, const AgentConfig& cfg, bool shutdown) {
    json body = {
        {"agent_uid", cfg.agent_uid},
        {"status", shutdown ? "offline" : "active"},
        {"shutdown", shutdown},
        {"process_tree", build_process_tree()},
        {"events", json::array()},
    };
    HttpResponse r = net.post_json("/agents/heartbeat", body.dump());
    if (!r.ok) std::cerr << "[agent] heartbeat failed: " << r.error << "\n";
}

int main() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    std::signal(SIGINT, request_shutdown);

    AgentConfig cfg = AgentConfig::load();
    HardenResult hard = harden_process();
    std::cout << "[agent] anti-tamper: " << hard.note
              << " (mem_protected=" << hard.memory_protected
              << ", signals_guarded=" << hard.signals_guarded << ")\n";
    std::cout << "[agent] uid=" << cfg.agent_uid << " servers=" << cfg.servers.size() << "\n";

    ServerFailover net(cfg);
    if (!enroll(net, cfg)) {
        std::cerr << "[agent] could not enroll with any server. Exiting.\n";
        curl_global_cleanup();
        return 1;
    }

    // Heartbeat loop with a responsive sleep so shutdown is prompt.
    while (g_running.load()) {
        send_heartbeat(net, cfg, /*shutdown=*/false);
        for (int i = 0; i < cfg.heartbeat_interval_s * 10 && g_running.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Clean, authorized shutdown → tell the server so it isn't flagged.
    send_heartbeat(net, cfg, /*shutdown=*/true);
    std::cout << "[agent] clean shutdown.\n";
    curl_global_cleanup();
    return 0;
}

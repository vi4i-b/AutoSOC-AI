// AutoSOC EDR agent — entry point.
//
// Lifecycle:  harden (anti-tamper) → enroll (receive a per-agent secret) →
// heartbeat loop (every 5s: process tree + failover), polling for pending
// commands after each heartbeat and enforcing them locally (isolate/release
// via iptables/netsh — see isolation.hpp). A clean shutdown sends
// shutdown=true so the server does NOT raise a compromise alarm; a hard kill
// stops the heartbeat and the server detects the silence.
//
// --once runs a single enroll + heartbeat + command-poll cycle and exits
// (used for integration testing/CI — see enterprise/README.md).
#include "anti_tamper.hpp"
#include "config.hpp"
#include "http_client.hpp"
#include "isolation.hpp"
#include "process_tree.hpp"

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
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

// Best-effort resolution of the active server's IP, so isolation can pin an
// allow-rule to it. Falls back to an empty string (isolate() still runs, it
// just won't special-case a server address — see isolation.hpp).
static std::string extract_host(const std::string& url) {
    size_t scheme = url.find("://");
    size_t start = (scheme == std::string::npos) ? 0 : scheme + 3;
    size_t path = url.find('/', start);
    std::string authority = (path == std::string::npos) ? url.substr(start) : url.substr(start, path - start);
    size_t colon = authority.rfind(':');
    return (colon == std::string::npos) ? authority : authority.substr(0, colon);
}

static bool enroll(ServerFailover& net, const AgentConfig& cfg, std::string& out_secret) {
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
            try {
                json parsed = json::parse(r.body);
                out_secret = parsed.value("agent_secret", "");
            } catch (const json::parse_error& e) {
                std::cerr << "[agent] enroll response was not valid JSON: " << e.what() << "\n";
                return false;
            }
            if (out_secret.empty()) {
                std::cerr << "[agent] enroll succeeded but no agent_secret was returned\n";
                return false;
            }
            std::cout << "[agent] enrolled via " << r.server << "\n";
            return true;
        }
        std::cerr << "[agent] enroll failed (" << r.error << "), retrying...\n";
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    return false;
}

static bool send_heartbeat(ServerFailover& net, const AgentConfig& cfg, const std::string& secret, bool shutdown) {
    json body = {
        {"agent_uid", cfg.agent_uid},
        {"status", shutdown ? "offline" : "active"},
        {"shutdown", shutdown},
        {"process_tree", build_process_tree()},
        {"events", json::array()},
    };
    HttpResponse r = net.post_json("/agents/heartbeat", body.dump(), secret);
    if (!r.ok) {
        std::cerr << "[agent] heartbeat failed: " << r.error << "\n";
        return false;
    }
    std::cout << "[agent] heartbeat ok via " << r.server << " -> " << r.body << "\n";
    return true;
}

// Polls for pending commands and enforces them locally. Returns the number
// of commands processed (0 is the normal, steady-state case).
static int poll_and_apply_commands(ServerFailover& net, const AgentConfig& cfg,
                                   const std::string& secret, const std::string& server_host) {
    HttpResponse poll = net.get_json("/agents/" + cfg.agent_uid + "/commands", secret);
    if (!poll.ok) {
        std::cerr << "[agent] command poll failed: " << poll.error << "\n";
        return 0;
    }

    json parsed;
    try {
        parsed = json::parse(poll.body);
    } catch (const json::parse_error& e) {
        std::cerr << "[agent] command poll response was not valid JSON: " << e.what() << "\n";
        return 0;
    }

    int processed = 0;
    for (const auto& cmd : parsed.value("commands", json::array())) {
        std::string id = cmd.value("id", "");
        std::string name = cmd.value("command", "");
        CommandOutcome outcome;

        if (name == "isolate") {
            outcome = isolate_host(server_host);
        } else if (name == "release") {
            outcome = release_host();
        } else {
            outcome = {false, "unknown command: " + name};
        }

        std::cout << "[agent] command '" << name << "' -> " << (outcome.ok ? "ok" : "FAILED")
                  << ": " << outcome.detail << "\n";

        json result_body = {{"ok", outcome.ok}, {"detail", outcome.detail}};
        net.post_json("/agents/" + cfg.agent_uid + "/commands/" + id + "/result", result_body.dump(), secret);
        ++processed;
    }
    return processed;
}

int main(int argc, char** argv) {
    bool once = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--once") == 0) once = true;
    }

    std::signal(SIGINT, request_shutdown);

    AgentConfig cfg = AgentConfig::load();
    HardenResult hard = harden_process();
    std::cout << "[agent] anti-tamper: " << hard.note
              << " (mem_protected=" << hard.memory_protected
              << ", signals_guarded=" << hard.signals_guarded << ")\n";
    std::cout << "[agent] uid=" << cfg.agent_uid << " servers=" << cfg.servers.size() << "\n";

    ServerFailover net(cfg);
    std::string secret;
    if (!enroll(net, cfg, secret)) {
        std::cerr << "[agent] could not enroll with any server. Exiting.\n";
        return 1;
    }
    std::string server_host = extract_host(net.active_server());

    if (once) {
        bool ok = send_heartbeat(net, cfg, secret, /*shutdown=*/false);
        poll_and_apply_commands(net, cfg, secret, server_host);
        send_heartbeat(net, cfg, secret, /*shutdown=*/true);
        std::cout << "[agent] --once cycle complete.\n";
        return ok ? 0 : 1;
    }

    // Heartbeat loop with a responsive sleep so shutdown is prompt.
    while (g_running.load()) {
        send_heartbeat(net, cfg, secret, /*shutdown=*/false);
        poll_and_apply_commands(net, cfg, secret, server_host);
        for (int i = 0; i < cfg.heartbeat_interval_s * 10 && g_running.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Clean, authorized shutdown → tell the server so it isn't flagged.
    send_heartbeat(net, cfg, secret, /*shutdown=*/true);
    std::cout << "[agent] clean shutdown.\n";
    return 0;
}

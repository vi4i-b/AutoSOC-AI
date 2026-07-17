// Local network isolation enforcement (module 3: "Агент изолирует хост
// локально").
//
// On Linux, isolation drops all inbound/outbound traffic except loopback,
// already-established connections, DNS, and the AutoSOC server itself — so a
// contained host can still be released remotely once the isolate command is
// rolled back. Every rule is tagged with a recognizable comment so release()
// can find and remove exactly (and only) the rules it added, even across
// process restarts.
#pragma once

#include <string>
#include <vector>

namespace autosoc {

struct CommandOutcome {
    bool ok = false;
    std::string detail;
};

// Pure, testable rule builder: returns the `iptables` argument vectors that
// implement isolation while keeping `server_ip` reachable. Exposed in the
// header so it can be unit-tested without touching the real firewall.
std::vector<std::vector<std::string>> build_isolation_rules(const std::string& server_ip);

// Applies/removes local network isolation for the current platform. Requires
// root (Linux) / Administrator (Windows); returns a descriptive failure
// otherwise rather than silently no-op'ing.
CommandOutcome isolate_host(const std::string& server_ip);
CommandOutcome release_host();

}  // namespace autosoc

// Local anti-tampering for the agent process.
//
// The goal is to make it hard for an attacker who lands on the host to quietly
// kill the sensor. We run with elevated rights (root/SYSTEM), block memory
// inspection, and refuse ordinary termination signals. A hard SIGKILL/handle
// termination can still stop us — but then the heartbeat stops, and the server
// raises "suspected agent compromise" (see server heartbeat monitor).
#pragma once

#include <atomic>
#include <string>

namespace autosoc {

// Set to true only by an authenticated in-band shutdown command; until then
// the agent refuses ordinary termination (anti-tamper).
extern std::atomic<bool> g_shutdown_authorized;

struct HardenResult {
    bool privileged = false;      // running as root / SYSTEM
    bool memory_protected = false;
    bool signals_guarded = false;
    std::string note;
};

// Apply all available protections for the current platform.
HardenResult harden_process();

}  // namespace autosoc

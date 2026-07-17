#include "isolation.hpp"

#include <array>
#include <cstdio>
#include <memory>
#include <sstream>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace autosoc {

namespace {

constexpr const char* kTag = "AUTOSOC_ISOLATION";

// Runs a command, capturing combined stdout+stderr and the exit status.
// Never throws; a failed popen() is reported as a normal CommandOutcome.
CommandOutcome run_command(const std::string& command_line) {
    std::string full = command_line + " 2>&1";
    std::array<char, 256> buffer{};
    std::string output;

#if defined(_WIN32)
    std::unique_ptr<FILE, int (*)(FILE*)> pipe(_popen(full.c_str(), "r"), _pclose);
#else
    std::unique_ptr<FILE, int (*)(FILE*)> pipe(popen(full.c_str(), "r"), pclose);
#endif
    if (!pipe) return {false, "failed to start subprocess: " + command_line};

    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr) {
        output += buffer.data();
    }
    int status = 0;
#if defined(_WIN32)
    status = _pclose(pipe.release());
#else
    status = pclose(pipe.release());
#endif
    CommandOutcome result;
    result.ok = (status == 0);
    result.detail = output.empty() ? (result.ok ? "ok" : "command exited non-zero") : output;
    return result;
}

}  // namespace

std::vector<std::vector<std::string>> build_isolation_rules(const std::string& server_ip) {
    // Each inner vector is one `iptables <...>` invocation's argument list
    // (excluding the "iptables" program name itself), tagged with kTag so
    // release_host() can find and remove exactly these rules later.
    std::vector<std::vector<std::string>> rules;
    auto tag = [](std::vector<std::string> v) {
        v.push_back("-m"); v.push_back("comment"); v.push_back("--comment"); v.push_back(kTag);
        return v;
    };

    rules.push_back(tag({"-A", "INPUT", "-i", "lo", "-j", "ACCEPT"}));
    rules.push_back(tag({"-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"}));
    rules.push_back(tag({"-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}));
    rules.push_back(tag({"-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}));
    if (!server_ip.empty()) {
        rules.push_back(tag({"-A", "OUTPUT", "-d", server_ip, "-j", "ACCEPT"}));
        rules.push_back(tag({"-A", "INPUT", "-s", server_ip, "-j", "ACCEPT"}));
    }
    rules.push_back(tag({"-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"}));  // keep DNS working
    rules.push_back(tag({"-A", "OUTPUT", "-j", "DROP"}));
    rules.push_back(tag({"-A", "INPUT", "-j", "DROP"}));
    return rules;
}

#if defined(_WIN32)

CommandOutcome isolate_host(const std::string& /*server_ip*/) {
    // Windows: block all inbound+outbound at the profile level. (A finer-
    // grained "except the AutoSOC server" rule would use `netsh advfirewall
    // firewall add rule` with a remoteip allow-list; the blanket policy
    // switch is used here for the same reversible, dependency-free approach
    // as the Linux path.)
    return run_command("netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound");
}

CommandOutcome release_host() {
    return run_command("netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound");
}

#else  // POSIX / Linux

static bool is_root() { return geteuid() == 0; }

CommandOutcome isolate_host(const std::string& server_ip) {
    if (!is_root()) {
        return {false, "isolation requires root (run the agent with sudo)"};
    }
    // Idempotent: clear any pre-existing AutoSOC isolation rules first.
    release_host();

    std::ostringstream summary;
    bool all_ok = true;
    for (const auto& args : build_isolation_rules(server_ip)) {
        std::ostringstream cmd;
        cmd << "iptables";
        for (const auto& arg : args) cmd << " " << arg;
        CommandOutcome r = run_command(cmd.str());
        if (!r.ok) {
            all_ok = false;
            summary << "FAILED(" << cmd.str() << "): " << r.detail << "; ";
        }
    }
    if (all_ok) {
        return {true, "iptables isolation applied (loopback/established/DNS/" +
                      (server_ip.empty() ? std::string("no-server-pin") : server_ip) + " kept reachable)"};
    }
    return {false, summary.str()};
}

CommandOutcome release_host() {
    if (!is_root()) {
        return {false, "release requires root (run the agent with sudo)"};
    }
    // Repeatedly delete the first rule matching our tag until none remain —
    // iptables allows duplicate rules, so a single -D per chain isn't enough.
    int removed = 0;
    for (int i = 0; i < 64; ++i) {
        CommandOutcome list = run_command("iptables -S 2>/dev/null | grep -F '" + std::string(kTag) + "'");
        if (list.detail.find(kTag) == std::string::npos) break;

        // Parse the first tagged line and re-issue it as a -D (delete).
        std::istringstream lines(list.detail);
        std::string line;
        if (!std::getline(lines, line)) break;
        if (line.rfind("-A ", 0) == 0) line = "-D " + line.substr(3);
        CommandOutcome del = run_command("iptables " + line);
        if (!del.ok) break;
        ++removed;
    }
    return {true, "removed " + std::to_string(removed) + " isolation rule(s)"};
}

#endif

}  // namespace autosoc

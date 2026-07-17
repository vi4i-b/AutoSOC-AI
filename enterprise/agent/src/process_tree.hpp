// Process-tree collection (parent → child, PID/PPID) as JSON.
//
// Cross-platform: Linux walks /proc; Windows uses the Toolhelp32 snapshot.
// The result is a nested tree rooted at PID 1 (or the synthetic root 0 on
// Windows), suitable for the server's hierarchy view.
#pragma once

#include <nlohmann/json.hpp>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace autosoc {

struct ProcInfo {
    int pid = 0;
    int ppid = 0;
    std::string name;
};

// Platform-specific enumeration (implemented in process_tree.cpp).
std::vector<ProcInfo> enumerate_processes();

inline nlohmann::json build_process_tree() {
    using nlohmann::json;
    std::vector<ProcInfo> procs = enumerate_processes();

    std::map<int, ProcInfo> by_pid;
    std::map<int, std::vector<int>> children;
    for (const auto& p : procs) {
        by_pid[p.pid] = p;
        children[p.ppid].push_back(p.pid);
    }

    // Recursive builder with a visited guard against cyclic PID reuse.
    std::map<int, bool> visited;
    std::function<json(int)> build = [&](int pid) -> json {
        json node;
        auto it = by_pid.find(pid);
        node["pid"] = pid;
        node["ppid"] = it != by_pid.end() ? it->second.ppid : 0;
        node["name"] = it != by_pid.end() ? it->second.name : "";
        json kids = json::array();
        if (!visited[pid]) {
            visited[pid] = true;
            for (int child : children[pid]) {
                if (child != pid) kids.push_back(build(child));
            }
        }
        node["children"] = kids;
        return node;
    };

    // Root at 1 (Linux init/systemd); fall back to synthetic 0.
    int root = by_pid.count(1) ? 1 : 0;
    json tree = build(root);
    tree["process_count"] = static_cast<int>(procs.size());
    return tree;
}

}  // namespace autosoc

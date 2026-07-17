// Platform-specific process enumeration + hostname detection.
#include "process_tree.hpp"
#include "config.hpp"

#include <functional>

#if defined(_WIN32)
#include <windows.h>
#include <tlhelp32.h>
#else
#include <dirent.h>
#include <unistd.h>
#include <cstdio>
#include <cctype>
#include <cstring>
#endif

namespace autosoc {

#if defined(_WIN32)

std::vector<ProcInfo> enumerate_processes() {
    std::vector<ProcInfo> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            ProcInfo p;
            p.pid = static_cast<int>(pe.th32ProcessID);
            p.ppid = static_cast<int>(pe.th32ParentProcessID);
            char name[MAX_PATH] = {0};
            wcstombs(name, pe.szExeFile, MAX_PATH - 1);
            p.name = name;
            out.push_back(p);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

std::string AgentConfig::detect_hostname() {
    char buf[256] = {0};
    DWORD n = sizeof(buf);
    if (GetComputerNameA(buf, &n)) return std::string(buf, n);
    return "windows-host";
}

#else  // POSIX / Linux

static bool is_number(const char* s) {
    for (; *s; ++s) if (!std::isdigit(static_cast<unsigned char>(*s))) return false;
    return true;
}

std::vector<ProcInfo> enumerate_processes() {
    std::vector<ProcInfo> out;
    DIR* proc = opendir("/proc");
    if (!proc) return out;
    struct dirent* entry;
    while ((entry = readdir(proc)) != nullptr) {
        if (!is_number(entry->d_name)) continue;
        int pid = std::atoi(entry->d_name);

        // /proc/<pid>/stat: "pid (comm) state ppid ..." — comm may contain
        // spaces/parens, so parse from the last ')'.
        char path[64];
        std::snprintf(path, sizeof(path), "/proc/%d/stat", pid);
        FILE* f = std::fopen(path, "r");
        if (!f) continue;
        char line[4096];
        if (std::fgets(line, sizeof(line), f)) {
            ProcInfo p;
            p.pid = pid;
            const char* rp = std::strrchr(line, ')');
            const char* lp = std::strchr(line, '(');
            if (lp && rp && rp > lp) p.name.assign(lp + 1, rp);
            if (rp) {
                char state;
                int ppid = 0;
                if (std::sscanf(rp + 2, "%c %d", &state, &ppid) == 2) p.ppid = ppid;
            }
            out.push_back(p);
        }
        std::fclose(f);
    }
    closedir(proc);
    return out;
}

std::string AgentConfig::detect_hostname() {
    char buf[256] = {0};
    if (gethostname(buf, sizeof(buf) - 1) == 0) return std::string(buf);
    return "linux-host";
}

#endif

}  // namespace autosoc

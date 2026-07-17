#include "anti_tamper.hpp"

#include <atomic>
#include <csignal>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#include <aclapi.h>
#else
#include <sys/prctl.h>
#include <unistd.h>
#endif

namespace autosoc {

// Set by an authenticated shutdown command; only then do we honor termination.
std::atomic<bool> g_shutdown_authorized{false};

#if defined(_WIN32)

static bool running_as_system() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    // Compare the token user SID against the well-known Local System SID.
    DWORD len = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &len);
    std::vector<char> buf(len);
    bool is_system = false;
    if (GetTokenInformation(token, TokenUser, buf.data(), len, &len)) {
        auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
        PSID system_sid = nullptr;
        SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &system_sid)) {
            is_system = EqualSid(tu->User.Sid, system_sid);
            FreeSid(system_sid);
        }
    }
    CloseHandle(token);
    return is_system;
}

// Deny PROCESS_TERMINATE to Everyone via a restrictive DACL on our own process.
static bool protect_from_terminate() {
    EXPLICIT_ACCESS ea{};
    PSID everyone = nullptr;
    SID_IDENTIFIER_AUTHORITY world = SECURITY_WORLD_SID_AUTHORITY;
    if (!AllocateAndInitializeSid(&world, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &everyone))
        return false;
    ea.grfAccessPermissions = PROCESS_TERMINATE;
    ea.grfAccessMode = DENY_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = reinterpret_cast<LPTSTR>(everyone);

    PACL acl = nullptr;
    bool ok = SetEntriesInAcl(1, &ea, nullptr, &acl) == ERROR_SUCCESS &&
              SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT,
                              DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr) == ERROR_SUCCESS;
    if (everyone) FreeSid(everyone);
    if (acl) LocalFree(acl);
    return ok;
}

HardenResult harden_process() {
    HardenResult r;
    r.privileged = running_as_system();
    r.memory_protected = false;  // DACL below also limits VM_READ if extended
    r.signals_guarded = protect_from_terminate();
    r.note = r.privileged ? "running as SYSTEM" : "NOT running as SYSTEM — protection limited";
    return r;
}

#else  // POSIX / Linux

static void ignore_termination(int) {
    // Anti-tamper: a plain `kill <pid>` (SIGTERM) is ignored. Only an
    // authenticated in-band shutdown flag lets the main loop exit cleanly.
    if (g_shutdown_authorized.load()) std::signal(SIGTERM, SIG_DFL);
}

HardenResult harden_process() {
    HardenResult r;
    r.privileged = (geteuid() == 0);
    // Prevent ptrace attach and core dumps from leaking agent memory.
    r.memory_protected = (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0);
    // Refuse ordinary termination signals.
    std::signal(SIGTERM, ignore_termination);
    std::signal(SIGHUP, SIG_IGN);
    r.signals_guarded = true;
    r.note = r.privileged ? "running as root" : "NOT running as root — protection limited";
    return r;
}

#endif

}  // namespace autosoc

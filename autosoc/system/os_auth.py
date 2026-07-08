"""Authentication against operating-system accounts.

On Windows, credentials are verified through ``LogonUserW`` so an operator
can sign in with their machine/domain account. On Linux there is no safe way
to verify another user's password without root/PAM configuration, so OS-level
login is disabled and only local AutoSOC accounts are used.
"""

import ctypes
import os

if os.name == "nt":
    from ctypes import wintypes

    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32.LogonUserW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _advapi32.LogonUserW.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
else:
    _advapi32 = None
    _kernel32 = None

LOGON32_LOGON_INTERACTIVE = 2
LOGON32_PROVIDER_DEFAULT = 0


def verify_os_credentials(username: str, password: str) -> str | None:
    """Return the canonical username when the OS accepts the credentials."""
    if os.name != "nt" or _advapi32 is None or not username or not password:
        return None

    from ctypes import wintypes

    for candidate_user, candidate_domain, canonical_username in _logon_candidates(username):
        token = wintypes.HANDLE()
        success = _advapi32.LogonUserW(
            candidate_user,
            candidate_domain,
            password,
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            ctypes.byref(token),
        )
        if success:
            if token:
                _kernel32.CloseHandle(token)
            return canonical_username
    return None


def _logon_candidates(username: str):
    normalized = (username or "").strip()
    if not normalized:
        return []

    candidates = []
    if "\\" in normalized:
        domain, user = normalized.split("\\", 1)
        candidates.append((user, domain or ".", normalized))
    elif "@" in normalized:
        candidates.append((normalized, None, normalized))
    else:
        machine_name = (os.environ.get("COMPUTERNAME") or "").strip()
        user_domain = (os.environ.get("USERDOMAIN") or "").strip()
        candidates.append((normalized, ".", normalized))
        if machine_name:
            candidates.append((normalized, machine_name, normalized))
        if user_domain and user_domain != machine_name:
            candidates.append((normalized, user_domain, normalized))
        candidates.append((normalized, None, normalized))

    unique = []
    seen = set()
    for candidate in candidates:
        key = (candidate[0], candidate[1])
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique

"""Authentication against operating-system accounts.

Operators can sign in to AutoSOC with the same account they use to log into the
machine:

* **Windows** — verified through ``LogonUserW`` (machine or domain account).
* **Linux** — verified through **PAM** (``libpam``) via ctypes. On a typical
  system the setuid ``unix_chkpwd`` helper lets a non-root process verify the
  *current* user's own password, so no elevated privileges are needed for the
  logged-in operator. If PAM is unavailable or rejects the credentials, the
  caller falls back to local AutoSOC accounts.

All failures degrade to ``None`` (credentials not accepted) — never an
exception — so login always has a safe fallback path.
"""

from __future__ import annotations

import ctypes
import os
import threading
from ctypes.util import find_library

from autosoc.logging_setup import get_logger

log = get_logger("system.os_auth")

LOGON32_LOGON_INTERACTIVE = 2
LOGON32_PROVIDER_DEFAULT = 0

# ── Windows ──────────────────────────────────────────────────────────

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


def verify_os_credentials(username: str, password: str) -> str | None:
    """Return the canonical username when the OS accepts the credentials."""
    if not username or not password:
        return None
    if os.name == "nt":
        return _verify_windows(username, password)
    if os.name == "posix":
        return _verify_linux_pam(username, password)
    return None


def _verify_windows(username: str, password: str) -> str | None:
    if _advapi32 is None:
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


# ── Linux PAM ────────────────────────────────────────────────────────

_PAM_SUCCESS = 0
_PAM_PROMPT_ECHO_OFF = 1
_PAM_PROMPT_ECHO_ON = 2

_pam_lock = threading.Lock()
_pam_password_holder: list[str] = [""]


class _PamMessage(ctypes.Structure):
    _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]


class _PamResponse(ctypes.Structure):
    _fields_ = [("resp", ctypes.c_char_p), ("resp_retcode", ctypes.c_int)]


_CONV_FUNC = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_int,
    ctypes.POINTER(ctypes.POINTER(_PamMessage)),
    ctypes.POINTER(ctypes.POINTER(_PamResponse)),
    ctypes.c_void_p,
)


class _PamConv(ctypes.Structure):
    _fields_ = [("conv", _CONV_FUNC), ("appdata_ptr", ctypes.c_void_p)]


def _load_pam():
    if os.name != "posix":
        return None, None
    pam_name = find_library("pam")
    libc_name = find_library("c")
    if not pam_name or not libc_name:
        return None, None
    try:
        libpam = ctypes.CDLL(pam_name)
        libc = ctypes.CDLL(libc_name)
    except OSError as exc:
        log.debug("PAM unavailable: %s", exc)
        return None, None

    libc.calloc.restype = ctypes.c_void_p
    libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
    libc.strdup.restype = ctypes.c_void_p
    libc.strdup.argtypes = [ctypes.c_char_p]

    libpam.pam_start.restype = ctypes.c_int
    libpam.pam_start.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(_PamConv), ctypes.POINTER(ctypes.c_void_p),
    ]
    libpam.pam_authenticate.restype = ctypes.c_int
    libpam.pam_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int]
    libpam.pam_acct_mgmt.restype = ctypes.c_int
    libpam.pam_acct_mgmt.argtypes = [ctypes.c_void_p, ctypes.c_int]
    libpam.pam_end.restype = ctypes.c_int
    libpam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
    return libpam, libc


_LIBPAM, _LIBC = _load_pam()


@_CONV_FUNC
def _pam_conversation(n_messages, messages, p_response, _app_data):
    if _LIBC is None:
        return 1
    array = _LIBC.calloc(n_messages, ctypes.sizeof(_PamResponse))
    p_response[0] = ctypes.cast(array, ctypes.POINTER(_PamResponse))
    password = _pam_password_holder[0].encode("utf-8")
    for i in range(n_messages):
        if messages[i].contents.msg_style in (_PAM_PROMPT_ECHO_OFF, _PAM_PROMPT_ECHO_ON):
            p_response[0][i].resp = ctypes.cast(_LIBC.strdup(password), ctypes.c_char_p)
            p_response[0][i].resp_retcode = 0
    return _PAM_SUCCESS


def _verify_linux_pam(username: str, password: str) -> str | None:
    if _LIBPAM is None:
        return None
    service = (os.getenv("AUTOSOC_PAM_SERVICE") or "login").strip() or "login"

    with _pam_lock:
        _pam_password_holder[0] = password
        try:
            handle = ctypes.c_void_p()
            conv = _PamConv(_pam_conversation, None)
            result = _LIBPAM.pam_start(service.encode(), username.encode(), ctypes.byref(conv),
                                       ctypes.byref(handle))
            if result != _PAM_SUCCESS:
                log.debug("pam_start failed (%s) for service %s", result, service)
                return None
            try:
                if _LIBPAM.pam_authenticate(handle, 0) != _PAM_SUCCESS:
                    return None
                if _LIBPAM.pam_acct_mgmt(handle, 0) != _PAM_SUCCESS:
                    return None
                return username.strip()
            finally:
                _LIBPAM.pam_end(handle, 0)
        except OSError as exc:
            log.debug("PAM authentication error: %s", exc)
            return None
        finally:
            _pam_password_holder[0] = ""

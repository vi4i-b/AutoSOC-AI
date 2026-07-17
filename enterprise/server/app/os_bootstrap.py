"""OS-bootstrap super-admin authentication.

Stage 1 of the two-stage auth: the platform owner proves control of the host
by authenticating with an operating-system administrator account. On Linux
this is verified through PAM (``libpam`` via ctypes — the current user's own
password authenticates without root on a typical box); on Windows through
``LogonUserW`` restricted to accounts in the Administrators group.

A successful bootstrap yields super-admin status (all permissions, all
tenants). All failure paths return ``None`` — never raise — so the login flow
degrades safely.
"""

from __future__ import annotations

import ctypes
import os
import threading
from ctypes.util import find_library

from app.config import settings

# ── Linux PAM (ctypes) ────────────────────────────────────────────────

_PAM_SUCCESS = 0
_PAM_PROMPT_ECHO_OFF = 1
_PAM_PROMPT_ECHO_ON = 2
_pam_lock = threading.Lock()
_pam_password: list[str] = [""]


class _PamMessage(ctypes.Structure):
    _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]


class _PamResponse(ctypes.Structure):
    _fields_ = [("resp", ctypes.c_char_p), ("resp_retcode", ctypes.c_int)]


_CONV = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_int,
    ctypes.POINTER(ctypes.POINTER(_PamMessage)),
    ctypes.POINTER(ctypes.POINTER(_PamResponse)),
    ctypes.c_void_p,
)


class _PamConv(ctypes.Structure):
    _fields_ = [("conv", _CONV), ("appdata_ptr", ctypes.c_void_p)]


def _load_pam():
    if os.name != "posix":
        return None, None
    pam_name, libc_name = find_library("pam"), find_library("c")
    if not pam_name or not libc_name:
        return None, None
    try:
        libpam, libc = ctypes.CDLL(pam_name), ctypes.CDLL(libc_name)
    except OSError:
        return None, None
    libc.calloc.restype = ctypes.c_void_p
    libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
    libc.strdup.restype = ctypes.c_void_p
    libc.strdup.argtypes = [ctypes.c_char_p]
    libpam.pam_start.restype = ctypes.c_int
    libpam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                 ctypes.POINTER(_PamConv), ctypes.POINTER(ctypes.c_void_p)]
    libpam.pam_authenticate.restype = ctypes.c_int
    libpam.pam_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int]
    libpam.pam_acct_mgmt.restype = ctypes.c_int
    libpam.pam_acct_mgmt.argtypes = [ctypes.c_void_p, ctypes.c_int]
    libpam.pam_end.restype = ctypes.c_int
    libpam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
    return libpam, libc


_LIBPAM, _LIBC = _load_pam()


@_CONV
def _conversation(n_messages, messages, p_response, _app_data):
    if _LIBC is None:
        return 1
    p_response[0] = ctypes.cast(
        _LIBC.calloc(n_messages, ctypes.sizeof(_PamResponse)), ctypes.POINTER(_PamResponse))
    pw = _pam_password[0].encode("utf-8")
    for i in range(n_messages):
        if messages[i].contents.msg_style in (_PAM_PROMPT_ECHO_OFF, _PAM_PROMPT_ECHO_ON):
            p_response[0][i].resp = ctypes.cast(_LIBC.strdup(pw), ctypes.c_char_p)
            p_response[0][i].resp_retcode = 0
    return _PAM_SUCCESS


def _verify_pam(username: str, password: str) -> bool:
    if _LIBPAM is None:
        return False
    with _pam_lock:
        _pam_password[0] = password
        try:
            handle = ctypes.c_void_p()
            conv = _PamConv(_conversation, None)
            if _LIBPAM.pam_start(settings.pam_service.encode(), username.encode(),
                                 ctypes.byref(conv), ctypes.byref(handle)) != _PAM_SUCCESS:
                return False
            try:
                if _LIBPAM.pam_authenticate(handle, 0) != _PAM_SUCCESS:
                    return False
                return _LIBPAM.pam_acct_mgmt(handle, 0) == _PAM_SUCCESS
            finally:
                _LIBPAM.pam_end(handle, 0)
        except OSError:
            return False
        finally:
            _pam_password[0] = ""


# ── Windows LogonUser + admin-group check ─────────────────────────────

def _verify_windows(username: str, password: str) -> bool:  # pragma: no cover - Windows only
    if os.name != "nt":
        return False
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.LogonUserW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                    wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.LogonUserW.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    # LOGON32_LOGON_INTERACTIVE=2, LOGON32_PROVIDER_DEFAULT=0
    domain = os.environ.get("COMPUTERNAME") or "."
    if not advapi32.LogonUserW(username, domain, password, 2, 0, ctypes.byref(token)):
        return False
    try:
        return _windows_is_admin(token)
    finally:
        kernel32.CloseHandle(token)


def _windows_is_admin(token) -> bool:  # pragma: no cover - Windows only
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    # CheckTokenMembership against the local Administrators SID.
    SECURITY_NT_AUTHORITY = (ctypes.c_byte * 6)(0, 0, 0, 0, 0, 5)
    sid = ctypes.c_void_p()
    # AllocateAndInitializeSid for S-1-5-32-544 (BUILTIN\Administrators)
    if not advapi32.AllocateAndInitializeSid(
            ctypes.byref(SECURITY_NT_AUTHORITY), 2, 32, 544, 0, 0, 0, 0, 0, 0, ctypes.byref(sid)):
        return False
    try:
        is_member = wintypes.BOOL()
        if not advapi32.CheckTokenMembership(token, sid, ctypes.byref(is_member)):
            return False
        return bool(is_member.value)
    finally:
        advapi32.FreeSid(sid)


def verify_os_admin(username: str, password: str) -> bool:
    """True only when the credentials belong to an OS administrator account."""
    if not username or not password:
        return False
    if os.name == "nt":
        return _verify_windows(username, password)
    if os.name == "posix":
        return _verify_pam(username, password)
    return False

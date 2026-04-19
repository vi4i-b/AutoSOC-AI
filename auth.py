import ctypes
import json
import os
from ctypes import wintypes

from database import DB_PATH, SOCDatabase
from security_utils import legacy_hash_password


REMEMBER_FILE = (os.getenv("AUTOSOC_REMEMBER_FILE", "remember.json") or "remember.json").strip()

LOGON32_LOGON_INTERACTIVE = 2
LOGON32_PROVIDER_DEFAULT = 0


def _hash_password(password: str) -> str:
    return legacy_hash_password(password)


if os.name == "nt":
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


def _with_db(callback):
    db = SOCDatabase(DB_PATH)
    try:
        return callback(db)
    finally:
        db.close()


def _windows_logon_candidates(username: str):
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


def _verify_windows_credentials(username: str, password: str) -> str | None:
    if os.name != "nt" or _advapi32 is None or not username or not password:
        return None

    for candidate_user, candidate_domain, canonical_username in _windows_logon_candidates(username):
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


def init_db():
    _with_db(lambda db: True)


def verify_user(username: str, password: str) -> dict | None:
    normalized_username = (username or "").strip()

    def _verify(db):
        windows_username = _verify_windows_credentials(normalized_username, password)
        if windows_username:
            user = db.ensure_user_profile(windows_username, role="System User")
            db.add_audit_event("login_success", windows_username, "Authenticated with Windows credentials.")
            return user

        user = db.authenticate(normalized_username, password)
        if user:
            db.add_audit_event("login_success", normalized_username, "Authenticated with local AutoSOC credentials.")
            return user

        db.add_audit_event("login_failure", normalized_username, "Failed login attempt.")
        return None

    return _with_db(_verify)


def register_user(
    username: str,
    password: str,
    role: str = "user",
    telegram_chat_id: str = "",
    telegram_user_id: str = "",
) -> bool:
    return _with_db(
        lambda db: db.register_user(
            username,
            password,
            role=role,
            telegram_chat_id=telegram_chat_id,
            telegram_user_id=telegram_user_id,
        )
    )


def update_user_telegram(username: str, telegram_chat_id: str, telegram_user_id: str = "") -> bool:
    return _with_db(lambda db: db.update_user_telegram(username, telegram_chat_id, telegram_user_id))


def get_user_telegram(username: str) -> dict | None:
    return _with_db(lambda db: db.get_user_telegram(username))


def is_telegram_chat_id_available(telegram_chat_id: str, exclude_username: str = "") -> bool:
    return _with_db(lambda db: db.is_telegram_chat_id_available(telegram_chat_id, exclude_username))


def save_latest_telegram_user(
    telegram_user_id: str,
    telegram_chat_id: str,
    username: str = "",
    first_name: str = "",
    last_name: str = "",
    raw_payload: str = "",
):
    def _save(db):
        db.save_latest_telegram_user(
            telegram_user_id=telegram_user_id,
            telegram_chat_id=telegram_chat_id,
            username=username,
            first_name=first_name,
            last_name=last_name,
            raw_payload=raw_payload,
        )
        return True

    _with_db(_save)


def get_latest_telegram_chat_id() -> str:
    value = _with_db(lambda db: db.get_setting("telegram_chat_id", ""))
    return (value or "").strip()


def save_remember(username: str):
    try:
        with open(REMEMBER_FILE, "w", encoding="utf-8") as remember_file:
            json.dump({"username": username}, remember_file, ensure_ascii=False, indent=2)
    except OSError:
        pass


def load_remember() -> str | None:
    if not os.path.exists(REMEMBER_FILE):
        return None

    try:
        with open(REMEMBER_FILE, "r", encoding="utf-8") as remember_file:
            data = json.load(remember_file)
            return data.get("username")
    except (OSError, json.JSONDecodeError):
        return None


def clear_remember():
    if os.path.exists(REMEMBER_FILE):
        try:
            os.remove(REMEMBER_FILE)
        except OSError:
            pass

"""User authentication and the "remember me" file.

Login order: OS credentials first (Windows only, see
:mod:`autosoc.system.os_auth`), then local AutoSOC accounts stored in the
database. Local accounts are protected by an account-lockout policy
(:data:`autosoc.database.MAX_FAILED_LOGINS` failures within
:data:`autosoc.database.LOCKOUT_WINDOW_SECONDS`).
"""

import json
import os

from autosoc.database import SOCDatabase
from autosoc.paths import data_file, migrate_legacy_file, restrict_file_permissions
from autosoc.system.os_auth import verify_os_credentials


class AccountLockedError(Exception):
    """Raised when login is temporarily blocked by the lockout policy."""

    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = int(retry_after_seconds)
        super().__init__(f"Account locked. Retry in {self.retry_after_seconds} seconds.")


def _remember_file() -> str:
    override = (os.getenv("AUTOSOC_REMEMBER_FILE") or "").strip()
    if override:
        return override
    path = data_file("remember.json")
    migrate_legacy_file(os.path.join(os.getcwd(), "remember.json"), path)
    return path


def _with_db(callback):
    db = SOCDatabase()
    try:
        return callback(db)
    finally:
        db.close()


def init_db():
    _with_db(lambda db: True)


def verify_user(username: str, password: str) -> dict | None:
    """Return the user profile, None for bad credentials.

    Raises :class:`AccountLockedError` when the lockout policy is active.
    """
    normalized_username = (username or "").strip()

    def _verify(db):
        lockout_seconds = db.login_lockout_remaining(normalized_username)
        if lockout_seconds:
            db.add_audit_event(
                "login_blocked",
                normalized_username,
                f"Login rejected by lockout policy ({lockout_seconds}s remaining).",
            )
            raise AccountLockedError(lockout_seconds)

        os_username = verify_os_credentials(normalized_username, password)
        if os_username:
            user = db.ensure_user_profile(os_username, role="System User")
            db.clear_failed_logins(normalized_username)
            db.add_audit_event("login_success", os_username, "Authenticated with OS credentials.")
            return user

        user = db.authenticate(normalized_username, password)
        if user:
            db.clear_failed_logins(normalized_username)
            db.add_audit_event("login_success", normalized_username, "Authenticated with local AutoSOC credentials.")
            return user

        db.record_failed_login(normalized_username)
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


def registration_mode() -> str:
    """open | invite | closed (default open, set via AUTOSOC_REGISTRATION_MODE)."""
    mode = (os.getenv("AUTOSOC_REGISTRATION_MODE") or "open").strip().lower()
    return mode if mode in ("open", "invite", "closed") else "open"


def register_account(
    username: str,
    password: str,
    telegram_chat_id: str = "",
    invite_code: str = "",
) -> tuple[bool, str]:
    """Register honouring the deployment policy. Returns (ok, message).

    - The very first account always becomes ``admin`` (bootstrap).
    - Otherwise the mode decides: ``open`` allows self-signup as ``analyst``;
      ``invite`` requires a valid invite code (which carries the role);
      ``closed`` refuses all self-registration.
    """
    def _register(db):
        first_user = db.count_users() == 0
        if first_user:
            role = "admin"
        else:
            mode = registration_mode()
            if mode == "closed":
                return False, "Registration is closed. Ask an administrator for an account."
            if mode == "invite" or invite_code:
                role = db.consume_invite(invite_code) if invite_code else None
                if not role:
                    return False, "A valid invite code is required to register."
            else:
                role = "analyst"

        ok = db.register_user(
            username, password, role=role,
            telegram_chat_id=telegram_chat_id,
        )
        if not ok:
            return False, "This username or Telegram Chat ID is already in use."
        note = " as the first administrator" if first_user else f" with role '{role}'"
        return True, f"Account created{note}."

    return _with_db(_register)


def create_invite(role: str, ttl_hours: int = 72, created_by: str = "") -> str:
    return _with_db(lambda db: db.create_invite(role=role, ttl_hours=ttl_hours, created_by=created_by))


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
    path = _remember_file()
    try:
        with open(path, "w", encoding="utf-8") as remember_file:
            json.dump({"username": username}, remember_file, ensure_ascii=False, indent=2)
        restrict_file_permissions(path)
    except OSError:
        pass


def load_remember() -> str | None:
    path = _remember_file()
    if not os.path.exists(path):
        return None

    try:
        with open(path, "r", encoding="utf-8") as remember_file:
            data = json.load(remember_file)
            return data.get("username")
    except (OSError, json.JSONDecodeError):
        return None


def clear_remember():
    path = _remember_file()
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass

import os
import secrets
import sqlite3
import threading
from datetime import datetime

from security_utils import hash_password, needs_rehash, verify_password


DB_PATH = (os.getenv("AUTOSOC_DB_PATH", "soc_audit.db") or "soc_audit.db").strip()


class SOCDatabase:
    def __init__(self, db_path=None):
        self.db_path = db_path or DB_PATH
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._configure_connection()
        self.create_tables()

    def _configure_connection(self):
        cursor = self.conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        self.conn.commit()

    def _now(self):
        return datetime.now().strftime("%d.%m.%Y %H:%M:%S")

    def close(self):
        with self._lock:
            try:
                self.conn.close()
            except sqlite3.Error:
                pass

    def _get_columns(self, table_name):
        cursor = self.conn.cursor()
        return {row["name"] for row in cursor.execute(f"PRAGMA table_info({table_name})").fetchall()}

    def _ensure_column(self, cursor, table_name, column_name, definition):
        existing_columns = self._get_columns(table_name)
        if column_name not in existing_columns:
            cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")

    def create_tables(self):
        with self._lock:
            cursor = self.conn.cursor()

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT,
                    target TEXT,
                    risk_level INTEGER,
                    summary TEXT
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL DEFAULT '',
                    role TEXT DEFAULT 'user',
                    telegram_chat_id TEXT DEFAULT '',
                    telegram_user_id TEXT DEFAULT '',
                    created_at TEXT,
                    updated_at TEXT
                )
                """
            )

            self._ensure_column(cursor, "users", "password_hash", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(cursor, "users", "role", "TEXT DEFAULT 'user'")
            self._ensure_column(cursor, "users", "telegram_chat_id", "TEXT DEFAULT ''")
            self._ensure_column(cursor, "users", "telegram_user_id", "TEXT DEFAULT ''")
            self._ensure_column(cursor, "users", "created_at", "TEXT")
            self._ensure_column(cursor, "users", "updated_at", "TEXT")

            existing_columns = self._get_columns("users")
            if "password" in existing_columns:
                cursor.execute(
                    """
                    UPDATE users
                    SET password_hash = password
                    WHERE COALESCE(password_hash, '') = '' AND COALESCE(password, '') <> ''
                    """
                )

            now = self._now()
            cursor.execute("UPDATE users SET created_at = COALESCE(created_at, ?)", (now,))
            cursor.execute("UPDATE users SET updated_at = COALESCE(updated_at, created_at, ?)", (now,))

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS telegram_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    telegram_user_id TEXT NOT NULL,
                    telegram_chat_id TEXT NOT NULL,
                    username TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    raw_payload TEXT,
                    updated_at TEXT
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TEXT
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT,
                    severity TEXT,
                    source TEXT,
                    details TEXT,
                    created_at TEXT
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    actor TEXT,
                    details TEXT,
                    created_at TEXT
                )
                """
            )

            try:
                cursor.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_telegram_chat_id_unique
                    ON users(telegram_chat_id)
                    WHERE telegram_chat_id <> ''
                    """
                )
            except sqlite3.Error:
                pass

            self.conn.commit()

    def _normalize_user_record(self, row, fallback_username="", fallback_role="user"):
        if not row:
            return {
                "username": fallback_username,
                "role": fallback_role,
                "telegram_chat_id": "",
                "telegram_user_id": "",
            }
        return {
            "username": row["username"] or fallback_username,
            "role": row["role"] or fallback_role,
            "telegram_chat_id": row["telegram_chat_id"] or "",
            "telegram_user_id": row["telegram_user_id"] or "",
        }

    def get_user_record(self, username):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT username, role, telegram_chat_id, telegram_user_id, password_hash
                FROM users
                WHERE username = ?
                """,
                ((username or "").strip(),),
            )
            return cursor.fetchone()

    def ensure_user_profile(self, username, role="System User"):
        normalized_username = (username or "").strip()
        if not normalized_username:
            return None

        with self._lock:
            row = self.get_user_record(normalized_username)
            if row:
                return self._normalize_user_record(row, fallback_username=normalized_username, fallback_role=role)

            now = self._now()
            placeholder_secret = f"windows-auth::{normalized_username}::{secrets.token_urlsafe(24)}"
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO users (
                    username, password_hash, role, telegram_chat_id, telegram_user_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (normalized_username, hash_password(placeholder_secret), role, "", "", now, now),
            )
            self.conn.commit()

        self.add_audit_event("windows_profile_synced", normalized_username, "Windows account mirrored into AutoSOC.")
        return self._normalize_user_record(
            self.get_user_record(normalized_username),
            fallback_username=normalized_username,
            fallback_role=role,
        )

    def register_user(self, username, password, role="Analyst", telegram_chat_id="", telegram_user_id=""):
        normalized_username = (username or "").strip()
        normalized_role = (role or "Analyst").strip() or "Analyst"
        normalized_chat_id = (telegram_chat_id or "").strip()
        normalized_user_id = (telegram_user_id or "").strip()
        now = self._now()

        try:
            with self._lock:
                if normalized_chat_id and not self.is_telegram_chat_id_available(normalized_chat_id):
                    return False

                cursor = self.conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO users (
                        username, password_hash, role, telegram_chat_id, telegram_user_id, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        normalized_username,
                        hash_password(password),
                        normalized_role,
                        normalized_chat_id,
                        normalized_user_id,
                        now,
                        now,
                    ),
                )
                self.conn.commit()
        except sqlite3.IntegrityError:
            return False

        self.add_audit_event(
            "user_registered",
            normalized_username,
            f"Role: {normalized_role}. Telegram linked: {'yes' if normalized_chat_id else 'no'}.",
        )
        return True

    def authenticate(self, username, password):
        normalized_username = (username or "").strip()
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT username, role, telegram_chat_id, telegram_user_id, password_hash
                FROM users
                WHERE username = ?
                """,
                (normalized_username,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            stored_hash = row["password_hash"] or ""
            if not verify_password(password, stored_hash):
                return None

            if needs_rehash(stored_hash):
                cursor.execute(
                    "UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ?",
                    (hash_password(password), self._now(), normalized_username),
                )
                self.conn.commit()

            return self._normalize_user_record(row, fallback_username=normalized_username)

    def update_user_telegram(self, username, telegram_chat_id, telegram_user_id=""):
        normalized_username = (username or "").strip()
        normalized_chat_id = (telegram_chat_id or "").strip()
        normalized_user_id = (telegram_user_id or "").strip()

        with self._lock:
            if normalized_chat_id and not self.is_telegram_chat_id_available(
                normalized_chat_id,
                exclude_username=normalized_username,
            ):
                return False

            cursor = self.conn.cursor()
            cursor.execute(
                """
                UPDATE users
                SET telegram_chat_id = ?, telegram_user_id = COALESCE(NULLIF(?, ''), telegram_user_id), updated_at = ?
                WHERE username = ?
                """,
                (normalized_chat_id, normalized_user_id, self._now(), normalized_username),
            )
            self.conn.commit()
            updated = cursor.rowcount > 0

        if updated:
            self.add_audit_event(
                "telegram_binding_updated",
                normalized_username,
                f"Telegram Chat ID updated to {normalized_chat_id or '[cleared]'}.",
            )
        return updated

    def get_user_telegram(self, username):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT telegram_chat_id, telegram_user_id FROM users WHERE username = ?",
                (((username or "").strip()),),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "telegram_chat_id": row["telegram_chat_id"] or "",
                "telegram_user_id": row["telegram_user_id"] or "",
            }

    def is_telegram_chat_id_available(self, telegram_chat_id, exclude_username=""):
        normalized_chat_id = (telegram_chat_id or "").strip()
        normalized_username = (exclude_username or "").strip()
        if not normalized_chat_id:
            return True

        with self._lock:
            cursor = self.conn.cursor()
            if normalized_username:
                cursor.execute(
                    "SELECT 1 FROM users WHERE telegram_chat_id = ? AND username <> ? LIMIT 1",
                    (normalized_chat_id, normalized_username),
                )
            else:
                cursor.execute(
                    "SELECT 1 FROM users WHERE telegram_chat_id = ? LIMIT 1",
                    (normalized_chat_id,),
                )
            return cursor.fetchone() is None

    def add_scan(self, target, risk, summary):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO scans (date, target, risk_level, summary) VALUES (?, ?, ?, ?)",
                (self._now(), target, risk, summary),
            )
            self.conn.commit()

    def get_all_scans(self):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT date, target, risk_level, summary FROM scans ORDER BY id DESC")
            return cursor.fetchall()

    def save_latest_telegram_user(
        self,
        telegram_user_id,
        telegram_chat_id,
        username="",
        first_name="",
        last_name="",
        raw_payload="",
    ):
        with self._lock:
            cursor = self.conn.cursor()
            now = self._now()
            cursor.execute(
                """
                INSERT INTO telegram_users (
                    telegram_user_id, telegram_chat_id, username, first_name, last_name, raw_payload, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(telegram_user_id),
                    str(telegram_chat_id),
                    username or "",
                    first_name or "",
                    last_name or "",
                    raw_payload or "",
                    now,
                ),
            )
            cursor.execute(
                """
                INSERT INTO app_settings (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                """,
                ("telegram_chat_id", str(telegram_chat_id), now),
            )
            self.conn.commit()

    def get_latest_telegram_user(self):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT telegram_user_id, telegram_chat_id, username, first_name, last_name, updated_at
                FROM telegram_users
                ORDER BY id DESC
                LIMIT 1
                """
            )
            return cursor.fetchone()

    def set_setting(self, key, value):
        with self._lock:
            cursor = self.conn.cursor()
            now = self._now()
            cursor.execute(
                """
                INSERT INTO app_settings (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                """,
                (str(key), "" if value is None else str(value), now),
            )
            self.conn.commit()

    def get_setting(self, key, default=None):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT value FROM app_settings WHERE key = ?", (str(key),))
            row = cursor.fetchone()
            if not row:
                return default
            return row["value"]

    def delete_setting(self, key):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM app_settings WHERE key = ?", (str(key),))
            self.conn.commit()

    def add_security_event(self, event_type, severity, source, details):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO security_events (event_type, severity, source, details, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (event_type, severity, source, details, self._now()),
            )
            self.conn.commit()

    def get_recent_security_events(self, limit=50):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT created_at, event_type, severity, source, details
                FROM security_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(limit),),
            )
            return cursor.fetchall()

    def add_audit_event(self, event_type, actor="", details=""):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_events (event_type, actor, details, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (event_type, actor or "", details or "", self._now()),
            )
            self.conn.commit()

    def get_recent_audit_events(self, limit=50):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT created_at, event_type, actor, details
                FROM audit_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(limit),),
            )
            return cursor.fetchall()

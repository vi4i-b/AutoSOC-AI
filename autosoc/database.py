"""SQLite storage: users, scans, settings, security and audit events.

The database lives in the per-user data directory (see :mod:`autosoc.paths`)
with owner-only permissions. A single connection is shared across threads and
guarded by an RLock.
"""

import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime

from autosoc.paths import data_file, migrate_legacy_file, restrict_file_permissions
from autosoc.security_utils import hash_password, needs_rehash, verify_password

# Account lockout policy: after MAX_FAILED_LOGINS failures within
# LOCKOUT_WINDOW_SECONDS, further attempts are rejected until the window
# passes (protects local accounts from brute force).
MAX_FAILED_LOGINS = 5
LOCKOUT_WINDOW_SECONDS = 900


def resolve_db_path() -> str:
    override = (os.getenv("AUTOSOC_DB_PATH") or "").strip()
    if override:
        return override
    path = data_file("soc_audit.db")
    migrate_legacy_file(os.path.join(os.getcwd(), "soc_audit.db"), path)
    return path


class SOCDatabase:
    def __init__(self, db_path=None):
        self.db_path = db_path or resolve_db_path()
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._configure_connection()
        self.create_tables()
        self.seed_default_rules()
        restrict_file_permissions(self.db_path)

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

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    attempted_at REAL NOT NULL
                )
                """
            )

            # ── SOC console tables ──────────────────────────────────
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    severity TEXT DEFAULT 'Medium',
                    status TEXT DEFAULT 'Open',
                    source TEXT DEFAULT '',
                    assignee TEXT DEFAULT '',
                    mitre TEXT DEFAULT '',
                    summary TEXT DEFAULT '',
                    created_by TEXT DEFAULT '',
                    created_at TEXT,
                    updated_at TEXT
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    author TEXT DEFAULT '',
                    note TEXT NOT NULL,
                    created_at TEXT,
                    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    severity TEXT DEFAULT 'Medium',
                    note TEXT DEFAULT '',
                    added_by TEXT DEFAULT '',
                    created_at TEXT,
                    UNIQUE(ioc_type, value)
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS agents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT UNIQUE NOT NULL,
                    hostname TEXT DEFAULT '',
                    platform TEXT DEFAULT '',
                    ip_address TEXT DEFAULT '',
                    status TEXT DEFAULT 'pending',
                    enrollment_token TEXT DEFAULT '',
                    labels TEXT DEFAULT '',
                    last_seen TEXT DEFAULT '',
                    created_at TEXT
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS ingested_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT DEFAULT '',
                    source TEXT DEFAULT '',
                    severity TEXT DEFAULT 'info',
                    message TEXT NOT NULL,
                    created_at TEXT
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_snapshots (
                    agent_id TEXT PRIMARY KEY,
                    data TEXT NOT NULL DEFAULT '{}',
                    updated_at TEXT
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS blocklist (
                    ip TEXT PRIMARY KEY,
                    reason TEXT DEFAULT '',
                    severity TEXT DEFAULT 'High',
                    added_by TEXT DEFAULT '',
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT,
                    updated_at TEXT
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS detection_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_key TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    category TEXT DEFAULT '',
                    severity TEXT DEFAULT 'Medium',
                    mitre TEXT DEFAULT '',
                    rule_type TEXT DEFAULT 'log_match',
                    pattern TEXT DEFAULT '',
                    threshold INTEGER DEFAULT 1,
                    window_seconds INTEGER DEFAULT 60,
                    ports TEXT DEFAULT '',
                    auto_incident INTEGER DEFAULT 0,
                    auto_block INTEGER DEFAULT 0,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    builtin INTEGER NOT NULL DEFAULT 0,
                    created_by TEXT DEFAULT '',
                    created_at TEXT
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    command TEXT NOT NULL,
                    args TEXT DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'pending',
                    result TEXT DEFAULT '',
                    requested_by TEXT DEFAULT '',
                    created_at TEXT,
                    updated_at TEXT
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS invites (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code_hash TEXT UNIQUE NOT NULL,
                    role TEXT NOT NULL DEFAULT 'analyst',
                    used INTEGER NOT NULL DEFAULT 0,
                    expires_at REAL,
                    created_by TEXT DEFAULT '',
                    created_at TEXT
                )
                """
            )

            # Network-isolation flag for endpoints (set from command results).
            self._ensure_column(cursor, "agents", "isolated", "INTEGER NOT NULL DEFAULT 0")

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

            # Indexes for the hot paths the SOC console polls frequently, so
            # queries stay fast as event/log volume grows (Linux and Windows).
            for index_sql in (
                "CREATE INDEX IF NOT EXISTS idx_security_events_id ON security_events(id DESC)",
                "CREATE INDEX IF NOT EXISTS idx_ingested_logs_id ON ingested_logs(id DESC)",
                "CREATE INDEX IF NOT EXISTS idx_agent_commands_agent ON agent_commands(agent_id, status)",
                "CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)",
                "CREATE INDEX IF NOT EXISTS idx_login_attempts_user ON login_attempts(username, attempted_at)",
            ):
                try:
                    cursor.execute(index_sql)
                except sqlite3.Error:
                    pass

            self.conn.commit()

    # ── users ────────────────────────────────────────────────────────

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
            placeholder_secret = f"os-auth::{normalized_username}::{secrets.token_urlsafe(24)}"
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

        self.add_audit_event("os_profile_synced", normalized_username, "OS account mirrored into AutoSOC.")
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
            row = self.get_user_record(normalized_username)
            if not row:
                return None

            stored_hash = row["password_hash"] or ""
            if not verify_password(password, stored_hash):
                return None

            if needs_rehash(stored_hash):
                cursor = self.conn.cursor()
                cursor.execute(
                    "UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ?",
                    (hash_password(password), self._now(), normalized_username),
                )
                self.conn.commit()

            return self._normalize_user_record(row, fallback_username=normalized_username)

    # ── login lockout ────────────────────────────────────────────────

    def record_failed_login(self, username):
        normalized = (username or "").strip()
        if not normalized:
            return
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO login_attempts (username, attempted_at) VALUES (?, ?)",
                (normalized, time.time()),
            )
            cursor.execute(
                "DELETE FROM login_attempts WHERE attempted_at < ?",
                (time.time() - LOCKOUT_WINDOW_SECONDS,),
            )
            self.conn.commit()

    def clear_failed_logins(self, username):
        normalized = (username or "").strip()
        if not normalized:
            return
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM login_attempts WHERE username = ?", (normalized,))
            self.conn.commit()

    def login_lockout_remaining(self, username) -> int:
        """Seconds until the account may try again (0 when not locked)."""
        normalized = (username or "").strip()
        if not normalized:
            return 0
        cutoff = time.time() - LOCKOUT_WINDOW_SECONDS
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT COUNT(*) AS attempts, MAX(attempted_at) AS latest
                FROM login_attempts
                WHERE username = ? AND attempted_at >= ?
                """,
                (normalized, cutoff),
            )
            row = cursor.fetchone()
            if not row or (row["attempts"] or 0) < MAX_FAILED_LOGINS:
                return 0
            remaining = int(row["latest"] + LOCKOUT_WINDOW_SECONDS - time.time())
            return max(remaining, 1)

    # ── telegram binding ─────────────────────────────────────────────

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

    # ── settings ─────────────────────────────────────────────────────

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

    # ── scans / events ───────────────────────────────────────────────

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

    # ── incidents ────────────────────────────────────────────────────

    def create_incident(self, title, severity="Medium", source="", summary="", created_by="", mitre=""):
        with self._lock:
            now = self._now()
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO incidents (
                    title, severity, status, source, assignee, mitre, summary, created_by, created_at, updated_at
                ) VALUES (?, ?, 'Open', ?, '', ?, ?, ?, ?, ?)
                """,
                (title, severity, source, mitre, summary, created_by, now, now),
            )
            self.conn.commit()
            return cursor.lastrowid

    def list_incidents(self, status=None, limit=200):
        with self._lock:
            cursor = self.conn.cursor()
            if status and status != "All":
                cursor.execute(
                    """
                    SELECT id, title, severity, status, source, assignee, mitre, summary, created_at, updated_at
                    FROM incidents WHERE status = ? ORDER BY id DESC LIMIT ?
                    """,
                    (status, int(limit)),
                )
            else:
                cursor.execute(
                    """
                    SELECT id, title, severity, status, source, assignee, mitre, summary, created_at, updated_at
                    FROM incidents ORDER BY id DESC LIMIT ?
                    """,
                    (int(limit),),
                )
            return cursor.fetchall()

    def get_incident(self, incident_id):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT id, title, severity, status, source, assignee, mitre, summary, created_by, created_at, updated_at
                FROM incidents WHERE id = ?
                """,
                (int(incident_id),),
            )
            return cursor.fetchone()

    def update_incident(self, incident_id, **fields):
        allowed = {"title", "severity", "status", "assignee", "mitre", "summary", "source"}
        updates = {key: value for key, value in fields.items() if key in allowed}
        if not updates:
            return False
        with self._lock:
            assignments = ", ".join(f"{key} = ?" for key in updates)
            values = list(updates.values()) + [self._now(), int(incident_id)]
            cursor = self.conn.cursor()
            cursor.execute(
                f"UPDATE incidents SET {assignments}, updated_at = ? WHERE id = ?",
                values,
            )
            self.conn.commit()
            return cursor.rowcount > 0

    def add_incident_note(self, incident_id, note, author=""):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO incident_notes (incident_id, author, note, created_at) VALUES (?, ?, ?, ?)",
                (int(incident_id), author, note, self._now()),
            )
            cursor.execute(
                "UPDATE incidents SET updated_at = ? WHERE id = ?",
                (self._now(), int(incident_id)),
            )
            self.conn.commit()
            return cursor.lastrowid

    def get_incident_notes(self, incident_id):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT created_at, author, note FROM incident_notes WHERE incident_id = ? ORDER BY id ASC",
                (int(incident_id),),
            )
            return cursor.fetchall()

    def incident_status_counts(self):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT status, COUNT(*) FROM incidents GROUP BY status")
            return {row[0]: row[1] for row in cursor.fetchall()}

    # ── IOCs ─────────────────────────────────────────────────────────

    def add_ioc(self, ioc_type, value, severity="Medium", note="", added_by=""):
        with self._lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO iocs (ioc_type, value, severity, note, added_by, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (ioc_type, value.strip(), severity, note, added_by, self._now()),
                )
                self.conn.commit()
                return cursor.lastrowid
            except sqlite3.IntegrityError:
                return None

    def list_iocs(self, limit=500):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT id, ioc_type, value, severity, note, added_by, created_at FROM iocs ORDER BY id DESC LIMIT ?",
                (int(limit),),
            )
            return cursor.fetchall()

    def delete_ioc(self, ioc_id):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM iocs WHERE id = ?", (int(ioc_id),))
            self.conn.commit()
            return cursor.rowcount > 0

    def match_iocs(self, value):
        value = (value or "").strip()
        if not value:
            return []
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT id, ioc_type, value, severity, note FROM iocs WHERE value = ?",
                (value,),
            )
            return cursor.fetchall()

    # ── agents / endpoints ───────────────────────────────────────────

    def register_agent(self, agent_id, hostname="", platform="", ip_address="", enrollment_token="", labels=""):
        with self._lock:
            now = self._now()
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO agents (agent_id, hostname, platform, ip_address, status, enrollment_token, labels, last_seen, created_at)
                VALUES (?, ?, ?, ?, 'pending', ?, ?, '', ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    hostname = excluded.hostname,
                    platform = excluded.platform,
                    ip_address = excluded.ip_address,
                    labels = excluded.labels
                """,
                (agent_id, hostname, platform, ip_address, enrollment_token, labels, now),
            )
            self.conn.commit()
            return cursor.lastrowid

    def list_agents(self):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT id, agent_id, hostname, platform, ip_address, status, labels, last_seen,
                       created_at, COALESCE(isolated, 0) AS isolated
                FROM agents ORDER BY id DESC
                """
            )
            return cursor.fetchall()

    def set_agent_isolated(self, agent_id, isolated):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "UPDATE agents SET isolated = ? WHERE agent_id = ?",
                (1 if isolated else 0, agent_id),
            )
            self.conn.commit()
            return cursor.rowcount > 0

    def set_agent_status(self, agent_id, status):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "UPDATE agents SET status = ?, last_seen = ? WHERE agent_id = ?",
                (status, self._now(), agent_id),
            )
            self.conn.commit()
            return cursor.rowcount > 0

    def delete_agent(self, agent_id):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))
            self.conn.commit()
            return cursor.rowcount > 0

    # ── ingested logs ────────────────────────────────────────────────

    def add_ingested_log(self, message, agent_id="", source="", severity="info"):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO ingested_logs (agent_id, source, severity, message, created_at) VALUES (?, ?, ?, ?, ?)",
                (agent_id, source, severity, message, self._now()),
            )
            self.conn.commit()
            return cursor.lastrowid

    def search_logs(self, query="", limit=300):
        query = (query or "").strip()
        with self._lock:
            cursor = self.conn.cursor()
            if query:
                like = f"%{query}%"
                cursor.execute(
                    """
                    SELECT created_at, agent_id, source, severity, message
                    FROM ingested_logs
                    WHERE message LIKE ? OR source LIKE ? OR agent_id LIKE ?
                    ORDER BY id DESC LIMIT ?
                    """,
                    (like, like, like, int(limit)),
                )
            else:
                cursor.execute(
                    """
                    SELECT created_at, agent_id, source, severity, message
                    FROM ingested_logs ORDER BY id DESC LIMIT ?
                    """,
                    (int(limit),),
                )
            return cursor.fetchall()

    def count_rows(self, table):
        allowed = {"incidents", "iocs", "agents", "ingested_logs", "security_events", "scans", "users"}
        if table not in allowed:
            raise ValueError(f"count_rows not allowed for table {table}")
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            return cursor.fetchone()[0]

    # ── agent collector ──────────────────────────────────────────────

    def get_or_create_ingestion_token(self):
        """Bearer token agents must present to the collector. Generated on first use."""
        token = (self.get_setting("ingestion_token", "") or "").strip()
        if not token:
            token = "ingest_" + secrets.token_urlsafe(24)
            self.set_setting("ingestion_token", token)
        return token

    def regenerate_ingestion_token(self):
        token = "ingest_" + secrets.token_urlsafe(24)
        self.set_setting("ingestion_token", token)
        return token

    def verify_ingestion_token(self, presented) -> bool:
        import hmac

        expected = self.get_or_create_ingestion_token()
        return hmac.compare_digest(str(presented or ""), expected)

    def mark_agent_seen(self, agent_id, hostname="", platform="", ip_address="", status="online"):
        """Upsert an agent on enroll/report and mark it online with a fresh last_seen."""
        agent_id = (agent_id or "").strip()
        if not agent_id:
            return False
        with self._lock:
            now = self._now()
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO agents (agent_id, hostname, platform, ip_address, status, last_seen, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    hostname = excluded.hostname,
                    platform = excluded.platform,
                    ip_address = excluded.ip_address,
                    status = excluded.status,
                    last_seen = excluded.last_seen
                """,
                (agent_id, hostname or "", platform or "", ip_address or "", status, now, now),
            )
            self.conn.commit()
            return True

    def save_agent_snapshot(self, agent_id, data_json):
        agent_id = (agent_id or "").strip()
        if not agent_id:
            return
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO agent_snapshots (agent_id, data, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    data = excluded.data,
                    updated_at = excluded.updated_at
                """,
                (agent_id, data_json, self._now()),
            )
            self.conn.commit()

    def get_agent_snapshot(self, agent_id):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT data, updated_at FROM agent_snapshots WHERE agent_id = ?", (agent_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return {"data": row["data"], "updated_at": row["updated_at"]}

    def mark_stale_agents(self, stale_seconds=120):
        """Flip agents that have not reported within the window to 'offline'."""
        import time as _time
        from datetime import datetime as _dt

        cutoff = _time.time() - stale_seconds
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT agent_id, last_seen, status FROM agents WHERE status = 'online'")
            rows = cursor.fetchall()
            flipped = []
            for row in rows:
                last_seen = row["last_seen"]
                try:
                    ts = _dt.strptime(last_seen, "%d.%m.%Y %H:%M:%S").timestamp()
                except (TypeError, ValueError):
                    continue
                if ts < cutoff:
                    flipped.append(row["agent_id"])
            for agent_id in flipped:
                cursor.execute("UPDATE agents SET status = 'offline' WHERE agent_id = ?", (agent_id,))
            if flipped:
                self.conn.commit()
            return flipped

    # ── blocklist (firewall threat feed) ─────────────────────────────

    def add_blocked_ip(self, ip, reason="", severity="High", added_by=""):
        """Add or re-activate an IP on the block list (feed served to appliances)."""
        ip = (ip or "").strip()
        if not ip:
            return False
        with self._lock:
            now = self._now()
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO blocklist (ip, reason, severity, added_by, active, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    reason = excluded.reason,
                    severity = excluded.severity,
                    added_by = excluded.added_by,
                    active = 1,
                    updated_at = excluded.updated_at
                """,
                (ip, reason, severity, added_by, now, now),
            )
            self.conn.commit()
            return True

    def remove_blocked_ip(self, ip):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "UPDATE blocklist SET active = 0, updated_at = ? WHERE ip = ?",
                (self._now(), (ip or "").strip()),
            )
            self.conn.commit()
            return cursor.rowcount > 0

    def list_blocked_ips(self, active_only=True):
        with self._lock:
            cursor = self.conn.cursor()
            if active_only:
                cursor.execute(
                    "SELECT ip, reason, severity, added_by, created_at FROM blocklist WHERE active = 1 ORDER BY rowid DESC"
                )
            else:
                cursor.execute(
                    "SELECT ip, reason, severity, added_by, created_at FROM blocklist ORDER BY rowid DESC"
                )
            return cursor.fetchall()

    def active_blocklist(self):
        """Just the IP strings currently blocked — used to render the feed."""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT ip FROM blocklist WHERE active = 1 ORDER BY ip")
            return [row["ip"] for row in cursor.fetchall()]

    # ── detection rules ──────────────────────────────────────────────

    def seed_default_rules(self):
        """Insert the built-in baseline rules that are missing (by rule_key)."""
        from autosoc.detection.default_rules import DEFAULT_RULES

        with self._lock:
            now = self._now()
            cursor = self.conn.cursor()
            for rule in DEFAULT_RULES:
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO detection_rules (
                        rule_key, name, description, category, severity, mitre, rule_type,
                        pattern, threshold, window_seconds, ports, auto_incident, auto_block,
                        enabled, builtin, created_by, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, 'system', ?)
                    """,
                    (
                        rule["rule_key"], rule["name"], rule.get("description", ""),
                        rule.get("category", ""), rule.get("severity", "Medium"),
                        rule.get("mitre", ""), rule.get("rule_type", "log_match"),
                        rule.get("pattern", ""), int(rule.get("threshold", 1)),
                        int(rule.get("window_seconds", 60)), rule.get("ports", ""),
                        int(rule.get("auto_incident", 0)), int(rule.get("auto_block", 0)), now,
                    ),
                )
            self.conn.commit()

    def list_rules(self, enabled_only=False):
        with self._lock:
            cursor = self.conn.cursor()
            query = (
                "SELECT id, rule_key, name, description, category, severity, mitre, rule_type, "
                "pattern, threshold, window_seconds, ports, auto_incident, auto_block, enabled, "
                "builtin, created_by, created_at FROM detection_rules"
            )
            if enabled_only:
                query += " WHERE enabled = 1"
            query += " ORDER BY builtin DESC, category, name"
            cursor.execute(query)
            return cursor.fetchall()

    def get_rule(self, rule_key):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM detection_rules WHERE rule_key = ?", (rule_key,))
            return cursor.fetchone()

    def add_rule(self, rule_key, name, pattern, severity="Medium", category="Custom", mitre="",
                 rule_type="log_match", threshold=1, window_seconds=60, ports="",
                 auto_incident=0, auto_block=0, description="", created_by=""):
        rule_key = (rule_key or "").strip()
        name = (name or "").strip()
        if not rule_key or not name:
            return None
        try:
            with self._lock:
                cursor = self.conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO detection_rules (
                        rule_key, name, description, category, severity, mitre, rule_type,
                        pattern, threshold, window_seconds, ports, auto_incident, auto_block,
                        enabled, builtin, created_by, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?)
                    """,
                    (rule_key, name, description, category, severity, mitre, rule_type,
                     pattern, int(threshold), int(window_seconds), ports,
                     int(auto_incident), int(auto_block), created_by, self._now()),
                )
                self.conn.commit()
                return cursor.lastrowid
        except sqlite3.IntegrityError:
            return None

    def set_rule_enabled(self, rule_key, enabled):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "UPDATE detection_rules SET enabled = ? WHERE rule_key = ?",
                (1 if enabled else 0, rule_key),
            )
            self.conn.commit()
            return cursor.rowcount > 0

    def delete_rule(self, rule_key):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM detection_rules WHERE rule_key = ?", (rule_key,))
            self.conn.commit()
            return cursor.rowcount > 0

    # ── agent command channel ────────────────────────────────────────

    def enqueue_agent_command(self, agent_id, command, args="", requested_by=""):
        agent_id = (agent_id or "").strip()
        command = (command or "").strip()
        if not agent_id or not command:
            return None
        with self._lock:
            now = self._now()
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO agent_commands (agent_id, command, args, status, requested_by, created_at, updated_at)
                VALUES (?, ?, ?, 'pending', ?, ?, ?)
                """,
                (agent_id, command, args, requested_by, now, now),
            )
            self.conn.commit()
            return cursor.lastrowid

    def claim_agent_commands(self, agent_id):
        """Return pending commands for an agent and mark them 'sent' atomically."""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT id, command, args FROM agent_commands WHERE agent_id = ? AND status = 'pending' ORDER BY id ASC",
                (agent_id,),
            )
            rows = cursor.fetchall()
            if rows:
                ids = [row["id"] for row in rows]
                cursor.executemany(
                    "UPDATE agent_commands SET status = 'sent', updated_at = ? WHERE id = ?",
                    [(self._now(), cid) for cid in ids],
                )
                self.conn.commit()
            return [{"id": row["id"], "command": row["command"], "args": row["args"]} for row in rows]

    def complete_agent_command(self, command_id, status, result=""):
        status = status if status in ("done", "failed") else "failed"
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "UPDATE agent_commands SET status = ?, result = ?, updated_at = ? WHERE id = ?",
                (status, str(result)[:2000], self._now(), int(command_id)),
            )
            self.conn.commit()
            cursor.execute("SELECT agent_id, command FROM agent_commands WHERE id = ?", (int(command_id),))
            return cursor.fetchone()

    def list_agent_commands(self, agent_id, limit=30):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT id, command, args, status, result, requested_by, created_at, updated_at
                FROM agent_commands WHERE agent_id = ? ORDER BY id DESC LIMIT ?
                """,
                (agent_id, int(limit)),
            )
            return cursor.fetchall()

    # ── users administration (RBAC) ──────────────────────────────────

    def count_users(self):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            return cursor.fetchone()[0]

    def count_admins(self):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users WHERE LOWER(role) = 'admin'")
            return cursor.fetchone()[0]

    def list_users(self):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT username, role, telegram_chat_id, created_at FROM users ORDER BY username"
            )
            return cursor.fetchall()

    def set_user_role(self, username, role):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "UPDATE users SET role = ?, updated_at = ? WHERE username = ?",
                (role, self._now(), (username or "").strip()),
            )
            self.conn.commit()
            return cursor.rowcount > 0

    def delete_user(self, username):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM users WHERE username = ?", ((username or "").strip(),))
            self.conn.commit()
            return cursor.rowcount > 0

    # ── invite codes ─────────────────────────────────────────────────

    def _hash_invite(self, code):
        import hashlib

        return hashlib.sha256((code or "").encode("utf-8")).hexdigest()

    def create_invite(self, role="analyst", ttl_hours=72, created_by=""):
        """Create a single-use invite and return the plaintext code (stored hashed)."""
        code = "inv-" + secrets.token_urlsafe(9)
        expires_at = time.time() + max(int(ttl_hours), 1) * 3600
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO invites (code_hash, role, used, expires_at, created_by, created_at)
                VALUES (?, ?, 0, ?, ?, ?)
                """,
                (self._hash_invite(code), role, expires_at, created_by, self._now()),
            )
            self.conn.commit()
        return code

    def consume_invite(self, code):
        """Validate and burn an invite; returns its role or None."""
        code_hash = self._hash_invite(code)
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT id, role, used, expires_at FROM invites WHERE code_hash = ?",
                (code_hash,),
            )
            row = cursor.fetchone()
            if not row or row["used"]:
                return None
            if row["expires_at"] and row["expires_at"] < time.time():
                return None
            cursor.execute("UPDATE invites SET used = 1 WHERE id = ?", (row["id"],))
            self.conn.commit()
            return row["role"]

    def list_invites(self, limit=50):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT role, used, expires_at, created_by, created_at FROM invites ORDER BY id DESC LIMIT ?",
                (int(limit),),
            )
            return cursor.fetchall()

import sqlite3
import hashlib
import os
import json
from datetime import datetime

# Единая база данных для всего проекта AutoSOC
DB_PATH = "soc_audit.db"
REMEMBER_FILE = "remember.json"


def _hash_password(password: str) -> str:
    """SHA-256 ilə parolu hashla (Təhlükəsizlik üçün)"""
    return hashlib.sha256(password.encode()).hexdigest()


def init_db():
    """Baza yaradılması və ilkin admin təyin edilməsi"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # İstifadəçilər cədvəli
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT "user"
        )
    ''')

    existing_columns = {row[1] for row in c.execute("PRAGMA table_info(users)").fetchall()}
    if "telegram_chat_id" not in existing_columns:
        c.execute('ALTER TABLE users ADD COLUMN telegram_chat_id TEXT DEFAULT ""')
    if "telegram_user_id" not in existing_columns:
        c.execute('ALTER TABLE users ADD COLUMN telegram_user_id TEXT DEFAULT ""')

    c.execute('''
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
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TEXT
        )
    ''')

    # Əgər heç bir istifadəçi yoxdursa — default admin:admin123 yarat
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                  ("admin", _hash_password("admin123"), "admin"))

    conn.commit()
    conn.close()


def verify_user(username: str, password: str) -> dict | None:
    """İstifadəçini yoxla və girişə icazə ver"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT username, role, telegram_chat_id, telegram_user_id FROM users WHERE username=? AND password_hash=?",
                  (username, _hash_password(password)))
        row = c.fetchone()
        conn.close()

        if row:
            return {
                "username": row[0],
                "role": row[1],
                "telegram_chat_id": row[2] or "",
                "telegram_user_id": row[3] or "",
            }
        return None
    except Exception:
        return None


def register_user(username: str, password: str, role: str = "user", telegram_chat_id: str = "", telegram_user_id: str = "") -> bool:
    """Yeni SOC analitiki qeydiyyatdan keçir"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        if telegram_chat_id:
            c.execute("SELECT username FROM users WHERE telegram_chat_id = ?", (telegram_chat_id,))
            if c.fetchone():
                conn.close()
                return False
        c.execute(
            "INSERT INTO users (username, password_hash, role, telegram_chat_id, telegram_user_id) VALUES (?, ?, ?, ?, ?)",
            (username, _hash_password(password), role, telegram_chat_id or "", telegram_user_id or ""),
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False  # İstifadəçi artıq mövcuddur
    except Exception:
        return False


def update_user_telegram(username: str, telegram_chat_id: str, telegram_user_id: str = "") -> bool:
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        if telegram_chat_id:
            c.execute(
                "SELECT username FROM users WHERE telegram_chat_id = ? AND username <> ?",
                (telegram_chat_id, username),
            )
            if c.fetchone():
                conn.close()
                return False
        c.execute(
            """
            UPDATE users
            SET telegram_chat_id = ?, telegram_user_id = COALESCE(NULLIF(?, ''), telegram_user_id)
            WHERE username = ?
            """,
            (telegram_chat_id or "", telegram_user_id or "", username),
        )
        conn.commit()
        updated = c.rowcount > 0
        conn.close()
        return updated
    except Exception:
        return False


def get_user_telegram(username: str) -> dict | None:
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT telegram_chat_id, telegram_user_id FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if not row:
            return None
        return {"telegram_chat_id": row[0] or "", "telegram_user_id": row[1] or ""}
    except Exception:
        return None


def is_telegram_chat_id_available(telegram_chat_id: str, exclude_username: str = "") -> bool:
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        if exclude_username:
            c.execute(
                "SELECT 1 FROM users WHERE telegram_chat_id = ? AND username <> ?",
                (telegram_chat_id, exclude_username),
            )
        else:
            c.execute("SELECT 1 FROM users WHERE telegram_chat_id = ?", (telegram_chat_id,))
        row = c.fetchone()
        conn.close()
        return row is None
    except Exception:
        return False


def save_latest_telegram_user(telegram_user_id: str, telegram_chat_id: str, username: str = "", first_name: str = "", last_name: str = "", raw_payload: str = ""):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        now = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        c.execute(
            """
            INSERT INTO telegram_users (
                telegram_user_id, telegram_chat_id, username, first_name, last_name, raw_payload, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (str(telegram_user_id), str(telegram_chat_id), username or "", first_name or "", last_name or "", raw_payload or "", now),
        )
        c.execute(
            """
            INSERT INTO app_settings (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            """,
            ("telegram_chat_id", str(telegram_chat_id), now),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_latest_telegram_chat_id() -> str:
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT value FROM app_settings WHERE key = 'telegram_chat_id'")
        row = c.fetchone()
        conn.close()
        return (row[0] if row and row[0] else "").strip()
    except Exception:
        return ""


def save_remember(username: str):
    """'Məni xatırla' funksiyası üçün məlumatı saxla"""
    try:
        with open(REMEMBER_FILE, "w") as f:
            json.dump({"username": username}, f)
    except:
        pass


def load_remember() -> str | None:
    """Saxlanmış istifadəçini yüklə"""
    if os.path.exists(REMEMBER_FILE):
        try:
            with open(REMEMBER_FILE, "r") as f:
                data = json.load(f)
                return data.get("username")
        except:
            return None
    return None


def clear_remember():
    """'Məni xatırla' yaddaşını təmizlə"""
    if os.path.exists(REMEMBER_FILE):
        try:
            os.remove(REMEMBER_FILE)
        except:
            pass

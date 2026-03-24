import sqlite3
import hashlib
import os
import json

DB_PATH = "users.db"
REMEMBER_FILE = "remember.json"


def _hash_password(password: str) -> str:
    """SHA-256 ilə parolu hashla"""
    return hashlib.sha256(password.encode()).hexdigest()


def init_db():
    """Verilənlər bazasını yarat və ilk admin istifadəçini əlavə et"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT "user"
        )
    ''')
    conn.commit()

    # Əgər heç bir istifadəçi yoxdursa — default admin yarat
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                  ("admin", _hash_password("admin123"), "admin"))
        conn.commit()

    conn.close()


def verify_user(username: str, password: str) -> dict | None:
    """
    İstifadəçini yoxla.
    Uğurlu olarsa: {'username': ..., 'role': ...}
    Uğursuz olarsa: None
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username, role FROM users WHERE username=? AND password_hash=?",
              (username, _hash_password(password)))
    row = c.fetchone()
    conn.close()

    if row:
        return {"username": row[0], "role": row[1]}
    return None


def add_user(username: str, password: str, role: str = "user") -> bool:
    """Yeni istifadəçi əlavə et. Uğurlu olarsa True qaytarır."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                  (username, _hash_password(password), role))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False  # İstifadəçi artıq mövcuddur


def save_remember(username: str):
    """'Məni xatırla' üçün istifadəçi adını saxla"""
    with open(REMEMBER_FILE, "w") as f:
        json.dump({"username": username}, f)


def load_remember() -> str | None:
    """Saxlanmış istifadəçi adını yüklə"""
    if os.path.exists(REMEMBER_FILE):
        with open(REMEMBER_FILE, "r") as f:
            data = json.load(f)
            return data.get("username")
    return None


def clear_remember():
    """'Məni xatırla' faylını sil"""
    if os.path.exists(REMEMBER_FILE):
        os.remove(REMEMBER_FILE)

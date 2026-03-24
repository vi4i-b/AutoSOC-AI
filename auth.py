import sqlite3
import hashlib
import os
import json

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
        c.execute("SELECT username, role FROM users WHERE username=? AND password_hash=?",
                  (username, _hash_password(password)))
        row = c.fetchone()
        conn.close()

        if row:
            return {"username": row[0], "role": row[1]}
        return None
    except Exception:
        return None


def register_user(username: str, password: str, role: str = "user") -> bool:
    """Yeni SOC analitiki qeydiyyatdan keçir"""
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
    except Exception:
        return False


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
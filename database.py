import hashlib
import sqlite3
from datetime import datetime


class SOCDatabase:
    def __init__(self):
        self.conn = sqlite3.connect("soc_audit.db", check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.create_tables()

    def create_tables(self):
        self.cursor.execute(
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

        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                role TEXT
            )
            """
        )

        self.cursor.execute(
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
        self.conn.commit()

    def add_scan(self, target, risk, summary):
        now = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        self.cursor.execute(
            "INSERT INTO scans (date, target, risk_level, summary) VALUES (?, ?, ?, ?)",
            (now, target, risk, summary),
        )
        self.conn.commit()

    def get_all_scans(self):
        self.cursor.execute("SELECT date, target, risk_level, summary FROM scans ORDER BY id DESC")
        return self.cursor.fetchall()

    def register_user(self, username, password, role="Analyst"):
        try:
            hashed_pw = hashlib.sha256(password.encode()).hexdigest()
            self.cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hashed_pw, role),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def authenticate(self, username, password):
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()
        self.cursor.execute(
            "SELECT username, role FROM users WHERE username = ? AND password = ?",
            (username, hashed_pw),
        )
        user = self.cursor.fetchone()
        if user:
            return {"username": user[0], "role": user[1]}
        return None

    def upsert_telegram_user(self, telegram_user_id, telegram_chat_id, username="", first_name="", last_name="", raw_payload=""):
        now = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        self.cursor.execute(
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
        self.conn.commit()

    def get_latest_telegram_user(self):
        self.cursor.execute(
            """
            SELECT telegram_user_id, telegram_chat_id, username, first_name, last_name, updated_at
            FROM telegram_users
            ORDER BY id DESC
            LIMIT 1
            """
        )
        return self.cursor.fetchone()

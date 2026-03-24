import sqlite3
import hashlib
from datetime import datetime


class SOCDatabase:
    def __init__(self):
        # Подключаемся к базе
        self.conn = sqlite3.connect("soc_audit.db", check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.create_tables()

    def create_tables(self):
        """Создает все необходимые таблицы"""
        # Таблица для сканирований
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT,
                target TEXT,
                risk_level INTEGER,
                summary TEXT
            )
        ''')

        # НОВАЯ ТАБЛИЦА: Пользователи
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                role TEXT
            )
        ''')
        self.conn.commit()

    # --- МЕТОДЫ ДЛЯ СКАНИРОВАНИЯ ---
    def add_scan(self, target, risk, summary):
        now = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        self.cursor.execute("INSERT INTO scans (date, target, risk_level, summary) VALUES (?, ?, ?, ?)",
                            (now, target, risk, summary))
        self.conn.commit()

    def get_all_scans(self):
        self.cursor.execute("SELECT date, target, risk_level, summary FROM scans ORDER BY id DESC")
        return self.cursor.fetchall()

    # --- МЕТОДЫ ДЛЯ АВТОРИЗАЦИИ (SOC ACCESS CONTROL) ---
    def register_user(self, username, password, role="Analyst"):
        """Регистрирует нового пользователя с хешированием пароля"""
        try:
            # SHA-256 хеширование — стандарт безопасности
            hashed_pw = hashlib.sha256(password.encode()).hexdigest()
            self.cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                                (username, hashed_pw, role))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # Пользователь уже существует

    def authenticate(self, username, password):
        """Проверяет логин и пароль"""
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()
        self.cursor.execute("SELECT username, role FROM users WHERE username = ? AND password = ?",
                            (username, hashed_pw))
        user = self.cursor.fetchone()
        if user:
            return {"username": user[0], "role": user[1]}
        return None

    def add_scan(self, target, risk, summary):
        """Добавляет результат сканирования в базу"""
        now = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        self.cursor.execute("INSERT INTO scans (date, target, risk_level, summary) VALUES (?, ?, ?, ?)",
                            (now, target, risk, summary))
        self.conn.commit()

    def get_all_scans(self):
        """Возвращает все записи из базы"""
        self.cursor.execute("SELECT date, target, risk_level, summary FROM scans ORDER BY id DESC")
        return self.cursor.fetchall()
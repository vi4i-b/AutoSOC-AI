import sqlite3
from datetime import datetime

class SOCDatabase:
    def __init__(self):
        # Создаем или подключаемся к файлу базы данных
        self.conn = sqlite3.connect("soc_audit.db", check_same_thread=False)
        self.cursor = self.conn.cursor()
        # Создаем таблицу, если её еще нет
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT,
                target TEXT,
                risk_level INTEGER,
                summary TEXT
            )
        ''')
        self.conn.commit()

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
import os
import sqlite3
import tempfile
import unittest

from database import SOCDatabase
from security_utils import legacy_hash_password


class DatabaseTests(unittest.TestCase):
    def test_register_and_authenticate_user(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = os.path.join(temp_dir, "autosoc.db")
            db = SOCDatabase(db_path)
            try:
                self.assertTrue(db.register_user("analyst1", "SecurePass123", telegram_chat_id="12345"))
                user = db.authenticate("analyst1", "SecurePass123")
                self.assertIsNotNone(user)
                self.assertEqual(user["username"], "analyst1")
                self.assertEqual(user["telegram_chat_id"], "12345")
            finally:
                db.close()

    def test_legacy_password_column_is_migrated(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = os.path.join(temp_dir, "autosoc_legacy.db")
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT,
                    role TEXT
                )
                """
            )
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                ("legacy_user", legacy_hash_password("LegacyPass9"), "user"),
            )
            conn.commit()
            conn.close()

            db = SOCDatabase(db_path)
            try:
                user = db.authenticate("legacy_user", "LegacyPass9")
                self.assertIsNotNone(user)
                row = db.get_user_record("legacy_user")
                self.assertTrue(row["password_hash"].startswith("pbkdf2_sha256$"))
            finally:
                db.close()

    def test_telegram_chat_id_must_be_unique(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = os.path.join(temp_dir, "autosoc_unique.db")
            db = SOCDatabase(db_path)
            try:
                self.assertTrue(db.register_user("alpha_user", "AlphaPass123", telegram_chat_id="777"))
                self.assertFalse(db.register_user("beta_user", "BetaPass123", telegram_chat_id="777"))
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()

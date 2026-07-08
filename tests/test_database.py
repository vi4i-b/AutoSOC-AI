import os
import tempfile
import unittest

from autosoc.database import LOCKOUT_WINDOW_SECONDS, MAX_FAILED_LOGINS, SOCDatabase


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db = SOCDatabase(db_path=os.path.join(self.tmpdir.name, "test.db"))

    def tearDown(self):
        self.db.close()
        self.tmpdir.cleanup()

    def test_register_and_authenticate(self):
        self.assertTrue(self.db.register_user("analyst", "passw0rd!", telegram_chat_id="111"))
        user = self.db.authenticate("analyst", "passw0rd!")
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "analyst")
        self.assertIsNone(self.db.authenticate("analyst", "wrong"))

    def test_duplicate_username_rejected(self):
        self.assertTrue(self.db.register_user("analyst", "passw0rd!"))
        self.assertFalse(self.db.register_user("analyst", "passw0rd!"))

    def test_chat_id_uniqueness(self):
        self.assertTrue(self.db.register_user("first", "passw0rd!", telegram_chat_id="42"))
        self.assertFalse(self.db.register_user("second", "passw0rd!", telegram_chat_id="42"))
        self.assertFalse(self.db.is_telegram_chat_id_available("42"))
        self.assertTrue(self.db.is_telegram_chat_id_available("42", exclude_username="first"))

    def test_lockout_after_repeated_failures(self):
        for _ in range(MAX_FAILED_LOGINS):
            self.db.record_failed_login("victim")
        remaining = self.db.login_lockout_remaining("victim")
        self.assertGreater(remaining, 0)
        self.assertLessEqual(remaining, LOCKOUT_WINDOW_SECONDS)

    def test_lockout_clears_on_success(self):
        for _ in range(MAX_FAILED_LOGINS):
            self.db.record_failed_login("victim")
        self.db.clear_failed_logins("victim")
        self.assertEqual(self.db.login_lockout_remaining("victim"), 0)

    def test_below_threshold_no_lockout(self):
        for _ in range(MAX_FAILED_LOGINS - 1):
            self.db.record_failed_login("victim")
        self.assertEqual(self.db.login_lockout_remaining("victim"), 0)

    def test_settings_roundtrip(self):
        self.db.set_setting("k", "v")
        self.assertEqual(self.db.get_setting("k"), "v")
        self.db.delete_setting("k")
        self.assertIsNone(self.db.get_setting("k"))

    def test_events_are_recorded(self):
        self.db.add_security_event("test_event", "High", "1.2.3.4", "details")
        self.db.add_audit_event("test_audit", "actor", "details")
        self.assertEqual(len(self.db.get_recent_security_events(10)), 1)
        self.assertEqual(len(self.db.get_recent_audit_events(10)), 1)


if __name__ == "__main__":
    unittest.main()

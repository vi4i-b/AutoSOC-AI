import os
import tempfile
import unittest

from autosoc.database import SOCDatabase
from autosoc.permissions import ACTIONS, has_permission, normalize_role


class PermissionMapTests(unittest.TestCase):
    def test_viewer_is_read_only(self):
        self.assertTrue(has_permission("viewer", "view"))
        for action in ("respond", "admin", "manage_rules", "triage"):
            self.assertFalse(has_permission("viewer", action))

    def test_analyst_can_triage_not_respond(self):
        self.assertTrue(has_permission("analyst", "triage"))
        self.assertTrue(has_permission("analyst", "add_rule"))
        self.assertFalse(has_permission("analyst", "respond"))
        self.assertFalse(has_permission("analyst", "admin"))

    def test_responder_can_respond_not_admin(self):
        self.assertTrue(has_permission("responder", "respond"))
        self.assertTrue(has_permission("responder", "manage_agents"))
        self.assertFalse(has_permission("responder", "admin"))
        self.assertFalse(has_permission("responder", "manage_rules"))

    def test_admin_can_everything(self):
        for action in ACTIONS:
            self.assertTrue(has_permission("admin", action))

    def test_bootstrap_grants_all(self):
        self.assertTrue(has_permission("viewer", "admin", bootstrap=True))

    def test_normalize_legacy_roles(self):
        self.assertEqual(normalize_role("user"), "analyst")
        self.assertEqual(normalize_role("System User"), "responder")
        self.assertEqual(normalize_role("SysAdmin"), "admin")
        self.assertEqual(normalize_role("garbage"), "analyst")
        self.assertEqual(normalize_role("ADMIN"), "admin")


class InviteAndRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db = SOCDatabase(db_path=os.path.join(self.tmpdir.name, "u.db"))

    def tearDown(self):
        self.db.close()
        self.tmpdir.cleanup()

    def test_invite_single_use_and_role(self):
        code = self.db.create_invite(role="responder", ttl_hours=1, created_by="admin")
        self.assertTrue(code.startswith("inv-"))
        self.assertEqual(self.db.consume_invite(code), "responder")
        self.assertIsNone(self.db.consume_invite(code))  # already used

    def test_invalid_invite(self):
        self.assertIsNone(self.db.consume_invite("inv-nonexistent"))

    def test_expired_invite(self):
        code = self.db.create_invite(role="analyst", ttl_hours=1)
        # Force expiry in the past.
        with self.db._lock:
            self.db.conn.execute("UPDATE invites SET expires_at = 1 WHERE code_hash = ?",
                                 (self.db._hash_invite(code),))
            self.db.conn.commit()
        self.assertIsNone(self.db.consume_invite(code))

    def test_admin_count_and_role(self):
        self.assertEqual(self.db.count_admins(), 0)
        self.db.register_user("boss", "passw0rd!", role="admin")
        self.assertEqual(self.db.count_admins(), 1)
        self.db.set_user_role("boss", "viewer")
        self.assertEqual(self.db.count_admins(), 0)


class RegisterAccountPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        os.environ["AUTOSOC_DB_PATH"] = os.path.join(self.tmpdir.name, "policy.db")
        # Ensure a clean module-level DB path.
        import importlib
        import autosoc.database as dbmod
        importlib.reload(dbmod)

    def tearDown(self):
        os.environ.pop("AUTOSOC_DB_PATH", None)
        os.environ.pop("AUTOSOC_REGISTRATION_MODE", None)
        self.tmpdir.cleanup()

    def test_first_user_becomes_admin(self):
        from autosoc.auth import register_account
        ok, msg = register_account("firstadmin", "passw0rd!", telegram_chat_id="1")
        self.assertTrue(ok)
        self.assertIn("administrator", msg)

    def test_invite_mode_requires_code(self):
        from autosoc.auth import create_invite, register_account
        register_account("firstadmin", "passw0rd!", telegram_chat_id="1")  # bootstrap admin
        os.environ["AUTOSOC_REGISTRATION_MODE"] = "invite"
        ok, _msg = register_account("bob", "passw0rd!", telegram_chat_id="2")
        self.assertFalse(ok)  # no code
        code = create_invite("analyst")
        ok2, _msg2 = register_account("bob", "passw0rd!", telegram_chat_id="2", invite_code=code)
        self.assertTrue(ok2)

    def test_closed_mode_blocks(self):
        from autosoc.auth import register_account
        register_account("firstadmin", "passw0rd!", telegram_chat_id="1")
        os.environ["AUTOSOC_REGISTRATION_MODE"] = "closed"
        ok, _msg = register_account("bob", "passw0rd!", telegram_chat_id="2")
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()

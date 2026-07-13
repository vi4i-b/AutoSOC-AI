import os
import tempfile
import unittest

from autosoc.database import SOCDatabase


class SOCConsoleDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db = SOCDatabase(db_path=os.path.join(self.tmpdir.name, "soc.db"))

    def tearDown(self):
        self.db.close()
        self.tmpdir.cleanup()

    def test_incident_lifecycle(self):
        iid = self.db.create_incident("Phishing case", severity="High", source="test", created_by="alice")
        self.assertTrue(iid)
        self.db.update_incident(iid, status="Investigating", assignee="bob", mitre="T1566")
        record = self.db.get_incident(iid)
        self.assertEqual(record["status"], "Investigating")
        self.assertEqual(record["assignee"], "bob")
        self.assertEqual(record["mitre"], "T1566")

    def test_incident_notes(self):
        iid = self.db.create_incident("Case", created_by="alice")
        self.db.add_incident_note(iid, "note one", author="alice")
        self.db.add_incident_note(iid, "note two", author="bob")
        notes = self.db.get_incident_notes(iid)
        self.assertEqual(len(notes), 2)
        self.assertEqual(notes[0][2], "note one")

    def test_incident_status_filter_and_counts(self):
        a = self.db.create_incident("A")
        self.db.create_incident("B")
        self.db.update_incident(a, status="Resolved")
        self.assertEqual(len(self.db.list_incidents(status="Resolved")), 1)
        self.assertEqual(len(self.db.list_incidents(status="Open")), 1)
        counts = self.db.incident_status_counts()
        self.assertEqual(counts.get("Resolved"), 1)
        self.assertEqual(counts.get("Open"), 1)

    def test_ioc_add_dedup_and_match(self):
        self.assertIsNotNone(self.db.add_ioc("ip", "203.0.113.9", "High"))
        self.assertIsNone(self.db.add_ioc("ip", "203.0.113.9"))  # duplicate
        matches = self.db.match_iocs("203.0.113.9")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][1], "ip")
        self.assertEqual(self.db.match_iocs("198.51.100.1"), [])

    def test_ioc_delete(self):
        ioc_id = self.db.add_ioc("domain", "evil.example")
        self.assertTrue(self.db.delete_ioc(ioc_id))
        self.assertEqual(self.db.list_iocs(), [])

    def test_agent_registration_and_status(self):
        self.db.register_agent("agent_1", hostname="web01", platform="linux", enrollment_token="tok")
        self.db.set_agent_status("agent_1", "online")
        agents = self.db.list_agents()
        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[0]["status"], "online")
        self.db.register_agent("agent_1", hostname="web01-renamed", platform="linux")  # upsert
        self.assertEqual(len(self.db.list_agents()), 1)

    def test_log_ingestion_and_search(self):
        self.db.add_ingested_log("Failed password for root from 10.0.0.5", agent_id="a1", source="auth.log", severity="warn")
        self.db.add_ingested_log("Accepted publickey for user", agent_id="a1", source="auth.log")
        self.assertEqual(len(self.db.search_logs("Failed")), 1)
        self.assertEqual(len(self.db.search_logs("")), 2)

    def test_count_rows_guard(self):
        self.assertEqual(self.db.count_rows("incidents"), 0)
        with self.assertRaises(ValueError):
            self.db.count_rows("users; DROP TABLE users")


if __name__ == "__main__":
    unittest.main()

"""Tamper-evident audit log: hash chaining, tamper/deletion detection, export."""

import csv
import os
import tempfile
import unittest

from autosoc.database import SOCDatabase


class AuditChainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = SOCDatabase(db_path=os.path.join(self.tmp.name, "soc.db"))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def _seed(self, n=5):
        for i in range(n):
            self.db.add_audit_event("test_event", actor=f"user{i}", details=f"did thing {i}")

    def test_intact_chain_verifies(self):
        self._seed()
        ok, broken = self.db.verify_audit_chain()
        self.assertTrue(ok)
        self.assertIsNone(broken)

    def test_edit_is_detected(self):
        self._seed()
        with self.db._lock:
            self.db.conn.execute("UPDATE audit_events SET details='FORGED' WHERE actor='user2'")
            self.db.conn.commit()
        ok, broken = self.db.verify_audit_chain()
        self.assertFalse(ok)
        self.assertIsNotNone(broken)

    def test_deletion_is_detected(self):
        self._seed()
        with self.db._lock:
            self.db.conn.execute("DELETE FROM audit_events WHERE actor='user1'")
            self.db.conn.commit()
        ok, _broken = self.db.verify_audit_chain()
        self.assertFalse(ok)

    def test_each_entry_has_a_hash(self):
        self._seed(3)
        with self.db._lock:
            rows = self.db.conn.execute("SELECT entry_hash FROM audit_events").fetchall()
        self.assertTrue(all(len(r["entry_hash"]) == 64 for r in rows))
        # Hashes must differ even for otherwise-identical events (chain advances).
        self.db.add_audit_event("dup", actor="x", details="same")
        self.db.add_audit_event("dup", actor="x", details="same")
        with self.db._lock:
            hashes = [r["entry_hash"] for r in
                      self.db.conn.execute("SELECT entry_hash FROM audit_events WHERE event_type='dup'").fetchall()]
        self.assertNotEqual(hashes[0], hashes[1])

    def test_export_writes_csv_with_hashes(self):
        self._seed(4)
        path = os.path.join(self.tmp.name, "audit.csv")
        count = self.db.export_audit_log(path)
        self.assertEqual(count, 4)
        with open(path, encoding="utf-8") as handle:
            rows = list(csv.reader(handle))
        self.assertEqual(rows[0], ["id", "created_at", "event_type", "actor", "details", "entry_hash"])
        self.assertEqual(len(rows), 5)  # header + 4
        self.assertEqual(len(rows[1][5]), 64)  # a real sha256 hash


if __name__ == "__main__":
    unittest.main()

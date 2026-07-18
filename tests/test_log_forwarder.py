"""Tests for log-destination forwarding, filtered queries, stats and retention."""

import json
import os
import socket
import tempfile
import unittest

from autosoc.database import SOCDatabase
from autosoc.system.log_forwarder import LogForwarder, parse_host_port


class LogQueryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = SOCDatabase(db_path=os.path.join(self.tmp.name, "soc.db"))
        self.db.add_ingested_log("Failed password for root from 8.8.8.8",
                                 agent_id="web01", source="auth.log", severity="warn")
        self.db.add_ingested_log("segfault in worker", agent_id="web01", source="syslog", severity="critical")
        self.db.add_ingested_log("routine heartbeat", agent_id="db02", source="app", severity="info")
        self.db.add_ingested_log("An account failed to log on 4625",
                                 agent_id="win01", source="WinEventLog:Security", severity="warn")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_query_logs_filters_are_anded(self):
        self.assertEqual(len(self.db.query_logs(severity="warn")), 2)
        self.assertEqual(len(self.db.query_logs(agent_id="web01")), 2)
        self.assertEqual(len(self.db.query_logs(source="app")), 1)
        self.assertEqual(len(self.db.query_logs(text="Failed")), 2)
        self.assertEqual(len(self.db.query_logs(severity="warn", agent_id="win01")), 1)
        self.assertEqual(len(self.db.query_logs(severity="warn", agent_id="db02")), 0)

    def test_log_stats(self):
        stats = self.db.log_stats()
        self.assertEqual(stats["total"], 4)
        self.assertEqual(stats["by_severity"]["warn"], 2)
        self.assertEqual(stats["by_severity"]["critical"], 1)
        top_sources = dict(stats["top_sources"])
        self.assertEqual(top_sources["auth.log"], 1)

    def test_distinct_log_values(self):
        self.assertEqual(set(self.db.distinct_log_values("agent_id")), {"web01", "db02", "win01"})
        self.assertIn("WinEventLog:Security", self.db.distinct_log_values("source"))
        with self.assertRaises(ValueError):
            self.db.distinct_log_values("message")  # not an allowed column

    def test_retention_purge_uses_datetime_not_string(self):
        # created_at is day-first ("%d.%m.%Y ..."), which is not lexically
        # sortable — the purge must parse it, so a genuinely old row goes and
        # recent rows stay.
        with self.db._lock:
            self.db.conn.execute("UPDATE ingested_logs SET created_at='01.01.2000 00:00:00' WHERE source='app'")
            self.db.conn.commit()
        self.assertEqual(self.db.purge_logs_older_than(0), 0)   # keep forever
        self.assertEqual(self.db.purge_logs_older_than(30), 1)  # only the old one
        self.assertEqual(self.db.log_stats()["total"], 3)
        self.assertEqual(len(self.db.query_logs(agent_id="web01")), 2)


class ParseHostPortTests(unittest.TestCase):
    def test_variants(self):
        self.assertEqual(parse_host_port("10.0.0.5:514"), ("10.0.0.5", 514))
        self.assertEqual(parse_host_port("10.0.0.5"), ("10.0.0.5", 514))
        self.assertEqual(parse_host_port("host:9999"), ("host", 9999))
        self.assertEqual(parse_host_port(""), (None, None))
        self.assertEqual(parse_host_port("bad:port"), ("bad", 514))  # non-numeric → default


class ForwarderFileSinkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = SOCDatabase(db_path=os.path.join(self.tmp.name, "soc.db"))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_disabled_by_default(self):
        fwd = LogForwarder(self.db)
        self.assertFalse(fwd.enabled)
        # forward() on a disabled forwarder is a silent no-op
        fwd.forward("nothing", severity="info")
        self.assertEqual(fwd.sent, 0)

    def test_file_sink_writes_jsonl(self):
        outfile = os.path.join(self.tmp.name, "sub", "out.jsonl")  # dir auto-created
        self.db.set_setting("log_forward_file", outfile)
        fwd = LogForwarder(self.db)
        self.assertTrue(fwd.enabled)
        fwd.forward("hello world", agent_id="a1", source="s1", severity="warn")
        with open(outfile, encoding="utf-8") as handle:
            rec = json.loads(handle.readline())
        self.assertEqual(rec["message"], "hello world")
        self.assertEqual(rec["severity"], "warn")
        self.assertEqual(rec["agent_id"], "a1")
        self.assertEqual(fwd.status()["sent"], 1)
        fwd.close()

    def test_syslog_sink_emits_udp_packet(self):
        # Bind a throwaway UDP socket and point the forwarder at it.
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.bind(("127.0.0.1", 0))
        rx.settimeout(2)
        host, port = rx.getsockname()
        self.db.set_setting("log_forward_syslog", f"{host}:{port}")
        fwd = LogForwarder(self.db)
        self.assertTrue(fwd.enabled)
        fwd.forward("brute force detected", agent_id="fw01", source="syslog", severity="critical")
        data, _ = rx.recvfrom(4096)
        text = data.decode("utf-8", "replace")
        self.assertTrue(text.startswith("<"))          # RFC3164 PRI header
        self.assertIn("brute force detected", text)
        self.assertIn("agent=fw01", text)
        rx.close()
        fwd.close()

    def test_reload_picks_up_new_destination(self):
        fwd = LogForwarder(self.db)
        self.assertFalse(fwd.enabled)
        self.db.set_setting("log_forward_file", os.path.join(self.tmp.name, "late.jsonl"))
        fwd.reload()
        self.assertTrue(fwd.enabled)
        fwd.close()


if __name__ == "__main__":
    unittest.main()

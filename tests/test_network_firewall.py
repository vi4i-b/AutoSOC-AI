import os
import tempfile
import unittest
import urllib.request
from unittest import mock

from autosoc.agents.server import CollectorService
from autosoc.agents.syslog_server import SyslogService, parse_syslog, severity_from_pri
from autosoc.database import SOCDatabase
from autosoc.system.appliance import FortiGateConnector, NullConnector, connector_from_settings
from autosoc.system.response import ResponseController


def _fake_response(status_code=200, json_body=None):
    resp = mock.Mock()
    resp.status_code = status_code
    resp.json.return_value = json_body or {"status": "success"}
    return resp


class SyslogParsingTests(unittest.TestCase):
    def test_severity_mapping(self):
        self.assertEqual(severity_from_pri(0), "critical")   # emerg
        self.assertEqual(severity_from_pri(11), "High")      # facility+err(3)
        self.assertEqual(severity_from_pri(12), "warn")      # facility+warn(4)
        self.assertEqual(severity_from_pri(14), "info")

    def test_parse_rfc3164(self):
        host, severity, message = parse_syslog(
            b"<38>Jul  8 10:00:00 fw01 sshd[123]: Failed password for root from 8.8.8.8",
            "10.0.0.1")
        self.assertEqual(host, "fw01")
        self.assertIn("Failed password", message)

    def test_parse_without_pri_uses_sender(self):
        host, _sev, message = parse_syslog(b"plain message no framing", "10.0.0.9")
        self.assertEqual(host, "10.0.0.9")
        self.assertIn("plain message", message)


class SyslogDetectionTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db = SOCDatabase(db_path=os.path.join(self.tmpdir.name, "s.db"))
        self.detections = []
        self.svc = SyslogService(self.db, on_detection=self.detections.append, threshold=3, window_seconds=600)

    def tearDown(self):
        self.db.close()
        self.tmpdir.cleanup()

    def test_message_is_stored(self):
        self.svc._process(b"<134>fw01 traffic allowed", "10.0.0.1")
        self.assertEqual(len(self.db.search_logs("traffic")), 1)

    def test_ssh_bruteforce_detected(self):
        for _ in range(4):
            self.svc._process(b"<38>fw01 sshd: Failed password for root from 45.66.77.88", "10.0.0.1")
        self.assertTrue(self.detections)
        self.assertEqual(self.detections[0]["ip"], "45.66.77.88")
        events = self.db.get_recent_security_events()
        self.assertTrue(any(e["event_type"] == "syslog_bruteforce" for e in events))

    def test_fortigate_login_failure_detected(self):
        line = (b'<190>date=2024-07-08 devname=FGT action="login" status="failed" '
                b'srcip=203.0.113.5 user="admin"')
        for _ in range(4):
            self.svc._process(line, "10.0.0.1")
        self.assertTrue(self.detections)
        self.assertEqual(self.detections[0]["ip"], "203.0.113.5")


class BlocklistFeedTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db = SOCDatabase(db_path=os.path.join(self.tmpdir.name, "b.db"))
        self.service = CollectorService(self.db, host="127.0.0.1", port=0)
        self.service.start()
        self.port = self.service._httpd.server_address[1]

    def tearDown(self):
        self.service.stop()
        self.db.close()
        self.tmpdir.cleanup()

    def test_feed_reflects_blocklist(self):
        self.db.add_blocked_ip("203.0.113.10", reason="test")
        self.db.add_blocked_ip("198.51.100.7", reason="test")
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/blocklist.txt", timeout=5) as resp:
            body = resp.read().decode()
        self.assertIn("203.0.113.10", body)
        self.assertIn("198.51.100.7", body)

    def test_deactivated_ip_leaves_feed(self):
        self.db.add_blocked_ip("203.0.113.10")
        self.db.remove_blocked_ip("203.0.113.10")
        self.assertEqual(self.db.active_blocklist(), [])


class BlocklistDbTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db = SOCDatabase(db_path=os.path.join(self.tmpdir.name, "b.db"))

    def tearDown(self):
        self.db.close()
        self.tmpdir.cleanup()

    def test_add_is_idempotent(self):
        self.db.add_blocked_ip("1.2.3.4", reason="a")
        self.db.add_blocked_ip("1.2.3.4", reason="b")
        self.assertEqual(self.db.active_blocklist(), ["1.2.3.4"])

    def test_invalid_ip_rejected(self):
        self.assertFalse(self.db.add_blocked_ip(""))


class FortiGateConnectorTests(unittest.TestCase):
    def setUp(self):
        self.fw = FortiGateConnector(host="10.0.0.1", api_token="secrettoken", vdom="root")

    def test_invalid_ip(self):
        ok, msg = self.fw.block_ip("not-an-ip")
        self.assertFalse(ok)
        self.assertIn("Invalid IP", msg)

    def test_block_ip_calls_address_and_group(self):
        with mock.patch("autosoc.system.appliance.requests") as req:
            req.post.return_value = _fake_response(200, {"status": "success"})
            req.put.return_value = _fake_response(200)
            ok, msg = self.fw.block_ip("203.0.113.9", reason="brute force")
        self.assertTrue(ok)
        self.assertGreaterEqual(req.post.call_count, 2)  # address + group member
        self.assertIn("203.0.113.9", msg)

    def test_token_redacted_in_errors(self):
        import requests as real_requests

        with mock.patch("autosoc.system.appliance.requests") as req:
            req.RequestException = real_requests.RequestException
            req.post.side_effect = real_requests.RequestException("fail with secrettoken in url")
            ok, msg = self.fw.block_ip("203.0.113.9")
        self.assertFalse(ok)
        self.assertNotIn("secrettoken", msg)
        self.assertIn("***TOKEN***", msg)

    def test_requires_host_and_token(self):
        fw = FortiGateConnector(host="", api_token="")
        ok, _msg = fw.test_connection()
        self.assertFalse(ok)


class ResponseControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db = SOCDatabase(db_path=os.path.join(self.tmpdir.name, "r.db"))

    def tearDown(self):
        self.db.close()
        self.tmpdir.cleanup()

    def test_block_adds_to_feed_without_appliance_or_local(self):
        controller = ResponseController(self.db, local_firewall=None)
        ok, summary, results = controller.block_ip("203.0.113.50", reason="test", use_local=False)
        self.assertTrue(ok)
        self.assertIn("203.0.113.50", self.db.active_blocklist())
        channels = [name for name, _ok, _msg in results]
        self.assertIn("feed", channels)

    def test_connector_from_settings_defaults_to_feed_only(self):
        self.assertIsInstance(connector_from_settings(self.db), NullConnector)
        self.db.set_setting("firewall_type", "fortigate")
        self.db.set_setting("firewall_host", "10.0.0.1")
        self.db.set_setting("firewall_token", "t")
        self.assertEqual(connector_from_settings(self.db).name, "fortigate")

    def test_block_pushes_to_configured_appliance(self):
        self.db.set_setting("firewall_type", "fortigate")
        self.db.set_setting("firewall_host", "10.0.0.1")
        self.db.set_setting("firewall_token", "t")
        controller = ResponseController(self.db, local_firewall=None)
        with mock.patch("autosoc.system.appliance.requests") as req:
            req.post.return_value = _fake_response(200, {"status": "success"})
            req.put.return_value = _fake_response(200)
            ok, _summary, results = controller.block_ip("203.0.113.60", use_local=False)
        self.assertTrue(ok)
        self.assertIn("fortigate", [name for name, _ok, _msg in results])


if __name__ == "__main__":
    unittest.main()

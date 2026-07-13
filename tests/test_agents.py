import importlib.util
import json
import os
import tempfile
import unittest
import urllib.error
import urllib.request

from autosoc.agents.server import CollectorService
from autosoc.database import SOCDatabase

AGENT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent", "autosoc_agent.py")


def _load_agent_module():
    spec = importlib.util.spec_from_file_location("autosoc_agent", AGENT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class IngestionTokenTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db = SOCDatabase(db_path=os.path.join(self.tmpdir.name, "soc.db"))

    def tearDown(self):
        self.db.close()
        self.tmpdir.cleanup()

    def test_token_is_stable_and_verifiable(self):
        token = self.db.get_or_create_ingestion_token()
        self.assertTrue(token.startswith("ingest_"))
        self.assertEqual(token, self.db.get_or_create_ingestion_token())
        self.assertTrue(self.db.verify_ingestion_token(token))
        self.assertFalse(self.db.verify_ingestion_token("wrong"))

    def test_regenerate_invalidates_old(self):
        old = self.db.get_or_create_ingestion_token()
        new = self.db.regenerate_ingestion_token()
        self.assertNotEqual(old, new)
        self.assertFalse(self.db.verify_ingestion_token(old))
        self.assertTrue(self.db.verify_ingestion_token(new))

    def test_mark_agent_seen_and_snapshot(self):
        self.db.mark_agent_seen("agent_1", hostname="web01", platform="Linux", ip_address="10.0.0.5")
        agents = self.db.list_agents()
        self.assertEqual(agents[0]["status"], "online")
        self.db.save_agent_snapshot("agent_1", json.dumps({"primary_ip": "10.0.0.5"}))
        snap = self.db.get_agent_snapshot("agent_1")
        self.assertIn("10.0.0.5", snap["data"])

    def test_mark_stale_agents(self):
        self.db.mark_agent_seen("agent_1", hostname="web01")
        # A negative window means "everything is stale".
        flipped = self.db.mark_stale_agents(stale_seconds=-1)
        self.assertIn("agent_1", flipped)
        self.assertEqual(self.db.list_agents()[0]["status"], "offline")


class CollectorServerTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db = SOCDatabase(db_path=os.path.join(self.tmpdir.name, "soc.db"))
        self.token = self.db.get_or_create_ingestion_token()
        self.service = CollectorService(self.db, host="127.0.0.1", port=0)
        # port=0 → let the OS pick a free port; read it back after binding.
        ok, _msg = self.service.start()
        self.assertTrue(ok)
        self.host, self.port = self.service._httpd.server_address

    def tearDown(self):
        self.service.stop()
        self.db.close()
        self.tmpdir.cleanup()

    def _post(self, path, payload, token=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        if token is not None:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, None

    def test_ping_no_auth(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/api/v1/ping", timeout=5) as resp:
            body = json.loads(resp.read().decode())
        self.assertTrue(body["ok"])

    def test_report_requires_token(self):
        status, _ = self._post("/api/v1/report", {"agent_id": "x"}, token="bad")
        self.assertEqual(status, 401)
        status, _ = self._post("/api/v1/report", {"agent_id": "x"}, token=None)
        self.assertEqual(status, 401)

    def test_enroll_and_report_flow(self):
        status, body = self._post("/api/v1/enroll",
                                  {"agent_id": "agent_9", "hostname": "srv9", "platform": "Linux",
                                   "local_ip": "10.1.1.9"}, token=self.token)
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])

        status, body = self._post("/api/v1/report", {
            "agent_id": "agent_9",
            "hostname": "srv9",
            "platform": "Linux",
            "local_ip": "10.1.1.9",
            "telemetry": {"primary_ip": "10.1.1.9", "processes": {"count": 3, "top": []}},
            "logs": ["sshd: Failed password for root from 8.8.8.8",
                     {"message": "structured entry", "source": "auth.log", "severity": "warn"}],
        }, token=self.token)
        self.assertEqual(status, 200)
        self.assertEqual(body["stored_logs"], 2)

        agents = self.db.list_agents()
        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[0]["hostname"], "srv9")
        self.assertEqual(agents[0]["status"], "online")
        snap = self.db.get_agent_snapshot("agent_9")
        self.assertIn("10.1.1.9", snap["data"])
        self.assertEqual(len(self.db.search_logs("Failed")), 1)

    def test_report_without_agent_id_rejected(self):
        status, _ = self._post("/api/v1/report", {"hostname": "x"}, token=self.token)
        self.assertEqual(status, 400)

    def _get(self, path, token=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib.request.Request(url, method="GET")
        if token is not None:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, None

    def test_command_channel_flow(self):
        self.db.mark_agent_seen("agent_c", hostname="h", platform="Linux")
        cid = self.db.enqueue_agent_command("agent_c", "isolate", requested_by="analyst")

        # poll requires auth
        status, _ = self._get("/api/v1/commands?agent_id=agent_c", token="bad")
        self.assertEqual(status, 401)

        status, body = self._get("/api/v1/commands?agent_id=agent_c", token=self.token)
        self.assertEqual(status, 200)
        self.assertEqual(len(body["commands"]), 1)
        self.assertEqual(body["commands"][0]["command"], "isolate")

        # claimed → second poll is empty
        _status, body2 = self._get("/api/v1/commands?agent_id=agent_c", token=self.token)
        self.assertEqual(body2["commands"], [])

        # result marks the agent isolated
        self._post("/api/v1/command_result",
                   {"agent_id": "agent_c", "command_id": cid, "status": "done", "result": "ok"},
                   token=self.token)
        agent = [a for a in self.db.list_agents() if a["agent_id"] == "agent_c"][0]
        self.assertEqual(agent["isolated"], 1)


class AgentIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = _load_agent_module()

    def test_isolation_commands_keep_server_reachable(self):
        rules = self.agent.build_isolation_commands("192.168.0.7")
        self.assertTrue(all("AUTOSOC_ISOLATION" in r for r in rules))
        drops = [r for r in rules if r[-1] == "DROP"]
        self.assertEqual(len(drops), 2)  # INPUT + OUTPUT default drop
        server_allows = [r for r in rules if "192.168.0.7" in r]
        self.assertEqual(len(server_allows), 2)  # in + out

    def test_isolation_without_server_ip(self):
        rules = self.agent.build_isolation_commands("")
        self.assertTrue(any(r[-1] == "DROP" for r in rules))

    def test_unknown_command_is_failed(self):
        status, _msg = self.agent.execute_command("http://x", {"command": "nope"})
        self.assertEqual(status, "failed")


class AgentModuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = _load_agent_module()

    def test_stable_agent_id_is_deterministic(self):
        a = self.agent.stable_agent_id("myid")
        self.assertEqual(a, "myid")
        auto1 = self.agent.stable_agent_id()
        auto2 = self.agent.stable_agent_id()
        self.assertTrue(auto1.startswith("agent_"))
        self.assertEqual(auto1, auto2)

    def test_guess_severity(self):
        self.assertEqual(self.agent._guess_severity("Failed password for root"), "warn")
        self.assertEqual(self.agent._guess_severity("segfault in worker"), "critical")
        self.assertEqual(self.agent._guess_severity("routine heartbeat"), "info")

    def test_log_tailer_reads_new_lines(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as handle:
            handle.write("line one\nline two\n")
            path = handle.name
        try:
            tailer = self.agent.LogTailer([path])
            first = tailer.read_new()
            self.assertEqual(len(first), 2)
            self.assertEqual(tailer.read_new(), [])  # nothing new
            with open(path, "a", encoding="utf-8") as handle:
                handle.write("line three\n")
            third = tailer.read_new()
            self.assertEqual(len(third), 1)
            self.assertEqual(third[0]["message"], "line three")
        finally:
            os.unlink(path)

    def test_collect_telemetry_shape(self):
        telemetry = self.agent.collect_telemetry()
        for key in ("hostname", "system", "primary_ip", "ipv4", "processes",
                    "network", "resources", "security", "os_pretty", "kernel"):
            self.assertIn(key, telemetry)
        self.assertIn("count", telemetry["processes"])
        self.assertIn("listening", telemetry["network"])
        self.assertIn("connections", telemetry["network"])

    def test_network_sockets_shape(self):
        net = self.agent.network_sockets()
        self.assertIsInstance(net["listening"], list)
        self.assertIsInstance(net["connections"], list)
        for item in net["listening"]:
            self.assertIn("local", item)
            self.assertIn("process", item)

    def test_recent_auth_failures_shape(self):
        result = self.agent.recent_auth_failures()
        self.assertIn("count", result)
        self.assertIsInstance(result["top_sources"], list)


if __name__ == "__main__":
    unittest.main()

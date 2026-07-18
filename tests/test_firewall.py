import unittest
from unittest import mock

from autosoc.system.commands import CommandResult
from autosoc.system.firewall import LinuxFirewall, WindowsFirewall


class LinuxFirewallTests(unittest.TestCase):
    def setUp(self):
        self.backend = LinuxFirewall()
        self.calls = []

    def _fake_run(self, ok_for=("-I", "-S")):
        # Note: "-D" is deliberately NOT ok by default, so _delete_all stops
        # after one attempt (simulating "no pre-existing rule to delete").
        def fake(args, timeout=30):
            self.calls.append(args)
            action = args[1] if len(args) > 1 else ""
            if action in ok_for:
                return CommandResult(0, "", "")
            return CommandResult(1, "", "No chain/target/match by that name.")

        return fake

    def test_block_port_inserts_at_top_for_tcp_udp_and_loopback(self):
        with mock.patch("autosoc.system.firewall.run_command", side_effect=self._fake_run()):
            success, rule_name, message = self.backend.set_port_blocked(3389, blocked=True)

        self.assertTrue(success)
        self.assertEqual(rule_name, "AutoSOC_Manual_3389")

        inserts = [call for call in self.calls if call[1] == "-I"]
        # tcp + tcp-lo + udp + udp-lo = 4 rules, all at INPUT position 1.
        self.assertEqual(len(inserts), 4)
        for call in inserts:
            self.assertEqual(call[:4], ["iptables", "-I", "INPUT", "1"])  # top of chain, overrides UFW
            self.assertIn("DROP", call)
            self.assertIn("AutoSOC_Manual_3389", call)
            self.assertNotIn(";", " ".join(call))

        protocols = {call[call.index("-p") + 1] for call in inserts}
        self.assertEqual(protocols, {"tcp", "udp"})
        # Exactly one loopback variant per protocol.
        loopback = [call for call in inserts if "-i" in call and call[call.index("-i") + 1] == "lo"]
        self.assertEqual(len(loopback), 2)
        self.assertIn("loopback", message.lower())
        # No append anywhere — the whole point of the fix.
        self.assertFalse([call for call in self.calls if call[1] == "-A"])

    def test_unblock_only_deletes_and_covers_loopback(self):
        # Make deletes "succeed once then stop" so we can see which specs are targeted.
        seen = set()

        def fake(args, timeout=30):
            self.calls.append(args)
            if args[1] == "-D":
                key = tuple(args)
                if key in seen:
                    return CommandResult(1, "", "no match")
                seen.add(key)
                return CommandResult(0, "", "")
            return CommandResult(1, "", "no")

        with mock.patch("autosoc.system.firewall.run_command", side_effect=fake):
            success, _rule, message = self.backend.set_port_blocked(3389, blocked=False)

        self.assertTrue(success)
        self.assertIn("No broad allow rule", message)
        # Never inserts/appends when unblocking.
        self.assertFalse([call for call in self.calls if call[1] in ("-A", "-I")])
        deletes = [call for call in self.calls if call[1] == "-D"]
        # Deletes target INPUT by full spec (with the AutoSOC comment) — exact,
        # never a bare chain flush.
        for call in deletes:
            self.assertEqual(call[:3], ["iptables", "-D", "INPUT"])
            self.assertIn("AutoSOC_Manual_3389", call)
        # Both a general and a loopback delete are issued.
        self.assertTrue(any("-i" in call and call[call.index("-i") + 1] == "lo" for call in deletes))
        self.assertTrue(any("-i" not in call for call in deletes))

    def test_block_ip_validates_address(self):
        success, _rule, message = self.backend.block_ip("not-an-ip; rm -rf /")
        self.assertFalse(success)
        self.assertIn("Invalid IP address", message)

    def test_block_ip_inserts_drop_rule(self):
        with mock.patch("autosoc.system.firewall.run_command", side_effect=self._fake_run()):
            success, rule_name, _message = self.backend.block_ip("203.0.113.7")

        self.assertTrue(success)
        self.assertEqual(rule_name, "AutoSOC_Guard_Block_203.0.113.7")
        inserts = [call for call in self.calls if call[1] == "-I"]
        self.assertEqual(len(inserts), 1)
        self.assertIn("203.0.113.7", inserts[0])

    def test_blocked_ports_parses_iptables_output(self):
        listing = (
            "-P INPUT ACCEPT\n"
            '-A INPUT -p tcp -m tcp --dport 445 -m comment --comment "AutoSOC_Manual_445" -j DROP\n'
            '-A INPUT -p udp -m udp --dport 445 -m comment --comment "AutoSOC_Manual_445" -j DROP\n'
            '-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT\n'
            '-A INPUT -s 203.0.113.7/32 -m comment --comment "AutoSOC_Guard_Block_203.0.113.7" -j DROP\n'
        )
        with mock.patch(
            "autosoc.system.firewall.run_command",
            return_value=CommandResult(0, listing, ""),
        ):
            self.assertEqual(self.backend.blocked_ports(), {445})


class WindowsFirewallTests(unittest.TestCase):
    def test_block_port_builds_netsh_rules(self):
        calls = []

        def fake(args, timeout=30):
            calls.append(args)
            return CommandResult(0, "Ok.", "")

        backend = WindowsFirewall()
        with mock.patch("autosoc.system.firewall.run_command", side_effect=fake):
            success, rule_name, _message = backend.set_port_blocked(445, blocked=True)

        self.assertTrue(success)
        self.assertEqual(rule_name, "AutoSOC_Manual_445")
        adds = [call for call in calls if "add" in call]
        self.assertEqual(len(adds), 2)
        for call in adds:
            self.assertEqual(call[0], "netsh")
            self.assertIn("action=block", call)


if __name__ == "__main__":
    unittest.main()

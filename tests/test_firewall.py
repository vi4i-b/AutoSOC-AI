import unittest
from unittest import mock

from autosoc.system.commands import CommandResult
from autosoc.system.firewall import LinuxFirewall, WindowsFirewall


class LinuxFirewallTests(unittest.TestCase):
    def setUp(self):
        self.backend = LinuxFirewall()
        self.calls = []

    def _fake_run(self, ok_for=("-A", "-I", "-S")):
        def fake(args, timeout=30):
            self.calls.append(args)
            action = args[1] if len(args) > 1 else ""
            if action in ok_for:
                return CommandResult(0, "", "")
            return CommandResult(1, "", "No chain/target/match by that name.")

        return fake

    def test_block_port_adds_tcp_and_udp_drop_rules(self):
        with mock.patch("autosoc.system.firewall.run_command", side_effect=self._fake_run()):
            success, rule_name, _message = self.backend.set_port_blocked(3389, blocked=True)

        self.assertTrue(success)
        self.assertEqual(rule_name, "AutoSOC_Manual_3389")
        adds = [call for call in self.calls if call[1] == "-A"]
        self.assertEqual(len(adds), 2)
        protocols = {call[call.index("-p") + 1] for call in adds}
        self.assertEqual(protocols, {"tcp", "udp"})
        for call in adds:
            self.assertEqual(call[0], "iptables")
            self.assertIn("DROP", call)
            self.assertIn("AutoSOC_Manual_3389", call)
            self.assertNotIn(";", " ".join(call))

    def test_unblock_only_deletes_rules(self):
        with mock.patch("autosoc.system.firewall.run_command", side_effect=self._fake_run()):
            success, _rule, message = self.backend.set_port_blocked(3389, blocked=False)

        self.assertTrue(success)
        self.assertIn("No broad allow rule", message)
        self.assertFalse([call for call in self.calls if call[1] in ("-A", "-I")])

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

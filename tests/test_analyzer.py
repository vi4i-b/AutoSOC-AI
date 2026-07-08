import unittest

from autosoc.analyzer import RiskAnalyzer
from autosoc.ports import TRACKED_PORTS


class RiskAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = RiskAnalyzer()

    def test_known_risky_port_is_flagged(self):
        findings = self.analyzer.analyze([{"port": 445}])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["port"], 445)
        self.assertEqual(findings[0]["info"]["risk"], "Critical")

    def test_unknown_port_is_ignored(self):
        self.assertEqual(self.analyzer.analyze([{"port": 65000}]), [])

    def test_risk_score_is_bounded(self):
        findings = self.analyzer.analyze([{"port": port} for port in TRACKED_PORTS])
        self.assertEqual(self.analyzer.calculate_risk_score(findings), 100)
        self.assertEqual(self.analyzer.calculate_risk_score([]), 0)

    def test_threat_catalog_covers_tracked_ports(self):
        # 443 is intentionally not a "threat"; everything else tracked should be described.
        for port in TRACKED_PORTS:
            if port == 443:
                continue
            self.assertIn(port, self.analyzer.threats, f"port {port} missing from threat catalog")


if __name__ == "__main__":
    unittest.main()

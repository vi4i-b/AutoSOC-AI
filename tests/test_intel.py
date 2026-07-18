"""Tests for threat-intel enrichment: classification, parsers, dispatch, scrub."""

import json
import os
import tempfile
import unittest

from autosoc.database import SOCDatabase
from autosoc.intel.enrichment import (
    SETTING_ABUSEIPDB,
    SETTING_OTX,
    SETTING_VT,
    ThreatIntelEnricher,
    classify_indicator,
)


class _FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f"HTTP {self.status_code}")


class _FakeSession:
    """Records requested URLs and replays canned responses keyed by substring."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, url, headers=None, timeout=None):
        self.calls.append((url, headers))
        for needle, response in self.routes.items():
            if needle in url:
                return response
        return _FakeResponse(404, {})


class ClassifyTests(unittest.TestCase):
    def test_types(self):
        self.assertEqual(classify_indicator("8.8.8.8"), "ip")
        self.assertEqual(classify_indicator("https://x.y/z"), "url")
        self.assertEqual(classify_indicator("bad.example.com"), "domain")
        self.assertEqual(classify_indicator("d41d8cd98f00b204e9800998ecf8427e"), "hash")
        self.assertEqual(classify_indicator("a@b.co"), "email")
        self.assertEqual(classify_indicator("???"), "unknown")


class EnricherDispatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = SOCDatabase(db_path=os.path.join(self.tmp.name, "soc.db"))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_no_keys_means_no_providers(self):
        enricher = ThreatIntelEnricher(self.db, session=_FakeSession({}))
        self.assertEqual(enricher.configured_providers(), [])
        self.assertEqual(enricher.enrich("8.8.8.8"), [])

    def test_ip_hits_vt_abuseipdb_otx(self):
        self.db.set_setting(SETTING_VT, "vtkey")
        self.db.set_setting(SETTING_ABUSEIPDB, "abkey")
        self.db.set_setting(SETTING_OTX, "otxkey")
        session = _FakeSession({
            "virustotal.com/api/v3/ip_addresses": _FakeResponse(200, {
                "data": {"attributes": {"last_analysis_stats":
                         {"malicious": 2, "suspicious": 0, "harmless": 60}}}}),
            "abuseipdb.com": _FakeResponse(200, {
                "data": {"abuseConfidenceScore": 90, "totalReports": 12, "countryCode": "RU"}}),
            "otx.alienvault.com": _FakeResponse(200, {"pulse_info": {"count": 3}}),
        })
        enricher = ThreatIntelEnricher(self.db, session=session)
        verdicts = {v.provider: v for v in enricher.enrich("45.66.77.88")}
        self.assertEqual(set(verdicts), {"VirusTotal", "AbuseIPDB", "AlienVault OTX"})
        self.assertTrue(verdicts["VirusTotal"].malicious)
        self.assertEqual(verdicts["AbuseIPDB"].score, "90%")
        self.assertEqual(verdicts["AlienVault OTX"].score, "3 pulses")

    def test_domain_skips_abuseipdb(self):
        self.db.set_setting(SETTING_VT, "vtkey")
        self.db.set_setting(SETTING_ABUSEIPDB, "abkey")
        session = _FakeSession({
            "virustotal.com/api/v3/domains": _FakeResponse(200, {
                "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 80}}}}),
        })
        enricher = ThreatIntelEnricher(self.db, session=session)
        providers = {v.provider for v in enricher.enrich("evil.example.com")}
        self.assertIn("VirusTotal", providers)
        self.assertNotIn("AbuseIPDB", providers)  # AbuseIPDB is IP-only

    def test_invalid_key_surfaces_as_error_verdict(self):
        self.db.set_setting(SETTING_VT, "wrongkey")
        session = _FakeSession({"virustotal.com": _FakeResponse(401, {})})
        enricher = ThreatIntelEnricher(self.db, session=session)
        verdict = enricher.enrich("8.8.8.8")[0]
        self.assertFalse(verdict.ok)
        self.assertIn("Invalid VirusTotal API key", verdict.error)

    def test_404_is_unknown_not_error(self):
        self.db.set_setting(SETTING_VT, "vtkey")
        session = _FakeSession({"virustotal.com": _FakeResponse(404, {})})
        enricher = ThreatIntelEnricher(self.db, session=session)
        verdict = enricher.enrich("1.2.3.4")[0]
        self.assertTrue(verdict.ok)
        self.assertFalse(verdict.malicious)
        self.assertIn("Unknown to VirusTotal", verdict.detail)

    def test_api_key_never_leaks_into_error(self):
        self.db.set_setting(SETTING_OTX, "SUPERSECRETKEY")

        class _Boom:
            def get(self, url, headers=None, timeout=None):
                raise __import__("requests").ConnectionError("failed talking with key SUPERSECRETKEY")

        enricher = ThreatIntelEnricher(self.db, session=_Boom())
        verdict = enricher.enrich("evil.example.com")[0]
        self.assertFalse(verdict.ok)
        self.assertNotIn("SUPERSECRETKEY", verdict.error)
        self.assertIn("***", verdict.error)


if __name__ == "__main__":
    unittest.main()

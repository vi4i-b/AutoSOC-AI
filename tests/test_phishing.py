import unittest

from autosoc.phishing import PhishingAnalyzer
from autosoc.phishing.content_features import analyze_content
from autosoc.phishing.fetcher import FetchResult, _is_public_ip
from autosoc.phishing.signals import clamp_score, verdict_for_score
from autosoc.phishing.spelling import analyze_spelling
from autosoc.phishing.url_features import analyze_url, normalize_url


class UrlFeatureTests(unittest.TestCase):
    def _titles(self, signal_set):
        return {s.title for s in signal_set.signals if s.hit}

    def test_clean_url_has_no_hits(self):
        signals = analyze_url("https://www.google.com/")
        self.assertEqual(self._titles(signals), set())

    def test_ip_host_flagged(self):
        self.assertIn("IP address host", self._titles(analyze_url("http://93.184.216.34/login")))

    def test_at_trick_flagged(self):
        self.assertIn("Embedded credentials / @ trick",
                      self._titles(analyze_url("http://user@evil.example.com/")))

    def test_punycode_flagged(self):
        self.assertIn("Punycode host", self._titles(analyze_url("https://xn--pypal-4ve.com/")))

    def test_brand_lookalike_flagged(self):
        titles = self._titles(analyze_url("http://paypal.secure-login.tk/verify/account"))
        self.assertIn("Brand look-alike", titles)
        self.assertIn("High-risk TLD", titles)

    def test_normalize_adds_scheme(self):
        self.assertEqual(normalize_url("example.com"), "http://example.com")


class SpellingTests(unittest.TestCase):
    def test_detects_common_misspellings(self):
        result = analyze_spelling("Please verifcation your acount immediatly.")
        bad_words = {bad for bad, _good in result["misspellings"]}
        self.assertIn("verifcation", bad_words)
        self.assertIn("acount", bad_words)

    def test_detects_homograph(self):
        # "Раypal" uses Cyrillic Р and а.
        result = analyze_spelling("Login to Раypal now")
        self.assertTrue(result["homographs"])

    def test_clean_text_has_no_findings(self):
        result = analyze_spelling("Please sign in to your account to continue securely.")
        self.assertEqual(result["misspellings"], [])
        self.assertEqual(result["homographs"], [])


class ScoringTests(unittest.TestCase):
    def test_clamp(self):
        self.assertEqual(clamp_score(150), 100)
        self.assertEqual(clamp_score(-5), 0)

    def test_verdict_bands(self):
        self.assertEqual(verdict_for_score(90)[0], "Dangerous")
        self.assertEqual(verdict_for_score(60)[0], "Suspicious")
        self.assertEqual(verdict_for_score(0)[0], "Likely Safe")

    def test_quick_scan_scores_phishing_higher_than_clean(self):
        analyzer = PhishingAnalyzer()
        clean = analyzer.quick_scan("https://www.google.com")
        phish = analyzer.quick_scan("http://paypal.secure-login.tk/verify/account")
        self.assertEqual(clean.score, 0)
        self.assertGreater(phish.score, clean.score)
        self.assertIn(phish.verdict, {"Questionable", "Suspicious", "Dangerous"})


class SsrfGuardTests(unittest.TestCase):
    def test_private_addresses_rejected(self):
        self.assertFalse(_is_public_ip("127.0.0.1"))
        self.assertFalse(_is_public_ip("localhost"))
        self.assertFalse(_is_public_ip("192.168.1.1"))
        self.assertFalse(_is_public_ip("10.0.0.1"))


class ContentFeatureTests(unittest.TestCase):
    def test_offsite_password_form_is_critical(self):
        result = FetchResult(
            ok=True, url="http://login.example.com", final_url="http://login.example.com",
            status_code=200, text="Please sign in", title="Sign in",
            password_inputs=1,
            forms=[{"action": "http://collector.evil.tld/steal", "method": "post", "inputs": ["text", "password"]}],
        )
        signals = analyze_content(result, expected_host="login.example.com")
        titles = {s.title for s in signals.signals if s.hit}
        self.assertIn("Credential form posts off-site", titles)

    def test_urgency_language_flagged(self):
        result = FetchResult(
            ok=True, url="http://x.tld", final_url="http://x.tld", status_code=200,
            text="Your account will be suspended. Confirm your identity within 24 hours.",
            title="Alert",
        )
        signals = analyze_content(result)
        self.assertIn("Urgency / scare language", {s.title for s in signals.signals if s.hit})


if __name__ == "__main__":
    unittest.main()

import unittest
from unittest import mock

import requests

from autosoc.net import RetryError, backoff_delays, retry_request


class _Resp:
    def __init__(self, status_code):
        self.status_code = status_code


class BackoffTests(unittest.TestCase):
    def test_delays_grow_and_count(self):
        delays = list(backoff_delays(4, base=0.5, cap=8.0, jitter=0.0))
        self.assertEqual(delays, [0.5, 1.0, 2.0])

    def test_cap_applied(self):
        delays = list(backoff_delays(6, base=1.0, cap=2.0, jitter=0.0))
        self.assertTrue(all(d <= 2.0 for d in delays))

    def test_no_delays_for_single_attempt(self):
        self.assertEqual(list(backoff_delays(1)), [])


class RetryRequestTests(unittest.TestCase):
    def test_success_first_try(self):
        resp = retry_request(lambda: _Resp(200), attempts=3)
        self.assertEqual(resp.status_code, 200)

    def test_4xx_not_retried(self):
        calls = {"n": 0}

        def attempt():
            calls["n"] += 1
            return _Resp(404)

        resp = retry_request(attempt, attempts=3)
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(calls["n"], 1)  # returned immediately, no retry

    def test_recovers_from_transient_connection_error(self):
        calls = {"n": 0}

        def attempt():
            calls["n"] += 1
            if calls["n"] < 3:
                raise requests.ConnectionError("boom")
            return _Resp(200)

        with mock.patch("autosoc.net.time.sleep"):
            resp = retry_request(attempt, attempts=5)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(calls["n"], 3)

    def test_retries_5xx_then_gives_up_returns_last(self):
        with mock.patch("autosoc.net.time.sleep"):
            resp = retry_request(lambda: _Resp(503), attempts=3)
        # after exhausting retries on a retryable status, the last response is returned
        self.assertEqual(resp.status_code, 503)

    def test_all_transient_failures_raise(self):
        def attempt():
            raise requests.Timeout("slow")

        with mock.patch("autosoc.net.time.sleep"):
            with self.assertRaises(RetryError):
                retry_request(attempt, attempts=3)


class OsAuthTests(unittest.TestCase):
    def test_empty_credentials_return_none(self):
        from autosoc.system.os_auth import verify_os_credentials
        self.assertIsNone(verify_os_credentials("", ""))
        self.assertIsNone(verify_os_credentials("user", ""))

    def test_wrong_password_rejected_cleanly(self):
        from autosoc.system.os_auth import verify_os_credentials
        # Must never raise; a wrong password just returns None.
        result = verify_os_credentials("nonexistent_user_zzz_123", "definitely-wrong")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()

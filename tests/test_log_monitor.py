import unittest

from autosoc.system.log_monitor import BruteForceTracker, LinuxAuthLogListener


class BruteForceTrackerTests(unittest.TestCase):
    def test_detects_burst_over_threshold(self):
        tracker = BruteForceTracker(threshold=3, window_seconds=10)
        base = 1000.0
        detections = [tracker.register_failure("10.0.0.5", base + i) for i in range(4)]
        self.assertTrue(all(d is None for d in detections[:3]))
        self.assertIsNotNone(detections[3])
        self.assertEqual(detections[3]["ip"], "10.0.0.5")

    def test_slow_attempts_do_not_trigger(self):
        tracker = BruteForceTracker(threshold=3, window_seconds=10)
        base = 1000.0
        for i in range(6):
            self.assertIsNone(tracker.register_failure("10.0.0.5", base + i * 30))

    def test_cooldown_suppresses_duplicate_alerts(self):
        tracker = BruteForceTracker(threshold=2, window_seconds=10)
        base = 1000.0
        results = [tracker.register_failure("10.0.0.5", base + i) for i in range(6)]
        fired = [r for r in results if r]
        self.assertEqual(len(fired), 1)

    def test_ips_are_tracked_independently(self):
        tracker = BruteForceTracker(threshold=2, window_seconds=10)
        base = 1000.0
        tracker.register_failure("10.0.0.5", base)
        tracker.register_failure("10.0.0.6", base + 1)
        self.assertIsNone(tracker.register_failure("10.0.0.5", base + 2))


class LinuxAuthLogParsingTests(unittest.TestCase):
    def _listener(self):
        detections = []
        listener = LinuxAuthLogListener(
            on_detection=detections.append,
            log_path="/dev/null",
            threshold=0,
            window_seconds=60,
        )
        return listener, detections

    def test_parses_sshd_failed_password(self):
        listener, detections = self._listener()
        listener._process_line(
            "Jul  8 10:00:00 host sshd[123]: Failed password for root from 203.0.113.9 port 4242 ssh2"
        )
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["ip"], "203.0.113.9")
        self.assertEqual(detections[0]["service"], "SSH/PAM Logon")

    def test_parses_invalid_user(self):
        listener, detections = self._listener()
        listener._process_line(
            "Jul  8 10:00:01 host sshd[123]: Invalid user admin from 198.51.100.3 port 5555"
        )
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["ip"], "198.51.100.3")

    def test_parses_pam_rhost(self):
        listener, detections = self._listener()
        listener._process_line(
            "Jul  8 10:00:02 host sshd[123]: pam_unix(sshd:auth): authentication failure; "
            "logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.77 user=root"
        )
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["ip"], "192.0.2.77")

    def test_ignores_unrelated_lines(self):
        listener, detections = self._listener()
        listener._process_line("Jul  8 10:00:03 host CRON[999]: pam_unix(cron:session): session opened for user root")
        listener._process_line("Jul  8 10:00:04 host sshd[123]: Accepted publickey for user from 192.0.2.1")
        self.assertEqual(detections, [])


if __name__ == "__main__":
    unittest.main()

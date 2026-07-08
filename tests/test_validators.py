import unittest

from autosoc.validators import (
    is_safe_scan_target,
    looks_like_chat_id,
    validate_password,
    validate_registration,
    validate_username,
)


class ChatIdTests(unittest.TestCase):
    def test_accepts_digits(self):
        self.assertTrue(looks_like_chat_id("123456789"))

    def test_accepts_negative_group_ids(self):
        self.assertTrue(looks_like_chat_id("-1001234567890"))

    def test_rejects_text_and_empty(self):
        self.assertFalse(looks_like_chat_id(""))
        self.assertFalse(looks_like_chat_id("abc"))
        self.assertFalse(looks_like_chat_id("12-34"))


class UsernamePasswordTests(unittest.TestCase):
    def test_valid_username(self):
        self.assertIsNone(validate_username("analyst_01"))

    def test_short_username_rejected(self):
        self.assertIsNotNone(validate_username("ab"))

    def test_username_with_shell_chars_rejected(self):
        self.assertIsNotNone(validate_username("user;rm -rf"))

    def test_password_policy(self):
        self.assertIsNotNone(validate_password("short1"))
        self.assertIsNotNone(validate_password("onlyletters"))
        self.assertIsNotNone(validate_password("12345678"))
        self.assertIsNone(validate_password("passw0rd"))

    def test_registration_requires_chat_id(self):
        self.assertIsNotNone(validate_registration("analyst", "passw0rd", "not-a-chat-id"))
        self.assertIsNone(validate_registration("analyst", "passw0rd", "12345"))


class ScanTargetTests(unittest.TestCase):
    def test_accepts_ip_cidr_hostname_localhost(self):
        self.assertTrue(is_safe_scan_target("192.168.1.10"))
        self.assertTrue(is_safe_scan_target("10.0.0.0/24"))
        self.assertTrue(is_safe_scan_target("example.com"))
        self.assertTrue(is_safe_scan_target("localhost"))

    def test_rejects_shell_metacharacters(self):
        for target in ("1.2.3.4; rm -rf /", "a|b", "host`id`", "$(reboot)", "a && b", "host >out"):
            self.assertFalse(is_safe_scan_target(target), target)

    def test_rejects_whitespace_and_empty(self):
        self.assertFalse(is_safe_scan_target(""))
        self.assertFalse(is_safe_scan_target("two words"))


if __name__ == "__main__":
    unittest.main()

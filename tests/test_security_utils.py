import unittest

from security_utils import hash_password, legacy_hash_password, needs_rehash, verify_password


class SecurityUtilsTests(unittest.TestCase):
    def test_modern_hash_roundtrip(self):
        password_hash = hash_password("StrongPass123")
        self.assertTrue(verify_password("StrongPass123", password_hash))
        self.assertFalse(verify_password("wrong-pass", password_hash))
        self.assertFalse(needs_rehash(password_hash))

    def test_legacy_hash_still_validates_and_requires_rehash(self):
        legacy_hash = legacy_hash_password("LegacyPass9")
        self.assertTrue(verify_password("LegacyPass9", legacy_hash))
        self.assertTrue(needs_rehash(legacy_hash))


if __name__ == "__main__":
    unittest.main()

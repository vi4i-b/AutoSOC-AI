import unittest

from autosoc.security_utils import (
    hash_password,
    legacy_hash_password,
    needs_rehash,
    verify_password,
)


class PasswordHashingTests(unittest.TestCase):
    def test_hash_and_verify_roundtrip(self):
        stored = hash_password("passw0rd!")
        self.assertTrue(stored.startswith("pbkdf2_sha256$"))
        self.assertTrue(verify_password("passw0rd!", stored))
        self.assertFalse(verify_password("wrong", stored))

    def test_hashes_are_salted(self):
        self.assertNotEqual(hash_password("same"), hash_password("same"))

    def test_legacy_hash_still_verifies_but_needs_rehash(self):
        legacy = legacy_hash_password("oldpass1")
        self.assertTrue(verify_password("oldpass1", legacy))
        self.assertTrue(needs_rehash(legacy))

    def test_modern_hash_does_not_need_rehash(self):
        self.assertFalse(needs_rehash(hash_password("passw0rd!")))

    def test_empty_or_none_rejected(self):
        self.assertFalse(verify_password(None, hash_password("x1234567")))
        self.assertFalse(verify_password("x", ""))
        with self.assertRaises(ValueError):
            hash_password(None)


if __name__ == "__main__":
    unittest.main()

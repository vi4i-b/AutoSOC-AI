import base64
import hashlib
import hmac
import secrets


PBKDF2_PREFIX = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 260000


def legacy_hash_password(password: str) -> str:
    return hashlib.sha256((password or "").encode("utf-8")).hexdigest()


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    if password is None:
        raise ValueError("Password cannot be None.")

    normalized_iterations = max(int(iterations), 100000)
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("ascii"),
        normalized_iterations,
    )
    encoded_digest = base64.urlsafe_b64encode(digest).decode("ascii")
    return f"{PBKDF2_PREFIX}${normalized_iterations}${salt}${encoded_digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    if password is None or not stored_hash:
        return False

    if stored_hash.startswith(f"{PBKDF2_PREFIX}$"):
        try:
            _, iterations, salt, encoded_digest = stored_hash.split("$", 3)
            expected = base64.urlsafe_b64decode(encoded_digest.encode("ascii"))
            candidate = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt.encode("ascii"),
                int(iterations),
            )
            return hmac.compare_digest(candidate, expected)
        except (TypeError, ValueError):
            return False

    return hmac.compare_digest(legacy_hash_password(password), stored_hash)


def needs_rehash(stored_hash: str) -> bool:
    if not stored_hash:
        return True

    if not stored_hash.startswith(f"{PBKDF2_PREFIX}$"):
        return True

    try:
        _, iterations, _, _ = stored_hash.split("$", 3)
        return int(iterations) < PBKDF2_ITERATIONS
    except (TypeError, ValueError):
        return True

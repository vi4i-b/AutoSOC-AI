import ipaddress
import re


HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,255}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
)
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.@-]{3,64}$")


def looks_like_chat_id(value: str) -> bool:
    normalized = (value or "").strip()
    if not normalized:
        return False
    if normalized.startswith("-"):
        return normalized[1:].isdigit()
    return normalized.isdigit()


def validate_username(username: str) -> str | None:
    normalized = (username or "").strip()
    if not normalized:
        return "Username is required."
    if not USERNAME_PATTERN.fullmatch(normalized):
        return "Username must be 3-64 chars and use letters, digits, dots, underscores, @ or -."
    return None


def validate_password(password: str) -> str | None:
    value = password or ""
    if len(value) < 8:
        return "Password must be at least 8 characters long."
    if not any(char.isalpha() for char in value) or not any(char.isdigit() for char in value):
        return "Password must contain at least one letter and one digit."
    return None


def validate_registration(username: str, password: str, telegram_chat_id: str) -> str | None:
    username_error = validate_username(username)
    if username_error:
        return username_error

    password_error = validate_password(password)
    if password_error:
        return password_error

    if not looks_like_chat_id(telegram_chat_id):
        return "Telegram Chat ID must contain digits only, optionally starting with '-'."

    return None


def is_safe_scan_target(target: str) -> bool:
    value = (target or "").strip()
    if not value or any(char.isspace() for char in value):
        return False

    if any(char in value for char in "\"';&|><`"):
        return False

    if value.lower() == "localhost":
        return True

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass

    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        pass

    return HOSTNAME_PATTERN.fullmatch(value) is not None

"""Localization for API messages, logs, and Telegram alerts (EN / RU / AZ)."""

from __future__ import annotations

import json
import os

_DIR = os.path.dirname(os.path.abspath(__file__))
SUPPORTED = ("en", "ru", "az")
_CATALOGS: dict[str, dict[str, str]] = {}


def _load() -> None:
    for lang in SUPPORTED:
        path = os.path.join(_DIR, f"{lang}.json")
        try:
            with open(path, "r", encoding="utf-8") as handle:
                _CATALOGS[lang] = json.load(handle)
        except (OSError, json.JSONDecodeError):
            _CATALOGS[lang] = {}


_load()


def normalize(lang: str | None) -> str:
    value = (lang or "").split("-")[0].lower()
    return value if value in SUPPORTED else "en"


def t(key: str, lang: str | None = "en", /, **kwargs) -> str:
    """Translate a key; falls back to English, then the key itself."""
    language = normalize(lang)
    template = _CATALOGS.get(language, {}).get(key) or _CATALOGS.get("en", {}).get(key) or key
    try:
        return template.format(**kwargs) if kwargs else template
    except (KeyError, IndexError):
        return template

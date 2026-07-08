"""Central logging configuration.

Everything logs through the ``autosoc`` logger hierarchy. Output goes to
stderr and to a rotating file in the user data directory, so security events
survive application restarts. Never log secrets (tokens, passwords, keys).
"""

import logging
import logging.handlers
import os

from autosoc.paths import data_file, restrict_file_permissions

_CONFIGURED = False


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"autosoc.{name}")


def configure_logging() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    _CONFIGURED = True

    level_name = (os.getenv("AUTOSOC_LOG_LEVEL") or "INFO").strip().upper()
    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger("autosoc")
    root.setLevel(level)
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    root.addHandler(console)

    log_path = data_file("autosoc.log")
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_path, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
        restrict_file_permissions(log_path)
    except OSError:
        pass

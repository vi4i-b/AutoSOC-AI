"""Filesystem locations for application data and bundled resources.

All mutable state (database, remembered login, AI memory, logs) lives in a
per-user data directory instead of the working directory, so the application
behaves the same no matter where it is launched from and the files can be
protected with restrictive permissions:

    Windows:  %APPDATA%\\AutoSOC
    Linux:    $XDG_DATA_HOME/autosoc (defaults to ~/.local/share/autosoc)

Set AUTOSOC_DATA_DIR to override the location entirely.
"""

import os
import shutil
import sys


def project_root() -> str:
    """Directory that contains bundled resources (assets/, .env)."""
    frozen_base = getattr(sys, "_MEIPASS", None)
    if frozen_base:
        return frozen_base
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resource_path(*parts) -> str:
    return os.path.join(project_root(), *parts)


def user_data_dir() -> str:
    override = (os.getenv("AUTOSOC_DATA_DIR") or "").strip()
    if override:
        path = os.path.abspath(override)
    elif os.name == "nt":
        base = os.getenv("APPDATA") or os.path.expanduser("~")
        path = os.path.join(base, "AutoSOC")
    else:
        base = (os.getenv("XDG_DATA_HOME") or "").strip() or os.path.join(
            os.path.expanduser("~"), ".local", "share"
        )
        path = os.path.join(base, "autosoc")

    os.makedirs(path, mode=0o700, exist_ok=True)
    _restrict_directory(path)
    return path


def data_file(name: str) -> str:
    return os.path.join(user_data_dir(), name)


def restrict_file_permissions(path: str) -> None:
    """Make a data file readable by the owner only (POSIX)."""
    if os.name == "nt":
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def migrate_legacy_file(legacy_path: str, new_path: str) -> None:
    """Move a data file from the old working-directory location, once."""
    if os.path.exists(new_path) or not os.path.isfile(legacy_path):
        return
    try:
        shutil.move(legacy_path, new_path)
        restrict_file_permissions(new_path)
    except OSError:
        pass


def _restrict_directory(path: str) -> None:
    if os.name == "nt":
        return
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass

"""Lightweight .env loader (no external dependency).

Existing environment variables always win; the file only fills in gaps.
The first .env found is used, searched in this order: an explicit path,
the current working directory, the project root, and (for frozen builds)
next to the executable.
"""

import os
import sys

from autosoc.paths import project_root


def load_env_file(path: str = ".env") -> None:
    candidates = []
    if path:
        candidates.append(path)

    candidates.extend(
        [
            os.path.join(os.getcwd(), ".env"),
            os.path.join(project_root(), ".env"),
        ]
    )

    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        candidates.extend(
            [
                os.path.join(exe_dir, ".env"),
                os.path.join(os.path.dirname(exe_dir), ".env"),
            ]
        )

    seen = set()
    for candidate in candidates:
        normalized = os.path.abspath(candidate)
        if normalized in seen or not os.path.isfile(normalized):
            continue
        seen.add(normalized)
        try:
            with open(normalized, "r", encoding="utf-8") as env_file:
                for raw_line in env_file:
                    line = raw_line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
            return
        except OSError:
            continue

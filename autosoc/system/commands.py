"""Safe subprocess execution for system commands.

Commands are always executed as argument lists (never through a shell) to
rule out shell injection, with a timeout so a hung tool cannot freeze the
application.
"""

import os
import subprocess
from dataclasses import dataclass

from autosoc.logging_setup import get_logger

log = get_logger("system.commands")

DEFAULT_TIMEOUT = 30


@dataclass
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run_command(args: list, timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
    """Run a command without a shell and capture its output."""
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            creationflags=creation_flags,
        )
        return CommandResult(completed.returncode, completed.stdout or "", completed.stderr or "")
    except subprocess.TimeoutExpired:
        log.warning("Command timed out: %s", args[0])
        return CommandResult(1, "", f"Command timed out after {timeout}s: {args[0]}")
    except OSError as exc:
        log.warning("Command failed to start: %s (%s)", args[0], exc)
        return CommandResult(1, "", str(exc))


def format_result(result: CommandResult) -> str:
    combined = " ".join(part.strip() for part in (result.stdout, result.stderr) if part and part.strip())
    if combined:
        return combined
    if result.ok:
        return "Ok."
    return f"command exited with code {result.returncode}."

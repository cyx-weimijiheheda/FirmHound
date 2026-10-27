"""Subprocess execution helpers with safety wrappers."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RunResult:
    """Result of a controlled subprocess invocation."""

    command: str
    returncode: int
    stdout: str
    stderr: str
    status: str  # success | failed | timeout


def _as_text(value: str | bytes | None) -> str:
    """Normalize captured output (timeout output may arrive as bytes)."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def run_command(
    cmd: Sequence[str] | str,
    *,
    cwd: str | Path | None = None,
    timeout: float = 60.0,
    shell: bool = False,
    env: dict[str, str] | None = None,
) -> RunResult:
    """Run a command safely and return a structured result.

    This helper never raises on non-zero exit codes; instead it returns a
    ``RunResult`` with ``status == "failed"``. Timeouts are captured as
    ``status == "timeout"``. A command that cannot be started at all (empty
    command, missing or non-executable binary, nonexistent ``cwd``) is also
    captured as ``status == "failed"`` with ``returncode == -1`` and the OS
    error in ``stderr``, so callers that probe for optional external tools
    degrade instead of crashing.

    The child's stdin is always ``/dev/null``: several external tools
    (7z during extraction, for one) read from stdin when it is a pipe and
    block forever if the caller's stdin never reaches EOF, hanging the
    whole pipeline instead of timing out.

    Args:
        cmd: Command and arguments as a list, or a string (split with shlex).
        cwd: Working directory for the child process.
        timeout: Maximum runtime in seconds.
        shell: If True, run through the shell (avoid unless required).
        env: Extra environment variables merged over the current environment.
            Used to pin a stable locale (``LC_ALL=C``) when parsing tool output.
    """
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    cmd = [str(c) for c in cmd]
    if not cmd:
        return RunResult(
            command="",
            returncode=-1,
            stdout="",
            stderr="empty command",
            status="failed",
        )
    # On Windows, resolve executable through PATHEXT so .bat/.cmd wrappers work.
    if sys.platform == "win32" and cmd and not Path(cmd[0]).is_absolute():
        resolved = shutil.which(cmd[0])
        if resolved:
            cmd[0] = resolved
    command_str = shlex.join(cmd)
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            timeout=timeout,
            shell=shell,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
            env={**os.environ, **env} if env else None,
        )
        status = "success" if proc.returncode == 0 else "failed"
        return RunResult(
            command=command_str,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            status=status,
        )
    except subprocess.TimeoutExpired as exc:
        return RunResult(
            command=command_str,
            returncode=-1,
            stdout=_as_text(exc.stdout),
            stderr=_as_text(exc.stderr),
            status="timeout",
        )
    except (OSError, ValueError) as exc:
        # Missing/non-executable binary, nonexistent cwd, embedded null
        # bytes, etc.: the process never started, so report it the same
        # way as a non-zero exit instead of propagating the exception.
        return RunResult(
            command=command_str,
            returncode=-1,
            stdout="",
            stderr=str(exc),
            status="failed",
        )

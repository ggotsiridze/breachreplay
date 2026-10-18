"""Safe subprocess execution for analyzer tools.

Python 3.9 compatible: this package is also shipped into the analyzer
containers, whose system interpreters are older than the backend's.

Rules enforced here:
* commands are argument lists, never shell strings (``shell=False``)
* every run has a timeout; the whole process group is killed on expiry
* a minimal environment is passed (no inherited secrets)
* output captured for diagnostics is truncated
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

MAX_DIAGNOSTIC_BYTES = 8000


class AnalyzerError(RuntimeError):
    def __init__(self, tool: str, message: str, detail: str = "", timed_out: bool = False) -> None:
        super().__init__(message)
        self.tool = tool
        self.message = message
        self.detail = detail
        self.timed_out = timed_out


@dataclass(frozen=True)
class ProcessResult:
    args: List[str]
    returncode: int
    duration_seconds: float
    stdout_tail: str
    stderr_tail: str


def _tail(data: bytes) -> str:
    return data[-MAX_DIAGNOSTIC_BYTES:].decode("utf-8", errors="replace")


def minimal_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "HOME": "/tmp",
    }
    if extra:
        env.update(extra)
    return env


def run_command(
    tool: str,
    args: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    env: Optional[Dict[str, str]] = None,
) -> ProcessResult:
    if isinstance(args, (str, bytes)) or not args:
        raise AnalyzerError(tool, "Analyzer command must be a non-empty argument list.")
    argv = [str(a) for a in args]
    if any("\x00" in a for a in argv):
        raise AnalyzerError(tool, "Analyzer command contains a NUL byte.")
    start = time.monotonic()
    try:
        proc = subprocess.Popen(  # noqa: S603 - argv list, shell=False
            argv,
            cwd=str(cwd),
            env=env if env is not None else minimal_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
    except (FileNotFoundError, PermissionError) as exc:
        raise AnalyzerError(tool, "{} is not installed or not executable.".format(tool), str(exc)) from exc
    try:
        stdout, stderr = proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        stdout, stderr = proc.communicate()
        raise AnalyzerError(
            tool,
            "{} exceeded the {:.0f}s analysis timeout.".format(tool, timeout_seconds),
            _tail(stderr),
            timed_out=True,
        ) from None
    return ProcessResult(
        args=argv,
        returncode=proc.returncode,
        duration_seconds=round(time.monotonic() - start, 3),
        stdout_tail=_tail(stdout),
        stderr_tail=_tail(stderr),
    )

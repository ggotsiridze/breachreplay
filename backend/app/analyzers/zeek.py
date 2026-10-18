"""Zeek offline analysis (Python 3.9 compatible)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional

from app.analyzers.process import AnalyzerError, ProcessResult, run_command

TOOL = "zeek"
DEFAULT_POLICY = Path(__file__).resolve().parents[3] / "analyzer" / "config" / "zeek" / "breachreplay.zeek"


def zeek_policy_path() -> Path:
    return Path(os.environ.get("ZEEK_POLICY_PATH", str(DEFAULT_POLICY)))


def build_zeek_command(pcap: Path, policy: Optional[Path] = None, zeek_binary: str = "zeek") -> List[str]:
    """Zeek reads the capture offline.

    -C  ignore checksums (captures taken with NIC offload are common)
    -D  deterministic mode: seeded RNG so connection UIDs are reproducible
    -r  read the capture file; no live interface is ever opened
    """
    args = [zeek_binary, "-C", "-D", "-r", str(pcap), "LogAscii::use_json=T"]
    policy = policy or zeek_policy_path()
    if policy.exists():
        args.append(str(policy))
    return args


def run_zeek(pcap: Path, output_dir: Path, timeout_seconds: float) -> Dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    result: ProcessResult = run_command(TOOL, build_zeek_command(pcap), cwd=output_dir, timeout_seconds=timeout_seconds)
    if result.returncode != 0:
        raise AnalyzerError(TOOL, "Zeek exited unexpectedly (exit code {}).".format(result.returncode), result.stderr_tail)
    logs = sorted(p.name for p in output_dir.glob("*.log"))
    return {
        "tool": TOOL,
        "returncode": result.returncode,
        "duration_seconds": result.duration_seconds,
        "logs": logs,
        "stderr_tail": result.stderr_tail[-2000:],
    }

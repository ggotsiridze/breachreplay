"""Suricata offline analysis (Python 3.9 compatible)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional

from app.analyzers.process import AnalyzerError, run_command

TOOL = "suricata"
DEFAULT_RULES = Path(__file__).resolve().parents[3] / "demo" / "rules" / "breachreplay-demo.rules"


def suricata_rules_path() -> Path:
    return Path(os.environ.get("SURICATA_RULES_PATH", str(DEFAULT_RULES)))


def build_suricata_command(
    pcap: Path,
    log_dir: Path,
    rules: Optional[Path] = None,
    config: Optional[Path] = None,
    suricata_binary: str = "suricata",
) -> List[str]:
    """Suricata reads the capture offline and writes EVE JSON.

    -r            read the capture file (offline, no interface)
    -k none       do not drop packets with bad checksums
    -S            use exclusively the given rules file
    --runmode     single-threaded, deterministic ordering
    """
    args = [suricata_binary]
    config = config or (Path(os.environ["SURICATA_CONFIG_PATH"]) if os.environ.get("SURICATA_CONFIG_PATH") else None)
    if config is not None:
        args += ["-c", str(config)]
    args += [
        "-r",
        str(pcap),
        "-l",
        str(log_dir),
        "-k",
        "none",
        "--runmode",
        "single",
        "-S",
        str(rules or suricata_rules_path()),
    ]
    return args


def run_suricata(pcap: Path, output_dir: Path, timeout_seconds: float) -> Dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    result = run_command(TOOL, build_suricata_command(pcap, output_dir), cwd=output_dir, timeout_seconds=timeout_seconds)
    if result.returncode != 0:
        raise AnalyzerError(TOOL, "Suricata exited unexpectedly (exit code {}).".format(result.returncode), result.stderr_tail)
    eve = output_dir / "eve.json"
    if not eve.exists():
        raise AnalyzerError(TOOL, "Suricata finished but produced no EVE JSON output.", result.stderr_tail)
    return {
        "tool": TOOL,
        "returncode": result.returncode,
        "duration_seconds": result.duration_seconds,
        "logs": sorted(p.name for p in output_dir.iterdir() if p.is_file()),
        "stderr_tail": result.stderr_tail[-2000:],
    }

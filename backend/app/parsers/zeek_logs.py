"""Resilient Zeek log parsing.

Supports JSON-lines logs (``LogAscii::use_json=T``) and Zeek's default TSV
format (``#fields`` header). Missing, empty and malformed logs never abort the
analysis: they are counted and reported.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Logs BreachReplay understands. Anything else Zeek writes is ignored.
SUPPORTED_LOGS = (
    "conn",
    "dns",
    "http",
    "ssl",
    "files",
    "notice",
    "weird",
    "smb_mapping",
    "smb_files",
    "ntlm",
    "dce_rpc",
    "ssh",
    "rdp",
    "kerberos",
    "ftp",
    "smtp",
)

MAX_RECORDS_PER_LOG = 200_000


@dataclass
class ZeekParseResult:
    records: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    stats: dict[str, dict[str, int]] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)

    def get(self, log: str) -> list[dict[str, Any]]:
        return self.records.get(log, [])


def _convert_tsv_value(value: str, type_name: str, unset: str, empty: str, set_sep: str) -> Any:
    if value == unset:
        return None
    if type_name.startswith(("set[", "vector[")):
        if value == empty:
            return []
        inner = type_name[type_name.index("[") + 1 : -1]
        return [_convert_tsv_value(v, inner, unset, empty, set_sep) for v in value.split(set_sep)]
    if type_name in ("count", "int", "port"):
        return int(value)
    if type_name in ("double", "time", "interval"):
        return float(value)
    if type_name == "bool":
        return value == "T"
    return value


def parse_zeek_lines(lines: list[str]) -> tuple[list[dict[str, Any]], int]:
    """Parse a Zeek log's lines in either JSON or TSV format.

    Returns (records, malformed_count).
    """
    records: list[dict[str, Any]] = []
    malformed = 0
    fields: list[str] | None = None
    types: list[str] | None = None
    separator, set_sep, empty, unset = "\t", ",", "(empty)", "-"
    for raw in lines:
        line = raw.rstrip("\n").rstrip("\r")
        if not line.strip():
            continue
        if line.startswith("#"):
            if line.startswith("#separator"):
                sep = line.split(" ", 1)[1].strip()
                separator = sep.encode().decode("unicode_escape") if sep.startswith("\\x") else sep
            elif line.startswith("#set_separator"):
                set_sep = line.split(separator, 1)[1]
            elif line.startswith("#empty_field"):
                empty = line.split(separator, 1)[1]
            elif line.startswith("#unset_field"):
                unset = line.split(separator, 1)[1]
            elif line.startswith("#fields"):
                fields = line.split(separator)[1:]
            elif line.startswith("#types"):
                types = line.split(separator)[1:]
            continue
        if line.lstrip().startswith("{"):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if not isinstance(obj, dict) or "ts" not in obj:
                malformed += 1
                continue
            records.append(obj)
        elif fields:
            values = line.split(separator)
            if len(values) != len(fields):
                malformed += 1
                continue
            try:
                rec = {
                    name: _convert_tsv_value(val, (types or ["string"] * len(fields))[i], unset, empty, set_sep)
                    for i, (name, val) in enumerate(zip(fields, values, strict=True))
                }
            except (ValueError, IndexError):
                malformed += 1
                continue
            records.append(rec)
        else:
            malformed += 1
        if len(records) >= MAX_RECORDS_PER_LOG:
            break
    valid: list[dict[str, Any]] = []
    for rec in records:
        try:
            rec["ts"] = float(rec["ts"])
        except (KeyError, TypeError, ValueError):
            malformed += 1
            continue
        valid.append(rec)
    return valid, malformed


def parse_zeek_directory(directory: Path) -> ZeekParseResult:
    result = ZeekParseResult()
    for log in SUPPORTED_LOGS:
        path = directory / f"{log}.log"
        if not path.is_file():
            result.missing.append(log)
            continue
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            records, malformed = parse_zeek_lines(fh.readlines())
        result.records[log] = records
        result.stats[log] = {"records": len(records), "malformed": malformed}
    return result

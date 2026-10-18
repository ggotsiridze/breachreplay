"""Resilient Suricata EVE JSON parsing."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

SUPPORTED_EVENT_TYPES = ("alert", "flow", "dns", "http", "tls", "ssh", "fileinfo", "anomaly", "smb", "dcerpc", "rdp", "krb5")
MAX_EVENTS = 500_000


@dataclass
class EveParseResult:
    events: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    malformed: int = 0
    unsupported: dict[str, int] = field(default_factory=dict)
    total: int = 0

    def get(self, event_type: str) -> list[dict[str, Any]]:
        return self.events.get(event_type, [])


def parse_eve_timestamp(value: str) -> float:
    """EVE timestamps look like ``2026-03-14T10:31:08.120000+0000``."""
    text = value.strip()
    if len(text) > 5 and text[-5] in "+-" and text[-3] != ":":
        text = f"{text[:-2]}:{text[-2:]}"
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def parse_eve_lines(lines: list[str]) -> EveParseResult:
    result = EveParseResult()
    kept = 0
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        result.total += 1
        try:
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise ValueError("not an object")
            event_type = obj["event_type"]
            obj["_ts"] = parse_eve_timestamp(obj["timestamp"])
            # Flow records are written when the flow manager times the flow out,
            # which depends on processing timing; the flow's own start is stable.
            start = (obj.get("flow") or {}).get("start") if event_type == "flow" else None
            if start:
                obj["_ts"] = parse_eve_timestamp(start)
        except (ValueError, KeyError, TypeError, AttributeError):
            result.malformed += 1
            continue
        if event_type not in SUPPORTED_EVENT_TYPES:
            result.unsupported[event_type] = result.unsupported.get(event_type, 0) + 1
            continue
        if kept >= MAX_EVENTS:
            continue
        result.events.setdefault(event_type, []).append(obj)
        kept += 1
    return result


def parse_eve_file(path: Path) -> EveParseResult:
    if not path.is_file():
        return EveParseResult()
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        return parse_eve_lines(fh.readlines())

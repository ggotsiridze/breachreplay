"""Sanitization for public exports (showcase JSON, PUBLIC_MODE responses)."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any

from app.models import Incident, NetworkEvidence

DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Evidence metadata keys that are safe to publish. Everything else is dropped.
SAFE_METADATA_KEYS = {
    "conn_state",
    "history",
    "duration_seconds",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "query",
    "qtype",
    "rcode",
    "answers",
    "method",
    "host",
    "uri",
    "status_code",
    "server_name",
    "version",
    "cipher",
    "established",
    "username",
    "domain",
    "workstation",
    "path",
    "share_type",
    "action",
    "name",
    "filename",
    "mime_type",
    "seen_bytes",
    "is_orig",
    "transport",
    "signature",
    "signature_id",
    "category",
    "severity",
    "app_proto",
    "http_url",
    "tls_sni",
    "note",
    "msg",
    "pkts_toserver",
    "pkts_toclient",
    "bytes_toserver",
    "bytes_toclient",
    "state",
    "url",
    "http_method",
    "status",
    "hostname",
    "type",
    "rrname",
    "rrtype",
    "sni",
    "command",
    "dialect",
    "size",
    "event",
}


def mask_ip(value: str) -> str:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return value
    if any(addr in n for n in DOC_NETS if n.version == addr.version):
        return value  # documentation ranges are already safe to publish
    if addr.version == 4 and addr.is_private:
        o = value.split(".")
        return f"{o[0]}.x.x.{o[3]}"
    digest = hashlib.sha256(value.encode()).hexdigest()[:6]
    return f"ext-{digest}"


def mask_text(text: str) -> str:
    return IP_RE.sub(lambda m: mask_ip(m.group(0)), text)


def _walk(value: Any, mask: bool) -> Any:
    if isinstance(value, str):
        return mask_text(value) if mask else value
    if isinstance(value, list):
        return [_walk(v, mask) for v in value]
    if isinstance(value, dict):
        return {k: _walk(v, mask) for k, v in value.items()}
    return value


def sanitize_evidence(ev: NetworkEvidence, mask: bool = True) -> dict[str, Any]:
    data = ev.model_dump(mode="json")
    meta = {k: v for k, v in data.get("metadata", {}).items() if k in SAFE_METADATA_KEYS}
    for key in ("uri", "url", "http_url"):
        if isinstance(meta.get(key), str) and len(meta[key]) > 160:
            meta[key] = meta[key][:160] + "…"
    data["metadata"] = meta
    return _walk(data, mask)


def sanitize_incident(incident: Incident, mask: bool = True) -> dict[str, Any]:
    data = incident.model_dump(mode="json")
    data["metadata"] = {k: v for k, v in data.get("metadata", {}).items() if k in {"correlation", "analyzers", "synthetic", "pipeline"}}
    return _walk(data, mask)

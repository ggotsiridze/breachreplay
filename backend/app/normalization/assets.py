"""Asset discovery and classification from observed network evidence."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from app.models import Asset, AssetState, AssetType

INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fd00::/8", "fe80::/10")]

DATABASE_PORTS = {1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB"}
WEB_PORTS = {80, 443, 8000, 8080, 8443}
ADMIN_PORTS = {22, 135, 139, 445, 3389, 5985, 5986}
INFRA_PORTS = {53, 67, 88, 123, 389, 636}

ESTABLISHED_STATES = {"SF", "S1", "S2", "S3", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"}


def is_internal(ip: str) -> bool:
    """RFC1918 / CGNAT / IPv6 ULA+link-local only.

    ``ipaddress``'s ``is_private`` also flags documentation ranges such as
    203.0.113.0/24, which must be treated as external here.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback:
        return True
    return any(addr in net for net in INTERNAL_NETWORKS if net.version == addr.version)


def is_ignorable(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_multicast or addr.is_unspecified or str(addr) == "255.255.255.255" or (addr.version == 4 and str(addr).endswith(".255"))


def normalize_ip(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def short_name(hostname: str) -> str:
    return hostname.split(".")[0].upper()


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


@dataclass
class AssetObservation:
    ip: str
    first_seen: float
    last_seen: float
    hostnames: dict[str, str] = field(default_factory=dict)  # name -> provenance
    accepted_ports: dict[int, set[str]] = field(default_factory=dict)
    initiated: int = 0
    accepted: int = 0

    def seen(self, ts: float) -> None:
        self.first_seen = min(self.first_seen, ts)
        self.last_seen = max(self.last_seen, ts)


class AssetInventory:
    """Collects observations, then builds classified Asset records."""

    def __init__(self, context: dict[str, Any] | None = None) -> None:
        self.context = context or {}
        self.obs: dict[str, AssetObservation] = {}
        self._ctx_assets = {normalize_ip(a.get("ip")): a for a in self.context.get("assets", []) if normalize_ip(a.get("ip"))}
        self._ctx_crown = {
            normalize_ip(c.get("ip")): c.get("reason", "Designated crown jewel in asset context")
            for c in self.context.get("crown_jewels", [])
            if normalize_ip(c.get("ip"))
        }

    def observe(self, ip: str | None, ts: float) -> AssetObservation | None:
        if ip is None or is_ignorable(ip):
            return None
        ob = self.obs.get(ip)
        if ob is None:
            ob = self.obs[ip] = AssetObservation(ip=ip, first_seen=ts, last_seen=ts)
        else:
            ob.seen(ts)
        return ob

    def observe_connection(self, src: str | None, dst: str | None, ts: float, dport: int | None, service: str | None, state: str | None) -> None:
        s = self.observe(src, ts)
        d = self.observe(dst, ts)
        if s:
            s.initiated += 1
        if d and dport is not None and (state in ESTABLISHED_STATES or state is None):
            d.accepted += 1
            d.accepted_ports.setdefault(dport, set())
            if service:
                d.accepted_ports[dport].update(x for x in service.split(",") if x)

    def add_hostname(self, ip: str | None, hostname: str | None, provenance: str) -> None:
        if not ip or not hostname or ip not in self.obs:
            return
        name = hostname.strip().rstrip(".").lower()
        if name and len(name) <= 253:
            self.obs[ip].hostnames.setdefault(name, provenance)

    def _classify(self, ob: AssetObservation) -> tuple[AssetType, str, list[str]]:
        ports = set(ob.accepted_ports)
        labels: list[str] = []
        if not is_internal(ob.ip):
            return AssetType.INTERNET, "External host", ["external"]
        db = sorted(p for p in ports if p in DATABASE_PORTS)
        if db:
            return AssetType.DATABASE, f"Database server ({DATABASE_PORTS[db[0]]})", labels
        if ports & INFRA_PORTS:
            return AssetType.INFRASTRUCTURE, "Infrastructure service", labels
        if ports & WEB_PORTS:
            return AssetType.SERVER, "Web server", labels
        if ob.initiated > 0 and (not ports or ports <= ADMIN_PORTS):
            return AssetType.WORKSTATION, "Workstation", labels
        if ports:
            return AssetType.SERVER, "Server", labels
        return AssetType.UNKNOWN, "Unclassified host", labels

    def build(self) -> list[Asset]:
        assets: list[Asset] = []
        used_ids: set[str] = set()
        for ip in sorted(self.obs, key=lambda i: (self.obs[i].first_seen, ipaddress.ip_address(i).packed)):
            ob = self.obs[ip]
            ctx = self._ctx_assets.get(ip, {})
            asset_type, role, labels = self._classify(ob)
            if ctx.get("asset_type") in AssetType.__members__:
                asset_type = AssetType[ctx["asset_type"]]
            role = ctx.get("role", role)
            labels = sorted(set(labels) | set(ctx.get("labels", [])))
            hostname = ctx.get("hostname") or self._best_hostname(ob)
            internal = is_internal(ip)
            display = short_name(hostname) if hostname and internal else ip
            base_id = f"asset-{slug(display)}"
            asset_id = base_id
            n = 2
            while asset_id in used_ids:
                asset_id = f"{base_id}-{n}"
                n += 1
            used_ids.add(asset_id)
            crown_reason = self._ctx_crown.get(ip)
            if crown_reason is None and not self._ctx_crown and asset_type == AssetType.DATABASE:
                crown_reason = "Inferred: accepts database-service connections (no analyst asset context supplied)"
            services = sorted(f"{p}/{'+'.join(sorted(s)) or 'tcp'}" for p, s in ob.accepted_ports.items())
            importance = {
                AssetType.DATABASE: 80,
                AssetType.SERVER: 60,
                AssetType.INFRASTRUCTURE: 50,
                AssetType.WORKSTATION: 40,
                AssetType.INTERNET: 20,
            }.get(asset_type, 10)
            if crown_reason:
                importance = 100
                labels = sorted(set(labels) | {"crown-jewel"})
            assets.append(
                Asset(
                    id=asset_id,
                    ip=ip,
                    hostname=hostname,
                    display_name=display,
                    role=role,
                    asset_type=asset_type,
                    labels=labels,
                    importance=importance,
                    internal=internal,
                    crown_jewel=crown_reason is not None,
                    crown_jewel_reason=crown_reason,
                    first_seen=ob.first_seen,
                    last_seen=ob.last_seen,
                    state=AssetState.NORMAL,
                    services=services,
                )
            )
        return assets

    @staticmethod
    def _best_hostname(ob: AssetObservation) -> str | None:
        if not ob.hostnames:
            return None
        # Prefer DNS-derived names, then NTLM/other provenance; stable ordering.
        ranked = sorted(ob.hostnames.items(), key=lambda kv: (kv[1] != "dns", kv[0]))
        return ranked[0][0]

"""Normalize Zeek and Suricata output into BreachReplay's evidence model.

Output:
* ``assets``      - discovered, classified assets
* ``evidence``    - one NetworkEvidence per useful analyzer record
* ``detections``  - Suricata alerts and Zeek notices
* ``activities``  - connection-level groupings (Zeek uid / 5-tuple) that the
                    correlation engine reasons over

Raw payloads are never copied: only protocol metadata and short summaries.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from app.models import Asset, Detection, EvidenceSource, NetworkEvidence
from app.normalization.assets import AssetInventory, normalize_ip
from app.parsers.suricata_eve import EveParseResult
from app.parsers.zeek_logs import ZeekParseResult

CONN_STATE_TEXT = {
    "S0": "connection attempt, no reply",
    "S1": "established, not terminated",
    "SF": "completed normally",
    "REJ": "rejected (reset)",
    "S2": "established, originator closed",
    "S3": "established, responder closed",
    "RSTO": "reset by originator",
    "RSTR": "reset by responder",
    "RSTOS0": "SYN then reset by originator",
    "RSTRH": "responder SYN-ACK then reset",
    "SH": "originator SYN then FIN",
    "SHR": "responder SYN-ACK then FIN",
    "OTH": "midstream traffic",
}

MAX_METADATA_STRING = 240


def human_bytes(n: int | None) -> str:
    if not n:
        return "0 B"
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def clip(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_METADATA_STRING:
        return value[:MAX_METADATA_STRING] + "…"
    return value


@dataclass
class Activity:
    """Everything observed about one network conversation."""

    key: str
    ts: float
    end_ts: float
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    proto: str
    service: str | None = None
    conn_state: str | None = None
    orig_bytes: int = 0
    resp_bytes: int = 0
    source_asset_id: str | None = None
    destination_asset_id: str | None = None
    evidence_ids: list[str] = field(default_factory=list)
    detection_ids: list[str] = field(default_factory=list)
    http: list[dict[str, Any]] = field(default_factory=list)
    dns: list[dict[str, Any]] = field(default_factory=list)
    tls_sni: list[str] = field(default_factory=list)
    smb_shares: list[str] = field(default_factory=list)
    smb_files: list[str] = field(default_factory=list)
    identities: list[str] = field(default_factory=list)
    files: list[dict[str, Any]] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)
    app_protocols: set[str] = field(default_factory=set)

    @property
    def tuple_key(self) -> tuple[str, int | None, str, int | None, str]:
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.proto)

    @property
    def rejected(self) -> bool:
        return self.conn_state in {"REJ", "S0", "RSTOS0", "RSTRH", "SH", "SHR"}

    @property
    def total_bytes(self) -> int:
        return self.orig_bytes + self.resp_bytes


@dataclass
class NormalizedEvidence:
    assets: list[Asset]
    evidence: list[NetworkEvidence]
    detections: list[Detection]
    activities: list[Activity]
    stats: dict[str, Any]

    def asset_by_ip(self) -> dict[str, Asset]:
        return {a.ip: a for a in self.assets}


def _tuple(rec: dict[str, Any]) -> tuple[str | None, int | None, str | None, int | None]:
    return (
        normalize_ip(rec.get("id.orig_h")),
        rec.get("id.orig_p"),
        normalize_ip(rec.get("id.resp_h")),
        rec.get("id.resp_p"),
    )


def _eve_proto(ev: dict[str, Any]) -> str:
    return str(ev.get("proto", "")).lower() or "unknown"


class Normalizer:
    def __init__(self, zeek: ZeekParseResult, eve: EveParseResult, context: dict[str, Any] | None = None) -> None:
        self.zeek = zeek
        self.eve = eve
        self.inventory = AssetInventory(context)
        self.evidence: list[NetworkEvidence] = []
        self.detections: list[Detection] = []
        self._counters: dict[str, int] = defaultdict(int)

    # -- helpers ---------------------------------------------------------

    def _next_id(self, prefix: str) -> str:
        self._counters[prefix] += 1
        return f"{prefix}-{self._counters[prefix]:05d}"

    def _name(self, ip: str | None) -> str:
        if ip is None:
            return "?"
        asset = self._assets_by_ip.get(ip)
        return asset.display_name if asset else ip

    # -- pipeline --------------------------------------------------------

    def run(self) -> NormalizedEvidence:
        self._discover_assets()
        activities = self._build_activities()
        self._attach_zeek_protocol_logs(activities)
        self._attach_suricata(activities)
        self._attach_notices(activities)
        ordered = sorted(activities.values(), key=lambda a: (a.ts, a.key))
        self.evidence.sort(key=lambda e: (e.timestamp, e.id))
        self.detections.sort(key=lambda d: (d.timestamp, d.id))
        stats = {
            "zeek_logs": {k: v for k, v in self.zeek.stats.items()},
            "zeek_missing_logs": self.zeek.missing,
            "suricata_events": {k: len(v) for k, v in self.eve.events.items()},
            "suricata_malformed": self.eve.malformed,
            "suricata_unsupported": self.eve.unsupported,
            "evidence_records": len(self.evidence),
            "detections": len(self.detections),
            "activities": len(ordered),
            "assets": len(self.assets),
        }
        return NormalizedEvidence(self.assets, self.evidence, self.detections, ordered, stats)

    def _discover_assets(self) -> None:
        inv = self.inventory
        for rec in self.zeek.get("conn"):
            src, _, dst, dport = _tuple(rec)
            inv.observe_connection(src, dst, rec["ts"], dport, rec.get("service"), rec.get("conn_state"))
        if not self.zeek.get("conn"):
            for ev in self.eve.get("flow"):
                inv.observe_connection(
                    normalize_ip(ev.get("src_ip")), normalize_ip(ev.get("dest_ip")), ev["_ts"], ev.get("dest_port"), ev.get("app_proto"), None
                )
        for ev in self.eve.get("alert"):
            inv.observe(normalize_ip(ev.get("src_ip")), ev["_ts"])
            inv.observe(normalize_ip(ev.get("dest_ip")), ev["_ts"])
        for rec in self.zeek.get("dns"):
            for answer in rec.get("answers") or []:
                ip = normalize_ip(answer)
                if ip and rec.get("query"):
                    inv.add_hostname(ip, rec["query"], "dns")
        for rec in self.zeek.get("ntlm"):
            if rec.get("hostname"):
                inv.add_hostname(normalize_ip(rec.get("id.orig_h")), rec["hostname"], "ntlm")
        self.assets = inv.build()
        self._assets_by_ip = {a.ip: a for a in self.assets}

    def _asset_id(self, ip: str | None) -> str | None:
        asset = self._assets_by_ip.get(ip) if ip else None
        return asset.id if asset else None

    def _add_evidence(self, **kwargs: Any) -> NetworkEvidence:
        src_ip, dst_ip = kwargs.get("source_ip"), kwargs.get("destination_ip")
        kwargs.setdefault("source_asset_id", self._asset_id(src_ip))
        kwargs.setdefault("destination_asset_id", self._asset_id(dst_ip))
        kwargs["metadata"] = {k: clip(v) for k, v in kwargs.get("metadata", {}).items() if v not in (None, "", [])}
        ev = NetworkEvidence(**kwargs)
        self.evidence.append(ev)
        return ev

    def _build_activities(self) -> dict[str, Activity]:
        activities: dict[str, Activity] = {}
        for rec in sorted(self.zeek.get("conn"), key=lambda r: (r["ts"], r.get("uid", ""))):
            src, sport, dst, dport = _tuple(rec)
            if src is None or dst is None:
                continue
            uid = str(rec.get("uid") or self._next_id("conn"))
            proto = str(rec.get("proto", "")).lower()
            service = rec.get("service") or None
            state = rec.get("conn_state")
            orig_b, resp_b = int(rec.get("orig_bytes") or 0), int(rec.get("resp_bytes") or 0)
            duration = float(rec.get("duration") or 0.0)
            ev = self._add_evidence(
                id=self._next_id("ev-zeek-conn"),
                timestamp=rec["ts"],
                source=EvidenceSource.ZEEK,
                log_type="conn",
                source_record_id=uid,
                source_ip=src,
                destination_ip=dst,
                source_port=sport,
                destination_port=dport,
                protocol=proto,
                service=service,
                event_type="connection",
                summary=(
                    f"{proto.upper()} {self._name(src)} → {self._name(dst)}:{dport}"
                    f"{f' ({service})' if service else ''} · {human_bytes(orig_b)} sent / {human_bytes(resp_b)} received"
                    f" · {CONN_STATE_TEXT.get(state or '', state or 'unknown state')}"
                ),
                metadata={
                    "conn_state": state,
                    "history": rec.get("history"),
                    "duration_seconds": round(duration, 3),
                    "orig_bytes": orig_b,
                    "resp_bytes": resp_b,
                    "orig_pkts": rec.get("orig_pkts"),
                    "resp_pkts": rec.get("resp_pkts"),
                },
            )
            act = Activity(
                key=uid,
                ts=rec["ts"],
                end_ts=rec["ts"] + duration,
                src_ip=src,
                dst_ip=dst,
                src_port=sport,
                dst_port=dport,
                proto=proto,
                service=service,
                conn_state=state,
                orig_bytes=orig_b,
                resp_bytes=resp_b,
                source_asset_id=self._asset_id(src),
                destination_asset_id=self._asset_id(dst),
                evidence_ids=[ev.id],
            )
            if service:
                act.app_protocols.update(s for s in service.split(",") if s)
            activities[uid] = act
        return activities

    def _attach_zeek_protocol_logs(self, activities: dict[str, Activity]) -> None:
        def base(rec: dict[str, Any], log: str, event_type: str, summary: str, metadata: dict[str, Any], service: str) -> NetworkEvidence:
            src, sport, dst, dport = _tuple(rec)
            return self._add_evidence(
                id=self._next_id(f"ev-zeek-{log.replace('_', '-')}"),
                timestamp=rec["ts"],
                source=EvidenceSource.ZEEK,
                log_type=log,
                source_record_id=str(rec.get("uid") or rec.get("fuid") or ""),
                source_ip=src,
                destination_ip=dst,
                source_port=sport,
                destination_port=dport,
                protocol=rec.get("proto") or "tcp",
                service=service,
                event_type=event_type,
                summary=summary,
                metadata=metadata,
            )

        def attach(rec: dict[str, Any], ev: NetworkEvidence) -> Activity | None:
            act = activities.get(str(rec.get("uid")))
            if act is not None:
                act.evidence_ids.append(ev.id)
            return act

        for rec in self.zeek.get("dns"):
            answers = [a for a in rec.get("answers") or []][:8]
            ev = base(
                rec,
                "dns",
                "dns_query",
                f"DNS {rec.get('qtype_name') or 'query'} {rec.get('query') or '?'} → {', '.join(map(str, answers)) or rec.get('rcode_name') or 'no answer'}",
                {"query": rec.get("query"), "qtype": rec.get("qtype_name"), "rcode": rec.get("rcode_name"), "answers": answers},
                "dns",
            )
            act = attach(rec, ev)
            if act:
                act.dns.append({"query": rec.get("query"), "answers": answers})

        for rec in self.zeek.get("http"):
            uri = rec.get("uri") or "/"
            ev = base(
                rec,
                "http",
                "http_request",
                f"HTTP {rec.get('method') or '?'} {rec.get('host') or ''}{clip(uri)} → {rec.get('status_code') or 'no response'}",
                {
                    "method": rec.get("method"),
                    "host": rec.get("host"),
                    "uri": uri,
                    "status_code": rec.get("status_code"),
                    "user_agent": rec.get("user_agent"),
                    "request_body_len": rec.get("request_body_len"),
                    "response_body_len": rec.get("response_body_len"),
                },
                "http",
            )
            act = attach(rec, ev)
            if act:
                act.http.append({"method": rec.get("method"), "uri": uri, "host": rec.get("host"), "status": rec.get("status_code")})
                act.app_protocols.add("http")

        for rec in self.zeek.get("ssl"):
            sni = rec.get("server_name")
            ev = base(
                rec,
                "ssl",
                "tls_session",
                f"TLS {rec.get('version') or ''} session{f' to {sni}' if sni else ''} ({'established' if rec.get('established') else 'not established'})",
                {"version": rec.get("version"), "cipher": rec.get("cipher"), "server_name": sni, "established": rec.get("established")},
                "ssl",
            )
            act = attach(rec, ev)
            if act:
                act.app_protocols.add("ssl")
                if sni:
                    act.tls_sni.append(sni)

        for rec in self.zeek.get("ntlm"):
            user = rec.get("username")
            domain = rec.get("domainname")
            identity = f"{domain}\\{user}" if domain and user else user
            ev = base(
                rec,
                "ntlm",
                "authentication",
                f"NTLM authentication as {identity or 'unknown account'} from workstation {rec.get('hostname') or '?'}",
                {"username": user, "domain": domain, "workstation": rec.get("hostname"), "success": rec.get("success")},
                "ntlm",
            )
            act = attach(rec, ev)
            if act and identity:
                act.identities.append(identity)

        for rec in self.zeek.get("smb_mapping"):
            path = rec.get("path") or "?"
            ev = base(
                rec,
                "smb_mapping",
                "smb_share_access",
                f"SMB tree connect to share {path} ({rec.get('share_type') or 'unknown type'})",
                {"path": path, "share_type": rec.get("share_type"), "service": rec.get("service")},
                "smb",
            )
            act = attach(rec, ev)
            if act:
                act.smb_shares.append(path)
                act.app_protocols.add("smb")

        for rec in self.zeek.get("smb_files"):
            name = rec.get("name") or "?"
            ev = base(
                rec,
                "smb_files",
                "smb_file_activity",
                f"SMB {str(rec.get('action') or 'file action').replace('SMB::FILE_', '').lower()} {name} on {rec.get('path') or 'share'}",
                {"action": rec.get("action"), "name": name, "path": rec.get("path"), "size": rec.get("size")},
                "smb",
            )
            act = attach(rec, ev)
            if act:
                act.smb_files.append(name)

        for rec in self.zeek.get("files"):
            uids = rec.get("conn_uids") or ([rec["uid"]] if rec.get("uid") else [])
            src = normalize_ip(rec.get("id.orig_h") or (rec.get("tx_hosts") or [None])[0])
            dst = normalize_ip(rec.get("id.resp_h") or (rec.get("rx_hosts") or [None])[0])
            direction = "uploaded by originator" if rec.get("is_orig") else "served by responder"
            fname = rec.get("filename")
            ev = self._add_evidence(
                id=self._next_id("ev-zeek-files"),
                timestamp=rec["ts"],
                source=EvidenceSource.ZEEK,
                log_type="files",
                source_record_id=str(rec.get("fuid") or ""),
                source_ip=src,
                destination_ip=dst,
                source_port=rec.get("id.orig_p"),
                destination_port=rec.get("id.resp_p"),
                protocol="tcp",
                service=str(rec.get("source") or "").lower() or None,
                event_type="file_transfer",
                summary=(
                    f"File over {rec.get('source') or '?'}: {fname or 'unnamed'} ({rec.get('mime_type') or 'unknown type'},"
                    f" {human_bytes(rec.get('seen_bytes'))}, {direction})"
                ),
                metadata={
                    "filename": fname,
                    "mime_type": rec.get("mime_type"),
                    "seen_bytes": rec.get("seen_bytes"),
                    "is_orig": rec.get("is_orig"),
                    "transport": rec.get("source"),
                    "md5": rec.get("md5"),
                    "sha1": rec.get("sha1"),
                },
            )
            for uid in uids:
                act = activities.get(str(uid))
                if act:
                    act.evidence_ids.append(ev.id)
                    act.files.append({"filename": fname, "mime_type": rec.get("mime_type"), "bytes": rec.get("seen_bytes"), "is_orig": rec.get("is_orig")})

        for log, service in (("ssh", "ssh"), ("rdp", "rdp"), ("dce_rpc", "dce_rpc"), ("kerberos", "krb"), ("ftp", "ftp"), ("smtp", "smtp")):
            for rec in self.zeek.get(log):
                detail = {
                    "ssh": lambda r: f"SSH {r.get('client') or 'client'} → {r.get('server') or 'server'} (auth: {r.get('auth_success')})",
                    "rdp": lambda r: f"RDP session (cookie {r.get('cookie') or 'n/a'}, result {r.get('result') or 'unknown'})",
                    "dce_rpc": lambda r: f"DCE/RPC {r.get('endpoint') or '?'}::{r.get('operation') or '?'}",
                    "kerberos": lambda r: f"Kerberos {r.get('request_type') or '?'} for {r.get('client') or '?'}",
                    "ftp": lambda r: f"FTP {r.get('command') or '?'} {r.get('arg') or ''}",
                    "smtp": lambda r: f"SMTP message from {r.get('mailfrom') or '?'}",
                }[log](rec)
                keep = {k: rec.get(k) for k in ("client", "server", "auth_success", "cookie", "result", "endpoint", "operation", "request_type", "command")}
                ev = base(rec, log, f"{service}_activity", detail, keep, service)
                act = attach(rec, ev)
                if act:
                    act.app_protocols.add(service)

        for rec in self.zeek.get("weird"):
            base(
                rec,
                "weird",
                "protocol_anomaly",
                f"Zeek protocol anomaly: {rec.get('name') or 'unknown'}",
                {"name": rec.get("name"), "addl": rec.get("addl")},
                "",
            )

    def _attach_suricata(self, activities: dict[str, Activity]) -> None:
        by_tuple: dict[tuple[str | None, int | None, str | None, int | None, str], list[Activity]] = defaultdict(list)
        for act in activities.values():
            by_tuple[act.tuple_key].append(act)

        def find_activity(ev: dict[str, Any]) -> Activity | None:
            src, dst = normalize_ip(ev.get("src_ip")), normalize_ip(ev.get("dest_ip"))
            key = (src, ev.get("src_port"), dst, ev.get("dest_port"), _eve_proto(ev))
            candidates = by_tuple.get(key) or by_tuple.get((dst, ev.get("dest_port"), src, ev.get("src_port"), _eve_proto(ev))) or []
            if not candidates:
                return None
            return min(candidates, key=lambda a: abs(a.ts - ev["_ts"]))

        detection_seq = 0
        alert_rows = sorted(self.eve.get("alert"), key=lambda e: (e["_ts"], e.get("pcap_cnt", 0)))
        for ev in alert_rows:
            alert = ev.get("alert") or {}
            src, dst = normalize_ip(ev.get("src_ip")), normalize_ip(ev.get("dest_ip"))
            evidence = self._add_evidence(
                id=self._next_id("ev-suricata-alert"),
                timestamp=ev["_ts"],
                source=EvidenceSource.SURICATA,
                log_type="eve.alert",
                source_record_id=str(ev.get("flow_id") or ""),
                source_ip=src,
                destination_ip=dst,
                source_port=ev.get("src_port"),
                destination_port=ev.get("dest_port"),
                protocol=_eve_proto(ev),
                service=ev.get("app_proto"),
                event_type="ids_alert",
                summary=f"Suricata alert [{alert.get('signature_id')}] {alert.get('signature')} (severity {alert.get('severity')})",
                metadata={
                    "signature": alert.get("signature"),
                    "signature_id": alert.get("signature_id"),
                    "category": alert.get("category"),
                    "severity": alert.get("severity"),
                    "action": alert.get("action"),
                    "app_proto": ev.get("app_proto"),
                    "http_url": (ev.get("http") or {}).get("url"),
                    "tls_sni": (ev.get("tls") or {}).get("sni"),
                },
            )
            detection_seq += 1
            det = Detection(
                id=f"det-{detection_seq:04d}",
                timestamp=ev["_ts"],
                source=EvidenceSource.SURICATA,
                signature=str(alert.get("signature") or "unknown signature"),
                signature_id=str(alert.get("signature_id") or ""),
                category=str(alert.get("category") or "uncategorized"),
                severity=int(alert.get("severity") or 3),
                source_ip=src,
                destination_ip=dst,
                source_port=ev.get("src_port"),
                destination_port=ev.get("dest_port"),
                source_asset_id=self._asset_id(src),
                destination_asset_id=self._asset_id(dst),
                evidence_ids=[evidence.id],
            )
            self.detections.append(det)
            act = find_activity(ev)
            if act:
                act.evidence_ids.append(evidence.id)
                act.detection_ids.append(det.id)

        summaries = {
            "flow": lambda e: (
                f"Suricata flow {e.get('app_proto') or _eve_proto(e)}: {(e.get('flow') or {}).get('pkts_toserver', 0)}"
                f"/{(e.get('flow') or {}).get('pkts_toclient', 0)} packets, state {(e.get('flow') or {}).get('state') or '?'}"
            ),
            "http": lambda e: f"Suricata HTTP {(e.get('http') or {}).get('http_method') or '?'} {(e.get('http') or {}).get('url') or ''}",
            "dns": lambda e: f"Suricata DNS {(e.get('dns') or {}).get('type') or ''} {(e.get('dns') or {}).get('rrname') or ''}",
            "tls": lambda e: f"Suricata TLS {(e.get('tls') or {}).get('version') or ''} SNI {(e.get('tls') or {}).get('sni') or 'n/a'}",
            "ssh": lambda e: "Suricata SSH session",
            "fileinfo": lambda e: (
                f"Suricata file {(e.get('fileinfo') or {}).get('filename') or 'unnamed'} ({(e.get('fileinfo') or {}).get('size') or 0} bytes)"
            ),
            "anomaly": lambda e: f"Suricata anomaly {(e.get('anomaly') or {}).get('event') or (e.get('anomaly') or {}).get('type') or ''}",
            "smb": lambda e: (
                f"Suricata SMB {str((e.get('smb') or {}).get('command') or '').replace('SMB2_COMMAND_', '')} → {(e.get('smb') or {}).get('status') or ''}"
            ),
            "dcerpc": lambda e: "Suricata DCERPC transaction",
            "rdp": lambda e: "Suricata RDP event",
            "krb5": lambda e: "Suricata Kerberos event",
        }
        meta_keys = {
            "flow": lambda e: {
                k: (e.get("flow") or {}).get(k) for k in ("pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient", "state", "reason")
            },
            "http": lambda e: {k: (e.get("http") or {}).get(k) for k in ("hostname", "url", "http_method", "status", "http_user_agent")},
            "dns": lambda e: {k: (e.get("dns") or {}).get(k) for k in ("type", "rrname", "rrtype", "rcode")},
            "tls": lambda e: {k: (e.get("tls") or {}).get(k) for k in ("sni", "version", "ja3s")},
            "fileinfo": lambda e: {k: (e.get("fileinfo") or {}).get(k) for k in ("filename", "size", "state", "magic")},
            "anomaly": lambda e: {k: (e.get("anomaly") or {}).get(k) for k in ("type", "event", "layer")},
            "smb": lambda e: {k: (e.get("smb") or {}).get(k) for k in ("command", "status", "dialect", "share", "filename")},
        }
        for event_type in ("flow", "http", "dns", "tls", "ssh", "fileinfo", "anomaly", "smb", "dcerpc", "rdp", "krb5"):
            for ev in sorted(self.eve.get(event_type), key=lambda e: (e["_ts"], e.get("pcap_cnt", 0))):
                src, dst = normalize_ip(ev.get("src_ip")), normalize_ip(ev.get("dest_ip"))
                evidence = self._add_evidence(
                    id=self._next_id(f"ev-suricata-{event_type}"),
                    timestamp=ev["_ts"],
                    source=EvidenceSource.SURICATA,
                    log_type=f"eve.{event_type}",
                    source_record_id=str(ev.get("flow_id") or ""),
                    source_ip=src,
                    destination_ip=dst,
                    source_port=ev.get("src_port"),
                    destination_port=ev.get("dest_port"),
                    protocol=_eve_proto(ev),
                    service=ev.get("app_proto") or (event_type if event_type not in ("flow", "fileinfo", "anomaly") else None),
                    event_type=f"suricata_{event_type}",
                    summary=summaries[event_type](ev),
                    metadata=meta_keys.get(event_type, lambda e: {})(ev),
                )
                act = find_activity(ev)
                if act:
                    act.evidence_ids.append(evidence.id)
                    if ev.get("app_proto") and ev["app_proto"] not in ("failed", "unknown"):
                        act.app_protocols.add(str(ev["app_proto"]))

    def _attach_notices(self, activities: dict[str, Activity]) -> None:
        seq = len(self.detections)
        for rec in sorted(self.zeek.get("notice"), key=lambda r: r["ts"]):
            src = normalize_ip(rec.get("src") or rec.get("id.orig_h"))
            dst = normalize_ip(rec.get("dst") or rec.get("id.resp_h"))
            note = str(rec.get("note") or "Notice")
            port = rec.get("p") if isinstance(rec.get("p"), int) else rec.get("id.resp_p")
            ev = self._add_evidence(
                id=self._next_id("ev-zeek-notice"),
                timestamp=rec["ts"],
                source=EvidenceSource.ZEEK,
                log_type="notice",
                source_record_id=str(rec.get("uid") or ""),
                source_ip=src,
                destination_ip=dst,
                source_port=rec.get("id.orig_p"),
                destination_port=port,
                protocol=rec.get("proto"),
                service=None,
                event_type="zeek_notice",
                summary=f"Zeek notice {note}: {rec.get('msg') or ''}",
                metadata={"note": note, "msg": rec.get("msg"), "sub": rec.get("sub")},
            )
            seq += 1
            det = Detection(
                id=f"det-{seq:04d}",
                timestamp=rec["ts"],
                source=EvidenceSource.ZEEK,
                signature=f"{note}: {rec.get('msg') or ''}".strip(": "),
                signature_id=note,
                category="Zeek notice",
                severity=2,
                source_ip=src,
                destination_ip=dst,
                destination_port=port,
                source_asset_id=self._asset_id(src),
                destination_asset_id=self._asset_id(dst),
                evidence_ids=[ev.id],
            )
            self.detections.append(det)
            act = activities.get(str(rec.get("uid"))) if rec.get("uid") else None
            if act:
                act.evidence_ids.append(ev.id)
                act.detection_ids.append(det.id)
                act.notices.append(note)


def normalize(zeek: ZeekParseResult, eve: EveParseResult, context: dict[str, Any] | None = None) -> NormalizedEvidence:
    return Normalizer(zeek, eve, context).run()

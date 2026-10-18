"""Deterministic evidence correlation.

The engine walks normalized activities in chronological order, proposes
candidate incident events from behavioural patterns, and scores each candidate
using only evidence available *up to that point in time* (plus aligned
detections). Every score is accompanied by its reasons.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.correlation.scoring import LABEL_RANK, Score
from app.mitre.mapping import TACTICS, MappingContext, map_technique
from app.models import (
    Asset,
    AssetState,
    AssetType,
    ConfidenceLabel,
    Detection,
    EventType,
    IncidentEvent,
    StateChange,
)
from app.normalization.assets import ADMIN_PORTS, DATABASE_PORTS
from app.normalization.normalizer import Activity, NormalizedEvidence, human_bytes

ADMIN_PROTOCOLS = {"smb", "rdp", "ssh", "dce_rpc", "winrm", "ntlm", "krb"}
LARGE_OUTBOUND_BYTES = 100 * 1024
PROXIMITY_SECONDS = 120.0
FANOUT_WINDOW_SECONDS = 30.0
FANOUT_MIN_TARGETS = 3
PERIODIC_MIN = 3
PERIODIC_WINDOW_SECONDS = 600.0
RECON_WINDOW_SECONDS = 120.0
PRECURSOR_WINDOW_SECONDS = 600.0

STATE_RANK = {AssetState.NORMAL: 0, AssetState.SUSPICIOUS: 1, AssetState.AFFECTED: 2}

TITLES = {
    EventType.EXTERNAL_RECON: "External probing",
    EventType.INITIAL_ACCESS: "Initial access",
    EventType.COMMAND_AND_CONTROL: "Command & control",
    EventType.DISCOVERY: "Internal discovery",
    EventType.LATERAL_MOVEMENT: "Lateral movement",
    EventType.CROWN_JEWEL_ACCESS: "Crown jewel access",
    EventType.EXFILTRATION: "Data exfiltration",
    EventType.SUSPICIOUS_CONNECTION: "Suspicious connection",
}


def clock(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%H:%M:%S")


@dataclass
class Candidate:
    event_type: EventType
    activities: list[Activity]
    source_asset_id: str | None
    destination_asset_id: str | None
    target_asset_ids: list[str] = field(default_factory=list)

    @property
    def ts(self) -> float:
        return min(a.ts for a in self.activities)

    @property
    def end_ts(self) -> float:
        return max(a.end_ts for a in self.activities)

    @property
    def primary(self) -> Activity:
        return self.activities[0]


@dataclass
class CorrelationResult:
    events: list[IncidentEvent]
    final_states: dict[str, AssetState]
    context_events_dropped: int
    candidates_considered: int


class CorrelationEngine:
    def __init__(self, normalized: NormalizedEvidence) -> None:
        self.n = normalized
        self.assets: dict[str, Asset] = {a.id: a for a in normalized.assets}
        self.detections: dict[str, Detection] = {d.id: d for d in normalized.detections}
        self.states: dict[str, AssetState] = {a.id: AssetState.NORMAL for a in normalized.assets}
        # asset id -> list of (timestamp, event index) for suspicious-or-higher events involving it
        self.suspicious_history: dict[str, list[tuple[float, int]]] = defaultdict(list)
        self.attacker_endpoints: dict[str, float] = {}
        self.c2_endpoints: set[str] = set()

    # -- helpers ---------------------------------------------------------

    def _asset(self, asset_id: str | None) -> Asset | None:
        return self.assets.get(asset_id) if asset_id else None

    def _name(self, asset_id: str | None) -> str:
        a = self._asset(asset_id)
        return a.display_name if a else "unknown host"

    def _internal(self, asset_id: str | None) -> bool:
        a = self._asset(asset_id)
        return bool(a and a.internal)

    def _protocols(self, c: Candidate) -> set[str]:
        out: set[str] = set()
        for act in c.activities:
            out |= {p.lower() for p in act.app_protocols}
        if out & {"ntlm", "gssapi"} and any(a.dst_port in (139, 445) for a in c.activities):
            out.add("smb")
        return out

    def _detections(self, c: Candidate) -> list[Detection]:
        seen: dict[str, Detection] = {}
        for act in c.activities:
            for det_id in act.detection_ids:
                seen[det_id] = self.detections[det_id]
        return sorted(seen.values(), key=lambda d: (d.timestamp, d.id))

    # -- candidate generation -----------------------------------------------

    def _fanout_groups(self) -> list[Candidate]:
        """Same source, same destination port, >=3 internal targets within a short window."""
        by_key: dict[tuple[str, int | None], list[Activity]] = defaultdict(list)
        for act in self.n.activities:
            if act.source_asset_id and act.destination_asset_id and self._internal(act.source_asset_id) and self._internal(act.destination_asset_id):
                by_key[(act.source_asset_id, act.dst_port)].append(act)
        groups: list[Candidate] = []
        for (src, _port), acts in by_key.items():
            acts.sort(key=lambda a: a.ts)
            i = 0
            while i < len(acts):
                window = [a for a in acts[i:] if a.ts - acts[i].ts <= FANOUT_WINDOW_SECONDS]
                targets = {a.destination_asset_id for a in window}
                failed = sum(1 for a in window if a.rejected)
                if len(targets) >= FANOUT_MIN_TARGETS and failed >= 2:
                    # Probe-only activities (no application bytes) belong to the sweep.
                    probes = [a for a in window if a.rejected or a.total_bytes == 0]
                    groups.append(
                        Candidate(
                            EventType.DISCOVERY,
                            probes,
                            src,
                            None,
                            sorted({a.destination_asset_id for a in probes if a.destination_asset_id}, key=self._name),
                        )
                    )
                    i += len(window)
                else:
                    i += 1
        return groups

    def _candidates(self) -> list[Candidate]:
        candidates: list[Candidate] = []
        fanouts = self._fanout_groups()
        in_fanout = {id(a) for g in fanouts for a in g.activities}
        candidates += fanouts

        recon_buckets: dict[tuple[str, str], list[Activity]] = defaultdict(list)
        periodic_buckets: dict[tuple[str, str, int | None], list[Activity]] = defaultdict(list)

        for act in self.n.activities:
            if id(act) in in_fanout:
                continue
            src, dst = act.source_asset_id, act.destination_asset_id
            if not src or not dst or src == dst:
                continue
            src_int, dst_int = self._internal(src), self._internal(dst)
            dst_asset = self.assets[dst]
            has_det = bool(act.detection_ids)

            if not src_int and dst_int:
                if act.rejected:
                    continue
                if has_det:
                    candidates.append(Candidate(EventType.INITIAL_ACCESS, [act], src, dst))
                elif act.http or act.app_protocols:
                    recon_buckets[(src, dst)].append(act)
                continue

            if src_int and not dst_int:
                if act.orig_bytes >= LARGE_OUTBOUND_BYTES and act.orig_bytes > 5 * max(act.resp_bytes, 1):
                    candidates.append(Candidate(EventType.EXFILTRATION, [act], src, dst))
                else:
                    periodic_buckets[(src, dst, act.dst_port)].append(act)
                continue

            if src_int and dst_int:
                if act.rejected:
                    continue
                protos = {p.lower() for p in act.app_protocols}
                admin = (act.dst_port in ADMIN_PORTS or bool(protos & ADMIN_PROTOCOLS)) and act.total_bytes > 0
                if dst_asset.crown_jewel and act.total_bytes > 0:
                    candidates.append(Candidate(EventType.CROWN_JEWEL_ACCESS, [act], src, dst))
                elif admin:
                    candidates.append(Candidate(EventType.LATERAL_MOVEMENT, [act], src, dst))
                elif has_det:
                    candidates.append(Candidate(EventType.SUSPICIOUS_CONNECTION, [act], src, dst))

        for (src, dst), acts in recon_buckets.items():
            acts.sort(key=lambda a: a.ts)
            group: list[Activity] = []
            for act in acts:
                if group and act.ts - group[-1].ts > RECON_WINDOW_SECONDS:
                    candidates.append(Candidate(EventType.EXTERNAL_RECON, group, src, dst))
                    group = []
                group.append(act)
            if group:
                candidates.append(Candidate(EventType.EXTERNAL_RECON, group, src, dst))

        for (src, dst, _port), acts in periodic_buckets.items():
            acts.sort(key=lambda a: a.ts)
            with_det = [a for a in acts if a.detection_ids]
            periodic = len(acts) >= PERIODIC_MIN and acts[-1].ts - acts[0].ts <= PERIODIC_WINDOW_SECONDS
            if with_det or periodic:
                candidates.append(Candidate(EventType.COMMAND_AND_CONTROL, acts, src, dst))

        candidates.sort(key=lambda c: (c.ts, c.event_type.value, c.source_asset_id or "", c.destination_asset_id or ""))
        return candidates

    # -- scoring ---------------------------------------------------------

    def _prior_suspicion(self, asset_id: str | None, before: float) -> tuple[float, int] | None:
        if not asset_id:
            return None
        prior = [h for h in self.suspicious_history.get(asset_id, []) if h[0] <= before]
        return prior[-1] if prior else None

    def _score(self, c: Candidate, events: list[IncidentEvent]) -> Score:
        score = Score(c.event_type)
        dets = self._detections(c)
        protos = self._protocols(c)
        src, dst = c.source_asset_id, c.destination_asset_id
        suricata = [d for d in dets if d.source.value == "suricata"]
        notices = [d for d in dets if d.source.value == "zeek"]
        if suricata:
            top = min(suricata, key=lambda d: d.severity)
            signal = {1: "detection_high", 2: "detection_medium"}.get(top.severity, "detection_low")
            score.add(signal, f"Suricata alert aligned to the activity: “{top.signature}” (severity {top.severity})")
            distinct = sorted({d.signature for d in suricata} - {top.signature})
            if distinct:
                score.add("additional_signature", f"Additional distinct signature on the same activity: “{distinct[0]}”")
        if notices:
            score.add("zeek_notice", f"Zeek notice raised: {notices[0].signature}")

        if c.event_type == EventType.DISCOVERY:
            # Zeek's sweep notice has no connection uid; align it by source and time.
            for det in self.n.detections:
                if det.source.value == "zeek" and det.source_asset_id == src and abs(det.timestamp - c.ts) <= FANOUT_WINDOW_SECONDS:
                    score.add("zeek_notice", f"Zeek notice raised: {det.signature}")
                    break
            failed = sum(1 for a in c.activities if a.rejected)
            score.add(
                "fanout",
                f"{self._name(src)} contacted {len(c.target_asset_ids)} internal hosts on TCP/{c.primary.dst_port} within "
                f"{max(1, round(c.end_ts - c.ts))} s; {failed} attempts were rejected or unanswered",
            )

        prior = self._prior_suspicion(src, c.ts)
        if prior and c.event_type not in (EventType.INITIAL_ACCESS, EventType.EXTERNAL_RECON):
            ts, idx = prior
            score.add(
                "source_previously_suspicious", f"Source {self._name(src)} was already involved in suspicious activity ({events[idx].title}, {clock(ts)})"
            )
            gap = c.ts - ts
            if 0 <= gap <= PROXIMITY_SECONDS:
                score.add("temporal_proximity", f"Occurred {gap:.0f} s after that earlier suspicious activity")

        if c.event_type == EventType.LATERAL_MOVEMENT:
            score.add(
                "admin_protocol", f"Internal-to-internal administrative protocol ({', '.join(sorted(protos & ADMIN_PROTOCOLS)) or f'TCP/{c.primary.dst_port}'})"
            )
            shares = [s for a in c.activities for s in a.smb_shares]
            admin_shares = [s for s in shares if s.upper().rstrip("\\").endswith(("ADMIN$", "C$"))]
            if admin_shares:
                score.add("admin_share", f"Administrative share accessed: {admin_shares[0]}")
            files = [f for a in c.activities for f in a.smb_files]
            if files:
                score.add("file_written", f"File created on the target over SMB: {files[0]}")
        identities = [i for a in c.activities for i in a.identities]
        if identities:
            score.add("identity_observed", f"Authenticated as {identities[0]} (NTLM, account name only)")

        dst_asset = self._asset(dst)
        if dst_asset and dst_asset.crown_jewel and c.event_type == EventType.CROWN_JEWEL_ACCESS:
            score.add("crown_jewel_target", f"Target {dst_asset.display_name} is a crown jewel ({dst_asset.crown_jewel_reason})")

        if c.event_type in (EventType.COMMAND_AND_CONTROL, EventType.EXFILTRATION) and dst in self.attacker_endpoints:
            score.add(
                "known_attacker_endpoint",
                f"Destination {self._name(dst)} is the external endpoint involved in initial access ({clock(self.attacker_endpoints[dst])})",
            )

        if c.event_type == EventType.COMMAND_AND_CONTROL and len(c.activities) >= PERIODIC_MIN:
            gaps = [b.ts - a.ts for a, b in zip(c.activities, c.activities[1:], strict=False)]
            score.add("periodic", f"{len(c.activities)} repeated outbound connections, about every {sum(gaps) / len(gaps):.0f} s")

        if c.event_type == EventType.EXFILTRATION:
            act = c.primary
            score.add("large_outbound", f"Large outbound transfer: {human_bytes(act.orig_bytes)} sent vs {human_bytes(act.resp_bytes)} received")

        if c.event_type == EventType.INITIAL_ACCESS:
            recon = [
                e
                for e in events
                if e.event_type == EventType.EXTERNAL_RECON
                and e.source_asset_id == src
                and e.destination_asset_id == dst
                and c.ts - e.end_timestamp <= PRECURSOR_WINDOW_SECONDS
            ]
            if recon:
                score.add("recon_precursor", f"Preceded by probing of {self._name(dst)} from the same external host ({clock(recon[-1].timestamp)})")
            uploads = [f for a in c.activities for f in a.files if f.get("is_orig")]
            if uploads:
                score.add(
                    "inbound_file", f"File uploaded to the server: {uploads[0].get('filename') or 'unnamed'} ({uploads[0].get('mime_type') or 'unknown type'})"
                )
        return score

    # -- state & description ---------------------------------------------

    def _escalate(self, asset_id: str | None, to: AssetState, changes: list[StateChange]) -> None:
        if not asset_id or asset_id not in self.states:
            return
        current = self.states[asset_id]
        if STATE_RANK.get(to, 0) > STATE_RANK.get(current, 0):
            changes.append(StateChange(asset_id=asset_id, from_state=current, to_state=to))
            self.states[asset_id] = to

    def _state_changes(self, c: Candidate, label: ConfidenceLabel) -> list[StateChange]:
        rank = LABEL_RANK[label]
        if rank == 0:
            return []
        changes: list[StateChange] = []
        strong = AssetState.AFFECTED if rank >= 2 else AssetState.SUSPICIOUS
        et = c.event_type
        if et == EventType.INITIAL_ACCESS or et in (EventType.LATERAL_MOVEMENT, EventType.CROWN_JEWEL_ACCESS):
            self._escalate(c.source_asset_id, AssetState.SUSPICIOUS, changes)
            self._escalate(c.destination_asset_id, strong, changes)
        elif et in (EventType.COMMAND_AND_CONTROL, EventType.EXFILTRATION):
            self._escalate(c.source_asset_id, strong, changes)
            self._escalate(c.destination_asset_id, AssetState.SUSPICIOUS, changes)
        elif et == EventType.DISCOVERY:
            self._escalate(c.source_asset_id, AssetState.SUSPICIOUS, changes)
        elif et == EventType.SUSPICIOUS_CONNECTION:
            self._escalate(c.destination_asset_id, AssetState.SUSPICIOUS, changes)
        return changes

    def _describe(self, c: Candidate) -> str:
        s, d = self._name(c.source_asset_id), self._name(c.destination_asset_id)
        act = c.primary
        port = f"TCP/{act.dst_port}" if act.proto == "tcp" else f"{act.proto.upper()}/{act.dst_port}"
        dets = self._detections(c)
        det_text = f" Suricata flagged it as “{next((x.signature for x in dets if x.source.value == 'suricata'), dets[0].signature)}”." if dets else ""
        et = c.event_type
        if et == EventType.EXTERNAL_RECON:
            paths = ", ".join(sorted({h.get("uri") or "/" for a in c.activities for h in a.http})[:5])
            return f"{s} made {len(c.activities)} web requests to {d} ({paths}). On their own these requests are ordinary; they matter because of what follows."
        if et == EventType.INITIAL_ACCESS:
            uploads = [f.get("filename") for a in c.activities for f in a.files if f.get("is_orig") and f.get("filename")]
            up = f" A file ({uploads[0]}) was uploaded in the same request." if uploads else ""
            return f"{s} sent a request to {d} over {port}.{det_text}{up}"
        if et == EventType.COMMAND_AND_CONTROL:
            return f"{s} made {len(c.activities)} outbound connections to {d} over {port}.{det_text}"
        if et == EventType.DISCOVERY:
            targets = ", ".join(self._name(t) for t in c.target_asset_ids)
            return f"{s} probed {len(c.target_asset_ids)} internal hosts on {port} ({targets}) in a few seconds.{det_text}"
        if et == EventType.LATERAL_MOVEMENT:
            share = next((sh for a in c.activities for sh in a.smb_shares), None)
            ident = next((i for a in c.activities for i in a.identities), None)
            extra = (f" It authenticated as {ident}" if ident else "") + (f" and connected to the {share} share" if share else "")
            return f"{s} opened an administrative session to {d} over {port}.{extra + '.' if extra else ''}{det_text}"
        if et == EventType.CROWN_JEWEL_ACCESS:
            return f"{s} connected to crown jewel {d} over {port} and received {human_bytes(act.resp_bytes)} of data.{det_text}"
        if et == EventType.EXFILTRATION:
            sni = next((x for a in c.activities for x in a.tls_sni), None)
            return f"{s} sent {human_bytes(act.orig_bytes)} to {d} over {port}{f' (TLS server name {sni})' if sni else ''}.{det_text}"
        return f"{s} connected to {d} over {port}.{det_text}"

    # -- main ------------------------------------------------------------

    def run(self) -> CorrelationResult:
        candidates = self._candidates()
        scored: list[IncidentEvent] = []
        for c in candidates:
            score = self._score(c, scored)
            label = score.label
            changes = self._state_changes(c, label)
            idx = len(scored)
            if LABEL_RANK[label] >= 1:
                for asset_id in (c.source_asset_id, c.destination_asset_id):
                    if asset_id:
                        self.suspicious_history[asset_id].append((c.ts, idx))
                if c.event_type in (EventType.INITIAL_ACCESS, EventType.EXTERNAL_RECON) and c.source_asset_id:
                    self.attacker_endpoints.setdefault(c.source_asset_id, c.ts)
                if c.event_type == EventType.COMMAND_AND_CONTROL and c.destination_asset_id:
                    self.c2_endpoints.add(c.destination_asset_id)
            scored.append(self._build_event(c, score, changes, idx))

        # Keep events at SUSPICIOUS or above, plus OBSERVED precursors that share
        # a source/destination pair with a later suspicious event.
        keep: list[IncidentEvent] = []
        dropped = 0
        for i, ev in enumerate(scored):
            if ev.confidence_label != ConfidenceLabel.OBSERVED:
                keep.append(ev)
                continue
            linked = any(
                later.confidence_label != ConfidenceLabel.OBSERVED
                and later.source_asset_id == ev.source_asset_id
                and later.destination_asset_id == ev.destination_asset_id
                and later.timestamp - ev.end_timestamp <= PRECURSOR_WINDOW_SECONDS
                for later in scored[i + 1 :]
            )
            if linked:
                keep.append(ev)
            else:
                dropped += 1
        renumbered = [ev.model_copy(update={"id": f"evt-{n + 1:02d}"}) for n, ev in enumerate(keep)]
        return CorrelationResult(renumbered, dict(self.states), dropped, len(candidates))

    def _build_event(self, c: Candidate, score: Score, changes: list[StateChange], idx: int) -> IncidentEvent:
        confidence, label = score.confidence, score.label
        dets = self._detections(c)
        protos = self._protocols(c)
        dst_asset = self._asset(c.destination_asset_id)
        src_asset = self._asset(c.source_asset_id)
        shares = tuple(s for a in c.activities for s in a.smb_shares)
        identity = next((i for a in c.activities for i in a.identities), None)
        mapping, not_mapped = (None, "Not mapped: confidence below SUSPICIOUS.")
        if LABEL_RANK[label] >= 1:
            mapping, not_mapped = map_technique(
                MappingContext(
                    event_type=c.event_type,
                    confidence=confidence,
                    app_protocols=frozenset(protos),
                    destination_port=c.primary.dst_port,
                    detection_categories=frozenset(d.category for d in dets),
                    admin_shares=shares,
                    destination_internal=bool(dst_asset and dst_asset.internal),
                    source_internal=bool(src_asset and src_asset.internal),
                    destination_is_known_c2=bool(c.destination_asset_id in self.c2_endpoints),
                    periodic=score.has("periodic"),
                    fanout_targets=len(c.target_asset_ids),
                    destination_is_database=bool(dst_asset and (dst_asset.asset_type == AssetType.DATABASE or c.primary.dst_port in DATABASE_PORTS)),
                )
            )
        if label == ConfidenceLabel.HIGH_CONFIDENCE or (c.event_type == EventType.CROWN_JEWEL_ACCESS and LABEL_RANK[label] >= 2):
            severity = "critical"
        else:
            severity = {3: "critical", 2: "high", 1: "medium"}.get(LABEL_RANK[label], "low")
        evidence_ids = sorted({e for a in c.activities for e in a.evidence_ids})
        service = ",".join(sorted(p for p in protos if p not in ("ntlm", "gssapi"))) or None
        title = TITLES[c.event_type]
        tags = sorted({c.event_type.value, *(f"proto:{p}" for p in protos)} | ({f"identity:{identity}"} if identity else set()))
        return IncidentEvent(
            id=f"cand-{idx:03d}",
            timestamp=c.ts,
            end_timestamp=c.end_ts,
            source_asset_id=c.source_asset_id,
            destination_asset_id=c.destination_asset_id,
            target_asset_ids=c.target_asset_ids or ([c.destination_asset_id] if c.destination_asset_id else []),
            event_type=c.event_type,
            phase=TACTICS[c.event_type],
            title=title,
            description=self._describe(c),
            severity=severity,
            confidence=confidence,
            confidence_label=label,
            reasons=score.reasons,
            technique_id=mapping.technique_id if mapping else None,
            technique_name=mapping.technique_name if mapping else None,
            technique_reason=mapping.reason if mapping else not_mapped,
            technique_confidence=mapping.confidence if mapping else None,
            technique=mapping,
            evidence_ids=evidence_ids,
            detection_ids=[d.id for d in dets],
            protocol=c.primary.proto,
            service=service,
            destination_port=c.primary.dst_port,
            identity=identity,
            state_changes=changes,
            tags=tags,
        )


def correlate(normalized: NormalizedEvidence) -> CorrelationResult:
    return CorrelationEngine(normalized).run()

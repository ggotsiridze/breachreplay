"""Incident graph construction.

Edges aggregate every observed conversation between two assets (so the
"all observed connections" view is complete), and are annotated with the
incident events that occurred on them. The primary attack path is the
earliest-arrival chain of access events from the external entry point to the
first crown jewel reached (or to the deepest asset reached when no crown
jewel was).
"""

from __future__ import annotations

import itertools
import uuid
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from app.correlation.engine import CorrelationResult
from app.correlation.scoring import LABEL_RANK
from app.models import (
    Asset,
    AssetState,
    ConfidenceLabel,
    EdgeState,
    EventType,
    Incident,
    IncidentEdge,
    IncidentEvent,
    IncidentSummary,
)
from app.normalization.normalizer import NormalizedEvidence

ACCESS_EVENTS = {EventType.INITIAL_ACCESS, EventType.LATERAL_MOVEMENT, EventType.CROWN_JEWEL_ACCESS}


def edge_id(src: str, dst: str) -> str:
    return f"edge-{src.removeprefix('asset-')}--{dst.removeprefix('asset-')}"


@dataclass
class PathResult:
    assets: list[str]
    events: list[str]
    edges: list[str]


def compute_primary_path(events: list[IncidentEvent], assets: dict[str, Asset]) -> PathResult:
    access = [e for e in events if e.event_type in ACCESS_EVENTS and LABEL_RANK[e.confidence_label] >= 1 and e.source_asset_id and e.destination_asset_id]
    if not access:
        return PathResult([], [], [])
    entry = next((e for e in access if e.event_type == EventType.INITIAL_ACCESS), access[0])
    root = entry.source_asset_id
    assert root is not None
    parent: dict[str, tuple[str, IncidentEvent]] = {}
    reached_order = [root]
    reached = {root}
    for e in sorted(access, key=lambda x: (x.timestamp, x.id)):
        src, dst = e.source_asset_id, e.destination_asset_id
        if src in reached and dst not in reached and dst is not None:
            parent[dst] = (src, e)
            reached.add(dst)
            reached_order.append(dst)
    target = next((a for a in reached_order if assets.get(a) and assets[a].crown_jewel), reached_order[-1])
    chain_assets = [target]
    chain_events: list[str] = []
    while chain_assets[-1] in parent:
        prev, ev = parent[chain_assets[-1]]
        chain_events.append(ev.id)
        chain_assets.append(prev)
    chain_assets.reverse()
    chain_events.reverse()
    if len(chain_assets) < 2:
        return PathResult([], [], [])
    edges = [edge_id(a, b) for a, b in itertools.pairwise(chain_assets)]
    return PathResult(chain_assets, chain_events, edges)


def build_edges(normalized: NormalizedEvidence, events: list[IncidentEvent], path_edges: set[str]) -> list[IncidentEdge]:
    agg: dict[tuple[str, str], dict[str, Any]] = {}
    for act in normalized.activities:
        if not act.source_asset_id or not act.destination_asset_id or act.source_asset_id == act.destination_asset_id:
            continue
        key = (act.source_asset_id, act.destination_asset_id)
        e = agg.setdefault(
            key,
            {"first": act.ts, "last": act.end_ts, "protocols": set(), "services": set(), "ports": set(), "evidence": [], "count": 0, "bytes": 0},
        )
        e["first"] = min(e["first"], act.ts)
        e["last"] = max(e["last"], act.end_ts)
        e["protocols"].add(act.proto)
        e["services"].update(p for p in act.app_protocols if p not in ("failed",))
        if act.dst_port is not None:
            e["ports"].add(act.dst_port)
        e["evidence"].append(act.evidence_ids[0])
        e["count"] += 1
        e["bytes"] += act.total_bytes

    event_map: dict[tuple[str, str], list[IncidentEvent]] = defaultdict(list)
    for ev in events:
        if not ev.source_asset_id:
            continue
        targets = ev.target_asset_ids or ([ev.destination_asset_id] if ev.destination_asset_id else [])
        for t in targets:
            event_map[(ev.source_asset_id, t)].append(ev)

    edges: list[IncidentEdge] = []
    for (src, dst), e in sorted(agg.items(), key=lambda kv: (kv[1]["first"], kv[0])):
        evs = event_map.get((src, dst), [])
        confidence = max((x.confidence for x in evs), default=0)
        top = max((LABEL_RANK[x.confidence_label] for x in evs), default=-1)
        if evs and all(x.event_type == EventType.DISCOVERY for x in evs):
            top = min(top, 1)  # probing a host is not traversing to it
        state = EdgeState.ATTACK if top >= 2 else EdgeState.SUSPICIOUS if top == 1 else EdgeState.OBSERVED
        eid = edge_id(src, dst)
        edges.append(
            IncidentEdge(
                id=eid,
                source_asset_id=src,
                destination_asset_id=dst,
                first_seen=e["first"],
                last_seen=e["last"],
                protocols=sorted(e["protocols"]),
                services=sorted(e["services"]),
                ports=sorted(e["ports"]),
                event_ids=[x.id for x in evs],
                evidence_ids=e["evidence"][:200],
                connection_count=e["count"],
                bytes_total=e["bytes"],
                confidence=confidence,
                state=state,
                on_primary_path=eid in path_edges,
            )
        )
    return edges


def build_incident(
    normalized: NormalizedEvidence,
    correlation: CorrelationResult,
    *,
    incident_id: str | None = None,
    name: str,
    source_type: str,
    demo: bool,
    metadata: dict[str, Any] | None = None,
) -> Incident:
    assets_by_id = {a.id: a for a in normalized.assets}
    path = compute_primary_path(correlation.events, assets_by_id)
    path_events = set(path.events)
    path_edges = set(path.edges)

    events: list[IncidentEvent] = []
    for ev in correlation.events:
        eid = edge_id(ev.source_asset_id, ev.destination_asset_id) if ev.source_asset_id and ev.destination_asset_id else None
        events.append(ev.model_copy(update={"edge_id": eid, "on_primary_path": ev.id in path_events}))

    edges = build_edges(normalized, events, path_edges)
    final_states = correlation.final_states
    assets = [a.model_copy(update={"state": final_states.get(a.id, AssetState.NORMAL)}) for a in normalized.assets]
    crown_jewels = [a.id for a in assets if a.crown_jewel]

    suspicious_plus = [e for e in events if LABEL_RANK[e.confidence_label] >= 1]
    crown_events = [e for e in suspicious_plus if e.event_type == EventType.CROWN_JEWEL_ACCESS and e.destination_asset_id in crown_jewels]
    in_incident = {a for e in events for a in (e.source_asset_id, *(e.target_asset_ids or [])) if a}
    capture_times = [x.timestamp for x in normalized.evidence]
    started = min((e.timestamp for e in events), default=None)
    ended = max((e.end_timestamp for e in events), default=None)
    path_ts = [e.timestamp for e in events if e.id in path_events]
    phases: list[str] = []
    for e in events:
        if e.phase not in phases and LABEL_RANK[e.confidence_label] >= 1:
            phases.append(e.phase)
    affected = [a for a in assets if a.state == AssetState.AFFECTED and a.internal]
    critical = [d for d in normalized.detections if d.severity == 1]
    crown_reached = bool(crown_events)
    if not suspicious_plus:
        headline = "No incident path found: activity was analyzed, but evidence was insufficient to reconstruct an attack path."
    elif crown_reached:
        jewel = assets_by_id[crown_events[0].destination_asset_id or ""].display_name
        headline = f"Observed attack path reached crown jewel {jewel} in {round(crown_events[0].timestamp - (started or 0))} s."
    else:
        headline = f"Suspicious activity reconstructed across {len(in_incident)} assets; no crown jewel access observed."

    summary = IncidentSummary(
        assets_observed=len(assets),
        assets_in_incident=len(in_incident),
        affected_assets=len(affected),
        suspicious_assets=len([a for a in assets if a.state == AssetState.SUSPICIOUS]),
        high_confidence_events=len([e for e in events if e.confidence_label == ConfidenceLabel.HIGH_CONFIDENCE]),
        incident_events=len(events),
        critical_detections=len(critical),
        detections=len(normalized.detections),
        evidence_records=len(normalized.evidence),
        crown_jewel_reached=crown_reached,
        crown_jewel_reached_at=crown_events[0].timestamp if crown_events else None,
        phases=phases,
        techniques=sorted({e.technique_id for e in events if e.technique_id}),
        identities=sorted({e.identity for e in events if e.identity}),
        path_duration_seconds=round(max(path_ts) - min(path_ts), 3) if len(path_ts) >= 2 else None,
        headline=headline,
    )
    return Incident(
        id=incident_id or uuid.uuid4().hex,
        name=name,
        source_type=source_type,
        demo=demo,
        started_at=started,
        ended_at=ended,
        duration_seconds=round((ended - started), 3) if started is not None and ended is not None else 0.0,
        capture_started_at=min(capture_times) if capture_times else None,
        capture_ended_at=max(capture_times) if capture_times else None,
        assets=assets,
        events=events,
        edges=edges,
        detections=normalized.detections,
        crown_jewels=crown_jewels,
        summary=summary,
        primary_attack_path=path.assets,
        primary_attack_edges=path.edges,
        incident_found=bool(suspicious_plus),
        metadata={
            **(metadata or {}),
            "correlation": {
                "candidates_considered": correlation.candidates_considered,
                "observed_context_events_dropped": correlation.context_events_dropped,
            },
            "normalization": normalized.stats,
        },
    )

"""Containment simulation over the reconstructed incident graph.

The simulation replays the OBSERVED incident events in order and asks, for
each one: was its source reachable in the simulated scenario, and would a
selected control (active at that moment) have blocked it? It never modifies
the incident or its evidence; it produces a separate SimulationResult.

This models the observed path only. It does not predict what a real attacker
would have done differently once blocked.
"""

from __future__ import annotations

import math
import uuid
from datetime import UTC, datetime

from app.correlation.scoring import LABEL_RANK
from app.models import (
    AssetState,
    ContainmentControl,
    ControlActivation,
    ControlType,
    EventOutcome,
    EventType,
    Incident,
    IncidentEvent,
    SimulatedEvent,
    SimulationMetrics,
    SimulationResult,
    StateChange,
)

ACCESS_EVENTS = {EventType.INITIAL_ACCESS, EventType.LATERAL_MOVEMENT, EventType.CROWN_JEWEL_ACCESS}
RANK = {AssetState.NORMAL: 0, AssetState.SUSPICIOUS: 1, AssetState.AFFECTED: 2}
PROTOCOL_ALIASES = {"tls": "ssl", "https": "ssl", "smb2": "smb", "cifs": "smb"}

DISCLAIMER = (
    "SIMULATED CONTAINMENT models the observed incident graph only. It shows where the observed attack path "
    "would have been interrupted under the selected hypothetical controls; it does not predict other actions a "
    "real attacker could have taken."
)


class SimulationError(ValueError):
    pass


def _clock(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%H:%M:%S")


class Simulator:
    def __init__(self, incident: Incident) -> None:
        self.incident = incident
        self.assets = {a.id: a for a in incident.assets}
        self.edges = {e.id: e for e in incident.edges}

    # -- validation & labels -------------------------------------------------

    def _name(self, asset_id: str | None) -> str:
        a = self.assets.get(asset_id or "")
        return a.display_name if a else "?"

    def label(self, c: ContainmentControl) -> str:
        t = c.control_type
        if t == ControlType.ISOLATE_ASSET:
            return f"Isolate {self._name(c.asset_id)}"
        if t == ControlType.BLOCK_EDGE:
            e = self.edges[c.edge_id or ""]
            return f"Block {self._name(e.source_asset_id)} → {self._name(e.destination_asset_id)}"
        if t == ControlType.BLOCK_PORT:
            return f"Block TCP/UDP {c.port}"
        if t == ControlType.BLOCK_PROTOCOL:
            return f"Block protocol {str(c.protocol).upper()}"
        if t == ControlType.SEGMENT_ASSETS:
            return f"Segment {', '.join(self._name(a) for a in c.segment_asset_ids)}"
        return f"Disable account {c.identity}"

    def validate(self, controls: list[ContainmentControl]) -> list[ContainmentControl]:
        identities = {e.identity for e in self.incident.events if e.identity}
        out: list[ContainmentControl] = []
        for i, c in enumerate(controls, start=1):
            t = c.control_type
            if t == ControlType.ISOLATE_ASSET and c.asset_id not in self.assets:
                raise SimulationError(f"Unknown asset for isolation: {c.asset_id!r}")
            if t == ControlType.ISOLATE_ASSET and not self.assets[c.asset_id or ""].internal:
                raise SimulationError("Only internal assets can be isolated; block the edge or port instead.")
            if t == ControlType.BLOCK_EDGE and c.edge_id not in self.edges:
                raise SimulationError(f"Unknown edge: {c.edge_id!r}")
            if t == ControlType.BLOCK_PORT and c.port is None:
                raise SimulationError("A port is required for a port block.")
            if t == ControlType.BLOCK_PROTOCOL and not (c.protocol and c.protocol.strip()):
                raise SimulationError("A protocol is required for a protocol block.")
            if t == ControlType.SEGMENT_ASSETS and (not c.segment_asset_ids or any(a not in self.assets for a in c.segment_asset_ids)):
                raise SimulationError("Segmentation needs one or more known assets.")
            if t == ControlType.DISABLE_IDENTITY:
                if not identities:
                    raise SimulationError("This incident contains no identity evidence, so no account can be disabled.")
                if c.identity not in identities:
                    raise SimulationError(f"Identity {c.identity!r} was not observed in this incident.")
            if c.activation == "custom" and c.activation_timestamp is None:
                raise SimulationError("A custom activation needs an activation_timestamp.")
            out.append(c.model_copy(update={"id": c.id or f"ctl-{i}"}))
        return out

    # -- matching ------------------------------------------------------------

    def _protocols(self, ev: IncidentEvent) -> set[str]:
        protos = {p for p in (ev.service or "").split(",") if p}
        if ev.protocol:
            protos.add(ev.protocol)
        return {PROTOCOL_ALIASES.get(p.lower(), p.lower()) for p in protos}

    def _endpoints(self, ev: IncidentEvent) -> set[str]:
        return {a for a in (ev.source_asset_id, ev.destination_asset_id) if a}

    def matches(self, c: ContainmentControl, ev: IncidentEvent) -> bool:
        t = c.control_type
        if t == ControlType.ISOLATE_ASSET:
            if ev.event_type == EventType.DISCOVERY:
                return ev.source_asset_id == c.asset_id
            return c.asset_id in self._endpoints(ev)
        if t == ControlType.BLOCK_EDGE:
            edge = self.edges[c.edge_id or ""]
            return ev.source_asset_id == edge.source_asset_id and edge.destination_asset_id in (ev.target_asset_ids or [ev.destination_asset_id])
        if t == ControlType.BLOCK_PORT:
            return ev.destination_port == c.port
        if t == ControlType.BLOCK_PROTOCOL:
            want = PROTOCOL_ALIASES.get(str(c.protocol).lower(), str(c.protocol).lower())
            return want in self._protocols(ev)
        if t == ControlType.SEGMENT_ASSETS:
            seg = set(c.segment_asset_ids)
            if not ev.source_asset_id or not ev.destination_asset_id:
                return False
            return (ev.source_asset_id in seg) != (ev.destination_asset_id in seg)
        return bool(ev.identity and ev.identity == c.identity)

    def activation_time(self, c: ContainmentControl) -> float:
        if c.activation == "preventive":
            return -math.inf
        if c.activation == "custom":
            return float(c.activation_timestamp or 0)
        start = self.incident.started_at or 0.0
        dets = [d for d in self.incident.detections if d.timestamp >= start - 1]
        t = c.control_type
        if t == ControlType.ISOLATE_ASSET:
            hits = [d.timestamp for d in dets if c.asset_id in (d.source_asset_id, d.destination_asset_id)]
        elif t == ControlType.BLOCK_EDGE:
            e = self.edges[c.edge_id or ""]
            hits = [d.timestamp for d in dets if d.source_asset_id == e.source_asset_id and d.destination_asset_id == e.destination_asset_id]
        elif t == ControlType.BLOCK_PORT:
            hits = [d.timestamp for d in dets if d.destination_port == c.port]
        elif t == ControlType.SEGMENT_ASSETS:
            seg = set(c.segment_asset_ids)
            hits = [d.timestamp for d in dets if (d.source_asset_id in seg) != (d.destination_asset_id in seg)]
        else:
            hits = [e.timestamp for e in self.incident.events if self.matches(c, e) and LABEL_RANK[e.confidence_label] >= 1]
        return min(hits) if hits else start

    # -- run -----------------------------------------------------------------

    def run(self, controls: list[ContainmentControl]) -> SimulationResult:
        controls = self.validate(controls)
        inc = self.incident
        start = inc.started_at or 0.0
        activation = {c.id: self.activation_time(c) for c in controls}
        labels = {c.id: self.label(c) for c in controls}
        events = sorted(inc.events, key=lambda e: (e.timestamp, e.id))

        reached: set[str] = {
            e.source_asset_id
            for e in events
            if e.source_asset_id and not self.assets[e.source_asset_id].internal and e.event_type in (EventType.INITIAL_ACCESS, EventType.EXTERNAL_RECON)
        }
        if not reached:
            reached = {e.source_asset_id for e in events[:1] if e.source_asset_id}
        observed_reached = set(reached)
        for e in events:
            if e.event_type in ACCESS_EVENTS and LABEL_RANK[e.confidence_label] >= 1 and e.destination_asset_id:
                observed_reached.add(e.destination_asset_id)

        sim_states: dict[str, AssetState] = {a.id: AssetState.NORMAL for a in inc.assets}
        contained: list[str] = []
        activations: list[ControlActivation] = []
        for c in controls:
            ts = activation[c.id]
            iso = [c.asset_id] if c.control_type == ControlType.ISOLATE_ASSET and c.asset_id else []
            activations.append(ControlActivation(control_id=c.id or "", timestamp=max(ts, start), label=labels[c.id], contained_asset_ids=iso))
            contained += iso

        pending_activation = sorted(activations, key=lambda a: a.timestamp)
        outcomes: list[SimulatedEvent] = []
        for ev in events:
            # Apply isolations that took effect before this event.
            while pending_activation and pending_activation[0].timestamp <= ev.timestamp:
                act = pending_activation.pop(0)
                for aid in act.contained_asset_ids:
                    sim_states[aid] = AssetState.CONTAINED
            src = ev.source_asset_id
            if src not in reached:
                outcomes.append(
                    SimulatedEvent(
                        event_id=ev.id,
                        outcome=EventOutcome.NOT_REACHED,
                        reason=f"{self._name(src)} was never reached in the simulated scenario, so this observed step could not follow.",
                    )
                )
                continue
            blocker = next((c for c in controls if activation[c.id] <= ev.timestamp and self.matches(c, ev)), None)
            if blocker is not None:
                when = "before the incident" if activation[blocker.id] == -math.inf else f"from {_clock(activation[blocker.id])}"
                target = self._name(ev.destination_asset_id) if ev.destination_asset_id else ", ".join(self._name(t) for t in ev.target_asset_ids)
                outcomes.append(
                    SimulatedEvent(
                        event_id=ev.id,
                        outcome=EventOutcome.INTERRUPTED,
                        blocked_by=blocker.id,
                        reason=(
                            f"Under the simulated control “{labels[blocker.id]}” (active {when}), the observed "
                            f"{ev.title.lower()} {self._name(src)} → {target} would have been blocked."
                        ),
                    )
                )
                continue
            changes: list[StateChange] = []
            for ch in ev.state_changes:
                cur = sim_states.get(ch.asset_id, AssetState.NORMAL)
                if cur in (AssetState.CONTAINED, AssetState.PROTECTED):
                    continue
                if RANK.get(ch.to_state, 0) > RANK.get(cur, 0):
                    changes.append(StateChange(asset_id=ch.asset_id, from_state=cur, to_state=ch.to_state))
                    sim_states[ch.asset_id] = ch.to_state
            if ev.event_type in ACCESS_EVENTS and ev.destination_asset_id and LABEL_RANK[ev.confidence_label] >= 1:
                reached.add(ev.destination_asset_id)
            outcomes.append(
                SimulatedEvent(event_id=ev.id, outcome=EventOutcome.OCCURRED, reason="Not affected by the selected controls.", state_changes=changes)
            )
        for act in pending_activation:
            for aid in act.contained_asset_ids:
                sim_states[aid] = AssetState.CONTAINED

        by_id = {o.event_id: o for o in outcomes}
        path_events = [e for e in events if e.on_primary_path]
        interrupted = [o for o in outcomes if o.outcome == EventOutcome.INTERRUPTED]
        on_path = [o for o in interrupted if any(o.event_id == e.id for e in path_events)]
        first = on_path[0] if on_path else (interrupted[0] if interrupted else None)
        first_event = next((e for e in events if first and e.id == first.event_id), None)

        protected = sorted(a for a in observed_reached - reached if self.assets[a].internal and a not in contained)
        for aid in protected:
            sim_states[aid] = AssetState.PROTECTED

        def metrics(sim: bool) -> SimulationMetrics:
            occurred: list[IncidentEvent] = []
            for e in path_events:
                if sim and by_id[e.id].outcome != EventOutcome.OCCURRED:
                    break
                occurred.append(e)
            reach = reached if sim else observed_reached
            internal_reach = {a for a in reach if self.assets[a].internal}
            states = sim_states if sim else {a.id: a.state for a in inc.assets}
            affected = [a for a, s in states.items() if s == AssetState.AFFECTED and self.assets[a].internal]
            jewel = any(self.assets[a].crown_jewel for a in reach)
            end_ts = occurred[-1].timestamp if occurred else None
            if sim and first_event is not None and on_path:
                end_ts = first_event.timestamp
            duration = round(end_ts - path_events[0].timestamp, 3) if path_events and end_ts is not None else None
            return SimulationMetrics(
                assets_reached=len(internal_reach),
                affected_assets=len(affected),
                crown_jewel_reached=jewel,
                path_complete=len(occurred) == len(path_events) and bool(path_events),
                path_length=len(occurred),
                path_duration_seconds=duration,
            )

        observed, simulated = metrics(False), metrics(True)
        explanation = self._explain(first_event, on_path != [], observed, simulated, outcomes, events, protected)
        return SimulationResult(
            id=uuid.uuid4().hex[:12],
            incident_id=inc.id,
            controls=controls,
            interrupted_event_id=first_event.id if first_event else None,
            interrupted_edge_id=first_event.edge_id if first_event else None,
            interrupted_at=first_event.timestamp if first_event else None,
            reachable_before=sorted(a for a in observed_reached if self.assets[a].internal),
            reachable_after=sorted(a for a in reached if self.assets[a].internal),
            crown_jewel_before=observed.crown_jewel_reached,
            crown_jewel_after=simulated.crown_jewel_reached,
            observed_path_length=observed.path_length,
            simulated_path_length=simulated.path_length,
            observed_assets_reached=observed.assets_reached,
            simulated_assets_reached=simulated.assets_reached,
            observed=observed,
            simulated=simulated,
            event_outcomes=outcomes,
            activations=activations,
            final_states=sim_states,
            protected_assets=protected,
            contained_assets=contained,
            explanation=explanation,
            disclaimer=DISCLAIMER,
        )

    def _explain(
        self,
        first: IncidentEvent | None,
        on_path: bool,
        observed: SimulationMetrics,
        simulated: SimulationMetrics,
        outcomes: list[SimulatedEvent],
        events: list[IncidentEvent],
        protected: list[str],
    ) -> str:
        if first is None:
            return (
                "The selected simulated controls would not have interrupted any observed incident step: none of the "
                "modeled connections match them at the time they occurred."
            )
        target = self._name(first.destination_asset_id) if first.destination_asset_id else "its targets"
        parts = [
            f"The observed attack path would have been interrupted at {self._name(first.source_asset_id)} → {target} "
            f"({first.title.lower()}, {_clock(first.timestamp)}) under the selected simulated control."
            if on_path
            else f"The selected control interrupts {first.title.lower()} at {_clock(first.timestamp)}, but not the primary attack path."
        ]
        if observed.crown_jewel_reached and not simulated.crown_jewel_reached:
            jewels = ", ".join(self._name(a) for a in self.incident.crown_jewels)
            parts.append(f"In the modeled path, crown jewel {jewels} is no longer reached.")
        elif simulated.crown_jewel_reached:
            parts.append("The crown jewel is still reached in the modeled path.")
        if protected:
            parts.append(f"Assets kept out of reach: {', '.join(self._name(a) for a in protected)}.")
        still = [
            e
            for e in events
            if any(o.event_id == e.id and o.outcome == EventOutcome.OCCURRED for o in outcomes)
            and LABEL_RANK[e.confidence_label] >= 1
            and e.timestamp > first.timestamp
        ]
        if still:
            parts.append("Still observed after the control: " + "; ".join(f"{e.title.lower()} ({self._name(e.source_asset_id)})" for e in still[:3]) + ".")
        return " ".join(parts)


def simulate(incident: Incident, controls: list[ContainmentControl]) -> SimulationResult:
    return Simulator(incident).run(controls)

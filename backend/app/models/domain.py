"""Core BreachReplay domain models.

Evidence (what the analyzers recorded) is kept separate from incident events
(what the correlation engine concluded) and from simulation results (what a
hypothetical control would have changed). Models are frozen where mutation
would blur that boundary.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True)


# --- Enumerations ----------------------------------------------------------


class AssetType(StrEnum):
    INTERNET = "INTERNET"
    SERVER = "SERVER"
    WORKSTATION = "WORKSTATION"
    DATABASE = "DATABASE"
    IDENTITY = "IDENTITY"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    UNKNOWN = "UNKNOWN"


class AssetState(StrEnum):
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    AFFECTED = "AFFECTED"
    CONTAINED = "CONTAINED"
    # Simulation only: an asset the observed path reached that the simulated
    # control kept out of reach.
    PROTECTED = "PROTECTED"


class EvidenceSource(StrEnum):
    ZEEK = "zeek"
    SURICATA = "suricata"


class ConfidenceLabel(StrEnum):
    OBSERVED = "OBSERVED"
    SUSPICIOUS = "SUSPICIOUS"
    LIKELY = "LIKELY"
    HIGH_CONFIDENCE = "HIGH CONFIDENCE"


class EventType(StrEnum):
    EXTERNAL_RECON = "external_recon"
    INITIAL_ACCESS = "initial_access"
    COMMAND_AND_CONTROL = "command_and_control"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    CROWN_JEWEL_ACCESS = "crown_jewel_access"
    EXFILTRATION = "exfiltration"
    SUSPICIOUS_CONNECTION = "suspicious_connection"


class EdgeState(StrEnum):
    OBSERVED = "OBSERVED"
    SUSPICIOUS = "SUSPICIOUS"
    ATTACK = "ATTACK"


class AnalysisState(StrEnum):
    UPLOADING = "UPLOADING"
    VALIDATING = "VALIDATING"
    RUNNING_ZEEK = "RUNNING_ZEEK"
    RUNNING_SURICATA = "RUNNING_SURICATA"
    NORMALIZING = "NORMALIZING"
    CORRELATING = "CORRELATING"
    BUILDING_GRAPH = "BUILDING_GRAPH"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


class ControlType(StrEnum):
    ISOLATE_ASSET = "isolate_asset"
    BLOCK_EDGE = "block_edge"
    BLOCK_PORT = "block_port"
    BLOCK_PROTOCOL = "block_protocol"
    SEGMENT_ASSETS = "segment_assets"
    DISABLE_IDENTITY = "disable_identity"


class EventOutcome(StrEnum):
    OCCURRED = "OCCURRED"
    INTERRUPTED = "INTERRUPTED"
    NOT_REACHED = "NOT_REACHED"


# --- Evidence --------------------------------------------------------------


class Asset(BaseModel):
    id: str
    ip: str
    hostname: str | None = None
    display_name: str
    role: str
    asset_type: AssetType
    labels: list[str] = Field(default_factory=list)
    importance: int = Field(ge=0, le=100, default=10)
    internal: bool = True
    crown_jewel: bool = False
    crown_jewel_reason: str | None = None
    first_seen: float
    last_seen: float
    state: AssetState = AssetState.NORMAL
    services: list[str] = Field(default_factory=list)


class NetworkEvidence(Frozen):
    id: str
    timestamp: float
    source: EvidenceSource
    log_type: str
    source_record_id: str | None = None
    source_asset_id: str | None = None
    destination_asset_id: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    service: str | None = None
    event_type: str
    summary: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class Detection(Frozen):
    id: str
    timestamp: float
    source: EvidenceSource
    signature: str
    signature_id: str
    category: str
    severity: int = Field(description="1 = highest (Suricata convention)")
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    source_asset_id: str | None = None
    destination_asset_id: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)


# --- Incident ----------------------------------------------------------------


class ScoreReason(Frozen):
    signal: str
    points: int
    text: str


class TechniqueMapping(Frozen):
    technique_id: str
    technique_name: str
    tactic: str
    reason: str
    confidence: int = Field(ge=0, le=100)
    url: str


class StateChange(Frozen):
    asset_id: str
    from_state: AssetState
    to_state: AssetState


class IncidentEvent(Frozen):
    id: str
    timestamp: float
    end_timestamp: float
    source_asset_id: str | None
    destination_asset_id: str | None
    target_asset_ids: list[str] = Field(default_factory=list)
    event_type: EventType
    phase: str
    title: str
    description: str
    severity: str
    confidence: int = Field(ge=0, le=100)
    confidence_label: ConfidenceLabel
    reasons: list[ScoreReason]
    technique_id: str | None = None
    technique_name: str | None = None
    technique_reason: str | None = None
    technique_confidence: int | None = None
    technique: TechniqueMapping | None = None
    evidence_ids: list[str]
    detection_ids: list[str] = Field(default_factory=list)
    protocol: str | None = None
    service: str | None = None
    destination_port: int | None = None
    identity: str | None = None
    edge_id: str | None = None
    on_primary_path: bool = False
    state_changes: list[StateChange] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class IncidentEdge(Frozen):
    id: str
    source_asset_id: str
    destination_asset_id: str
    first_seen: float
    last_seen: float
    protocols: list[str]
    services: list[str]
    ports: list[int]
    event_ids: list[str]
    evidence_ids: list[str]
    connection_count: int
    bytes_total: int
    confidence: int
    state: EdgeState
    on_primary_path: bool = False


class IncidentSummary(Frozen):
    assets_observed: int
    assets_in_incident: int
    affected_assets: int
    suspicious_assets: int
    high_confidence_events: int
    incident_events: int
    critical_detections: int
    detections: int
    evidence_records: int
    crown_jewel_reached: bool
    crown_jewel_reached_at: float | None
    phases: list[str]
    techniques: list[str]
    identities: list[str]
    path_duration_seconds: float | None
    headline: str


class Incident(BaseModel):
    id: str
    name: str
    source_type: str
    demo: bool
    showcase: bool = False
    started_at: float | None
    ended_at: float | None
    duration_seconds: float
    capture_started_at: float | None = None
    capture_ended_at: float | None = None
    assets: list[Asset]
    events: list[IncidentEvent]
    edges: list[IncidentEdge]
    detections: list[Detection]
    crown_jewels: list[str]
    summary: IncidentSummary
    primary_attack_path: list[str]
    primary_attack_edges: list[str]
    incident_found: bool
    metadata: dict[str, Any] = Field(default_factory=dict)


# --- Simulation --------------------------------------------------------------


class ContainmentControl(BaseModel):
    id: str | None = None
    control_type: ControlType
    asset_id: str | None = None
    edge_id: str | None = None
    protocol: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    identity: str | None = None
    segment_asset_ids: list[str] = Field(default_factory=list)
    activation: str = Field(default="preventive", pattern="^(preventive|first_detection|custom)$")
    activation_timestamp: float | None = None


class SimulationRequest(BaseModel):
    controls: list[ContainmentControl] = Field(min_length=1, max_length=8)


class SimulatedEvent(Frozen):
    event_id: str
    outcome: EventOutcome
    blocked_by: str | None = None
    reason: str
    state_changes: list[StateChange] = Field(default_factory=list)


class ControlActivation(Frozen):
    control_id: str
    timestamp: float
    label: str
    contained_asset_ids: list[str] = Field(default_factory=list)


class SimulationMetrics(Frozen):
    assets_reached: int
    affected_assets: int
    crown_jewel_reached: bool
    path_complete: bool
    path_length: int
    path_duration_seconds: float | None


class SimulationResult(Frozen):
    id: str
    incident_id: str
    controls: list[ContainmentControl]
    interrupted_event_id: str | None
    interrupted_edge_id: str | None
    interrupted_at: float | None
    reachable_before: list[str]
    reachable_after: list[str]
    crown_jewel_before: bool
    crown_jewel_after: bool
    observed_path_length: int
    simulated_path_length: int
    observed_assets_reached: int
    simulated_assets_reached: int
    observed: SimulationMetrics
    simulated: SimulationMetrics
    event_outcomes: list[SimulatedEvent]
    activations: list[ControlActivation]
    final_states: dict[str, AssetState]
    protected_assets: list[str]
    contained_assets: list[str]
    explanation: str
    disclaimer: str


# --- Analysis job ------------------------------------------------------------


class AnalysisStep(Frozen):
    state: AnalysisState
    label: str
    status: str  # pending | running | done | failed | skipped
    detail: str | None = None
    started_at: float | None = None
    finished_at: float | None = None


class AnalysisStatus(BaseModel):
    incident_id: str
    state: AnalysisState
    steps: list[AnalysisStep]
    demo: bool
    showcase: bool = False
    filename: str | None = None
    error_code: str | None = None
    error_title: str | None = None
    error_message: str | None = None
    error_detail: str | None = None
    created_at: float
    updated_at: float
    stats: dict[str, Any] = Field(default_factory=dict)

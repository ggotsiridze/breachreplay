"""Transparent confidence scoring.

Each correlation signal carries an evidence weight ``w`` in (0, 1). Signals are
combined as independent pieces of evidence:

    confidence = 1 - Π (1 - wᵢ)

so every additional signal raises confidence with diminishing returns and no
combination reaches 100%. An event that has *no corroborating signal* (no
detection, no notice, no previously-suspicious source, no known attacker
endpoint, no behavioural pattern) is capped at the OBSERVED band: a single
plain connection never becomes "suspicious" on its own.

Labels:
    0-39   OBSERVED
    40-64  SUSPICIOUS
    65-84  LIKELY
    85-99  HIGH CONFIDENCE
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.models import ConfidenceLabel, EventType, ScoreReason

BASE_WEIGHTS: dict[EventType, float] = {
    EventType.EXTERNAL_RECON: 0.15,
    EventType.INITIAL_ACCESS: 0.25,
    EventType.COMMAND_AND_CONTROL: 0.20,
    EventType.DISCOVERY: 0.25,
    EventType.LATERAL_MOVEMENT: 0.20,
    EventType.CROWN_JEWEL_ACCESS: 0.15,
    EventType.EXFILTRATION: 0.25,
    EventType.SUSPICIOUS_CONNECTION: 0.10,
}

SIGNAL_WEIGHTS: dict[str, float] = {
    "detection_high": 0.45,  # Suricata severity 1 aligned to the activity
    "detection_medium": 0.30,  # severity 2
    "detection_low": 0.20,  # severity 3+
    "additional_signature": 0.10,  # a second, distinct signature on the same activity
    "zeek_notice": 0.20,
    "source_previously_suspicious": 0.25,
    "temporal_proximity": 0.10,  # within 120 s of the source's previous suspicious activity
    "admin_protocol": 0.10,
    "admin_share": 0.15,
    "file_written": 0.05,
    "identity_observed": 0.05,
    "crown_jewel_target": 0.10,
    "known_attacker_endpoint": 0.25,
    "large_outbound": 0.20,
    "periodic": 0.15,
    "fanout": 0.25,
    "recon_precursor": 0.15,
    "inbound_file": 0.05,
}

# Signals that independently corroborate suspicion.
CORROBORATING = {
    "detection_high",
    "detection_medium",
    "detection_low",
    "zeek_notice",
    "source_previously_suspicious",
    "known_attacker_endpoint",
    "fanout",
    "periodic",
}

OBSERVED_CAP = 39
MAX_CONFIDENCE = 99


def label_for(confidence: int) -> ConfidenceLabel:
    if confidence >= 85:
        return ConfidenceLabel.HIGH_CONFIDENCE
    if confidence >= 65:
        return ConfidenceLabel.LIKELY
    if confidence >= 40:
        return ConfidenceLabel.SUSPICIOUS
    return ConfidenceLabel.OBSERVED


LABEL_RANK = {
    ConfidenceLabel.OBSERVED: 0,
    ConfidenceLabel.SUSPICIOUS: 1,
    ConfidenceLabel.LIKELY: 2,
    ConfidenceLabel.HIGH_CONFIDENCE: 3,
}


@dataclass
class Score:
    event_type: EventType
    reasons: list[ScoreReason] = field(default_factory=list)
    _signals: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        base = BASE_WEIGHTS[self.event_type]
        self.reasons.append(ScoreReason(signal="base", points=round(base * 100), text=f"Activity pattern: {self.event_type.value.replace('_', ' ')}"))

    def add(self, signal: str, text: str) -> None:
        if signal in self._signals:
            return
        self._signals.add(signal)
        self.reasons.append(ScoreReason(signal=signal, points=round(SIGNAL_WEIGHTS[signal] * 100), text=text))

    def has(self, signal: str) -> bool:
        return signal in self._signals

    @property
    def corroborated(self) -> bool:
        return bool(self._signals & CORROBORATING)

    @property
    def confidence(self) -> int:
        remaining = 1.0 - BASE_WEIGHTS[self.event_type]
        for signal in self._signals:
            remaining *= 1.0 - SIGNAL_WEIGHTS[signal]
        value = round((1.0 - remaining) * 100)
        if not self.corroborated:
            value = min(value, OBSERVED_CAP)
        return max(0, min(MAX_CONFIDENCE, value))

    @property
    def label(self) -> ConfidenceLabel:
        return label_for(self.confidence)

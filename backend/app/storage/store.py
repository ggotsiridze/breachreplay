"""Bounded in-memory incident store.

Incidents are kept in memory (LRU, ``MAX_INCIDENTS``). Nothing derived from an
uploaded capture is written to disk beyond the per-job analysis workspace,
which is deleted when analysis finishes.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass, field

from app.models import AnalysisStatus, Incident, NetworkEvidence, SimulationResult

MAX_SIMULATIONS_PER_INCIDENT = 50


@dataclass
class IncidentRecord:
    status: AnalysisStatus
    incident: Incident | None = None
    evidence: dict[str, NetworkEvidence] = field(default_factory=dict)
    simulations: OrderedDict[str, SimulationResult] = field(default_factory=OrderedDict)
    touched: float = field(default_factory=time.time)

    def add_simulation(self, result: SimulationResult) -> None:
        self.simulations[result.id] = result
        while len(self.simulations) > MAX_SIMULATIONS_PER_INCIDENT:
            self.simulations.popitem(last=False)


class IncidentStore:
    def __init__(self, max_incidents: int) -> None:
        self.max_incidents = max_incidents
        self._records: OrderedDict[str, IncidentRecord] = OrderedDict()

    def create(self, status: AnalysisStatus) -> IncidentRecord:
        record = IncidentRecord(status=status)
        self._records[status.incident_id] = record
        self._records.move_to_end(status.incident_id)
        while len(self._records) > self.max_incidents:
            self._records.popitem(last=False)
        return record

    def get(self, incident_id: str) -> IncidentRecord | None:
        record = self._records.get(incident_id)
        if record is not None:
            record.touched = time.time()
        return record

    def __len__(self) -> int:
        return len(self._records)

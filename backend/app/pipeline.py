"""Analysis orchestration: capture -> Zeek + Suricata -> normalize -> correlate -> graph."""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from fastapi import UploadFile

from app.analyzers.client import Analyzers
from app.analyzers.process import AnalyzerError
from app.config import REPO_ROOT, Settings
from app.correlation.engine import correlate
from app.graph.builder import build_incident
from app.models import AnalysisState, AnalysisStatus, AnalysisStep, Incident, NetworkEvidence
from app.normalization.normalizer import normalize
from app.parsers.suricata_eve import parse_eve_file
from app.parsers.zeek_logs import parse_zeek_directory
from app.security.capture_validation import CaptureValidationError, inspect_capture_header, validate_filename, validate_size
from app.storage.store import IncidentRecord, IncidentStore
from app.storage.workspace import Workspace, new_job_id
from app.websocket.hub import ProgressHub

log = logging.getLogger("breachreplay.pipeline")

STEPS: list[tuple[AnalysisState, str]] = [
    (AnalysisState.UPLOADING, "Capture received"),
    (AnalysisState.VALIDATING, "File validated"),
    (AnalysisState.RUNNING_ZEEK, "Zeek analysis"),
    (AnalysisState.RUNNING_SURICATA, "Suricata analysis"),
    (AnalysisState.NORMALIZING, "Normalizing evidence"),
    (AnalysisState.CORRELATING, "Correlating incident"),
    (AnalysisState.BUILDING_GRAPH, "Building attack graph"),
]
CHUNK = 1024 * 1024


class PipelineFailure(Exception):
    def __init__(self, code: str, title: str, message: str, detail: str = "") -> None:
        super().__init__(message)
        self.code, self.title, self.message, self.detail = code, title, message, detail


def initial_status(incident_id: str, *, demo: bool, filename: str | None, showcase: bool = False) -> AnalysisStatus:
    now = time.time()
    return AnalysisStatus(
        incident_id=incident_id,
        state=AnalysisState.UPLOADING,
        steps=[AnalysisStep(state=s, label=label, status="pending") for s, label in STEPS],
        demo=demo,
        showcase=showcase,
        filename=filename,
        created_at=now,
        updated_at=now,
    )


class AnalysisService:
    def __init__(self, settings: Settings, store: IncidentStore, hub: ProgressHub, analyzers: Analyzers) -> None:
        self.settings = settings
        self.store = store
        self.hub = hub
        self.analyzers = analyzers
        self._tasks: set[asyncio.Task[None]] = set()

    # -- progress -----------------------------------------------------------

    def _publish(self, record: IncidentRecord) -> None:
        record.status.updated_at = time.time()
        self.hub.publish(record.status.incident_id, {"type": "status", "status": record.status.model_dump(mode="json")})

    def _step(self, record: IncidentRecord, state: AnalysisState, status: str, detail: str | None = None) -> None:
        steps = []
        now = time.time()
        for step in record.status.steps:
            if step.state == state:
                step = step.model_copy(
                    update={
                        "status": status,
                        "detail": detail if detail is not None else step.detail,
                        "started_at": step.started_at or now,
                        "finished_at": now if status in ("done", "failed", "skipped") else None,
                    }
                )
            steps.append(step)
        record.status.steps = steps
        if status == "running":
            record.status.state = state
        self._publish(record)

    def _fail(self, record: IncidentRecord, failure: PipelineFailure) -> None:
        running = next((s.state for s in record.status.steps if s.status == "running"), None)
        if running is not None:
            self._step(record, running, "failed", failure.message)
        record.status.state = AnalysisState.FAILED
        record.status.error_code = failure.code
        record.status.error_title = failure.title
        record.status.error_message = failure.message
        record.status.error_detail = failure.detail[-4000:] or None
        self._publish(record)

    # -- entry points -------------------------------------------------------

    def _spawn(self, coro: Any) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def ensure_demo_capture(self) -> Path:
        path = self.settings.demo_pcap_path
        if not path.is_file():
            script = REPO_ROOT / "scripts" / "generate_demo_pcap.py"
            subprocess.run([sys.executable, str(script), "-o", str(path)], check=True, shell=False, timeout=60, capture_output=True)  # noqa: S603
        return path

    async def start_demo(self) -> AnalysisStatus:
        job_id = new_job_id()
        record = self.store.create(initial_status(job_id, demo=True, filename="breachreplay-demo.pcap"))
        self._spawn(self._run_demo(record))
        return record.status

    async def _run_demo(self, record: IncidentRecord) -> None:
        workspace = Workspace(self.settings.workspace_root, record.status.incident_id)
        try:
            self._step(record, AnalysisState.UPLOADING, "running")
            source = await asyncio.to_thread(self.ensure_demo_capture)
            workspace.create()
            data = await asyncio.to_thread(source.read_bytes)
            await asyncio.to_thread(workspace.capture.write_bytes, data)
            workspace.capture.chmod(0o640)
            self._step(record, AnalysisState.UPLOADING, "done", f"Synthetic demo capture ({len(data):,} bytes)")
            context = json.loads(self.settings.demo_context_path.read_text()) if self.settings.demo_context_path.is_file() else None
            await self._analyze(record, workspace, context, name="Demo incident · synthetic network traffic", source_type="demo", demo=True)
        except PipelineFailure as failure:
            self._fail(record, failure)
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("demo analysis failed")
            self._fail(record, PipelineFailure("INTERNAL_ERROR", "ANALYSIS FAILED", "An unexpected error stopped the analysis.", repr(exc)))
        finally:
            if not self.settings.keep_workspaces:
                workspace.cleanup()

    async def start_upload(self, upload: UploadFile, declared_size: int | None) -> AnalysisStatus:
        display = validate_filename(upload.filename)
        if declared_size is not None and declared_size > self.settings.max_upload_bytes + 64 * 1024:
            validate_size(declared_size, self.settings.max_upload_bytes)
        job_id = new_job_id()
        workspace = Workspace(self.settings.workspace_root, job_id).create()
        size = 0
        head = b""
        try:
            with workspace.capture.open("wb") as fh:
                while chunk := await upload.read(CHUNK):
                    if not head:
                        head = chunk[:4096]
                        inspect_capture_header(head)  # reject non-captures before reading further
                    size += len(chunk)
                    if size > self.settings.max_upload_bytes:
                        validate_size(size, self.settings.max_upload_bytes)
                    fh.write(chunk)
            validate_size(size, self.settings.max_upload_bytes)
            workspace.capture.chmod(0o640)
        except BaseException:
            workspace.cleanup()
            raise
        record = self.store.create(initial_status(job_id, demo=False, filename=display))
        self._spawn(self._run_upload(record, workspace, head, size))
        return record.status

    async def _run_upload(self, record: IncidentRecord, workspace: Workspace, head: bytes, size: int) -> None:
        try:
            self._step(record, AnalysisState.UPLOADING, "done", f"{record.status.filename} ({size:,} bytes)")
            await self._analyze(record, workspace, None, name=f"Uploaded capture · {record.status.filename}", source_type="upload", demo=False, head=head)
        except PipelineFailure as failure:
            self._fail(record, failure)
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("upload analysis failed")
            self._fail(record, PipelineFailure("INTERNAL_ERROR", "ANALYSIS FAILED", "An unexpected error stopped the analysis.", repr(exc)))
        finally:
            if not self.settings.keep_workspaces:
                workspace.cleanup()

    # -- core -------------------------------------------------------------

    async def _analyze(
        self,
        record: IncidentRecord,
        workspace: Workspace,
        context: dict[str, Any] | None,
        *,
        name: str,
        source_type: str,
        demo: bool,
        head: bytes | None = None,
    ) -> None:
        self._step(record, AnalysisState.VALIDATING, "running")
        if head is None:
            head = workspace.capture.read_bytes()[:4096]
        try:
            fmt, link_type = inspect_capture_header(head)
        except CaptureValidationError as exc:
            raise PipelineFailure(exc.code, exc.title, exc.message) from exc
        self._step(record, AnalysisState.VALIDATING, "done", f"{fmt} capture, link type {link_type if link_type is not None else 'per-interface'}")

        analyzers: dict[str, Any] = {}
        for state, tool, runner in (
            (AnalysisState.RUNNING_ZEEK, "Zeek", self.analyzers.run_zeek),
            (AnalysisState.RUNNING_SURICATA, "Suricata", self.analyzers.run_suricata),
        ):
            self._step(record, state, "running")
            try:
                info = await runner(workspace.path)
            except AnalyzerError as exc:
                raise PipelineFailure("ANALYZER_FAILED", "ANALYSIS FAILED", exc.message, exc.detail) from exc
            analyzers[tool.lower()] = {
                "version": info.get("version"),
                "duration_seconds": info.get("duration_seconds"),
                "outputs": info.get("logs", []),
            }
            self._step(record, state, "done", f"{len(info.get('logs', []))} output files in {info.get('duration_seconds', 0)} s")

        self._step(record, AnalysisState.NORMALIZING, "running")
        zeek = await asyncio.to_thread(parse_zeek_directory, workspace.path / "zeek")
        eve = await asyncio.to_thread(parse_eve_file, workspace.path / "suricata" / "eve.json")
        normalized = await asyncio.to_thread(normalize, zeek, eve, context)
        if not zeek.get("conn") and not eve.get("flow"):
            raise PipelineFailure(
                "UNSUPPORTED_CAPTURE",
                "UNSUPPORTED CAPTURE",
                "No compatible Ethernet/IP traffic could be analyzed.",
                f"Zeek produced {len(zeek.records)} logs and Suricata {eve.total} events, but no IP connections.",
            )
        self._step(
            record,
            AnalysisState.NORMALIZING,
            "done",
            f"{len(normalized.evidence)} evidence records · {len(normalized.assets)} assets · {len(normalized.detections)} detections",
        )

        self._step(record, AnalysisState.CORRELATING, "running")
        correlation = await asyncio.to_thread(correlate, normalized)
        self._step(record, AnalysisState.CORRELATING, "done", f"{len(correlation.events)} incident events from {correlation.candidates_considered} candidates")

        self._step(record, AnalysisState.BUILDING_GRAPH, "running")
        incident: Incident = build_incident(
            normalized,
            correlation,
            incident_id=record.status.incident_id,
            name=name,
            source_type=source_type,
            demo=demo,
            metadata={"analyzers": analyzers, "synthetic": demo},
        )
        record.incident = incident
        record.evidence = {e.id: e for e in normalized.evidence}
        self._step(record, AnalysisState.BUILDING_GRAPH, "done", f"{len(incident.assets)} nodes · {len(incident.edges)} edges")
        record.status.stats = {
            "evidence_records": len(normalized.evidence),
            "assets": len(incident.assets),
            "edges": len(incident.edges),
            "events": len(incident.events),
            "detections": len(normalized.detections),
            "incident_found": incident.incident_found,
        }
        record.status.state = AnalysisState.COMPLETE
        self._publish(record)

    # -- showcase -----------------------------------------------------------

    def load_showcase(self) -> AnalysisStatus:
        path = self.settings.showcase_path
        if not path.is_file():
            raise PipelineFailure("SHOWCASE_MISSING", "SHOWCASE UNAVAILABLE", "The precomputed showcase incident file is missing.")
        data = json.loads(path.read_text())
        incident = Incident.model_validate(data["incident"])
        evidence = [NetworkEvidence.model_validate(e) for e in data.get("evidence", [])]
        status = initial_status(incident.id, demo=True, filename="showcase-incident.json", showcase=True)
        record = self.store.get(incident.id) or self.store.create(status)
        record.incident = incident
        record.evidence = {e.id: e for e in evidence}
        now = time.time()
        record.status.steps = [
            AnalysisStep(
                state=s,
                label=label,
                status="skipped" if s not in (AnalysisState.UPLOADING,) else "done",
                detail="Precomputed earlier by the full pipeline" if s != AnalysisState.UPLOADING else "Loaded precomputed showcase incident",
                started_at=now,
                finished_at=now,
            )
            for s, label in STEPS
        ]
        record.status.state = AnalysisState.COMPLETE
        record.status.showcase = True
        record.status.stats = {"evidence_records": len(evidence), "assets": len(incident.assets), "edges": len(incident.edges), "events": len(incident.events)}
        return record.status

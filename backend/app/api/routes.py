"""REST API."""

from __future__ import annotations

import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse

from app.config import Settings
from app.models import AnalysisState, SimulationRequest
from app.pipeline import AnalysisService, PipelineFailure
from app.security.capture_validation import CaptureValidationError
from app.simulation.engine import SimulationError, simulate
from app.storage.sanitize import sanitize_evidence, sanitize_incident
from app.storage.store import IncidentRecord

router = APIRouter()
STARTED = time.time()


def get_service(request: Request) -> AnalysisService:
    return request.app.state.service


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


Service = Annotated[AnalysisService, Depends(get_service)]
Config = Annotated[Settings, Depends(get_settings_dep)]


def error(status: int, code: str, title: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "title": title, "message": message})


def _record(service: AnalysisService, incident_id: str) -> IncidentRecord:
    if len(incident_id) > 64 or not incident_id.replace("-", "").isalnum():
        raise error(404, "NOT_FOUND", "NOT FOUND", "Unknown incident.")
    record = service.store.get(incident_id)
    if record is None:
        raise error(404, "NOT_FOUND", "NOT FOUND", "Unknown incident.")
    return record


def _complete(service: AnalysisService, incident_id: str) -> IncidentRecord:
    record = _record(service, incident_id)
    if record.incident is None:
        if record.status.state == AnalysisState.FAILED:
            raise error(409, record.status.error_code or "FAILED", record.status.error_title or "ANALYSIS FAILED", record.status.error_message or "")
        raise error(409, "NOT_READY", "ANALYSIS IN PROGRESS", f"Analysis is still running ({record.status.state.value}).")
    return record


def _incident_payload(record: IncidentRecord, settings: Settings) -> dict[str, Any]:
    assert record.incident is not None
    return sanitize_incident(record.incident, mask=settings.public_mode)


@router.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "uptime_seconds": round(time.time() - STARTED, 1)}


@router.get("/api/status")
async def status(service: Service, settings: Config) -> dict[str, Any]:
    analyzers: dict[str, Any] = {"mode": "showcase"} if settings.showcase_mode else await service.analyzers.health()
    return {
        "service": "breachreplay",
        "showcase_mode": settings.showcase_mode,
        "public_mode": settings.public_mode,
        "uploads_enabled": not settings.showcase_mode,
        "max_upload_mb": settings.max_upload_mb,
        "analyzers": analyzers,
        "incidents_in_memory": len(service.store),
    }


@router.post("/api/incidents/demo", status_code=202)
async def start_demo(service: Service, settings: Config) -> dict[str, Any]:
    if settings.showcase_mode:
        try:
            st = service.load_showcase()
        except PipelineFailure as f:
            raise error(503, f.code, f.title, f.message) from f
        return st.model_dump(mode="json")
    st = await service.start_demo()
    return st.model_dump(mode="json")


@router.post("/api/incidents/upload", status_code=202)
async def upload(request: Request, service: Service, settings: Config, file: Annotated[UploadFile, File()]) -> Any:
    if settings.showcase_mode:
        raise error(
            403,
            "UPLOADS_DISABLED",
            "UPLOADS DISABLED",
            "This is a showcase deployment: uploads are disabled. Run BreachReplay locally to analyze your own captures.",
        )
    declared = request.headers.get("content-length")
    try:
        st = await service.start_upload(file, int(declared) if declared and declared.isdigit() else None)
    except CaptureValidationError as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": {"code": exc.code, "title": exc.title, "message": exc.message}})
    return st.model_dump(mode="json")


@router.get("/api/incidents/{incident_id}/status")
async def analysis_status(incident_id: str, service: Service) -> dict[str, Any]:
    return _record(service, incident_id).status.model_dump(mode="json")


@router.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str, service: Service, settings: Config) -> dict[str, Any]:
    record = _complete(service, incident_id)
    return {"status": record.status.model_dump(mode="json"), "incident": _incident_payload(record, settings)}


@router.get("/api/incidents/{incident_id}/graph")
async def get_graph(incident_id: str, service: Service, settings: Config) -> dict[str, Any]:
    data = _incident_payload(_complete(service, incident_id), settings)
    return {
        "nodes": data["assets"],
        "edges": data["edges"],
        "primary_attack_path": data["primary_attack_path"],
        "primary_attack_edges": data["primary_attack_edges"],
        "crown_jewels": data["crown_jewels"],
    }


@router.get("/api/incidents/{incident_id}/events")
async def get_events(incident_id: str, service: Service, settings: Config) -> dict[str, Any]:
    data = _incident_payload(_complete(service, incident_id), settings)
    return {"events": data["events"], "count": len(data["events"])}


@router.get("/api/incidents/{incident_id}/timeline")
async def get_timeline(incident_id: str, service: Service) -> dict[str, Any]:
    inc = _complete(service, incident_id).incident
    assert inc is not None
    start = inc.started_at or 0.0
    return {
        "started_at": inc.started_at,
        "ended_at": inc.ended_at,
        "duration_seconds": inc.duration_seconds,
        "entries": [
            {
                "event_id": e.id,
                "offset_seconds": round(e.timestamp - start, 3),
                "timestamp": e.timestamp,
                "phase": e.phase,
                "title": e.title,
                "confidence_label": e.confidence_label.value,
                "state_changes": [s.model_dump(mode="json") for s in e.state_changes],
                "on_primary_path": e.on_primary_path,
            }
            for e in inc.events
        ],
    }


@router.get("/api/incidents/{incident_id}/assets")
async def get_assets(incident_id: str, service: Service, settings: Config) -> dict[str, Any]:
    data = _incident_payload(_complete(service, incident_id), settings)
    return {"assets": data["assets"]}


@router.get("/api/incidents/{incident_id}/evidence")
async def list_evidence(incident_id: str, service: Service, settings: Config, ids: str = "", offset: int = 0, limit: int = 50) -> dict[str, Any]:
    record = _complete(service, incident_id)
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    if ids:
        wanted = [i for i in ids.split(",") if i][:200]
        items = [record.evidence[i] for i in wanted if i in record.evidence]
        total = len(items)
        items = items[offset : offset + limit]
    else:
        all_items = list(record.evidence.values())
        total = len(all_items)
        items = all_items[offset : offset + limit]
    return {"total": total, "offset": offset, "limit": limit, "items": [sanitize_evidence(e, mask=settings.public_mode) for e in items]}


@router.get("/api/incidents/{incident_id}/evidence/{evidence_id}")
async def get_evidence(incident_id: str, evidence_id: str, service: Service, settings: Config) -> dict[str, Any]:
    record = _complete(service, incident_id)
    ev = record.evidence.get(evidence_id)
    if ev is None:
        raise error(404, "NOT_FOUND", "NOT FOUND", "Unknown evidence record.")
    return sanitize_evidence(ev, mask=settings.public_mode)


@router.post("/api/incidents/{incident_id}/simulate", status_code=201)
async def run_simulation(incident_id: str, body: SimulationRequest, service: Service) -> dict[str, Any]:
    record = _complete(service, incident_id)
    assert record.incident is not None
    if not record.incident.incident_found:
        raise error(422, "NO_INCIDENT_PATH", "NO INCIDENT PATH", "There is no reconstructed incident path to simulate against.")
    try:
        result = simulate(record.incident, body.controls)
    except SimulationError as exc:
        raise error(422, "INVALID_CONTROL", "INVALID CONTROL", str(exc)) from exc
    record.add_simulation(result)
    return result.model_dump(mode="json")


@router.get("/api/incidents/{incident_id}/simulation/{simulation_id}")
async def get_simulation(incident_id: str, simulation_id: str, service: Service) -> dict[str, Any]:
    record = _complete(service, incident_id)
    result = record.simulations.get(simulation_id)
    if result is None:
        raise error(404, "NOT_FOUND", "NOT FOUND", "Unknown simulation.")
    return result.model_dump(mode="json")


@router.get("/api/incidents/{incident_id}/export")
async def export_incident(incident_id: str, service: Service) -> dict[str, Any]:
    """Sanitized export used to produce the showcase incident (always masked)."""
    record = _complete(service, incident_id)
    assert record.incident is not None
    return {
        "format": "breachreplay-showcase/1",
        "incident": sanitize_incident(record.incident, mask=True),
        "evidence": [sanitize_evidence(e, mask=True) for e in record.evidence.values()],
    }

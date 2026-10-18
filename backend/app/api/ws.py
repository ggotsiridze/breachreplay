"""WebSocket analysis progress: /ws/incidents/{incident_id}."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.models import AnalysisState

router = APIRouter()
TERMINAL = {AnalysisState.COMPLETE, AnalysisState.FAILED}


@router.websocket("/ws/incidents/{incident_id}")
async def incident_progress(websocket: WebSocket, incident_id: str) -> None:
    service = websocket.app.state.service
    record = service.store.get(incident_id) if len(incident_id) <= 64 else None
    await websocket.accept()
    if record is None:
        await websocket.send_json({"type": "error", "code": "NOT_FOUND", "message": "Unknown incident."})
        await websocket.close(code=4404)
        return
    queue = service.hub.subscribe(incident_id)
    try:
        await websocket.send_json({"type": "status", "status": record.status.model_dump(mode="json")})
        state = record.status.state
        while state not in TERMINAL:
            try:
                message = await asyncio.wait_for(queue.get(), timeout=15)
            except TimeoutError:
                await websocket.send_json({"type": "ping"})
                continue
            await websocket.send_json(message)
            state = AnalysisState(message["status"]["state"])
        await websocket.close(code=1000)
    except WebSocketDisconnect:
        pass
    finally:
        service.hub.unsubscribe(incident_id, queue)

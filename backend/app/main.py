"""BreachReplay API application."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.analyzers.client import Analyzers, build_analyzers
from app.api import routes, ws
from app.config import Settings, get_settings
from app.pipeline import AnalysisService
from app.storage.store import IncidentStore
from app.websocket.hub import ProgressHub


def create_app(settings: Settings | None = None, analyzers: Analyzers | None = None) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if settings.showcase_mode:
            try:
                app.state.service.load_showcase()
            except Exception:
                logging.getLogger("breachreplay").warning("showcase incident could not be preloaded")
        yield

    app = FastAPI(
        title="BreachReplay API",
        version="1.0.0",
        description="Turn network evidence into an attack you can watch.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    store = IncidentStore(settings.max_incidents)
    app.state.service = AnalysisService(settings, store, ProgressHub(), analyzers or build_analyzers(settings))

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "detail": {
                    "code": "VALIDATION_ERROR",
                    "title": "INVALID REQUEST",
                    "message": "The request was not valid.",
                    "errors": [{"loc": list(e.get("loc", [])), "msg": e.get("msg")} for e in exc.errors()[:10]],
                }
            },
        )

    @app.exception_handler(HTTPException)
    async def http_handler(_: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, dict) else {"code": "HTTP_ERROR", "title": "REQUEST FAILED", "message": str(exc.detail)}
        return JSONResponse(status_code=exc.status_code, content={"detail": detail})

    app.include_router(routes.router)
    app.include_router(ws.router)
    return app


app = create_app()

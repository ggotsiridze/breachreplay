"""Backend-side access to the analyzers.

``RemoteAnalyzers`` sends an opaque job id to the analyzer containers (which
have no outbound network access). ``LocalAnalyzers`` runs zeek/suricata
binaries from PATH, which is convenient for native development and CI.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Protocol

import httpx

from app.analyzers.process import AnalyzerError
from app.analyzers.suricata import run_suricata
from app.analyzers.zeek import run_zeek
from app.config import Settings


class Analyzers(Protocol):
    async def run_zeek(self, job_dir: Path) -> dict[str, Any]: ...

    async def run_suricata(self, job_dir: Path) -> dict[str, Any]: ...

    async def health(self) -> dict[str, Any]: ...


class LocalAnalyzers:
    def __init__(self, timeout_seconds: float) -> None:
        self.timeout = timeout_seconds

    async def run_zeek(self, job_dir: Path) -> dict[str, Any]:
        return await asyncio.to_thread(run_zeek, job_dir / "capture.pcap", job_dir / "zeek", self.timeout)

    async def run_suricata(self, job_dir: Path) -> dict[str, Any]:
        return await asyncio.to_thread(run_suricata, job_dir / "capture.pcap", job_dir / "suricata", self.timeout)

    async def health(self) -> dict[str, Any]:
        import shutil

        return {
            "mode": "local",
            "zeek": "available" if shutil.which("zeek") else "missing",
            "suricata": "available" if shutil.which("suricata") else "missing",
        }


class RemoteAnalyzers:
    def __init__(self, zeek_url: str, suricata_url: str, timeout_seconds: float) -> None:
        self.urls = {"zeek": zeek_url.rstrip("/"), "suricata": suricata_url.rstrip("/")}
        self.timeout = timeout_seconds

    async def _run(self, tool: str, job_dir: Path) -> dict[str, Any]:
        url = f"{self.urls[tool]}/analyze"
        try:
            async with httpx.AsyncClient(timeout=self.timeout + 15, trust_env=False) as client:
                response = await client.post(url, json={"job_id": job_dir.name})
        except httpx.HTTPError as exc:
            raise AnalyzerError(tool, f"The {tool} analyzer service is unreachable.", repr(exc)) from exc
        if response.status_code != 200:
            raise AnalyzerError(tool, f"The {tool} analyzer rejected the job (HTTP {response.status_code}).", response.text[:2000])
        body = response.json()
        if not body.get("ok"):
            raise AnalyzerError(tool, body.get("error", f"{tool} failed"), body.get("detail", ""), bool(body.get("timed_out")))
        return body

    async def run_zeek(self, job_dir: Path) -> dict[str, Any]:
        return await self._run("zeek", job_dir)

    async def run_suricata(self, job_dir: Path) -> dict[str, Any]:
        return await self._run("suricata", job_dir)

    async def health(self) -> dict[str, Any]:
        out: dict[str, Any] = {"mode": "remote"}
        async with httpx.AsyncClient(timeout=3, trust_env=False) as client:
            for tool, base in self.urls.items():
                try:
                    r = await client.get(f"{base}/health")
                    out[tool] = r.json().get("version", "ok") if r.status_code == 200 else f"HTTP {r.status_code}"
                except httpx.HTTPError:
                    out[tool] = "unreachable"
        return out


def build_analyzers(settings: Settings) -> Analyzers:
    if settings.analyzer_mode == "local":
        return LocalAnalyzers(settings.analyzer_timeout_seconds)
    return RemoteAnalyzers(settings.zeek_url, settings.suricata_url, settings.analyzer_timeout_seconds)

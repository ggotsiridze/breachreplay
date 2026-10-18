from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import REPO_ROOT, Settings
from app.correlation.engine import correlate
from app.graph.builder import build_incident
from app.main import create_app
from app.models import Incident
from app.normalization.normalizer import NormalizedEvidence, normalize
from app.parsers.suricata_eve import parse_eve_file
from app.parsers.zeek_logs import parse_zeek_directory

FIXTURES = Path(__file__).parent / "fixtures"
DEMO_ANALYSIS = FIXTURES / "demo-analysis"
DEMO_CONTEXT = REPO_ROOT / "demo" / "asset-context.json"

sys.path.insert(0, str(REPO_ROOT / "scripts"))


@pytest.fixture(scope="session")
def demo_context() -> dict[str, Any]:
    return json.loads(DEMO_CONTEXT.read_text())


@pytest.fixture(scope="session")
def normalized(demo_context: dict[str, Any]) -> NormalizedEvidence:
    zeek = parse_zeek_directory(DEMO_ANALYSIS / "zeek")
    eve = parse_eve_file(DEMO_ANALYSIS / "suricata" / "eve.json")
    return normalize(zeek, eve, demo_context)


@pytest.fixture(scope="session")
def incident(normalized: NormalizedEvidence) -> Incident:
    return build_incident(normalized, correlate(normalized), incident_id="0" * 32, name="test", source_type="demo", demo=True)


class RecordedAnalyzers:
    """Stands in for the analyzer containers by copying recorded real Zeek/Suricata output.

    The capture written to the workspace is still validated by the pipeline; only
    the analyzer execution is replaced.
    """

    def __init__(self, fail: str | None = None, empty: bool = False) -> None:
        self.fail = fail
        self.empty = empty
        self.calls: list[str] = []

    async def run_zeek(self, job_dir: Path) -> dict[str, Any]:
        from app.analyzers.process import AnalyzerError

        self.calls.append("zeek")
        assert (job_dir / "capture.pcap").is_file()
        if self.fail == "zeek":
            raise AnalyzerError("zeek", "Zeek exited unexpectedly (exit code 1).", "fatal error: simulated")
        out = job_dir / "zeek"
        if self.empty:
            out.mkdir()
        else:
            shutil.copytree(DEMO_ANALYSIS / "zeek", out)
        return {"ok": True, "logs": sorted(p.name for p in out.iterdir()), "duration_seconds": 0.01, "version": "recorded"}

    async def run_suricata(self, job_dir: Path) -> dict[str, Any]:
        from app.analyzers.process import AnalyzerError

        self.calls.append("suricata")
        if self.fail == "suricata":
            raise AnalyzerError("suricata", "Suricata exited unexpectedly (exit code 1).", "")
        out = job_dir / "suricata"
        out.mkdir()
        if not self.empty:
            shutil.copy(DEMO_ANALYSIS / "suricata" / "eve.json", out / "eve.json")
        else:
            (out / "eve.json").write_text("")
        return {"ok": True, "logs": ["eve.json"], "duration_seconds": 0.01, "version": "recorded"}

    async def health(self) -> dict[str, Any]:
        return {"mode": "recorded", "zeek": "recorded", "suricata": "recorded"}


@pytest.fixture
def make_client(tmp_path: Path):
    clients: list[TestClient] = []

    def factory(analyzers: Any | None = None, **overrides: Any) -> TestClient:
        values = {"WORKSPACE_ROOT": tmp_path / "ws", "DATA_DIR": tmp_path / "data", "MAX_UPLOAD_MB": 1, **overrides}
        settings = Settings(**values)
        client = TestClient(create_app(settings, analyzers or RecordedAnalyzers()))
        client.__enter__()
        clients.append(client)
        return client

    yield factory
    for c in clients:
        c.__exit__(None, None, None)


def wait_complete(client: TestClient, incident_id: str, timeout: float = 10) -> dict[str, Any]:
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        st = client.get(f"/api/incidents/{incident_id}/status").json()
        if st["state"] in ("COMPLETE", "FAILED"):
            return st
        time.sleep(0.05)
    raise AssertionError("analysis did not finish")

"""Analyzer worker: a tiny internal HTTP service run inside the analyzer containers.

It exposes exactly one action per container (Zeek or Suricata) against a capture
that the backend has already validated and placed in the shared workspace
volume. The worker never accepts commands, paths or arguments from the caller:
only an opaque job id that must match ``^[a-f0-9]{32}$``.

Python 3.9 compatible, standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Dict, Tuple

from app.analyzers.process import AnalyzerError, run_command
from app.analyzers.suricata import run_suricata
from app.analyzers.zeek import run_zeek

JOB_ID = re.compile(r"^[a-f0-9]{32}$")
CAPTURE_NAME = "capture.pcap"
MAX_BODY = 4096

RUNNERS: Dict[str, Callable[[Path, Path, float], Dict[str, object]]] = {
    "zeek": run_zeek,
    "suricata": run_suricata,
}
VERSION_ARGS = {"zeek": ["zeek", "--version"], "suricata": ["suricata", "-V"]}


class Worker:
    def __init__(self, tool: str, workspace_root: Path, timeout: float) -> None:
        self.tool = tool
        self.workspace_root = workspace_root.resolve()
        self.timeout = timeout
        self.lock = threading.Semaphore(2)
        self.version = self._version()

    def _version(self) -> str:
        try:
            result = run_command(self.tool, VERSION_ARGS[self.tool], cwd=Path("/tmp"), timeout_seconds=15)
            return (result.stdout_tail or result.stderr_tail).strip().splitlines()[0]
        except (AnalyzerError, IndexError):
            return "unknown"

    def analyze(self, job_id: str) -> Tuple[int, Dict[str, object]]:
        if not JOB_ID.match(job_id or ""):
            return 400, {"ok": False, "error": "invalid job id"}
        job_dir = (self.workspace_root / job_id).resolve()
        if job_dir.parent != self.workspace_root:
            return 400, {"ok": False, "error": "invalid job id"}
        capture = job_dir / CAPTURE_NAME
        if not capture.is_file() or capture.is_symlink():
            return 404, {"ok": False, "error": "capture not found for job"}
        with self.lock:
            try:
                info = RUNNERS[self.tool](capture, job_dir / self.tool, self.timeout)
            except AnalyzerError as exc:
                return 200, {
                    "ok": False,
                    "tool": self.tool,
                    "error": exc.message,
                    "detail": exc.detail[-4000:],
                    "timed_out": exc.timed_out,
                }
        info.update({"ok": True, "version": self.version})
        return 200, info


def make_handler(worker: Worker) -> type:
    class Handler(BaseHTTPRequestHandler):
        server_version = "breachreplay-analyzer"

        def _send(self, status: int, body: Dict[str, object]) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            if self.path == "/health":
                self._send(200, {"status": "ok", "tool": worker.tool, "version": worker.version})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:
            if self.path != "/analyze":
                self._send(404, {"error": "not found"})
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_BODY:
                self._send(400, {"error": "invalid body"})
                return
            try:
                payload = json.loads(self.rfile.read(length))
                job_id = str(payload.get("job_id", ""))
            except (ValueError, AttributeError):
                self._send(400, {"error": "invalid json"})
                return
            status, body = worker.analyze(job_id)
            self._send(status, body)

        def log_message(self, format: str, *args: object) -> None:
            print("[{}] {}".format(worker.tool, format % args), flush=True)

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description="BreachReplay analyzer worker")
    parser.add_argument("--tool", choices=sorted(RUNNERS), required=True)
    parser.add_argument("--host", default="0.0.0.0")  # noqa: S104 - internal network only
    parser.add_argument("--port", type=int, default=8700)
    args = parser.parse_args()
    root = Path(os.environ.get("WORKSPACE_ROOT", "/workspaces"))
    timeout = float(os.environ.get("ANALYZER_TIMEOUT_SECONDS", "180"))
    worker = Worker(args.tool, root, timeout)
    print("analyzer worker ready: {} ({})".format(args.tool, worker.version), flush=True)
    ThreadingHTTPServer((args.host, args.port), make_handler(worker)).serve_forever()


if __name__ == "__main__":
    main()

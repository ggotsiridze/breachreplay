#!/usr/bin/env python3
"""Export the sanitized SHOWCASE incident.

Runs the demo capture through the FULL pipeline of a running BreachReplay
backend (Zeek + Suricata + correlation), then saves the sanitized export to
``showcase/showcase-incident.json``. Showcase Mode serves that file so the
product can be explored without running the analyzers.

Usage:
    python scripts/export_showcase.py [--api http://localhost:8000] [--output showcase/showcase-incident.json]

Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SHOWCASE_ID = "showcase-demo-incident"


def call(method: str, url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        raise SystemExit(f"error: refusing non-HTTP URL {url!r}")
    req = urllib.request.Request(url, method=method, headers={"Accept": "application/json"})  # noqa: S310 - scheme checked above
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - scheme checked above
        return json.loads(resp.read())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--output", type=Path, default=ROOT / "showcase" / "showcase-incident.json")
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args(argv)
    api = args.api.rstrip("/")

    status = call("GET", f"{api}/api/status")
    if status.get("showcase_mode"):
        print(
            "error: the backend is in SHOWCASE_MODE; export must come from the full pipeline",
            file=sys.stderr,
        )
        return 2

    started = call("POST", f"{api}/api/incidents/demo")
    incident_id = started["incident_id"]
    deadline = time.time() + args.timeout
    while True:
        st = call("GET", f"{api}/api/incidents/{incident_id}/status")
        if st["state"] == "COMPLETE":
            break
        if st["state"] == "FAILED":
            print(
                f"error: analysis failed: {st.get('error_message')}\n{st.get('error_detail') or ''}",
                file=sys.stderr,
            )
            return 1
        if time.time() > deadline:
            print("error: analysis timed out", file=sys.stderr)
            return 1
        time.sleep(0.5)

    export = call("GET", f"{api}/api/incidents/{incident_id}/export")
    incident = export["incident"]
    incident["id"] = SHOWCASE_ID
    incident["showcase"] = True
    incident["metadata"]["pipeline"] = {
        "description": "Precomputed by the full BreachReplay pipeline from the synthetic demo capture.",
        "steps": [s["label"] for s in st["steps"]],
        "step_details": {s["label"]: s.get("detail") for s in st["steps"]},
    }
    export["notice"] = "SHOWCASE DEMO - PRECOMPUTED SYNTHETIC INCIDENT. Generated from synthetic traffic; contains no real network data."
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(export, indent=1, sort_keys=True) + "\n")
    print(
        f"wrote {args.output}: {len(incident['assets'])} assets, {len(incident['edges'])} edges, "
        f"{len(incident['events'])} events, {len(export['evidence'])} evidence records"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

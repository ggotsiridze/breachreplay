import struct

from app.config import REPO_ROOT

from .conftest import RecordedAnalyzers, wait_complete

DEMO_PCAP = REPO_ROOT / "demo" / "generated" / "breachreplay-demo.pcap"


def start_demo(client):
    r = client.post("/api/incidents/demo")
    assert r.status_code == 202
    body = r.json()
    assert len(body["incident_id"]) == 32
    st = wait_complete(client, body["incident_id"])
    assert st["state"] == "COMPLETE", st
    return body["incident_id"]


def test_health(make_client):
    r = make_client().get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_status(make_client):
    body = make_client().get("/api/status").json()
    assert body["showcase_mode"] is False and body["uploads_enabled"] is True
    assert body["analyzers"]["mode"] == "recorded"


def test_demo_start_and_incident(make_client):
    client = make_client()
    iid = start_demo(client)
    data = client.get(f"/api/incidents/{iid}").json()
    assert data["incident"]["demo"] is True
    assert data["incident"]["summary"]["crown_jewel_reached"] is True
    assert [s["status"] for s in data["status"]["steps"]] == ["done"] * 7


def test_events_graph_timeline_assets(make_client):
    client = make_client()
    iid = start_demo(client)
    events = client.get(f"/api/incidents/{iid}/events").json()
    assert events["count"] == 7
    graph = client.get(f"/api/incidents/{iid}/graph").json()
    assert len(graph["nodes"]) == 9 and len(graph["edges"]) == 16
    assert graph["primary_attack_path"][-1] == "asset-db-01"
    timeline = client.get(f"/api/incidents/{iid}/timeline").json()
    offsets = [e["offset_seconds"] for e in timeline["entries"]]
    assert offsets[0] == 0 and offsets == sorted(offsets)
    assets = client.get(f"/api/incidents/{iid}/assets").json()["assets"]
    assert any(a["crown_jewel"] for a in assets)


def test_evidence_endpoints(make_client):
    client = make_client()
    iid = start_demo(client)
    events = client.get(f"/api/incidents/{iid}/events").json()["events"]
    lateral = next(e for e in events if e["event_type"] == "lateral_movement")
    ev_id = lateral["evidence_ids"][0]
    ev = client.get(f"/api/incidents/{iid}/evidence/{ev_id}").json()
    assert ev["id"] == ev_id and ev["summary"]
    batch = client.get(f"/api/incidents/{iid}/evidence", params={"ids": ",".join(lateral["evidence_ids"])}).json()
    assert batch["total"] == len(lateral["evidence_ids"])
    page = client.get(f"/api/incidents/{iid}/evidence", params={"limit": 10, "offset": 5}).json()
    assert len(page["items"]) == 10 and page["total"] > 100
    assert client.get(f"/api/incidents/{iid}/evidence/ev-nope").status_code == 404


def test_simulation_roundtrip(make_client):
    client = make_client()
    iid = start_demo(client)
    r = client.post(f"/api/incidents/{iid}/simulate", json={"controls": [{"control_type": "isolate_asset", "asset_id": "asset-ws-03"}]})
    assert r.status_code == 201
    sim = r.json()
    assert sim["crown_jewel_before"] is True and sim["crown_jewel_after"] is False
    again = client.get(f"/api/incidents/{iid}/simulation/{sim['id']}").json()
    assert again["id"] == sim["id"]
    # observed incident unchanged
    inc = client.get(f"/api/incidents/{iid}").json()["incident"]
    assert inc["summary"]["crown_jewel_reached"] is True


def test_simulation_validation_errors(make_client):
    client = make_client()
    iid = start_demo(client)
    assert client.post(f"/api/incidents/{iid}/simulate", json={"controls": []}).status_code == 422
    r = client.post(f"/api/incidents/{iid}/simulate", json={"controls": [{"control_type": "isolate_asset", "asset_id": "asset-nope"}]})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "INVALID_CONTROL"
    r = client.post(f"/api/incidents/{iid}/simulate", json={"controls": [{"control_type": "launch_missiles"}]})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "VALIDATION_ERROR"
    assert client.get(f"/api/incidents/{iid}/simulation/nope").status_code == 404


def test_unknown_incident(make_client):
    client = make_client()
    assert client.get("/api/incidents/" + "f" * 32).status_code == 404
    assert client.get("/api/incidents/../../etc/passwd").status_code == 404


def test_upload_valid_capture(make_client):
    client = make_client(MAX_UPLOAD_MB=5)
    r = client.post("/api/incidents/upload", files={"file": ("my capture.pcap", DEMO_PCAP.read_bytes(), "application/vnd.tcpdump.pcap")})
    assert r.status_code == 202, r.text
    st = wait_complete(client, r.json()["incident_id"])
    assert st["state"] == "COMPLETE" and st["filename"] == "my capture.pcap"


def test_upload_validation_errors(make_client):
    client = make_client(MAX_UPLOAD_MB=1)
    head = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    cases = [
        (("notes.txt", b"hello"), 400, "INVALID_EXTENSION"),
        (("../../evil.pcap", head), 400, "SUSPICIOUS_FILENAME"),
        (("fake.pcap", b"MZ" + b"\x00" * 100), 400, "NOT_A_CAPTURE"),
        (("big.pcap", head + b"\x00" * (1024 * 1024 + 10)), 413, "FILE_TOO_LARGE"),
    ]
    for (name, data), status, code in cases:
        r = client.post("/api/incidents/upload", files={"file": (name, data)})
        assert r.status_code == status, (name, r.text)
        assert r.json()["detail"]["code"] == code
    assert r.json()["detail"]["title"]


def test_upload_leaves_no_workspace_on_rejection(make_client, tmp_path):
    client = make_client()
    client.post("/api/incidents/upload", files={"file": ("fake.pcap", b"not a capture at all" * 10)})
    ws = tmp_path / "ws"
    assert not ws.exists() or list(ws.iterdir()) == []


def test_workspace_cleaned_after_analysis(make_client, tmp_path):
    client = make_client()
    start_demo(client)
    assert list((tmp_path / "ws").iterdir()) == []


def test_analyzer_failure_is_reported(make_client):
    client = make_client(RecordedAnalyzers(fail="zeek"))
    iid = client.post("/api/incidents/demo").json()["incident_id"]
    st = wait_complete(client, iid)
    assert st["state"] == "FAILED"
    assert st["error_title"] == "ANALYSIS FAILED"
    assert "Zeek exited unexpectedly" in st["error_message"]
    assert st["error_detail"]
    r = client.get(f"/api/incidents/{iid}")
    assert r.status_code == 409


def test_capture_without_ip_traffic(make_client):
    client = make_client(RecordedAnalyzers(empty=True))
    iid = client.post("/api/incidents/demo").json()["incident_id"]
    st = wait_complete(client, iid)
    assert st["state"] == "FAILED" and st["error_code"] == "UNSUPPORTED_CAPTURE"


def test_public_mode_masks_internal_ips(make_client):
    client = make_client(PUBLIC_MODE=True)
    iid = start_demo(client)
    assets = client.get(f"/api/incidents/{iid}/assets").json()["assets"]
    ips = {a["ip"] for a in assets}
    assert "10.x.x.33" in ips and "10.20.2.33" not in ips
    assert "203.0.113.45" in ips  # documentation range retained


def test_export_is_sanitized(make_client):
    client = make_client()
    iid = start_demo(client)
    data = client.get(f"/api/incidents/{iid}/export").json()
    text = str(data)
    assert "10.20.2.33" not in text
    assert data["format"] == "breachreplay-showcase/1"
    assert all(set(e["metadata"]) <= {*e["metadata"]} for e in data["evidence"])
    assert not any("user_agent" in e["metadata"] for e in data["evidence"])


def test_showcase_mode(make_client, tmp_path):
    import json

    client = make_client()
    iid = start_demo(client)
    export = client.get(f"/api/incidents/{iid}/export").json()
    path = tmp_path / "showcase.json"
    path.write_text(json.dumps(export))
    showcase = make_client(SHOWCASE_MODE=True, SHOWCASE_PATH=path)
    status = showcase.get("/api/status").json()
    assert status["showcase_mode"] is True and status["uploads_enabled"] is False
    r = showcase.post("/api/incidents/demo")
    assert r.status_code == 202 and r.json()["showcase"] is True and r.json()["state"] == "COMPLETE"
    sid = r.json()["incident_id"]
    assert showcase.get(f"/api/incidents/{sid}/graph").status_code == 200
    sim = showcase.post(f"/api/incidents/{sid}/simulate", json={"controls": [{"control_type": "isolate_asset", "asset_id": "asset-ws-03"}]})
    assert sim.status_code == 201 and sim.json()["crown_jewel_after"] is False
    assert showcase.post("/api/incidents/upload", files={"file": ("a.pcap", b"x")}).status_code == 403

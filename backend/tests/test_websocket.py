from .conftest import RecordedAnalyzers


def collect(client, iid):
    states = []
    with client.websocket_connect(f"/ws/incidents/{iid}") as ws:
        while True:
            try:
                msg = ws.receive_json()
            except Exception:  # server closed the socket after a terminal state
                break
            if msg["type"] == "status":
                states.append(msg["status"]["state"])
                if msg["status"]["state"] in ("COMPLETE", "FAILED"):
                    break
    return states


def test_state_progression_to_complete(make_client):
    client = make_client()
    iid = client.post("/api/incidents/demo").json()["incident_id"]
    states = collect(client, iid)
    assert states[-1] == "COMPLETE"
    order = ["UPLOADING", "VALIDATING", "RUNNING_ZEEK", "RUNNING_SURICATA", "NORMALIZING", "CORRELATING", "BUILDING_GRAPH", "COMPLETE"]
    idx = [order.index(s) for s in states]
    assert idx == sorted(idx)


def test_failure_is_streamed(make_client):
    client = make_client(RecordedAnalyzers(fail="suricata"))
    iid = client.post("/api/incidents/demo").json()["incident_id"]
    states = collect(client, iid)
    assert states[-1] == "FAILED"


def test_unknown_incident_socket(make_client):
    client = make_client()
    with client.websocket_connect("/ws/incidents/" + "a" * 32) as ws:
        msg = ws.receive_json()
        assert msg["type"] == "error" and msg["code"] == "NOT_FOUND"

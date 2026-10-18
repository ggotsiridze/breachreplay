from app.correlation.engine import correlate
from app.correlation.scoring import OBSERVED_CAP, Score, label_for
from app.models import ConfidenceLabel, EventType
from app.normalization.normalizer import normalize
from app.parsers.suricata_eve import EveParseResult
from app.parsers.zeek_logs import ZeekParseResult


def conn(uid, ts, src, sport, dst, dport, service=None, state="SF", ob=100, rb=100):
    return {
        "ts": ts,
        "uid": uid,
        "id.orig_h": src,
        "id.orig_p": sport,
        "id.resp_h": dst,
        "id.resp_p": dport,
        "proto": "tcp",
        "service": service,
        "conn_state": state,
        "orig_bytes": ob,
        "resp_bytes": rb,
        "duration": 0.5,
    }


def run(conns, alerts=(), context=None):
    zeek = ZeekParseResult(records={"conn": list(conns)})
    eve = EveParseResult(events={"alert": list(alerts)} if alerts else {})
    n = normalize(zeek, eve, context)
    return n, correlate(n)


def alert(ts, src, sport, dst, dport, sid=1, sev=1, sig="test signature", cat="Web Application Attack"):
    return {
        "_ts": ts,
        "timestamp": "",
        "event_type": "alert",
        "src_ip": src,
        "src_port": sport,
        "dest_ip": dst,
        "dest_port": dport,
        "proto": "TCP",
        "alert": {"signature_id": sid, "signature": sig, "category": cat, "severity": sev},
    }


def test_demo_events_reconstructed(incident):
    types = [e.event_type for e in incident.events]
    assert types == [
        EventType.EXTERNAL_RECON,
        EventType.INITIAL_ACCESS,
        EventType.COMMAND_AND_CONTROL,
        EventType.DISCOVERY,
        EventType.LATERAL_MOVEMENT,
        EventType.CROWN_JEWEL_ACCESS,
        EventType.EXFILTRATION,
    ]


def test_chronological_ordering(incident):
    ts = [e.timestamp for e in incident.events]
    assert ts == sorted(ts)
    assert [e.id for e in incident.events] == [f"evt-{i:02d}" for i in range(1, len(incident.events) + 1)]


def test_confidence_labels_and_scores(incident):
    by_type = {e.event_type: e for e in incident.events}
    assert by_type[EventType.EXTERNAL_RECON].confidence_label == ConfidenceLabel.OBSERVED
    assert by_type[EventType.INITIAL_ACCESS].confidence_label == ConfidenceLabel.LIKELY
    assert by_type[EventType.LATERAL_MOVEMENT].confidence_label == ConfidenceLabel.HIGH_CONFIDENCE
    for e in incident.events:
        assert 0 <= e.confidence <= 99
        assert e.confidence_label == label_for(e.confidence)


def test_score_formula_is_transparent():
    s = Score(EventType.LATERAL_MOVEMENT)
    s.add("detection_high", "x")
    s.add("admin_protocol", "y")
    expected = round((1 - (1 - 0.20) * (1 - 0.45) * (1 - 0.10)) * 100)
    assert s.confidence == expected
    assert [r.points for r in s.reasons] == [20, 45, 10]
    s.add("detection_high", "dup")  # duplicate signals are not double counted
    assert s.confidence == expected


def test_uncorroborated_activity_is_capped_at_observed():
    s = Score(EventType.CROWN_JEWEL_ACCESS)
    s.add("crown_jewel_target", "x")
    s.add("admin_protocol", "y")
    s.add("admin_share", "z")
    s.add("file_written", "w")
    assert s.confidence <= OBSERVED_CAP
    assert s.label == ConfidenceLabel.OBSERVED


def test_evidence_reasons_present(incident):
    lateral = next(e for e in incident.events if e.event_type == EventType.LATERAL_MOVEMENT)
    signals = {r.signal for r in lateral.reasons}
    assert {"base", "detection_high", "zeek_notice", "source_previously_suspicious", "temporal_proximity", "admin_protocol", "admin_share"} <= signals
    assert all(r.text for r in lateral.reasons)
    assert lateral.evidence_ids and lateral.detection_ids


def test_source_destination_chaining(incident):
    by_type = {e.event_type: e for e in incident.events}
    lateral, crown = by_type[EventType.LATERAL_MOVEMENT], by_type[EventType.CROWN_JEWEL_ACCESS]
    assert lateral.destination_asset_id == crown.source_asset_id == "asset-ws-03"
    assert any(r.signal == "source_previously_suspicious" and "Lateral movement" in r.text for r in crown.reasons)


def test_temporal_correlation(incident):
    crown = next(e for e in incident.events if e.event_type == EventType.CROWN_JEWEL_ACCESS)
    proximity = next(r for r in crown.reasons if r.signal == "temporal_proximity")
    assert "30 s" in proximity.text


def test_single_plain_connection_is_not_suspicious():
    _n, result = run([conn("C1", 100.0, "10.0.0.5", 50000, "10.0.0.9", 445, service="smb")])
    # admin protocol on its own: candidate, but OBSERVED and dropped as unlinked context
    assert result.events == []
    assert result.context_events_dropped == 1
    assert all(s.value == "NORMAL" for s in result.final_states.values())


def test_plain_crown_jewel_access_is_not_flagged(normalized):
    # WS-01 queries DB-01 during the baseline: observed, never escalated.
    result = correlate(normalized)
    assert not any(e.source_asset_id == "asset-ws-01" for e in result.events)


def test_detection_raises_confidence_and_state():
    _n, result = run(
        [conn("C1", 100.0, "198.51.100.7", 40000, "10.0.0.10", 80, service="http")],
        [alert(100.2, "198.51.100.7", 40000, "10.0.0.10", 80)],
    )
    assert len(result.events) == 1
    ev = result.events[0]
    assert ev.event_type == EventType.INITIAL_ACCESS
    assert ev.confidence_label == ConfidenceLabel.SUSPICIOUS
    assert [c.to_state.value for c in ev.state_changes] == ["SUSPICIOUS", "SUSPICIOUS"]


def test_fanout_detected_as_discovery():
    conns = [conn(f"C{i}", 100.0 + i, "10.0.0.5", 50000 + i, f"10.0.0.{20 + i}", 445, state="REJ", ob=0, rb=0) for i in range(4)]
    alerts = [alert(101.0, "10.0.0.5", 50001, "10.0.0.21", 445, sev=3, sig="sweep", cat="Detection of a Network Scan")]
    _, result = run(conns, alerts)
    assert [e.event_type for e in result.events] == [EventType.DISCOVERY]
    assert len(result.events[0].target_asset_ids) == 4
    assert result.events[0].technique_id == "T1046"


def test_deterministic_output(normalized):
    a = correlate(normalized)
    b = correlate(normalized)
    assert [e.model_dump() for e in a.events] == [e.model_dump() for e in b.events]

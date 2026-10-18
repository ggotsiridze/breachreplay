from app.graph.builder import compute_primary_path, edge_id
from app.models import AssetState, EdgeState, EventType


def test_node_creation(incident):
    ids = {a.id for a in incident.assets}
    assert {"asset-web-01", "asset-ws-03", "asset-db-01", "asset-203-0-113-45"} <= ids
    assert len(incident.assets) == 9


def test_edge_creation(incident):
    edges = {e.id: e for e in incident.edges}
    lateral = edges[edge_id("asset-web-01", "asset-ws-03")]
    assert lateral.state == EdgeState.ATTACK
    assert 445 in lateral.ports
    assert "smb" in lateral.services
    assert lateral.connection_count == 2
    baseline = edges[edge_id("asset-ws-01", "asset-db-01")]
    assert baseline.state == EdgeState.OBSERVED and baseline.event_ids == []
    probe = edges[edge_id("asset-web-01", "asset-ws-01")]
    assert probe.state == EdgeState.SUSPICIOUS  # probed, not traversed


def test_state_transitions(incident):
    states = {a.id: a.state for a in incident.assets}
    assert states["asset-web-01"] == AssetState.AFFECTED
    assert states["asset-ws-03"] == AssetState.AFFECTED
    assert states["asset-db-01"] == AssetState.AFFECTED
    assert states["asset-ws-01"] == AssetState.NORMAL
    assert states["asset-203-0-113-45"] == AssetState.SUSPICIOUS
    # every transition is driven by an event and only escalates
    seen = {}
    for e in incident.events:
        for ch in e.state_changes:
            assert seen.get(ch.asset_id, AssetState.NORMAL) == ch.from_state
            seen[ch.asset_id] = ch.to_state


def test_primary_path(incident):
    assert incident.primary_attack_path == ["asset-203-0-113-45", "asset-web-01", "asset-ws-03", "asset-db-01"]
    assert incident.primary_attack_edges == [
        "edge-203-0-113-45--web-01",
        "edge-web-01--ws-03",
        "edge-ws-03--db-01",
    ]
    on_path = [e.event_type for e in incident.events if e.on_primary_path]
    assert on_path == [EventType.INITIAL_ACCESS, EventType.LATERAL_MOVEMENT, EventType.CROWN_JEWEL_ACCESS]


def test_crown_jewel_relationship(incident):
    assert incident.crown_jewels == ["asset-db-01"]
    assert incident.summary.crown_jewel_reached
    crown = next(e for e in incident.events if e.event_type == EventType.CROWN_JEWEL_ACCESS)
    assert incident.summary.crown_jewel_reached_at == crown.timestamp
    assert incident.primary_attack_path[-1] in incident.crown_jewels


def test_no_path_without_events():
    assert compute_primary_path([], {}).assets == []


def test_summary_counts(incident):
    s = incident.summary
    assert s.assets_observed == 9
    assert s.affected_assets == 3
    assert s.incident_events == 7
    assert s.detections == 13
    assert s.identities == ["CORP-DEMO\\svc-demo"]
    assert "DB-01" in s.headline

import pytest

from app.models import AssetState, ContainmentControl, ControlType, EventOutcome
from app.simulation.engine import SimulationError, simulate


def outcomes(result):
    return {o.event_id: o.outcome for o in result.event_outcomes}


def test_isolate_asset_interrupts_path(incident):
    r = simulate(incident, [ContainmentControl(control_type=ControlType.ISOLATE_ASSET, asset_id="asset-ws-03", activation="first_detection")])
    assert r.interrupted_event_id == "evt-05"
    assert r.interrupted_edge_id == "edge-web-01--ws-03"
    assert r.crown_jewel_before and not r.crown_jewel_after
    assert outcomes(r)["evt-06"] == EventOutcome.NOT_REACHED
    assert r.final_states["asset-ws-03"] == AssetState.CONTAINED
    assert r.final_states["asset-db-01"] == AssetState.PROTECTED
    assert r.observed.path_complete and not r.simulated.path_complete
    assert r.simulated_assets_reached < r.observed_assets_reached
    assert "would have been interrupted" in r.explanation
    assert "SIMULATED CONTAINMENT" in r.disclaimer


def test_isolate_after_compromise_blocks_outbound(incident):
    lateral = next(e for e in incident.events if e.id == "evt-05")
    r = simulate(
        incident,
        [ContainmentControl(control_type=ControlType.ISOLATE_ASSET, asset_id="asset-ws-03", activation="custom", activation_timestamp=lateral.timestamp + 10)],
    )
    o = outcomes(r)
    assert o["evt-05"] == EventOutcome.OCCURRED
    assert o["evt-06"] == EventOutcome.INTERRUPTED
    assert o["evt-07"] == EventOutcome.INTERRUPTED
    assert not r.crown_jewel_after


def test_block_edge(incident):
    r = simulate(incident, [ContainmentControl(control_type=ControlType.BLOCK_EDGE, edge_id="edge-ws-03--db-01")])
    o = outcomes(r)
    assert o["evt-06"] == EventOutcome.INTERRUPTED
    assert o["evt-07"] == EventOutcome.OCCURRED  # exfiltration did not depend on the DB edge
    assert not r.crown_jewel_after
    assert "Still observed after the control" in r.explanation


def test_block_port(incident):
    r = simulate(incident, [ContainmentControl(control_type=ControlType.BLOCK_PORT, port=5432)])
    assert r.interrupted_event_id == "evt-06"
    assert r.simulated.path_length == 2


def test_block_protocol(incident):
    r = simulate(incident, [ContainmentControl(control_type=ControlType.BLOCK_PROTOCOL, protocol="SMB")])
    assert r.interrupted_event_id == "evt-05"
    assert not r.crown_jewel_after


def test_disable_identity(incident):
    r = simulate(incident, [ContainmentControl(control_type=ControlType.DISABLE_IDENTITY, identity="CORP-DEMO\\svc-demo")])
    assert r.interrupted_event_id == "evt-05"


def test_segment_assets(incident):
    r = simulate(incident, [ContainmentControl(control_type=ControlType.SEGMENT_ASSETS, segment_asset_ids=["asset-db-01"])])
    assert r.interrupted_event_id == "evt-06"
    assert not r.crown_jewel_after


def test_control_that_matches_nothing(incident):
    r = simulate(incident, [ContainmentControl(control_type=ControlType.BLOCK_PORT, port=3389)])
    assert r.interrupted_event_id is None
    assert r.crown_jewel_after and r.simulated == r.observed
    assert "would not have interrupted" in r.explanation


def test_crown_jewel_reachability(incident):
    r = simulate(incident, [ContainmentControl(control_type=ControlType.BLOCK_PORT, port=445)])
    assert "asset-db-01" in r.reachable_before
    assert "asset-db-01" not in r.reachable_after


def test_original_incident_is_immutable(incident):
    before = incident.model_dump_json()
    simulate(incident, [ContainmentControl(control_type=ControlType.ISOLATE_ASSET, asset_id="asset-web-01")])
    simulate(incident, [ContainmentControl(control_type=ControlType.BLOCK_PORT, port=445)])
    assert incident.model_dump_json() == before


@pytest.mark.parametrize(
    "control",
    [
        ContainmentControl(control_type=ControlType.ISOLATE_ASSET, asset_id="asset-nope"),
        ContainmentControl(control_type=ControlType.ISOLATE_ASSET, asset_id="asset-203-0-113-45"),
        ContainmentControl(control_type=ControlType.BLOCK_EDGE, edge_id="edge-x--y"),
        ContainmentControl(control_type=ControlType.BLOCK_PORT),
        ContainmentControl(control_type=ControlType.DISABLE_IDENTITY, identity="someone-else"),
        ContainmentControl(control_type=ControlType.ISOLATE_ASSET, asset_id="asset-ws-03", activation="custom"),
    ],
)
def test_invalid_controls(incident, control):
    with pytest.raises(SimulationError):
        simulate(incident, [control])


def test_deterministic(incident):
    c = [ContainmentControl(control_type=ControlType.ISOLATE_ASSET, asset_id="asset-ws-03")]
    a, b = simulate(incident, c), simulate(incident, c)
    assert a.model_dump(exclude={"id"}) == b.model_dump(exclude={"id"})

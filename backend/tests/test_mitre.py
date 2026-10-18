from app.mitre.mapping import CATALOG, MappingContext, map_technique
from app.models import EventType


def ctx(event_type, **kw):
    base = dict(
        event_type=event_type,
        confidence=80,
        app_protocols=frozenset(),
        destination_port=None,
        detection_categories=frozenset(),
        admin_shares=(),
        destination_internal=True,
        source_internal=True,
        destination_is_known_c2=False,
        periodic=False,
        fanout_targets=0,
        destination_is_database=False,
    )
    base.update(kw)
    return MappingContext(**base)


def test_supported_mapping_smb_admin_share():
    m, _ = map_technique(ctx(EventType.LATERAL_MOVEMENT, app_protocols=frozenset({"smb"}), destination_port=445, admin_shares=("\\\\10.0.0.9\\ADMIN$",)))
    assert m and m.technique_id == "T1021.002"
    assert m.technique_name == CATALOG["T1021.002"][0]
    assert "ADMIN$" in m.reason
    assert m.url == "https://attack.mitre.org/techniques/T1021/002/"


def test_mapping_confidence_is_bounded_by_event_confidence():
    m, _ = map_technique(ctx(EventType.LATERAL_MOVEMENT, confidence=50, app_protocols=frozenset({"smb"}), admin_shares=("\\\\h\\C$",)))
    assert m and m.confidence == 50


def test_smb_without_admin_share_is_not_mapped():
    m, reason = map_technique(ctx(EventType.LATERAL_MOVEMENT, app_protocols=frozenset({"smb"}), destination_port=445))
    assert m is None
    assert reason.startswith("Not mapped")


def test_initial_access_requires_web_attack_detection():
    m, _ = map_technique(ctx(EventType.INITIAL_ACCESS, app_protocols=frozenset({"http"})))
    assert m is None
    m, _ = map_technique(ctx(EventType.INITIAL_ACCESS, app_protocols=frozenset({"http"}), detection_categories=frozenset({"Web Application Attack"})))
    assert m and m.technique_id == "T1190"


def test_exfil_only_mapped_when_destination_is_c2():
    assert map_technique(ctx(EventType.EXFILTRATION))[0] is None
    m, _ = map_technique(ctx(EventType.EXFILTRATION, destination_is_known_c2=True))
    assert m and m.technique_id == "T1041"


def test_recon_never_mapped():
    m, reason = map_technique(ctx(EventType.EXTERNAL_RECON, app_protocols=frozenset({"http"})))
    assert m is None and "Not mapped" in reason


def test_demo_mappings_have_reasons(incident):
    mapped = {e.event_type: e for e in incident.events if e.technique_id}
    assert mapped[EventType.LATERAL_MOVEMENT].technique_id == "T1021.002"
    assert mapped[EventType.INITIAL_ACCESS].technique_id == "T1190"
    assert mapped[EventType.DISCOVERY].technique_id == "T1046"
    for e in mapped.values():
        assert e.technique_reason and e.technique and e.technique.confidence <= e.confidence
    recon = next(e for e in incident.events if e.event_type == EventType.EXTERNAL_RECON)
    assert recon.technique_id is None and recon.technique_reason and recon.technique_reason.startswith("Not mapped")

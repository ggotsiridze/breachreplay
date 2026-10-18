from app.models import AssetType, EvidenceSource
from app.normalization.assets import AssetInventory, is_internal, normalize_ip
from app.normalization.normalizer import normalize
from app.parsers.suricata_eve import EveParseResult
from app.parsers.zeek_logs import ZeekParseResult


def test_ip_normalization():
    assert normalize_ip(" 10.020.1.10 ") is None  # leading zeros are ambiguous and rejected
    assert normalize_ip("10.20.1.10") == "10.20.1.10"
    assert normalize_ip("2001:DB8::0001") == "2001:db8::1"
    assert normalize_ip("not-an-ip") is None


def test_internal_vs_documentation_ranges():
    assert is_internal("10.20.1.10") and is_internal("192.168.1.1") and is_internal("172.16.5.5")
    # Python's ipaddress marks documentation ranges as private; BreachReplay must not.
    assert not is_internal("203.0.113.45")
    assert not is_internal("198.51.100.20")
    assert not is_internal("8.8.8.8")


def test_asset_discovery(normalized):
    by_ip = normalized.asset_by_ip()
    assert set(by_ip) == {"10.20.0.2", "10.20.1.10", "10.20.2.21", "10.20.2.22", "10.20.2.33", "10.20.2.34", "10.20.3.50", "203.0.113.45", "198.51.100.20"}
    assert by_ip["10.20.1.10"].display_name == "WEB-01"
    assert by_ip["10.20.1.10"].hostname == "web-01.corp.example"  # from DNS answers
    assert by_ip["10.20.3.50"].asset_type == AssetType.DATABASE
    assert by_ip["10.20.3.50"].crown_jewel
    assert by_ip["203.0.113.45"].asset_type == AssetType.INTERNET and not by_ip["203.0.113.45"].internal
    assert by_ip["10.20.2.34"].hostname is None and by_ip["10.20.2.34"].display_name == "10.20.2.34"


def test_asset_type_inference_without_context(normalized):
    inv = AssetInventory()
    inv.observe_connection("10.0.0.5", "10.0.0.9", 1.0, 5432, None, "SF")
    inv.observe_connection("10.0.0.5", "10.0.0.7", 2.0, 80, "http", "SF")
    assets = {a.ip: a for a in inv.build()}
    assert assets["10.0.0.9"].asset_type == AssetType.DATABASE
    assert assets["10.0.0.9"].crown_jewel and "Inferred" in (assets["10.0.0.9"].crown_jewel_reason or "")
    assert assets["10.0.0.7"].asset_type == AssetType.SERVER
    assert assets["10.0.0.5"].asset_type == AssetType.WORKSTATION


def test_timestamps_and_ordering(normalized):
    ts = [e.timestamp for e in normalized.evidence]
    assert ts == sorted(ts)
    assert all(1773484200 < t < 1773484400 for t in ts)


def test_source_mapping_and_evidence_ids(normalized):
    ids = [e.id for e in normalized.evidence]
    assert len(ids) == len(set(ids))
    sources = {e.source for e in normalized.evidence}
    assert sources == {EvidenceSource.ZEEK, EvidenceSource.SURICATA}
    conn = [e for e in normalized.evidence if e.log_type == "conn"]
    assert all(e.id.startswith("ev-zeek-conn-") and e.source_record_id for e in conn)
    alerts = [e for e in normalized.evidence if e.log_type == "eve.alert"]
    assert len(alerts) == 11
    assert all(e.source_asset_id and e.destination_asset_id for e in alerts)


def test_activities_link_zeek_and_suricata(normalized):
    smb = next(a for a in normalized.activities if a.dst_port == 445 and a.total_bytes > 0)
    assert smb.identities == ["CORP-DEMO\\svc-demo"]
    assert any(s.endswith("ADMIN$") for s in smb.smb_shares)
    assert len(smb.detection_ids) >= 3  # Suricata alerts + Zeek notice aligned by uid / 5-tuple
    for prefix in ("ev-zeek-conn-", "ev-zeek-ntlm-", "ev-zeek-smb-mapping-", "ev-zeek-notice-", "ev-suricata-alert-", "ev-suricata-smb-"):
        assert any(e.startswith(prefix) for e in smb.evidence_ids), prefix


def test_no_raw_payloads_in_evidence(normalized):
    for ev in normalized.evidence:
        for value in ev.metadata.values():
            assert not isinstance(value, bytes)
            if isinstance(value, str):
                assert len(value) <= 241


def test_empty_inputs_normalize_cleanly():
    result = normalize(ZeekParseResult(), EveParseResult())
    assert result.assets == [] and result.evidence == [] and result.activities == []

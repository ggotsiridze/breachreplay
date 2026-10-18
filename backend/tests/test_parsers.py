from pathlib import Path

from app.parsers.suricata_eve import parse_eve_file, parse_eve_lines, parse_eve_timestamp
from app.parsers.zeek_logs import parse_zeek_directory, parse_zeek_lines

from .conftest import DEMO_ANALYSIS

TSV_CONN = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\ttunnel_parents
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tset[string]
1773484302.000000\tCabc\t10.20.1.10\t49228\t10.20.2.33\t445\ttcp\tsmb\t3.88\t2406\t802\tSF\t(empty)
1773484303.000000\tCdef\t10.20.1.10\t49229\t10.20.2.34\t445\ttcp\t-\t-\t-\t-\tS0\t(empty)
#close\t2026-03-14-10-40-00
"""


# --- Zeek -----------------------------------------------------------------------


def test_zeek_json_demo_logs_parse():
    result = parse_zeek_directory(DEMO_ANALYSIS / "zeek")
    assert len(result.get("conn")) == 35
    assert result.stats["conn"]["malformed"] == 0
    for log in ("dns", "http", "ssl", "files", "notice", "smb_mapping", "smb_files", "ntlm"):
        assert result.get(log), log


def test_zeek_representative_conn_record():
    conn = parse_zeek_directory(DEMO_ANALYSIS / "zeek").get("conn")
    smb = [r for r in conn if r["id.resp_p"] == 445 and r.get("service")]
    assert smb and smb[0]["id.orig_h"] == "10.20.1.10" and smb[0]["id.resp_h"] == "10.20.2.33"
    assert "smb" in smb[0]["service"]
    assert isinstance(smb[0]["ts"], float)


def test_zeek_representative_protocol_records():
    result = parse_zeek_directory(DEMO_ANALYSIS / "zeek")
    assert result.get("ntlm")[0]["username"] == "svc-demo"
    assert result.get("smb_mapping")[0]["path"].endswith("ADMIN$")
    assert any(r.get("server_name") == "sync-drop.demo.example" for r in result.get("ssl"))
    assert any("BREACHREPLAY-DEMO-MARKER-INITIAL-ACCESS" in (r.get("uri") or "") for r in result.get("http"))


def test_zeek_tsv_format():
    records, malformed = parse_zeek_lines(TSV_CONN.splitlines(keepends=True))
    assert malformed == 0
    assert len(records) == 2
    assert records[0]["id.resp_p"] == 445 and records[0]["orig_bytes"] == 2406
    assert records[0]["tunnel_parents"] == []
    assert records[1]["service"] is None and records[1]["conn_state"] == "S0"


def test_zeek_missing_logs(tmp_path: Path):
    result = parse_zeek_directory(tmp_path)
    assert result.get("conn") == []
    assert "conn" in result.missing and "ssh" in result.missing


def test_zeek_empty_logs(tmp_path: Path):
    (tmp_path / "conn.log").write_text("")
    result = parse_zeek_directory(tmp_path)
    assert result.get("conn") == []
    assert result.stats["conn"] == {"records": 0, "malformed": 0}


def test_zeek_malformed_rows_are_counted_not_fatal():
    lines = [
        '{"ts": 1.0, "uid": "C1", "id.orig_h": "10.0.0.1"}\n',
        '{"ts": 2.0, "uid": "C2"\n',  # truncated JSON
        '["not", "an", "object"]\n',
        '{"uid": "no-ts"}\n',
        '{"ts": "not-a-number"}\n',
        "garbage line\n",
    ]
    records, malformed = parse_zeek_lines(lines)
    assert [r["uid"] for r in records] == ["C1"]
    assert malformed == 5


def test_zeek_tsv_wrong_column_count():
    lines = TSV_CONN.splitlines(keepends=True)
    lines.insert(9, "1773484304.0\tCxyz\t10.0.0.1\n")
    records, malformed = parse_zeek_lines(lines)
    assert len(records) == 2 and malformed == 1


# --- Suricata ---------------------------------------------------------------------


def test_eve_demo_parse():
    result = parse_eve_file(DEMO_ANALYSIS / "suricata" / "eve.json")
    assert result.malformed == 0
    assert len(result.get("alert")) == 11
    assert len(result.get("flow")) == 35
    assert result.unsupported == {"stats": 1}


def test_eve_alert_fields():
    alerts = parse_eve_file(DEMO_ANALYSIS / "suricata" / "eve.json").get("alert")
    sids = {a["alert"]["signature_id"] for a in alerts}
    assert {9100001, 9100002, 9100003, 9100004, 9100005, 9100006, 9100007} <= sids
    first = min(alerts, key=lambda a: a["_ts"])
    assert first["src_ip"] == "203.0.113.45" and first["alert"]["severity"] == 1


def test_eve_flow_events():
    flows = parse_eve_file(DEMO_ANALYSIS / "suricata" / "eve.json").get("flow")
    assert all("flow" in f and "_ts" in f for f in flows)


def test_eve_malformed_json():
    result = parse_eve_lines(['{"event_type": "alert", "timestamp": "2026-03-14T10:31:08.120000+0000"}', "{oops", '{"timestamp": "x"}', "[]"])
    assert len(result.get("alert")) == 1
    assert result.malformed == 3


def test_eve_unsupported_event_types_are_counted():
    result = parse_eve_lines(
        [
            '{"event_type": "stats", "timestamp": "2026-03-14T10:31:08+0000"}',
            '{"event_type": "netflow", "timestamp": "2026-03-14T10:31:08+0000"}',
        ]
    )
    assert result.events == {}
    assert result.unsupported == {"stats": 1, "netflow": 1}


def test_eve_missing_file(tmp_path: Path):
    result = parse_eve_file(tmp_path / "eve.json")
    assert result.total == 0 and result.events == {}


def test_eve_timestamp_formats():
    assert parse_eve_timestamp("2026-03-14T10:31:08.120000+0000") == parse_eve_timestamp("2026-03-14T10:31:08.120000+00:00")
    assert round(parse_eve_timestamp("2026-03-14T10:31:08Z")) == 1773484268


def test_eve_flow_records_use_flow_start_time():
    line = (
        '{"event_type": "flow", "timestamp": "2026-03-14T10:32:50.008999+0000", "src_ip": "10.0.0.1", '
        '"flow": {"start": "2026-03-14T10:31:20.000000+0000", "end": "2026-03-14T10:31:20.180000+0000"}}'
    )
    flow = parse_eve_lines([line]).get("flow")[0]
    assert flow["_ts"] == parse_eve_timestamp("2026-03-14T10:31:20.000000+0000")

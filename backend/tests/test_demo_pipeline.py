"""Demo pipeline: synthetic PCAP -> analyzer outputs -> normalization -> correlation -> graph -> incident."""

import hashlib
import ipaddress
import os
import shutil
import struct
from pathlib import Path

import generate_demo_pcap as gen
import pytest

from app.correlation.engine import correlate
from app.graph.builder import build_incident
from app.normalization.normalizer import normalize
from app.parsers.suricata_eve import parse_eve_file
from app.parsers.zeek_logs import parse_zeek_directory


def read_pcap(data: bytes):
    magic, major, minor, _, _, snaplen, linktype = struct.unpack("<IHHiIII", data[:24])
    assert (magic, major, minor, linktype) == (0xA1B2C3D4, 2, 4, 1)
    off, packets = 24, []
    while off < len(data):
        sec, usec, incl, orig = struct.unpack("<IIII", data[off : off + 16])
        packets.append((sec + usec / 1e6, data[off + 16 : off + 16 + incl]))
        assert incl == orig <= snaplen
        off += 16 + incl
    assert off == len(data)
    return packets


def test_generator_is_deterministic():
    a, b = gen.build_capture(), gen.build_capture()
    assert hashlib.sha256(a).digest() == hashlib.sha256(b).digest()


def test_generated_pcap_is_valid_and_safe():
    packets = read_pcap(gen.build_capture())
    assert len(packets) > 300
    ts = [t for t, _ in packets]
    assert ts == sorted(ts)
    allowed = [ipaddress.ip_network(n) for n in ("10.20.0.0/16", "203.0.113.0/24", "198.51.100.0/24")]
    for _, frame in packets:
        assert frame[12:14] == b"\x08\x00"
        ip = frame[14:]
        assert gen.checksum(ip[:20]) == 0  # valid IPv4 header checksum
        for raw in (ip[12:16], ip[16:20]):
            addr = ipaddress.ip_address(raw)
            assert any(addr in n for n in allowed), addr
        proto, total = ip[9], struct.unpack("!H", ip[2:4])[0]
        seg = ip[20:total]
        pseudo = ip[12:20] + struct.pack("!BBH", 0, proto, len(seg))
        assert gen.checksum(pseudo + seg) == 0  # valid TCP/UDP checksum


def test_demo_markers_are_harmless():
    data = gen.build_capture()
    assert b"BREACHREPLAY-DEMO-MARKER-INITIAL-ACCESS" in data
    for forbidden in (b"/bin/sh", b"cmd.exe", b"powershell", b"\x90\x90\x90\x90\x90\x90\x90\x90", b"MZ\x90\x00"):
        assert forbidden not in data


def test_fixture_pipeline_to_incident(demo_context):
    from .conftest import DEMO_ANALYSIS

    zeek = parse_zeek_directory(DEMO_ANALYSIS / "zeek")
    eve = parse_eve_file(DEMO_ANALYSIS / "suricata" / "eve.json")
    n = normalize(zeek, eve, demo_context)
    inc = build_incident(n, correlate(n), name="demo", source_type="demo", demo=True)
    assert inc.incident_found
    assert [a for a in inc.primary_attack_path] == ["asset-203-0-113-45", "asset-web-01", "asset-ws-03", "asset-db-01"]


def _analyzer_mode() -> str | None:
    if os.environ.get("ZEEK_ANALYZER_URL") and os.environ.get("SURICATA_ANALYZER_URL") and os.environ.get("WORKSPACE_ROOT"):
        return "remote"
    if shutil.which("zeek") and shutil.which("suricata"):
        return "local"
    return None


@pytest.mark.analyzers
@pytest.mark.skipif(_analyzer_mode() is None, reason="no Zeek/Suricata available (binaries or analyzer containers)")
async def test_real_analyzers_reproduce_fixtures(tmp_path: Path, demo_context):
    """Runs the REAL analyzers on a freshly generated demo capture."""
    from app.analyzers.client import LocalAnalyzers, RemoteAnalyzers
    from app.storage.workspace import Workspace, new_job_id

    if _analyzer_mode() == "remote":
        analyzers = RemoteAnalyzers(os.environ["ZEEK_ANALYZER_URL"], os.environ["SURICATA_ANALYZER_URL"], 120)
        ws = Workspace(Path(os.environ["WORKSPACE_ROOT"]), new_job_id()).create()
    else:
        analyzers = LocalAnalyzers(120)
        ws = Workspace(tmp_path, new_job_id()).create()
    try:
        ws.capture.write_bytes(gen.build_capture())
        ws.capture.chmod(0o640)
        zeek_info = await analyzers.run_zeek(ws.path)
        suri_info = await analyzers.run_suricata(ws.path)
        assert "conn.log" in zeek_info["logs"] and "eve.json" in suri_info["logs"]
        n = normalize(parse_zeek_directory(ws.path / "zeek"), parse_eve_file(ws.path / "suricata" / "eve.json"), demo_context)
        inc = build_incident(n, correlate(n), name="demo", source_type="demo", demo=True)
        assert inc.primary_attack_path == ["asset-203-0-113-45", "asset-web-01", "asset-ws-03", "asset-db-01"]
        assert len(inc.events) == 7
        assert len(n.detections) == 13
    finally:
        ws.cleanup()

#!/usr/bin/env python3
"""Generate the BreachReplay synthetic demo capture.

The capture is SAFE and SYNTHETIC:

* every internal address is RFC1918 (10.20.0.0/16)
* the only "external" peers use RFC5737 documentation ranges
  (203.0.113.0/24, 198.51.100.0/24)
* hostnames use the reserved ``.example`` TLD
* payloads are plain-text markers (``BREACHREPLAY-DEMO-MARKER-*``) that the
  project-local Suricata rules in ``demo/rules`` recognise; there is no
  exploit code, malware, credential material or destructive content
* the NTLM exchange carries a fictional account name with *empty* challenge
  responses, so there is nothing to crack or replay

The generator is deterministic: the same output bytes are produced on every
run, so the analysis pipeline is reproducible.

Only the Python standard library is used. Packets carry correct IPv4, TCP and
UDP checksums so Zeek and Suricata process them like any other capture.

Scenario (all times UTC, 2026-03-14):

    10:30:00  baseline: DNS, internal web, normal database query, HTTPS egress
    10:31:00  external host probes WEB-01 over HTTP
    10:31:08  request carrying the initial-access demo marker + file upload
    10:31:20  WEB-01 beacons out to the external host (C2 demo marker)
    10:31:34  WEB-01 sweeps internal hosts on TCP/445 (service discovery)
    10:31:42  WEB-01 -> WS-03 SMB: NTLM session as "svc-demo", ADMIN$ share,
              demo file written
    10:32:12  WS-03 -> DB-01 PostgreSQL query containing crown-jewel marker
    10:32:38  WS-03 -> external host, large TLS upload (exfiltration demo SNI)
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "demo" / "generated" / "breachreplay-demo.pcap"

BASE_TIME = datetime(2026, 3, 14, 10, 30, 0, tzinfo=UTC).timestamp()

# --- Synthetic environment -------------------------------------------------

DNS_SERVER = "10.20.0.2"
WEB_01 = "10.20.1.10"
WS_01 = "10.20.2.21"
WS_02 = "10.20.2.22"
WS_03 = "10.20.2.33"
PRINTER = "10.20.2.34"
DB_01 = "10.20.3.50"
EXTERNAL_ACTOR = "203.0.113.45"  # RFC5737 TEST-NET-3
UPDATE_SERVER = "198.51.100.20"  # RFC5737 TEST-NET-2
GATEWAY_MAC = "02:00:00:00:00:01"

HOSTNAMES = {
    WEB_01: "web-01.corp.example",
    WS_01: "ws-01.corp.example",
    WS_02: "ws-02.corp.example",
    WS_03: "ws-03.corp.example",
    DB_01: "db-01.corp.example",
    DNS_SERVER: "dns-01.corp.example",
}

MARKER_INITIAL = "BREACHREPLAY-DEMO-MARKER-INITIAL-ACCESS"
MARKER_C2 = "BREACHREPLAY-DEMO-MARKER-BEACON"
MARKER_LATERAL = "BREACHREPLAY-DEMO-MARKER-LATERAL"
MARKER_CROWN = "BREACHREPLAY-DEMO-MARKER-CROWN-JEWEL"
EXFIL_SNI = "sync-drop.demo.example"
DEMO_ACCOUNT = "svc-demo"
DEMO_DOMAIN = "CORP-DEMO"


def mac_for(ip: str) -> bytes:
    """Locally-administered MAC per host; external hosts sit behind the gateway."""
    if not ip.startswith("10."):
        return bytes.fromhex(GATEWAY_MAC.replace(":", ""))
    octets = [int(o) for o in ip.split(".")]
    return bytes([0x02, 0x00, 0x0A, octets[1], octets[2], octets[3]])


def ip_bytes(ip: str) -> bytes:
    return bytes(int(o) for o in ip.split("."))


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def deterministic_bytes(seed: str, length: int) -> bytes:
    """Pseudo-random filler (stands in for encrypted bytes) derived from a seed."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        counter += 1
    return bytes(out[:length])


# --- Packet construction ---------------------------------------------------


class PcapWriter:
    def __init__(self) -> None:
        self.records: list[tuple[float, bytes]] = []
        self._ip_id = 1000

    def next_ip_id(self) -> int:
        self._ip_id = (self._ip_id + 1) & 0xFFFF
        return self._ip_id

    def add(self, ts: float, frame: bytes) -> None:
        self.records.append((ts, frame))

    def to_bytes(self) -> bytes:
        out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in sorted(self.records, key=lambda r: r[0]):
            sec = int(ts)
            usec = round((ts - sec) * 1_000_000)
            if usec >= 1_000_000:
                sec, usec = sec + 1, usec - 1_000_000
            out += struct.pack("<IIII", sec, usec, len(frame), len(frame))
            out += frame
        return bytes(out)


def ipv4_packet(writer: PcapWriter, src: str, dst: str, proto: int, payload: bytes) -> bytes:
    total_len = 20 + len(payload)
    ttl = 64 if src.startswith("10.") else 52
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        writer.next_ip_id(),
        0x4000,  # don't fragment
        ttl,
        proto,
        0,
        ip_bytes(src),
        ip_bytes(dst),
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def ethernet_frame(src: str, dst: str, ip_packet: bytes) -> bytes:
    return mac_for(dst) + mac_for(src) + b"\x08\x00" + ip_packet


def tcp_segment(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    offset = 5 << 4
    header = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, offset, flags, 64240, 0, 0)
    pseudo = ip_bytes(src) + ip_bytes(dst) + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    csum = checksum(pseudo + header + payload)
    return header[:16] + struct.pack("!H", csum) + header[18:] + payload


def udp_datagram(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = ip_bytes(src) + ip_bytes(dst) + struct.pack("!BBH", 0, 17, length)
    csum = checksum(pseudo + header + payload) or 0xFFFF
    return header[:6] + struct.pack("!H", csum) + payload


FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


@dataclass
class TcpSession:
    """A small TCP state machine that emits a well-formed conversation."""

    writer: PcapWriter
    client: str
    server: str
    sport: int
    dport: int
    t: float
    rtt: float = 0.002
    client_seq: int = field(default=0)
    server_seq: int = field(default=0)

    def __post_init__(self) -> None:
        seed = int(hashlib.sha256(f"{self.client}:{self.sport}->{self.server}:{self.dport}".encode()).hexdigest()[:8], 16)
        self.client_seq = seed
        self.server_seq = (seed * 7919) & 0xFFFFFFFF

    def _emit(self, from_client: bool, flags: int, payload: bytes = b"") -> None:
        if from_client:
            src, dst, sp, dp, seq, ack = self.client, self.server, self.sport, self.dport, self.client_seq, self.server_seq
        else:
            src, dst, sp, dp, seq, ack = self.server, self.client, self.dport, self.sport, self.server_seq, self.client_seq
        seg = tcp_segment(src, dst, sp, dp, seq, ack if flags & ACK else 0, flags, payload)
        self.writer.add(self.t, ethernet_frame(src, dst, ipv4_packet(self.writer, src, dst, 6, seg)))
        advance = len(payload) + (1 if flags & (SYN | FIN) else 0)
        if from_client:
            self.client_seq = (self.client_seq + advance) & 0xFFFFFFFF
        else:
            self.server_seq = (self.server_seq + advance) & 0xFFFFFFFF
        self.t += self.rtt / 2

    def handshake(self) -> TcpSession:
        self._emit(True, SYN)
        self._emit(False, SYN | ACK)
        self._emit(True, ACK)
        return self

    def refused(self) -> TcpSession:
        """SYN answered by RST (closed port)."""
        self._emit(True, SYN)
        self.server_seq = 0
        self.client_seq = (self.client_seq) & 0xFFFFFFFF
        self._emit(False, RST | ACK)
        return self

    def unanswered(self, retries: int = 1) -> TcpSession:
        for _ in range(retries + 1):
            seg_seq = self.client_seq
            self._emit(True, SYN)
            self.client_seq = seg_seq
            self.t += 0.5
        return self

    def _send(self, from_client: bool, data: bytes, mss: int = 1400) -> None:
        for i in range(0, len(data), mss):
            self._emit(from_client, PSH | ACK, data[i : i + mss])
        self._emit(not from_client, ACK)

    def client_send(self, data: bytes) -> TcpSession:
        self._send(True, data)
        return self

    def server_send(self, data: bytes) -> TcpSession:
        self._send(False, data)
        return self

    def pause(self, seconds: float) -> TcpSession:
        self.t += seconds
        return self

    def close(self) -> TcpSession:
        self._emit(True, FIN | ACK)
        self._emit(False, FIN | ACK)
        self._emit(True, ACK)
        return self


def udp_exchange(writer: PcapWriter, t: float, client: str, server: str, sport: int, dport: int, req: bytes, resp: bytes) -> None:
    writer.add(t, ethernet_frame(client, server, ipv4_packet(writer, client, server, 17, udp_datagram(client, server, sport, dport, req))))
    writer.add(
        t + 0.0015,
        ethernet_frame(server, client, ipv4_packet(writer, server, client, 17, udp_datagram(server, client, dport, sport, resp))),
    )


# --- Application payloads --------------------------------------------------


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def dns_query_response(txid: int, name: str, answer_ip: str | None) -> tuple[bytes, bytes]:
    question = dns_name(name) + struct.pack("!HH", 1, 1)
    query = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question
    if answer_ip is None:
        response = struct.pack("!HHHHHH", txid, 0x8183, 1, 0, 0, 0) + question  # NXDOMAIN
    else:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ip_bytes(answer_ip)
        response = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + question + answer
    return query, response


def http_request(method: str, host: str, path: str, headers: dict[str, str] | None = None, body: bytes = b"") -> bytes:
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", "User-Agent: BreachReplay-Demo-Client/1.0", "Accept: */*"]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def http_response(status: int, reason: str, body: bytes, content_type: str = "text/html") -> bytes:
    head = f"HTTP/1.1 {status} {reason}\r\nServer: demo-httpd\r\nContent-Type: {content_type}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    return head.encode() + body


def tls_client_hello(sni: str, seed: str) -> bytes:
    sni_bytes = sni.encode()
    server_name = b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
    sni_ext = struct.pack("!HH", 0x0000, len(server_name) + 2) + struct.pack("!H", len(server_name)) + server_name
    groups = struct.pack("!HHH", 0x000A, 4, 2) + struct.pack("!H", 0x0017)
    extensions = sni_ext + groups
    ciphers = struct.pack("!HHH", 4, 0xC02F, 0xC030)
    body = struct.pack("!H", 0x0303) + deterministic_bytes(seed + "-cr", 32) + b"\x00" + ciphers + b"\x01\x00" + struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def tls_server_hello(seed: str) -> bytes:
    body = struct.pack("!H", 0x0303) + deterministic_bytes(seed + "-sr", 32) + b"\x00" + struct.pack("!H", 0xC02F) + b"\x00"
    handshake = b"\x02" + struct.pack("!I", len(body))[1:] + body
    done = b"\x0e\x00\x00\x00"
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake + done)) + handshake + done


def tls_ccs_and_finished(seed: str) -> bytes:
    ccs = b"\x14\x03\x03\x00\x01\x01"
    finished = deterministic_bytes(seed + "-fin", 40)
    return ccs + b"\x16\x03\x03" + struct.pack("!H", len(finished)) + finished


def tls_app_data(seed: str, length: int) -> bytes:
    out = bytearray()
    chunk = 16000
    for i in range(0, length, chunk):
        data = deterministic_bytes(f"{seed}-{i}", min(chunk, length - i))
        out += b"\x17\x03\x03" + struct.pack("!H", len(data)) + data
    return bytes(out)


# SMB2 -----------------------------------------------------------------------

SMB2_NEGOTIATE, SMB2_SESSION_SETUP, SMB2_TREE_CONNECT, SMB2_CREATE, SMB2_CLOSE, SMB2_WRITE = 0x00, 0x01, 0x03, 0x05, 0x06, 0x09


def netbios(payload: bytes) -> bytes:
    return b"\x00" + struct.pack("!I", len(payload))[1:] + payload


def smb2_header(command: int, message_id: int, *, response: bool, status: int = 0, tree_id: int = 0, session_id: int = 0) -> bytes:
    flags = 0x00000001 if response else 0
    return (
        b"\xfeSMB" + struct.pack("<HHIHHIIQII", 64, 1, status, command, 1, flags, 0, message_id, 0xFEFF, tree_id) + struct.pack("<Q", session_id) + b"\x00" * 16
    )


def smb2_negotiate_request() -> bytes:
    body = struct.pack("<HHHHI", 36, 2, 1, 0, 0) + deterministic_bytes("client-guid", 16) + b"\x00" * 8 + struct.pack("<HH", 0x0202, 0x0210)
    return body


def smb2_negotiate_response() -> bytes:
    sec_offset = 64 + 64
    body = (
        struct.pack("<HHHH", 65, 1, 0x0210, 0)
        + deterministic_bytes("server-guid", 16)
        + struct.pack("<IIII", 0x7, 65536, 65536, 65536)
        + struct.pack("<QQ", 0, 0)
        + struct.pack("<HHI", sec_offset, 0, 0)
    )
    return body


def utf16(s: str) -> bytes:
    return s.encode("utf-16-le")


def ntlm_negotiate() -> bytes:
    flags = 0x00000001 | 0x00000004 | 0x00000200 | 0x00008000
    return b"NTLMSSP\x00" + struct.pack("<II", 1, flags) + struct.pack("<HHI", 0, 0, 0) * 2


def ntlm_challenge() -> bytes:
    target = utf16(DEMO_DOMAIN)
    flags = 0x00000001 | 0x00000004 | 0x00000200 | 0x00010000
    header_len = 48
    return (
        b"NTLMSSP\x00"
        + struct.pack("<I", 2)
        + struct.pack("<HHI", len(target), len(target), header_len)
        + struct.pack("<I", flags)
        + deterministic_bytes("server-challenge", 8)
        + b"\x00" * 8
        + struct.pack("<HHI", 0, 0, header_len + len(target))
        + target
    )


def ntlm_authenticate(user: str, domain: str, workstation: str) -> bytes:
    """AUTHENTICATE message with a fictional identity and EMPTY responses."""
    header_len = 64
    domain_b, user_b, ws_b = utf16(domain), utf16(user), utf16(workstation)
    off = header_len
    fields = b""
    fields += struct.pack("<HHI", 0, 0, off)  # LM response: empty
    fields += struct.pack("<HHI", 0, 0, off)  # NT response: empty
    fields += struct.pack("<HHI", len(domain_b), len(domain_b), off)
    off += len(domain_b)
    fields += struct.pack("<HHI", len(user_b), len(user_b), off)
    off += len(user_b)
    fields += struct.pack("<HHI", len(ws_b), len(ws_b), off)
    off += len(ws_b)
    fields += struct.pack("<HHI", 0, 0, off)  # session key: empty
    flags = 0x00000001 | 0x00000200
    return b"NTLMSSP\x00" + struct.pack("<I", 3) + fields + struct.pack("<I", flags) + domain_b + user_b + ws_b


def smb2_session_setup_request(blob: bytes) -> bytes:
    return struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 64 + 24, len(blob), 0) + blob


def smb2_session_setup_response(blob: bytes) -> bytes:
    return struct.pack("<HHHH", 9, 0, 64 + 8, len(blob)) + blob


def smb2_tree_connect_request(path: str) -> bytes:
    p = utf16(path)
    return struct.pack("<HHHH", 9, 0, 64 + 8, len(p)) + p


def smb2_tree_connect_response() -> bytes:
    # share type 1 = DISK
    return struct.pack("<HBBIII", 16, 1, 0, 0, 0, 0x001F01FF)


def smb2_create_request(name: str) -> bytes:
    n = utf16(name)
    return (
        struct.pack("<HBBIQQ", 57, 0, 0, 2, 0, 0)
        + struct.pack("<IIIII", 0x0012019F, 0x80, 0x7, 5, 0x40)  # access, attrs, share, OVERWRITE_IF, NON_DIRECTORY
        + struct.pack("<HHII", 64 + 56, len(n), 0, 0)
        + n
    )


FILE_ID = deterministic_bytes("file-id", 16)


def smb2_create_response() -> bytes:
    return struct.pack("<HBBI", 89, 0, 0, 2) + struct.pack("<QQQQ", 0, 0, 0, 0) + struct.pack("<QQII", 0, 0, 0x80, 0) + FILE_ID + struct.pack("<II", 0, 0)


def smb2_write_request(data: bytes) -> bytes:
    return struct.pack("<HHIQ", 49, 64 + 48, len(data), 0) + FILE_ID + struct.pack("<IIHHI", 0, 0, 0, 0, 0) + data


def smb2_write_response(count: int) -> bytes:
    return struct.pack("<HHIIHH", 17, 0, count, 0, 0, 0)


def smb2_close_request() -> bytes:
    return struct.pack("<HHI", 24, 0, 0) + FILE_ID


def smb2_close_response() -> bytes:
    return struct.pack("<HHI", 60, 0, 0) + b"\x00" * 52


# PostgreSQL -----------------------------------------------------------------


def pg_startup(user: str, database: str) -> bytes:
    params = b"user\x00" + user.encode() + b"\x00database\x00" + database.encode() + b"\x00\x00"
    return struct.pack("!II", 8 + len(params), 196608) + params


def pg_message(tag: bytes, payload: bytes) -> bytes:
    return tag + struct.pack("!I", 4 + len(payload)) + payload


def pg_query(sql: str) -> bytes:
    return pg_message(b"Q", sql.encode() + b"\x00")


def pg_auth_ok_ready() -> bytes:
    return pg_message(b"R", struct.pack("!I", 0)) + pg_message(b"Z", b"I")


def pg_rows(columns: list[str], rows: list[list[str]]) -> bytes:
    desc = struct.pack("!H", len(columns))
    for col in columns:
        desc += col.encode() + b"\x00" + struct.pack("!IHIhih", 0, 0, 25, -1, -1, 0)
    out = pg_message(b"T", desc)
    for row in rows:
        data = struct.pack("!H", len(row))
        for value in row:
            v = value.encode()
            data += struct.pack("!I", len(v)) + v
        out += pg_message(b"D", data)
    out += pg_message(b"C", f"SELECT {len(rows)}".encode() + b"\x00") + pg_message(b"Z", b"I")
    return out


# --- Scenario --------------------------------------------------------------


def at(seconds: float) -> float:
    return BASE_TIME + seconds


def build_capture() -> bytes:
    w = PcapWriter()
    port = iter(range(49200, 65000))

    # Baseline -----------------------------------------------------------
    txid = 0x1000
    lookups = [
        (2.0, WS_01, "web-01.corp.example", WEB_01),
        (4.5, WS_02, "web-01.corp.example", WEB_01),
        (7.0, WS_01, "db-01.corp.example", DB_01),
        (9.0, WS_03, "updates.vendor.example", UPDATE_SERVER),
        (12.0, WS_02, "ws-03.corp.example", WS_03),
        (15.0, WEB_01, "db-01.corp.example", DB_01),
        (20.0, WS_03, "ws-03.corp.example", WS_03),
        (24.0, WS_01, "ws-01.corp.example", WS_01),
        (26.0, WS_02, "ws-02.corp.example", WS_02),
        (28.0, WS_01, "intranet-wiki.corp.example", None),
    ]
    for offset, client, name, ip in lookups:
        q, r = dns_query_response(txid, name, ip)
        udp_exchange(w, at(offset), client, DNS_SERVER, next(port), 53, q, r)
        txid += 1

    for offset, client, path in [(3.0, WS_01, "/"), (5.0, WS_02, "/dashboard"), (18.0, WS_01, "/reports/weekly"), (40.0, WS_02, "/")]:
        s = TcpSession(w, client, WEB_01, next(port), 80, at(offset))
        s.handshake().client_send(http_request("GET", "web-01.corp.example", path))
        s.server_send(http_response(200, "OK", b"<html><body>Corp demo intranet</body></html>")).close()

    # Normal application query to the database (must NOT be treated as an attack).
    s = TcpSession(w, WS_01, DB_01, next(port), 5432, at(8.0))
    s.handshake().client_send(pg_startup("report_reader", "inventory")).server_send(pg_auth_ok_ready())
    s.client_send(pg_query("SELECT count(*) FROM inventory_items;")).server_send(pg_rows(["count"], [["1284"]])).close()

    # Routine HTTPS software-update check from WS-03.
    s = TcpSession(w, WS_03, UPDATE_SERVER, next(port), 443, at(10.0), rtt=0.03)
    s.handshake().client_send(tls_client_hello("updates.vendor.example", "upd"))
    s.server_send(tls_server_hello("upd")).client_send(tls_ccs_and_finished("upd-c")).server_send(tls_ccs_and_finished("upd-s"))
    s.client_send(tls_app_data("upd-req", 600)).server_send(tls_app_data("upd-resp", 4200)).close()

    # External interaction with WEB-01 -------------------------------------
    for offset, path in [(60.0, "/"), (61.5, "/admin"), (63.0, "/login"), (64.2, "/upload.php")]:
        s = TcpSession(w, EXTERNAL_ACTOR, WEB_01, next(port), 80, at(offset), rtt=0.04)
        s.handshake().client_send(http_request("GET", "web-01.corp.example", path))
        status = (404, "Not Found") if path == "/admin" else (200, "OK")
        s.server_send(http_response(status[0], status[1], b"<html><body>demo</body></html>")).close()

    # Initial access: request carrying the harmless demo marker, plus a benign text upload.
    upload_body = (
        b"--demo-boundary\r\n"
        b'Content-Disposition: form-data; name="file"; filename="breachreplay-demo.txt"\r\n'
        b"Content-Type: text/plain\r\n\r\n"
        + f"{MARKER_INITIAL}\nThis is a harmless BreachReplay demo file. It contains no code.\n".encode()
        + b"\r\n--demo-boundary--\r\n"
    )
    s = TcpSession(w, EXTERNAL_ACTOR, WEB_01, next(port), 80, at(68.0), rtt=0.04)
    s.handshake().client_send(
        http_request(
            "POST",
            "web-01.corp.example",
            f"/upload.php?demo={MARKER_INITIAL}",
            {"Content-Type": "multipart/form-data; boundary=demo-boundary", "X-BreachReplay-Demo": "initial-access"},
            upload_body,
        )
    )
    s.server_send(http_response(200, "OK", b"upload accepted (demo)", "text/plain")).close()

    # Command-and-control style beacons from WEB-01 to the external host.
    for i, offset in enumerate([80.0, 86.0, 92.0]):
        s = TcpSession(w, WEB_01, EXTERNAL_ACTOR, next(port), 8080, at(offset), rtt=0.04)
        s.handshake().client_send(http_request("GET", "203.0.113.45:8080", f"/beacon?id=web-01&seq={i}&tag={MARKER_C2}", {"X-BreachReplay-Demo": "beacon"}))
        s.server_send(http_response(200, "OK", b"noop", "text/plain")).close()

    # Internal service discovery: WEB-01 sweeps TCP/445.
    sweep_start = 94.0
    TcpSession(w, WEB_01, WS_01, next(port), 445, at(sweep_start)).refused()
    TcpSession(w, WEB_01, WS_02, next(port), 445, at(sweep_start + 0.4)).refused()
    TcpSession(w, WEB_01, PRINTER, next(port), 445, at(sweep_start + 0.8)).unanswered()
    s = TcpSession(w, WEB_01, WS_03, next(port), 445, at(sweep_start + 1.2))
    s.handshake().close()

    # Lateral movement: SMB2 from WEB-01 to WS-03 with ADMIN$ access.
    s = TcpSession(w, WEB_01, WS_03, next(port), 445, at(102.0))
    s.handshake()
    sid, tid = 0x0000100000000041, 0x5
    mid = 0

    def smb(cmd: int, req: bytes, resp: bytes, *, status: int = 0, tree: int = 0, sess: int = 0, resp_tree: int | None = None) -> None:
        nonlocal mid
        s.client_send(netbios(smb2_header(cmd, mid, response=False, tree_id=tree, session_id=sess) + req))
        rtree = tree if resp_tree is None else resp_tree
        s.server_send(netbios(smb2_header(cmd, mid, response=True, status=status, tree_id=rtree, session_id=sess) + resp))
        mid += 1
        s.pause(0.15)

    smb(SMB2_NEGOTIATE, smb2_negotiate_request(), smb2_negotiate_response())
    smb(
        SMB2_SESSION_SETUP,
        smb2_session_setup_request(ntlm_negotiate()),
        smb2_session_setup_response(ntlm_challenge()),
        status=0xC0000016,  # STATUS_MORE_PROCESSING_REQUIRED
        sess=sid,
    )
    smb(
        SMB2_SESSION_SETUP,
        smb2_session_setup_request(ntlm_authenticate(DEMO_ACCOUNT, DEMO_DOMAIN, "WEB-01")),
        smb2_session_setup_response(b""),
        sess=sid,
    )
    s.pause(0.6)
    smb(SMB2_TREE_CONNECT, smb2_tree_connect_request("\\\\10.20.2.33\\ADMIN$"), smb2_tree_connect_response(), sess=sid, resp_tree=tid)
    s.pause(1.2)
    smb(SMB2_CREATE, smb2_create_request("Temp\\breachreplay-demo-task.txt"), smb2_create_response(), tree=tid, sess=sid)
    demo_file = (f"{MARKER_LATERAL}\nHarmless BreachReplay demo artifact written over SMB.\nIt contains no executable content.\n").encode() * 12
    smb(SMB2_WRITE, smb2_write_request(demo_file), smb2_write_response(len(demo_file)), tree=tid, sess=sid)
    smb(SMB2_CLOSE, smb2_close_request(), smb2_close_response(), tree=tid, sess=sid)
    s.pause(1.0).close()

    # WS-03 resolves and queries DB-01 (crown jewel).
    q, r = dns_query_response(0x2001, "db-01.corp.example", DB_01)
    udp_exchange(w, at(131.0), WS_03, DNS_SERVER, next(port), 53, q, r)
    s = TcpSession(w, WS_03, DB_01, next(port), 5432, at(132.0))
    s.handshake().client_send(pg_startup("svc-demo", "customers")).server_send(pg_auth_ok_ready())
    s.pause(0.8)
    s.client_send(pg_query(f"SELECT customer_id, email, plan FROM customers /* {MARKER_CROWN} */;"))  # noqa: S608 - static synthetic payload
    rows = [[f"{i:05d}", f"demo-customer-{i:05d}@example.com", "standard"] for i in range(1, 401)]
    s.server_send(pg_rows(["customer_id", "email", "plan"], rows))
    s.pause(0.5).close()

    # Exfiltration-style large outbound TLS transfer from WS-03.
    q, r = dns_query_response(0x2002, EXFIL_SNI, EXTERNAL_ACTOR)
    udp_exchange(w, at(157.5), WS_03, DNS_SERVER, next(port), 53, q, r)
    s = TcpSession(w, WS_03, EXTERNAL_ACTOR, next(port), 443, at(158.0), rtt=0.04)
    s.handshake().client_send(tls_client_hello(EXFIL_SNI, "exf"))
    s.server_send(tls_server_hello("exf")).client_send(tls_ccs_and_finished("exf-c")).server_send(tls_ccs_and_finished("exf-s"))
    s.client_send(tls_app_data("exf-up", 180_000)).server_send(tls_app_data("exf-ack", 300)).close()

    # Some unrelated baseline noise after the incident.
    for offset, client, path in [(150.0, WS_02, "/status"), (170.0, WS_01, "/")]:
        s = TcpSession(w, client, WEB_01, next(port), 80, at(offset))
        s.handshake().client_send(http_request("GET", "web-01.corp.example", path))
        s.server_send(http_response(200, "OK", b"<html>ok</html>")).close()

    return w.to_bytes()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-o", "--output", type=Path, default=DEFAULT_OUTPUT, help="output .pcap path")
    args = parser.parse_args(argv)
    data = build_capture()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"wrote {args.output} ({len(data)} bytes, sha256 {digest[:16]}...)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

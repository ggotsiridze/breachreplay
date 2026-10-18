import struct

import pytest

from app.security.capture_validation import (
    CaptureValidationError,
    inspect_capture_header,
    sanitize_display_name,
    validate_capture_bytes,
    validate_filename,
)

PCAP_HEAD = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
MB = 1024 * 1024


def pcapng_head(link_type: int = 1) -> bytes:
    shb = struct.pack("<II", 0x0A0D0D0A, 28) + b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1) + struct.pack("<I", 28)
    idb = struct.pack("<IIHHI", 1, 20, link_type, 0, 65535) + struct.pack("<I", 20)
    return shb + idb


def test_valid_pcap():
    info = validate_capture_bytes(PCAP_HEAD, 1000, "capture.pcap", MB)
    assert info.format == "pcap"
    assert info.link_type == 1
    assert info.link_type_name == "Ethernet"


def test_valid_pcapng():
    info = validate_capture_bytes(pcapng_head(), 1000, "trace.PCAPNG", MB)
    assert info.format == "pcapng"
    assert info.link_type == 1


@pytest.mark.parametrize("name", ["notes.txt", "capture.pcap.exe", "capture", "image.png"])
def test_invalid_extension(name):
    with pytest.raises(CaptureValidationError) as exc:
        validate_filename(name)
    assert exc.value.code == "INVALID_EXTENSION"


def test_oversized_upload():
    with pytest.raises(CaptureValidationError) as exc:
        validate_capture_bytes(PCAP_HEAD, 2 * MB, "big.pcap", MB)
    assert exc.value.code == "FILE_TOO_LARGE"
    assert exc.value.status_code == 413


def test_empty_upload():
    with pytest.raises(CaptureValidationError) as exc:
        validate_capture_bytes(b"", 0, "empty.pcap", MB)
    assert exc.value.code == "EMPTY_FILE"


@pytest.mark.parametrize("head", [b"GIF89a" + b"\x00" * 30, b"\x00" * 40, b"#!/bin/sh\nrm -rf /\n" + b"\x00" * 20])
def test_malformed_capture_rejected(head):
    with pytest.raises(CaptureValidationError) as exc:
        inspect_capture_header(head)
    assert exc.value.code == "NOT_A_CAPTURE"


def test_bad_pcap_version_rejected():
    head = struct.pack("<IHHiIII", 0xA1B2C3D4, 9, 4, 0, 0, 65535, 1)
    with pytest.raises(CaptureValidationError) as exc:
        inspect_capture_header(head)
    assert exc.value.code == "MALFORMED_CAPTURE"


def test_unsupported_linktype():
    head = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 147)
    with pytest.raises(CaptureValidationError) as exc:
        validate_capture_bytes(head, 100, "usb.pcap", MB)
    assert exc.value.code == "UNSUPPORTED_LINKTYPE"


@pytest.mark.parametrize("name", ["../../etc/passwd.pcap", "..\\..\\win.pcap", "dir/capture.pcap", "/abs/capture.pcap"])
def test_path_traversal_rejected(name):
    with pytest.raises(CaptureValidationError) as exc:
        validate_filename(name)
    assert exc.value.code == "SUSPICIOUS_FILENAME"


@pytest.mark.parametrize("name", ["cap\x00.pcap", "cap\n.pcap", "a" * 300 + ".pcap"])
def test_suspicious_filename_rejected(name):
    with pytest.raises(CaptureValidationError) as exc:
        validate_filename(name)
    assert exc.value.code == "SUSPICIOUS_FILENAME"


def test_display_name_is_sanitized():
    assert sanitize_display_name("<script>x</script>.pcap") == "script_.pcap"  # path components dropped
    assert sanitize_display_name("my <b>capture</b>.pcap") == "b_.pcap"
    assert sanitize_display_name("weird name$(rm).pcap") == "weird name__rm_.pcap"
    assert "/" not in sanitize_display_name("a/b/c.pcap")

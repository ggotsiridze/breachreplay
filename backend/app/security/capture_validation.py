"""Validation of untrusted capture uploads.

The original filename is only ever used for display (after sanitising); the
file is stored under an internally generated name. Validation checks the
extension, size, and the capture's magic bytes / link type.
"""

from __future__ import annotations

import re
import struct
import unicodedata
from dataclasses import dataclass

ALLOWED_EXTENSIONS = (".pcap", ".pcapng", ".cap")

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("pcap", "<"),  # little-endian, microsecond
    b"\xa1\xb2\xc3\xd4": ("pcap", ">"),
    b"\x4d\x3c\xb2\xa1": ("pcap", "<"),  # nanosecond
    b"\xa1\xb2\x3c\x4d": ("pcap", ">"),
}
PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"

# Link types Zeek and Suricata can decode into IP traffic.
SUPPORTED_LINKTYPES = {
    0: "BSD loopback",
    1: "Ethernet",
    101: "Raw IP",
    113: "Linux cooked (SLL)",
    228: "Raw IPv4",
    229: "Raw IPv6",
    276: "Linux cooked v2 (SLL2)",
}

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._ -]")


class CaptureValidationError(ValueError):
    def __init__(self, code: str, title: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.title = title
        self.message = message
        self.status_code = status_code


@dataclass(frozen=True)
class CaptureInfo:
    format: str
    link_type: int | None
    link_type_name: str | None
    size_bytes: int
    display_name: str


def sanitize_display_name(filename: str | None) -> str:
    """A display-only version of an uploaded filename. Never used as a path."""
    if not filename:
        return "capture.pcap"
    base = filename.replace("\\", "/").split("/")[-1]
    base = unicodedata.normalize("NFKC", base)
    base = _SAFE_NAME.sub("_", base).strip(" .")
    return (base or "capture.pcap")[:96]


def validate_filename(filename: str | None) -> str:
    if not filename or not filename.strip():
        raise CaptureValidationError("INVALID_FILENAME", "INVALID FILE", "The upload has no filename.")
    if "\x00" in filename or any(ord(ch) < 32 for ch in filename):
        raise CaptureValidationError("SUSPICIOUS_FILENAME", "SUSPICIOUS FILENAME", "The filename contains control characters.")
    if "/" in filename or "\\" in filename or ".." in filename:
        raise CaptureValidationError("SUSPICIOUS_FILENAME", "SUSPICIOUS FILENAME", "The filename contains path components and was rejected.")
    if len(filename) > 255:
        raise CaptureValidationError("SUSPICIOUS_FILENAME", "SUSPICIOUS FILENAME", "The filename is too long.")
    lower = filename.lower()
    if not lower.endswith(ALLOWED_EXTENSIONS):
        raise CaptureValidationError(
            "INVALID_EXTENSION",
            "UNSUPPORTED FILE TYPE",
            "Only packet captures (.pcap, .pcapng, .cap) can be analyzed.",
        )
    return sanitize_display_name(filename)


def validate_size(size: int, max_bytes: int) -> None:
    if size > max_bytes:
        raise CaptureValidationError(
            "FILE_TOO_LARGE",
            "CAPTURE TOO LARGE",
            f"The capture exceeds the {max_bytes // (1024 * 1024)} MB upload limit.",
            status_code=413,
        )
    if size == 0:
        raise CaptureValidationError("EMPTY_FILE", "EMPTY CAPTURE", "The uploaded file is empty.")


def inspect_capture_header(head: bytes) -> tuple[str, int | None]:
    """Return (format, link_type) from the first bytes of a capture or raise."""
    if len(head) >= 24 and head[:4] in PCAP_MAGICS:
        fmt, endian = PCAP_MAGICS[head[:4]]
        major, minor = struct.unpack(f"{endian}HH", head[4:8])
        if major != 2:
            raise CaptureValidationError("MALFORMED_CAPTURE", "MALFORMED CAPTURE", f"Unsupported pcap version {major}.{minor}.")
        snaplen, network = struct.unpack(f"{endian}II", head[16:24])
        link_type = network & 0x0FFFFFFF
        if snaplen == 0:
            raise CaptureValidationError("MALFORMED_CAPTURE", "MALFORMED CAPTURE", "The pcap header declares a zero snapshot length.")
        return fmt, link_type
    if len(head) >= 28 and head[:4] == PCAPNG_SHB:
        bom = head[8:12]
        if bom == b"\x4d\x3c\x2b\x1a":
            endian = "<"
        elif bom == b"\x1a\x2b\x3c\x4d":
            endian = ">"
        else:
            raise CaptureValidationError("MALFORMED_CAPTURE", "MALFORMED CAPTURE", "Invalid pcapng byte-order magic.")
        (shb_len,) = struct.unpack(f"{endian}I", head[4:8])
        if shb_len < 28 or shb_len % 4:
            raise CaptureValidationError("MALFORMED_CAPTURE", "MALFORMED CAPTURE", "Invalid pcapng section header length.")
        link_type = None
        # The first Interface Description Block normally follows the SHB.
        idb = shb_len
        if len(head) >= idb + 12:
            block_type, _block_len = struct.unpack(f"{endian}II", head[idb : idb + 8])
            if block_type == 1:
                (link_type,) = struct.unpack(f"{endian}H", head[idb + 8 : idb + 10])
        return "pcapng", link_type
    raise CaptureValidationError(
        "NOT_A_CAPTURE",
        "UNSUPPORTED CAPTURE",
        "The file is not a pcap or pcapng packet capture (magic bytes did not match).",
    )


def validate_capture_bytes(head: bytes, size: int, filename: str | None, max_bytes: int) -> CaptureInfo:
    display = validate_filename(filename)
    validate_size(size, max_bytes)
    fmt, link_type = inspect_capture_header(head)
    if link_type is not None and link_type not in SUPPORTED_LINKTYPES:
        raise CaptureValidationError(
            "UNSUPPORTED_LINKTYPE",
            "UNSUPPORTED CAPTURE",
            f"Link type {link_type} is not supported. No compatible Ethernet/IP traffic could be analyzed.",
            status_code=422,
        )
    return CaptureInfo(
        format=fmt,
        link_type=link_type,
        link_type_name=SUPPORTED_LINKTYPES.get(link_type) if link_type is not None else None,
        size_bytes=size,
        display_name=display,
    )

"""Evidence-gated MITRE ATT&CK mapping.

A technique is only attached when the event's evidence satisfies the rule's
preconditions. When no rule applies, the event carries an explicit
"not mapped" reason instead of a decorative technique.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models import EventType, TechniqueMapping

ATTACK_URL = "https://attack.mitre.org/techniques/{}/"

TACTICS = {
    EventType.EXTERNAL_RECON: "Reconnaissance",
    EventType.INITIAL_ACCESS: "Initial Access",
    EventType.COMMAND_AND_CONTROL: "Command and Control",
    EventType.DISCOVERY: "Discovery",
    EventType.LATERAL_MOVEMENT: "Lateral Movement",
    EventType.CROWN_JEWEL_ACCESS: "Collection",
    EventType.EXFILTRATION: "Exfiltration",
    EventType.SUSPICIOUS_CONNECTION: "Suspicious Activity",
}

CATALOG: dict[str, tuple[str, str]] = {
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "Command and Control"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    "T1021.004": ("Remote Services: SSH", "Lateral Movement"),
    "T1021.006": ("Remote Services: Windows Remote Management", "Lateral Movement"),
    "T1213": ("Data from Information Repositories", "Collection"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
}


@dataclass(frozen=True)
class MappingContext:
    event_type: EventType
    confidence: int
    app_protocols: frozenset[str]
    destination_port: int | None
    detection_categories: frozenset[str]
    admin_shares: tuple[str, ...]
    destination_internal: bool
    source_internal: bool
    destination_is_known_c2: bool
    periodic: bool
    fanout_targets: int
    destination_is_database: bool


def _mapping(technique_id: str, reason: str, confidence: int) -> TechniqueMapping:
    name, tactic = CATALOG[technique_id]
    return TechniqueMapping(
        technique_id=technique_id,
        technique_name=name,
        tactic=tactic,
        reason=reason,
        confidence=max(0, min(100, confidence)),
        url=ATTACK_URL.format(technique_id.replace(".", "/")),
    )


def map_technique(ctx: MappingContext) -> tuple[TechniqueMapping | None, str]:
    """Return (mapping, explanation). ``mapping`` is None when evidence is insufficient."""
    et = ctx.event_type
    web = bool(ctx.app_protocols & {"http", "ssl", "tls"})

    if et == EventType.INITIAL_ACCESS:
        if "http" in ctx.app_protocols and "Web Application Attack" in ctx.detection_categories and ctx.destination_internal:
            return _mapping(
                "T1190",
                "Inbound HTTP request from an external host to an internal web server matched a web-application-attack "
                "signature, and the server began initiating suspicious activity afterwards.",
                min(ctx.confidence, 75),
            ), ""
        return None, "Not mapped: inbound activity lacked a web-application-attack detection on a public-facing service."

    if et == EventType.COMMAND_AND_CONTROL:
        if web and (ctx.periodic or any("Command and Control" in c for c in ctx.detection_categories)):
            return _mapping(
                "T1071.001",
                "An internal host already involved in suspicious activity made repeated outbound web-protocol requests "
                "to the external endpoint involved in initial access, matching a command-and-control detection.",
                min(ctx.confidence, 80),
            ), ""
        return None, "Not mapped: outbound activity was not web-protocol beaconing with corroborating detections."

    if et == EventType.DISCOVERY:
        if ctx.fanout_targets >= 3:
            return _mapping(
                "T1046",
                f"One internal host probed {ctx.fanout_targets} internal hosts on the same service port within seconds, "
                "with most attempts rejected or unanswered.",
                min(ctx.confidence, 80),
            ), ""
        return None, "Not mapped: fewer than three probed hosts."

    if et == EventType.LATERAL_MOVEMENT:
        protos = ctx.app_protocols
        port = ctx.destination_port
        if ("smb" in protos or port in (139, 445)) and any(s.upper().rstrip("\\").endswith(("ADMIN$", "C$")) for s in ctx.admin_shares):
            return _mapping(
                "T1021.002",
                "Administrative SMB share access (" + ", ".join(ctx.admin_shares) + ") observed between internal assets "
                "during the reconstructed suspicious sequence.",
                min(ctx.confidence, 85),
            ), ""
        if "rdp" in protos or port == 3389:
            return _mapping("T1021.001", "RDP session between internal assets during the suspicious sequence.", min(ctx.confidence, 75)), ""
        if "ssh" in protos or port == 22:
            return _mapping("T1021.004", "SSH session between internal assets during the suspicious sequence.", min(ctx.confidence, 70)), ""
        if port in (5985, 5986):
            return _mapping("T1021.006", "WinRM connection between internal assets during the suspicious sequence.", min(ctx.confidence, 70)), ""
        return None, "Not mapped: administrative-protocol use without share, session or service evidence specific enough for a technique."

    if et == EventType.CROWN_JEWEL_ACCESS:
        if ctx.destination_is_database and ctx.detection_categories:
            return _mapping(
                "T1213",
                "A host already involved in the incident queried the designated crown-jewel database, and the query "
                "matched a detection. Network evidence shows access, not what was read.",
                min(ctx.confidence, 60),
            ), ""
        return None, "Not mapped: crown-jewel access without detection evidence describing what was accessed."

    if et == EventType.EXFILTRATION:
        if ctx.destination_is_known_c2:
            return _mapping(
                "T1041",
                "Large outbound transfer from an affected internal host to the same external endpoint used for "
                "command-and-control traffic earlier in the incident.",
                min(ctx.confidence, 70),
            ), ""
        return None, "Not mapped: large outbound transfer, but the destination was not tied to earlier C2 activity."

    if et == EventType.EXTERNAL_RECON:
        return None, "Not mapped: a handful of web requests is not enough evidence for an Active Scanning technique."

    return None, "Not mapped: no ATT&CK rule matched the available evidence."

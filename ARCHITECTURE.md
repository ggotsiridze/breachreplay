# BreachReplay architecture

BreachReplay turns a packet capture into an explainable, replayable incident. This document describes each stage, the data model, and the boundaries between them.

```
                ┌─────────────────────────── docker network: analysis (internal, no egress) ───┐
 browser ──▶ nginx ──▶ FastAPI backend ──job id──▶ analyzer-zeek      (Zeek 7.0.5)              │
 (React)   :8080        :8000   │      ──job id──▶ analyzer-suricata  (Suricata 7.0.10)         │
                                │                        ▲                                       │
                                └──── shared volume: /workspaces/<job id>/capture.pcap ──────────┘
```

## 1. Analyzer pipeline

| Stage | Code | Notes |
|---|---|---|
| Upload & validation | `backend/app/security/capture_validation.py`, `pipeline.py` | Extension allow-list, size limit (streamed, aborted early), pcap/pcapng magic bytes, pcap version, supported link types, filename checks (path separators, `..`, control characters, length). |
| Workspace | `backend/app/storage/workspace.py` | `/workspaces/<32 hex job id>/capture.pcap`. The uploaded filename is display-only. The workspace is deleted when analysis ends unless `KEEP_WORKSPACES=true`. |
| Zeek | `backend/app/analyzers/zeek.py` | `zeek -C -D -r capture.pcap LogAscii::use_json=T breachreplay.zeek`. `-D` seeds Zeek's RNG so connection UIDs are reproducible. The policy (`analyzer/config/zeek/breachreplay.zeek`) raises notices for admin-share access and internal port sweeps. |
| Suricata | `backend/app/analyzers/suricata.py` | `suricata -r capture.pcap -l <out> -k none --runmode single -S <rules>`, which writes EVE JSON. Project-local rules: `demo/rules/breachreplay-demo.rules`. |
| Execution | `backend/app/analyzers/process.py` | Argument lists only, `shell=False`, new process session, timeout kills the process group, minimal environment, truncated diagnostics. |
| Workers | `backend/app/analyzers/worker.py` | Standard-library HTTP service inside each analyzer container (Python 3.9 compatible, because that is the analyzer images' system Python). `POST /analyze {"job_id": …}` accepts nothing else. |
| Client | `backend/app/analyzers/client.py` | `RemoteAnalyzers` (containers, default) or `LocalAnalyzers` (binaries on PATH, `ANALYZER_MODE=local`). |

Progress is published through states: `UPLOADING → VALIDATING → RUNNING_ZEEK → RUNNING_SURICATA → NORMALIZING → CORRELATING → BUILDING_GRAPH → COMPLETE | FAILED`, streamed on `/ws/incidents/{id}` (with a polling fallback in the UI).

Failures are typed: `ANALYZER_FAILED` (tool exit code and stderr tail), `UNSUPPORTED_CAPTURE` (no IP connections found), validation codes such as `NOT_A_CAPTURE` and `FILE_TOO_LARGE`. When analysis succeeds but no incident path is found, the result is a successful analysis with `incident_found=false`; nothing is fabricated.

## 2. Normalization

`backend/app/parsers/` reads Zeek logs (JSON and TSV, including `#fields`/`#types` headers) and Suricata EVE JSON. Malformed lines, empty and missing logs, and unsupported event types are counted in `stats` and never abort the run.

`backend/app/normalization/normalizer.py` produces:

- **Assets** (`assets.py`): every IP seen, excluding multicast and broadcast. Internal means RFC1918, CGNAT or IPv6 ULA/link-local. (Python's `is_private` also flags documentation ranges, so it is not used.) Hostnames come from DNS answers, then NTLM workstation names. Type is inferred from accepted services (database ports → DATABASE, DNS/Kerberos/LDAP → INFRASTRUCTURE, web → SERVER, initiator-only → WORKSTATION). Analyst context (`demo/asset-context.json`) can set roles and **crown jewels**. Without context, database servers are proposed as crown jewels and the reason says so.
- **NetworkEvidence**: one record per useful analyzer record, with a stable id (`ev-zeek-conn-00012`, `ev-suricata-alert-00003`, …), the source record id (Zeek uid / Suricata flow id), endpoints, protocol, a human summary and allow-listed metadata. Payload bytes are never copied.
- **Detections**: Suricata alerts (signature, sid, category, severity) and Zeek notices.
- **Activities**: one per conversation, keyed by Zeek uid, with Suricata events joined by 5-tuple (either direction, nearest in time). An activity accumulates HTTP requests, TLS SNI, SMB shares and files, NTLM identities, file transfers, detections and evidence ids.

## 3. Correlation

`backend/app/correlation/engine.py` is deterministic and does not use machine learning.

**Candidates** come from behaviour, not from single packets:

| Event type | Pattern |
|---|---|
| External probing | external → internal requests without detections (grouped per pair, 120 s gap) |
| Initial access | external → internal activity with an aligned detection |
| Command & control | internal → external, repeated (≥3 within 10 min) and/or with detections |
| Discovery | one source → ≥3 internal hosts on one port within 30 s, ≥2 rejected/unanswered |
| Lateral movement | internal → internal administrative protocol (SMB, RDP, SSH, WinRM, RPC) carrying data |
| Crown-jewel access | internal → crown-jewel asset carrying data |
| Exfiltration | internal → external, ≥100 KB sent and >5× the bytes received |

**Scoring** (`scoring.py`) treats each signal as independent evidence with weight *w*: `confidence = 1 − Π(1 − wᵢ)`. Weights are documented in code (for example, Suricata severity-1 alert 0.45, Zeek notice 0.20, source previously suspicious 0.25, within 120 s of that activity 0.10, admin share 0.15). Signals only use evidence available *up to that moment* (causal), plus detections aligned to the activity itself.

Labels: 0–39 OBSERVED · 40–64 SUSPICIOUS · 65–84 LIKELY · 85–99 HIGH CONFIDENCE. An event with no corroborating signal (detection, notice, previously suspicious source, known attacker endpoint, sweep or beacon pattern) is capped at 39, so one plain connection is never "suspicious".

OBSERVED candidates are kept only as precursors of a later suspicious event on the same pair (e.g. the probing before initial access). Everything else stays as evidence and is visible in the *All observed connections* view.

**State transitions** only escalate (NORMAL → SUSPICIOUS → AFFECTED) and are attached to the event that caused them. LIKELY or HIGH CONFIDENCE access into an asset makes it AFFECTED, and the UI calls it "high-confidence affected" only when the causing event was HIGH CONFIDENCE. The word *compromised* is deliberately not used.

## 4. MITRE ATT&CK

`backend/app/mitre/mapping.py` maps only when the event's evidence satisfies a rule's preconditions:

| Technique | Requires |
|---|---|
| T1190 Exploit Public-Facing Application | inbound HTTP + *Web Application Attack* detection to an internal server |
| T1071.001 Web Protocols | outbound web protocol + periodicity or C2-category detection |
| T1046 Network Service Discovery | ≥3 probed hosts |
| T1021.002 SMB/Windows Admin Shares | SMB + ADMIN$ or C$ tree connect |
| T1021.001 / .004 / .006 | RDP / SSH / WinRM session in the suspicious sequence |
| T1213 Data from Information Repositories | crown-jewel database access with a detection (mapping confidence capped at 60) |
| T1041 Exfiltration Over C2 Channel | large outbound transfer to the endpoint already used for C2 |

The mapping confidence never exceeds the event confidence. Unmapped events carry an explicit reason (for example, *"a handful of web requests is not enough evidence for an Active Scanning technique"*).

## 5. Incident graph

`backend/app/graph/builder.py` aggregates every activity into directed **edges** (protocols, services, ports, counts, bytes, evidence) and annotates them with incident events. Edges carrying only probes are capped at SUSPICIOUS: probing a host is not traversing to it.

The **primary attack path** is computed from access events (initial access, lateral movement, crown-jewel access) at SUSPICIOUS or above: start at the external source of initial access, expand in time order (earliest arrival), stop at the first crown jewel reached (or the deepest asset), and backtrack.

## 6. Replay state

`frontend/src/replay/engine.ts` builds a timeline (incident start minus a 3 s lead to end plus 4 s). `frameAt(timeline, t)` recomputes node states, revealed and active edges, current event and phase, crown-jewel status, and counters from scratch. Seeking is therefore exact and deterministic. At 1x, one replay second equals one second of capture time. The demo defaults to 5x, and the UI always shows the active speed (`5x REPLAY`).

React Flow renders custom nodes and edges. Edges compute their own Bézier geometry from node centres (backward edges arc above the path), animate an SVG packet along the active edge, and draw a containment marker on blocked edges. The layout (`graph/layout.ts`) is deterministic: the primary path runs left to right, probed siblings stack beneath the path asset that shares their discovery event, external peers sit above, and internal peers below.

## 7. Simulation model

`backend/app/simulation/engine.py` replays the observed events in time order:

- The attacker starts at the external source(s) of initial access.
- An event can only occur if its source was reached in the simulated scenario; otherwise it is `NOT_REACHED`.
- An event is `INTERRUPTED` when a selected control is active at its timestamp and matches it (isolated endpoint, blocked edge, destination port, protocol, segment boundary or identity).
- Occurring access events extend the set of reached assets.

Controls can be *in place before the incident* or *active from first detection* (the first detection involving the controlled asset, edge or port), or have a custom activation time. The result reports interrupted event and edge, reachable assets before and after, crown-jewel reachability, path length and duration, per-event outcomes with simulated state changes, contained assets and protected assets. It carries an explanation and a disclaimer: the observed path *would have been interrupted* under the hypothetical control, which is not a prediction of attacker behaviour. The incident object is never mutated (covered by tests).

## 8. Showcase mode

`scripts/export_showcase.py` runs the demo through a full-mode backend and saves `GET /api/incidents/{id}/export`: incident and evidence passed through `storage/sanitize.py`. That step masks internal IPv4 addresses (`10.x.x.33`), hashes non-documentation external addresses, keeps RFC 5737 documentation addresses, restricts evidence metadata to an allow-list, truncates URLs and drops user agents. With `SHOWCASE_MODE=true` the backend loads that file at start-up, reports every analyzer step as *precomputed*, disables uploads, and serves the same API, so replay, investigation and simulation behave identically.

## 9. Security boundaries

| Boundary | Control |
|---|---|
| Browser → nginx | static assets, strict CSP, `X-Frame-Options: DENY`, upload size limit |
| nginx → API | only `/api`, `/health`, `/ws` proxied; frontend never reaches analyzers |
| API → analyzers | internal Docker network (`internal: true`); request body is a validated job id |
| Analyzers | non-root, read-only rootfs, tmpfs `/tmp`, all capabilities dropped, `no-new-privileges`, no egress, offline file mode only |
| Data at rest | per-job workspace deleted after analysis; incidents kept in a bounded in-memory LRU |
| Public exports | sanitized and IP-masked; `PUBLIC_MODE` masks API responses |

## 10. Known limitations

- Rule-based correlation tuned on a synthetic scenario. It has not been evaluated on labeled real-world datasets, so no accuracy, precision or recall is claimed.
- Detection quality depends on the supplied Suricata rules. Only safe demo rules ship with the project.
- No authentication or persistence. It is meant for local or access-controlled deployments.
- Encrypted sessions are analyzed from metadata only.
- Simulation reasons over the observed path only.

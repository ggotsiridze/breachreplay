# Architecture diagrams

See [ARCHITECTURE.md](../../ARCHITECTURE.md) for the full description.

## Runtime topology

```mermaid
flowchart LR
  user([Browser]) -->|":8080"| nginx[nginx<br/>static UI + proxy]
  nginx -->|/api /ws /health| api[FastAPI backend]
  subgraph analysis [Docker network: analysis · internal, no egress]
    api -->|job id| zeek[analyzer-zeek<br/>Zeek 7.0.5]
    api -->|job id| suri[analyzer-suricata<br/>Suricata 7.0.10]
  end
  vol[(workspaces volume<br/>per-job capture + outputs)]
  api --- vol
  zeek --- vol
  suri --- vol
```

## Analysis pipeline

```mermaid
flowchart TD
  pcap[PCAP / PCAPNG] --> val[Validation<br/>extension · size · magic · link type]
  val --> ws[Isolated workspace]
  ws --> zeek[Zeek offline<br/>conn dns http ssl files smb ntlm notice]
  ws --> suri[Suricata offline<br/>EVE alert flow http tls dns smb fileinfo]
  zeek --> norm[Normalization<br/>assets · evidence · detections · activities]
  suri --> norm
  norm --> corr[Correlation engine<br/>candidates · weighted signals · labels · reasons]
  corr --> mitre[ATT&CK mapping<br/>evidence-gated]
  corr --> graph[Incident graph<br/>edges · state changes · primary path · crown jewels]
  mitre --> graph
  graph --> api[REST + WebSocket]
  api --> ui[Replay · Investigate · Contain]
  graph --> sim[Containment simulation<br/>separate SimulationResult]
  sim --> api
```

## Simulation semantics

```mermaid
sequenceDiagram
  participant O as Observed events (time order)
  participant S as Simulator
  participant C as Selected controls
  loop each event
    S->>S: source reached in simulation?
    alt not reached
      S-->>O: NOT_REACHED
    else control active and matching
      S->>C: matches(event)?
      S-->>O: INTERRUPTED (blocked_by)
    else
      S-->>O: OCCURRED (+ simulated state changes, reach expands)
    end
  end
```

import { useEffect, useMemo, useState } from 'react';

import { ConfidenceChip, ConfidenceMeter, Eyebrow, StateBadge, TechniqueChip, protocolText } from '../components/ui';
import { AssetIcon, CloseIcon, CrownIcon } from '../graph/icons';
import { formatClock } from '../replay/engine';
import { phaseColor } from '../replay/Timeline';
import { useApp } from '../stores/appStore';
import type { Asset, Incident, IncidentEdge, IncidentEvent, NetworkEvidence } from '../types/incident';

const fmtBytes = (n: number) => (n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`);

function useNames(incident: Incident) {
  return useMemo(() => new Map(incident.assets.map((a) => [a.id, a.internal ? a.display_name : a.ip])), [incident]);
}

export function EvidenceDrawer({ incident }: { incident: Incident }) {
  const { selection, select, setMode } = useApp();
  const close = () => {
    select(null);
    setMode('replay');
  };
  let body: React.ReactNode = null;
  if (selection?.kind === 'asset') {
    const asset = incident.assets.find((a) => a.id === selection.id);
    if (asset) body = <AssetDetail incident={incident} asset={asset} />;
  } else if (selection?.kind === 'event') {
    const event = incident.events.find((e) => e.id === selection.id);
    if (event) body = <EventDetail incident={incident} event={event} standalone />;
  } else if (selection?.kind === 'edge') {
    const edge = incident.edges.find((e) => e.id === selection.id);
    if (edge) body = <EdgeDetail incident={incident} edge={edge} />;
  }
  return (
    <aside className="br-drawer" data-testid="investigate-drawer" aria-label="Evidence">
      <div className="br-drawer-top">
        <Eyebrow>Investigate · observed evidence</Eyebrow>
        <button type="button" className="br-icon-btn" onClick={close} aria-label="Close evidence panel">
          <CloseIcon />
        </button>
      </div>
      {body ?? (
        <div className="br-empty">
          <p className="br-empty-title">Select something to investigate</p>
          <p className="br-muted">Click any system, connection or event to see the evidence behind it and why BreachReplay classified it the way it did.</p>
        </div>
      )}
    </aside>
  );
}

function AssetDetail({ incident, asset }: { incident: Incident; asset: Asset }) {
  const names = useNames(incident);
  const select = useApp((s) => s.select);
  const events = incident.events.filter((e) => e.source_asset_id === asset.id || e.target_asset_ids.includes(asset.id) || e.destination_asset_id === asset.id);
  const detections = incident.detections.filter((d) => d.source_asset_id === asset.id || d.destination_asset_id === asset.id);
  const highConfidence = incident.events.some((e) => e.confidence_label === 'HIGH CONFIDENCE' && e.state_changes.some((c) => c.asset_id === asset.id && c.to_state === 'AFFECTED'));
  const inbound = incident.edges.filter((e) => e.destination_asset_id === asset.id && e.event_ids.length);
  const outbound = incident.edges.filter((e) => e.source_asset_id === asset.id && e.event_ids.length);
  const key =
    events.find((e) => e.target_asset_ids.includes(asset.id) && e.on_primary_path) ??
    events.find((e) => e.state_changes.some((c) => c.asset_id === asset.id && c.to_state === 'AFFECTED')) ??
    events.find((e) => e.confidence_label !== 'OBSERVED');

  const timeline = [
    ...events.map((e) => ({ ts: e.timestamp, kind: 'event' as const, text: e.title, sub: e.confidence_label, id: e.id })),
    ...detections.map((d) => ({ ts: d.timestamp, kind: 'detection' as const, text: `${d.source === 'suricata' ? 'Suricata' : 'Zeek'} detection`, sub: d.signature, id: d.id })),
  ].sort((a, b) => a.ts - b.ts);

  return (
    <div className="br-detail" data-testid="asset-detail">
      <header className={`br-detail-head is-${asset.state.toLowerCase()}`}>
        <div className="br-detail-icon">
          <AssetIcon type={asset.asset_type} crown={asset.crown_jewel} size={24} />
        </div>
        <div>
          <h2 className="br-detail-title">{asset.internal ? asset.display_name : asset.ip}</h2>
          <div className="br-detail-sub">
            {asset.role} · <span className="br-mono">{asset.ip}</span>
          </div>
          {asset.hostname && <div className="br-detail-sub br-mono">{asset.hostname}</div>}
        </div>
      </header>
      <div className="br-eyebrow br-badges-label">Incident classification (end of capture)</div>
      <div className="br-detail-badges">
        <StateBadge state={asset.state} highConfidence={highConfidence} />
        {asset.crown_jewel && (
          <span className="br-chip br-crown-chip">
            <CrownIcon size={12} /> Crown jewel
          </span>
        )}
        {asset.services.slice(0, 3).map((s) => (
          <span key={s} className="br-chip br-chip-ghost br-mono">
            {s}
          </span>
        ))}
      </div>
      {asset.crown_jewel_reason && <p className="br-note">{asset.crown_jewel_reason}</p>}

      <h4 className="br-section">Observed timeline</h4>
      {timeline.length ? (
        <ol className="br-mini-timeline">
          {timeline.slice(0, 14).map((row) => (
            <li key={`${row.kind}-${row.id}`} className={`is-${row.kind}`}>
              <span className="br-mono br-mini-time">{formatClock(row.ts)}</span>
              {row.kind === 'event' ? (
                <button type="button" className="br-link" onClick={() => select({ kind: 'event', id: row.id })}>
                  {row.text}
                </button>
              ) : (
                <span>{row.text}</span>
              )}
              <span className="br-mini-sub">{row.sub}</span>
            </li>
          ))}
        </ol>
      ) : (
        <p className="br-muted br-small">No incident events involve this asset. Its connections are visible in “All observed connections”.</p>
      )}

      {(inbound.length > 0 || outbound.length > 0) && (
        <>
          <h4 className="br-section">Observed relationships</h4>
          <ul className="br-rel-list">
            {[...inbound, ...outbound].map((e) => (
              <li key={e.id}>
                <button type="button" className="br-rel" onClick={() => select({ kind: 'edge', id: e.id })}>
                  <span>{names.get(e.source_asset_id)}</span>
                  <span className="br-rel-arrow">→</span>
                  <span>{names.get(e.destination_asset_id)}</span>
                  <span className="br-mono br-muted">{protocolText(e.services.join(','), e.protocols[0] ?? null, e.ports.length === 1 ? e.ports[0] : null)}</span>
                </button>
              </li>
            ))}
          </ul>
        </>
      )}

      {key && (
        <>
          <h4 className="br-section">Key event</h4>
          <EventDetail incident={incident} event={key} />
        </>
      )}
    </div>
  );
}

export function EventDetail({ incident, event, standalone }: { incident: Incident; event: IncidentEvent; standalone?: boolean }) {
  const names = useNames(incident);
  const target = event.target_asset_ids.length > 1 ? event.target_asset_ids.map((t) => names.get(t)).join(', ') : names.get(event.destination_asset_id ?? '') ?? '—';
  const dets = incident.detections.filter((d) => event.detection_ids.includes(d.id));
  return (
    <div className={`br-event-detail ${standalone ? 'is-standalone' : ''}`} data-testid="event-detail">
      {standalone && (
        <header className="br-event-head">
          <span className="br-phase-dot" style={{ background: phaseColor(event.phase) }} />
          <div>
            <div className="br-eyebrow">{event.phase}</div>
            <h2 className="br-detail-title">{event.title}</h2>
          </div>
        </header>
      )}
      <div className="br-classification">
        <span className="br-eyebrow">Classification</span>
        <div className="br-class-line">
          {event.confidence_label} {event.title.toUpperCase()}
        </div>
      </div>

      <div className="br-relationship">
        <div className="br-rel-node">{names.get(event.source_asset_id ?? '') ?? '—'}</div>
        <div className="br-rel-down" aria-hidden>
          ↓
        </div>
        <div className="br-rel-node">{target}</div>
        <div className="br-rel-meta br-mono">{protocolText(event.service, event.protocol, event.destination_port)}</div>
        {event.identity && <div className="br-rel-meta">Account observed: {event.identity}</div>}
      </div>

      <div className="br-block">
        <span className="br-eyebrow">MITRE ATT&amp;CK</span>
        {event.technique ? (
          <div className="br-mitre" data-testid="mitre-mapping">
            <TechniqueChip id={event.technique.technique_id} name={event.technique.technique_name} url={event.technique.url} />
            <div className="br-mitre-tactic">Tactic: {event.technique.tactic} · mapping confidence {event.technique.confidence}%</div>
            <p className="br-mitre-reason">{event.technique.reason}</p>
          </div>
        ) : (
          <p className="br-muted br-small" data-testid="mitre-unmapped">
            {event.technique_reason ?? 'Not mapped.'}
          </p>
        )}
      </div>

      <div className="br-block">
        <div className="br-conf-row">
          <span className="br-eyebrow">Confidence</span>
          <ConfidenceChip label={event.confidence_label} />
        </div>
        <ConfidenceMeter value={event.confidence} label={event.confidence_label} />
      </div>

      <div className="br-block">
        <span className="br-eyebrow">Why?</span>
        <ul className="br-reasons" data-testid="reasons">
          {event.reasons.map((r) => (
            <li key={r.signal} className={r.signal === 'base' ? 'is-base' : ''}>
              <span className="br-reason-points br-mono">+{r.points}</span>
              <span>{r.text}</span>
            </li>
          ))}
        </ul>
        <p className="br-footnote">
          Evidence weights combine as 1 − Π(1 − w). Without a corroborating signal an event stays OBSERVED, so a single plain connection is never labelled malicious.
        </p>
      </div>

      {dets.length > 0 && (
        <div className="br-block">
          <span className="br-eyebrow">Detections</span>
          <ul className="br-dets">
            {dets.map((d) => (
              <li key={d.id}>
                <span className={`br-src-badge is-${d.source}`}>{d.source}</span>
                <span className="br-det-sig">{d.signature}</span>
                <span className="br-mono br-muted">{formatClock(d.timestamp)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <EvidenceList ids={event.evidence_ids} />
    </div>
  );
}

function EdgeDetail({ incident, edge }: { incident: Incident; edge: IncidentEdge }) {
  const names = useNames(incident);
  const select = useApp((s) => s.select);
  const events = incident.events.filter((e) => edge.event_ids.includes(e.id));
  return (
    <div className="br-detail" data-testid="edge-detail">
      <header className="br-detail-head">
        <div>
          <div className="br-eyebrow">Observed relationship</div>
          <h2 className="br-detail-title">
            {names.get(edge.source_asset_id)} → {names.get(edge.destination_asset_id)}
          </h2>
        </div>
      </header>
      <dl className="br-kv">
        <dt>Protocols</dt>
        <dd className="br-mono">{[...edge.protocols, ...edge.services].map((s) => s.toUpperCase()).join(' · ') || '—'}</dd>
        <dt>Destination ports</dt>
        <dd className="br-mono">{edge.ports.join(', ') || '—'}</dd>
        <dt>Connections</dt>
        <dd>{edge.connection_count}</dd>
        <dt>Bytes</dt>
        <dd>{fmtBytes(edge.bytes_total)}</dd>
        <dt>First / last seen</dt>
        <dd className="br-mono">
          {formatClock(edge.first_seen)} – {formatClock(edge.last_seen)}
        </dd>
        <dt>State</dt>
        <dd>{edge.state}</dd>
      </dl>
      {events.length > 0 ? (
        <>
          <h4 className="br-section">Incident events on this connection</h4>
          <ul className="br-rel-list">
            {events.map((e) => (
              <li key={e.id}>
                <button type="button" className="br-rel" onClick={() => select({ kind: 'event', id: e.id })}>
                  <span>{e.title}</span>
                  <ConfidenceChip label={e.confidence_label} />
                </button>
              </li>
            ))}
          </ul>
        </>
      ) : (
        <p className="br-note">Observed traffic only. No incident event was reconstructed on this connection.</p>
      )}
      <EvidenceList ids={edge.evidence_ids.slice(0, 40)} title="Connection records" />
    </div>
  );
}

function EvidenceList({ ids, title = 'Evidence' }: { ids: string[]; title?: string }) {
  const { evidence, loadEvidence, evidenceLoading } = useApp();
  const [open, setOpen] = useState<string | null>(null);
  const key = ids.join(',');
  useEffect(() => {
    void loadEvidence(ids);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  const items = ids.map((id) => evidence[id]).filter((x): x is NetworkEvidence => Boolean(x));
  return (
    <div className="br-block" data-testid="evidence-list">
      <div className="br-conf-row">
        <span className="br-eyebrow">{title}</span>
        <span className="br-muted br-small">{ids.length} records</span>
      </div>
      {evidenceLoading && items.length === 0 && <div className="br-skeleton" />}
      <ul className="br-evidence">
        {items.map((ev) => (
          <li key={ev.id} className={open === ev.id ? 'is-open' : ''}>
            <button type="button" className="br-evidence-row" onClick={() => setOpen(open === ev.id ? null : ev.id)} aria-expanded={open === ev.id}>
              <span className={`br-src-badge is-${ev.source}`}>{ev.source === 'zeek' ? `zeek ${ev.log_type}` : ev.log_type.replace('eve.', 'eve ')}</span>
              <span className="br-evidence-summary">{ev.summary}</span>
            </button>
            {open === ev.id && (
              <dl className="br-kv br-kv-tight">
                <dt>Record</dt>
                <dd className="br-mono">{ev.id}</dd>
                <dt>Time</dt>
                <dd className="br-mono">{formatClock(ev.timestamp)} UTC</dd>
                {ev.source_record_id && (
                  <>
                    <dt>{ev.source === 'zeek' ? 'Zeek uid' : 'Flow id'}</dt>
                    <dd className="br-mono">{ev.source_record_id}</dd>
                  </>
                )}
                <dt>Endpoints</dt>
                <dd className="br-mono">
                  {ev.source_ip}:{ev.source_port ?? '-'} → {ev.destination_ip}:{ev.destination_port ?? '-'}
                </dd>
                {Object.entries(ev.metadata).map(([k, v]) => (
                  <MetaRow key={k} k={k} v={v} />
                ))}
              </dl>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function MetaRow({ k, v }: { k: string; v: unknown }) {
  const text = Array.isArray(v) ? v.join(', ') : typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v);
  return (
    <>
      <dt>{k.replace(/_/g, ' ')}</dt>
      <dd className="br-mono">{text}</dd>
    </>
  );
}

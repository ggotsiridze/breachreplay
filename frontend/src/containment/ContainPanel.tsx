import { useEffect, useMemo, useRef, useState } from 'react';

import { Eyebrow } from '../components/ui';
import { ShieldIcon } from '../graph/icons';
import { useApp } from '../stores/appStore';
import type { Activation, ContainmentControl, ControlType, Incident } from '../types/incident';
import { ComparisonPanel } from './ComparisonPanel';

interface Draft {
  enabled: boolean;
  value: string;
  activation: Activation;
}

const LABELS: Record<ControlType, { title: string; hint: string }> = {
  isolate_asset: { title: 'Isolate asset', hint: 'Cut the asset off from all modeled traffic' },
  block_edge: { title: 'Block connection', hint: 'Deny one observed relationship' },
  block_port: { title: 'Block destination port', hint: 'Deny traffic to a port' },
  block_protocol: { title: 'Block protocol', hint: 'Deny an application protocol' },
  segment_assets: { title: 'Segment asset', hint: 'Deny traffic crossing into or out of it' },
  disable_identity: { title: 'Disable observed account', hint: 'Account seen in authentication evidence' },
};

export function useControlOptions(incident: Incident) {
  return useMemo(() => {
    const names = new Map(incident.assets.map((a) => [a.id, a.internal ? a.display_name : a.ip]));
    const involved = new Set<string>();
    for (const e of incident.events) {
      if (e.confidence_label === 'OBSERVED') continue;
      if (e.source_asset_id) involved.add(e.source_asset_id);
      if (e.destination_asset_id) involved.add(e.destination_asset_id);
    }
    const path = incident.primary_attack_path;
    const rank = (id: string) => (path.includes(id) ? path.indexOf(id) : 100);
    const internal = incident.assets
      .filter((a) => a.internal && involved.has(a.id))
      .sort((a, b) => rank(a.id) - rank(b.id) || a.display_name.localeCompare(b.display_name));
    const edges = incident.edges
      .filter((e) => e.event_ids.length && e.state !== 'SUSPICIOUS')
      .sort((a, b) => Number(b.on_primary_path) - Number(a.on_primary_path) || a.first_seen - b.first_seen);
    const ports = [...new Set(incident.events.filter((e) => e.confidence_label !== 'OBSERVED' && e.destination_port).map((e) => e.destination_port as number))].sort((a, b) => a - b);
    const protocols = [
      ...new Set(
        incident.events
          .filter((e) => e.confidence_label !== 'OBSERVED')
          .flatMap((e) => (e.service ?? '').split(','))
          .filter(Boolean),
      ),
    ].sort();
    const identities = incident.summary.identities;
    const firstLateral = incident.events.find((e) => e.event_type === 'lateral_movement' && e.on_primary_path);
    return {
      names,
      assets: internal.map((a) => ({ value: a.id, label: `${a.display_name} · ${a.role}` })),
      edges: edges.map((e) => ({ value: e.id, label: `${names.get(e.source_asset_id)} → ${names.get(e.destination_asset_id)}` })),
      ports: ports.map((p) => ({ value: String(p), label: `TCP/${p}` })),
      protocols: protocols.map((p) => ({ value: p, label: p === 'ssl' ? 'TLS' : p.toUpperCase() })),
      identities: identities.map((i) => ({ value: i, label: i })),
      defaultIsolate: firstLateral?.destination_asset_id ?? internal[0]?.id ?? '',
    };
  }, [incident]);
}

export function ContainPanel({ incident }: { incident: Incident }) {
  const { runSimulation, simulating, simulationError, simulation, clearSimulation, setT, setPlaying, scenario, setScenario } = useApp();
  const options = useControlOptions(incident);
  const resultRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (simulation) resultRef.current?.scrollIntoView?.({ behavior: 'smooth', block: 'start' });
  }, [simulation]);
  const crownName = incident.crown_jewels.map((id) => options.names.get(id)).join(', ');

  const [drafts, setDrafts] = useState<Record<ControlType, Draft>>(() => ({
    isolate_asset: { enabled: true, value: options.defaultIsolate, activation: 'first_detection' },
    block_edge: { enabled: false, value: options.edges[0]?.value ?? '', activation: 'preventive' },
    block_port: { enabled: false, value: options.ports[0]?.value ?? '', activation: 'preventive' },
    block_protocol: { enabled: false, value: options.protocols[0]?.value ?? '', activation: 'preventive' },
    segment_assets: { enabled: false, value: incident.crown_jewels[0] ?? options.assets[0]?.value ?? '', activation: 'preventive' },
    disable_identity: { enabled: false, value: options.identities[0]?.value ?? '', activation: 'preventive' },
  }));

  const choices: Record<ControlType, { value: string; label: string }[]> = {
    isolate_asset: options.assets,
    block_edge: options.edges,
    block_port: options.ports,
    block_protocol: options.protocols,
    segment_assets: options.assets,
    disable_identity: options.identities,
  };

  const update = (type: ControlType, patch: Partial<Draft>) => setDrafts((d) => ({ ...d, [type]: { ...d[type], ...patch } }));

  const controls: ContainmentControl[] = (Object.keys(drafts) as ControlType[])
    .filter((t) => drafts[t].enabled && drafts[t].value)
    .map((t) => {
      const d = drafts[t];
      const c: ContainmentControl = { control_type: t, activation: d.activation };
      if (t === 'isolate_asset') c.asset_id = d.value;
      if (t === 'block_edge') c.edge_id = d.value;
      if (t === 'block_port') c.port = Number(d.value);
      if (t === 'block_protocol') c.protocol = d.value;
      if (t === 'segment_assets') c.segment_asset_ids = [d.value];
      if (t === 'disable_identity') c.identity = d.value;
      return c;
    });

  return (
    <aside className="br-contain" data-testid="contain-panel" aria-label="Simulated containment">
      <div className="br-contain-head">
        <Eyebrow className="is-green">
          <ShieldIcon size={12} /> Simulated containment
        </Eyebrow>
        <h2 className="br-contain-title">Stop the breach</h2>
        <p className="br-muted br-small">
          Pick hypothetical controls. BreachReplay replays the <strong>same observed attack graph</strong> with the controls applied and shows where the observed
          path would have been interrupted{crownName ? ` before reaching ${crownName}` : ''}.
        </p>
      </div>

      <div className="br-controls-list">
        {(Object.keys(drafts) as ControlType[]).map((type) => {
          const opts = choices[type];
          if (!opts.length) return null;
          const d = drafts[type];
          return (
            <div key={type} className={`br-control ${d.enabled ? 'is-on' : ''}`} data-testid={`control-${type}`}>
              <label className="br-control-toggle">
                <input type="checkbox" checked={d.enabled} onChange={(e) => update(type, { enabled: e.target.checked })} aria-label={LABELS[type].title} />
                <span className="br-check" aria-hidden />
                <span className="br-control-text">
                  <span className="br-control-title">{LABELS[type].title}</span>
                  <span className="br-control-hint">{LABELS[type].hint}</span>
                </span>
              </label>
              {d.enabled && (
                <div className="br-control-opts">
                  <select value={d.value} onChange={(e) => update(type, { value: e.target.value })} aria-label={`${LABELS[type].title} target`}>
                    {opts.map((o) => (
                      <option key={o.value} value={o.value}>
                        {o.label}
                      </option>
                    ))}
                  </select>
                  <select value={d.activation} onChange={(e) => update(type, { activation: e.target.value as Activation })} aria-label={`${LABELS[type].title} activation`}>
                    <option value="first_detection">Active from first detection</option>
                    <option value="preventive">In place before the incident</option>
                  </select>
                </div>
              )}
            </div>
          );
        })}
      </div>

      <button type="button" className="br-run" disabled={!controls.length || simulating} onClick={() => void runSimulation(controls)} data-testid="run-simulation">
        {simulating ? 'Simulating…' : simulation ? 'Run simulation again' : 'Run simulation'}
      </button>
      {simulationError && (
        <p className="br-error-inline" role="alert">
          {simulationError}
        </p>
      )}

      {simulation && (
        <div className="br-sim-result" ref={resultRef}>
          <ComparisonPanel incident={incident} result={simulation} />
          <div className="br-sim-actions">
            <button
              type="button"
              className="br-btn"
              onClick={() => {
                if (scenario !== 'simulated') setScenario('simulated');
                setT(0);
                setPlaying(true);
              }}
            >
              Replay simulation
            </button>
            <button type="button" className="br-btn" onClick={() => setScenario(scenario === 'simulated' ? 'observed' : 'simulated')}>
              Show {scenario === 'simulated' ? 'observed' : 'simulated'}
            </button>
            <button type="button" className="br-btn br-btn-ghost" onClick={clearSimulation}>
              Clear
            </button>
          </div>
        </div>
      )}
    </aside>
  );
}

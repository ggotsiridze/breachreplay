import { Eyebrow } from '../components/ui';
import type { Incident, SimulationResult } from '../types/incident';

const secs = (s: number | null) => (s === null ? '—' : `${Math.round(s)} sec`);

export function ComparisonPanel({ incident, result }: { incident: Incident; result: SimulationResult }) {
  const names = new Map(incident.assets.map((a) => [a.id, a.internal ? a.display_name : a.ip]));
  const o = result.observed;
  const s = result.simulated;
  const protectedJewel = o.crown_jewel_reached && !s.crown_jewel_reached;
  const interrupted = result.interrupted_event_id !== null;
  const rows: { label: string; observed: string; simulated: string; better: boolean }[] = [
    { label: 'Assets reached', observed: String(o.assets_reached), simulated: String(s.assets_reached), better: s.assets_reached < o.assets_reached },
    { label: 'Affected assets', observed: String(o.affected_assets), simulated: String(s.affected_assets), better: s.affected_assets < o.affected_assets },
    { label: 'Crown jewel reached', observed: o.crown_jewel_reached ? 'YES' : 'NO', simulated: s.crown_jewel_reached ? 'YES' : 'NO', better: protectedJewel },
    { label: 'Observed path', observed: o.path_complete ? 'COMPLETE' : 'PARTIAL', simulated: s.path_complete ? 'COMPLETE' : 'INTERRUPTED', better: !s.path_complete && o.path_complete },
    { label: 'Path duration', observed: secs(o.path_duration_seconds), simulated: secs(s.path_duration_seconds), better: (s.path_duration_seconds ?? 0) < (o.path_duration_seconds ?? 0) },
  ];
  const interruptedEvent = incident.events.find((e) => e.id === result.interrupted_event_id);
  return (
    <section className={`br-compare ${protectedJewel ? 'is-protected' : interrupted ? 'is-interrupted' : 'is-none'}`} data-testid="comparison-panel">
      <div className="br-compare-verdict">
        <Eyebrow>{protectedJewel ? 'Breach interrupted' : interrupted ? 'Path interrupted' : 'No interruption'}</Eyebrow>
        {interruptedEvent ? (
          <div className="br-compare-where">
            Interrupted at{' '}
            <strong>
              {names.get(interruptedEvent.source_asset_id ?? '')} → {names.get(interruptedEvent.destination_asset_id ?? '') ?? `${interruptedEvent.target_asset_ids.length} hosts`}
            </strong>{' '}
            ({interruptedEvent.title.toLowerCase()})
          </div>
        ) : (
          <div className="br-compare-where">The selected controls do not match any step of the observed path when it occurred.</div>
        )}
      </div>
      <table className="br-compare-table">
        <thead>
          <tr>
            <th />
            <th className="is-observed">Observed</th>
            <th className="is-simulated">Simulated</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.label}>
              <th scope="row">{r.label}</th>
              <td className="is-observed br-mono">{r.observed}</td>
              <td className={`is-simulated br-mono ${r.better ? 'is-better' : ''}`} data-testid={`compare-${r.label.toLowerCase().replace(/ /g, '-')}`}>
                {r.simulated}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="br-compare-explain">{result.explanation}</p>
      <p className="br-footnote">{result.disclaimer}</p>
    </section>
  );
}

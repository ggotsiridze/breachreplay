import { ConfidenceChip } from '../components/ui';
import { useApp } from '../stores/appStore';
import type { Incident } from '../types/incident';
import { type ReplayFrame, type Timeline, formatOffset } from './engine';
import { phaseColor } from './Timeline';

export function EventFeed({ incident, timeline, frame }: { incident: Incident; timeline: Timeline; frame: ReplayFrame }) {
  const { select, setT, setPlaying, selection } = useApp();
  const names = new Map(incident.assets.map((a) => [a.id, a.internal ? a.display_name : a.ip]));
  return (
    <section className="br-card br-feed">
      <div className="br-feed-head">
        <span className="br-eyebrow">Reconstructed events</span>
        <span className="br-muted br-small">
          {frame.counters.events}/{timeline.events.length}
        </span>
      </div>
      <ol className="br-feed-list" data-testid="event-feed">
        {timeline.events.map((te, i) => {
          const target = te.event.target_asset_ids.length > 1 ? `${te.event.target_asset_ids.length} hosts` : names.get(te.event.destination_asset_id ?? '') ?? '';
          return (
            <li key={te.event.id}>
              <button
                type="button"
                className={[
                  'br-feed-item',
                  i <= frame.currentIndex ? 'is-past' : 'is-future',
                  i === frame.currentIndex ? 'is-current' : '',
                  selection?.kind === 'event' && selection.id === te.event.id ? 'is-selected' : '',
                  te.outcome !== 'OCCURRED' && i <= frame.currentIndex ? `is-${te.outcome.toLowerCase().replace('_', '-')}` : '',
                ].join(' ')}
                onClick={() => {
                  setPlaying(false);
                  setT(te.at + 0.01);
                  select({ kind: 'event', id: te.event.id });
                }}
                data-testid={`feed-${te.event.id}`}
              >
                <span className="br-feed-rail" style={{ background: phaseColor(te.event.phase) }} />
                <span className="br-feed-time br-mono">{formatOffset(te.at)}</span>
                <span className="br-feed-main">
                  <span className="br-feed-title">{te.event.title}</span>
                  <span className="br-feed-sub">
                    {names.get(te.event.source_asset_id ?? '')} → {target}
                  </span>
                </span>
                <ConfidenceChip label={te.event.confidence_label} />
              </button>
            </li>
          );
        })}
      </ol>
    </section>
  );
}

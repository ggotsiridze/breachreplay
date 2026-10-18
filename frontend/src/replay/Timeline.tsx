import { type CSSProperties, useMemo } from 'react';

import { useApp } from '../stores/appStore';
import { type ReplayFrame, type Timeline as TimelineModel, formatOffset } from './engine';

const PHASE_COLORS: Record<string, string> = {
  Reconnaissance: 'var(--c-slate)',
  'Initial Access': 'var(--c-amber)',
  'Command and Control': 'var(--c-violet)',
  Discovery: 'var(--c-cyan)',
  'Lateral Movement': 'var(--c-red)',
  Collection: 'var(--c-gold)',
  Exfiltration: 'var(--c-red-deep)',
};

const SHORT: Record<string, string> = { Reconnaissance: 'Recon', 'Command and Control': 'C2' };

export function phaseColor(phase: string): string {
  return PHASE_COLORS[phase] ?? 'var(--c-slate)';
}

export function Timeline({ timeline, frame }: { timeline: TimelineModel; frame: ReplayFrame }) {
  const setT = useApp((s) => s.setT);
  const setPlaying = useApp((s) => s.setPlaying);
  const pct = (x: number) => `${(Math.min(Math.max(x / timeline.duration, 0), 1) * 100).toFixed(3)}%`;

  const markers = useMemo(
    () =>
      timeline.events.map((te, i) => ({
        i,
        id: te.event.id,
        left: pct(te.at),
        label: te.event.confidence_label,
        crown: te.event.event_type === 'crown_jewel_access',
        outcome: te.outcome,
        title: `${formatOffset(te.at)} · ${te.event.title}`,
        at: te.at,
      })),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [timeline],
  );

  return (
    <div className="br-timeline" style={{ '--progress': pct(frame.t) } as CSSProperties}>
      <div className="br-timeline-phases" aria-hidden>
        {timeline.phases.map((p) => (
          <div
            key={`${p.phase}-${p.from}`}
            className={`br-timeline-phase ${frame.phase === p.phase ? 'is-current' : ''}`}
            style={{ left: pct(p.from), width: `calc(${pct(p.to)} - ${pct(p.from)})`, '--phase': phaseColor(p.phase) } as CSSProperties}
          >
            <span>{SHORT[p.phase] ?? p.phase}</span>
          </div>
        ))}
      </div>
      <div className="br-timeline-track">
        <div className="br-timeline-fill" />
        {markers.map((m) => (
          <button
            key={m.id}
            type="button"
            className={[
              'br-timeline-marker',
              `is-${m.label.replace(' ', '-').toLowerCase()}`,
              m.crown ? 'is-crown' : '',
              m.outcome !== 'OCCURRED' ? `is-${m.outcome.toLowerCase().replace('_', '-')}` : '',
              m.i <= frame.currentIndex ? 'is-past' : '',
              m.i === frame.currentIndex ? 'is-current' : '',
            ].join(' ')}
            style={{ left: m.left }}
            title={m.title}
            aria-label={`Jump to ${m.title}`}
            onClick={() => {
              setPlaying(false);
              setT(m.at + 0.01);
            }}
          />
        ))}
        {timeline.interruptionAt !== null && <div className="br-timeline-interrupt" style={{ left: pct(timeline.interruptionAt) }} title="Simulated interruption" />}
        <div className="br-timeline-head" />
        <input
          className="br-timeline-input"
          type="range"
          min={0}
          max={timeline.duration}
          step={0.05}
          value={frame.t}
          aria-label="Replay timeline"
          data-testid="timeline-scrubber"
          onChange={(e) => {
            setPlaying(false);
            setT(Number(e.target.value));
          }}
        />
      </div>
    </div>
  );
}

import { AnimatePresence, motion } from 'framer-motion';

import { ConfidenceChip, ConfidenceMeter, Eyebrow, TechniqueChip, protocolText } from '../components/ui';
import type { Incident } from '../types/incident';
import { type ReplayFrame, formatOffset } from './engine';
import { phaseColor } from './Timeline';

export function CurrentEvent({ incident, frame }: { incident: Incident; frame: ReplayFrame }) {
  const te = frame.current;
  const names = new Map(incident.assets.map((a) => [a.id, a.internal ? a.display_name : a.ip]));
  return (
    <section className="br-card br-current" data-testid="current-event" aria-live="polite">
      <Eyebrow>Current event</Eyebrow>
      <AnimatePresence mode="wait" initial={false}>
        {te ? (
          <motion.div
            key={te.event.id}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.25, ease: 'easeOut' }}
            className="br-current-body"
            data-event-id={te.event.id}
          >
            <div className="br-current-head">
              <span className="br-phase-dot" style={{ background: phaseColor(te.event.phase) }} />
              <h3 className="br-current-title">{te.event.title}</h3>
              <span className="br-current-at br-mono">{formatOffset(te.at)}</span>
            </div>
            {te.outcome !== 'OCCURRED' && (
              <div className={`br-outcome is-${te.outcome.toLowerCase().replace('_', '-')}`}>
                {te.outcome === 'INTERRUPTED' ? 'Interrupted by simulated control' : 'Not reached in simulation'}
              </div>
            )}
            <div className="br-flowline">
              <span className="br-flow-asset">{names.get(te.event.source_asset_id ?? '') ?? '—'}</span>
              <span className={`br-flow-arrow ${te.outcome === 'INTERRUPTED' ? 'is-blocked' : ''}`} aria-hidden>
                {te.outcome === 'INTERRUPTED' ? '✕' : '→'}
              </span>
              <span className="br-flow-asset">
                {te.event.target_asset_ids.length > 1
                  ? `${te.event.target_asset_ids.length} hosts`
                  : names.get(te.event.destination_asset_id ?? '') ?? '—'}
              </span>
            </div>
            <div className="br-current-proto br-mono">{protocolText(te.event.service, te.event.protocol, te.event.destination_port)}</div>
            {te.event.technique_id ? (
              <TechniqueChip id={te.event.technique_id} name={te.event.technique_name} url={te.event.technique?.url} />
            ) : (
              <div className="br-muted br-small">No ATT&CK technique mapped</div>
            )}
            <div className="br-current-conf">
              <ConfidenceChip label={te.event.confidence_label} />
              <ConfidenceMeter value={te.event.confidence} label={te.event.confidence_label} />
            </div>
            <p className="br-current-desc">{te.event.description}</p>
          </motion.div>
        ) : (
          <motion.div key="idle" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="br-current-idle">
            <p>Baseline traffic. The first reconstructed incident event appears in a moment.</p>
          </motion.div>
        )}
      </AnimatePresence>
    </section>
  );
}

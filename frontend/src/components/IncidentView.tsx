import { AnimatePresence, motion } from 'framer-motion';
import { useEffect, useMemo, useState } from 'react';

import { ContainPanel } from '../containment/ContainPanel';
import { IncidentGraph } from '../graph/IncidentGraph';
import { CrownIcon, FitIcon, ShieldIcon } from '../graph/icons';
import { EvidenceDrawer } from '../investigate/EvidenceDrawer';
import { CurrentEvent } from '../replay/CurrentEvent';
import { EventFeed } from '../replay/EventFeed';
import { ReplayControls } from '../replay/ReplayControls';
import { Timeline, phaseColor } from '../replay/Timeline';
import { buildTimeline, frameAt, nextEventAt, previousEventAt } from '../replay/engine';
import { useReplayClock } from '../replay/useReplayClock';
import { useApp } from '../stores/appStore';
import type { Incident } from '../types/incident';
import { TopBar } from './TopBar';

export function IncidentView({ incident }: { incident: Incident }) {
  const { mode, selection, select, viewMode, setViewMode, scenario, simulation, t, speed } = useApp();
  const [fitSignal, setFitSignal] = useState(0);
  const sim = scenario === 'simulated' ? simulation : null;
  const timeline = useMemo(() => buildTimeline(incident, sim), [incident, sim]);
  const assetIds = useMemo(() => incident.assets.map((a) => a.id), [incident]);
  const frame = useMemo(() => frameAt(timeline, assetIds, t), [timeline, assetIds, t]);
  useReplayClock(timeline.duration);

  // Keyboard: space = play/pause, arrows = previous/next event.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement | null)?.tagName;
      if (tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA') return;
      const s = useApp.getState();
      if (e.code === 'Space') {
        e.preventDefault();
        s.setPlaying(!s.playing);
      } else if (e.key === 'ArrowRight') {
        s.setPlaying(false);
        const n = nextEventAt(timeline, s.t);
        s.setT(n !== null ? n + 0.01 : timeline.duration);
      } else if (e.key === 'ArrowLeft') {
        s.setPlaying(false);
        s.setT(previousEventAt(timeline, s.t) ?? 0);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [timeline]);

  const names = new Map(incident.assets.map((a) => [a.id, a.internal ? a.display_name : a.ip]));
  const crownMoment = frame.crownJewelReached && frame.currentIndex === frame.crownJewelEventIndex;
  const interruptedIdx = timeline.events.findIndex((e) => e.outcome === 'INTERRUPTED');
  const interruptMoment = sim !== null && frame.interrupted && frame.currentIndex <= interruptedIdx + 1;
  const crownName = incident.crown_jewels.map((id) => names.get(id)).join(', ');
  const crownAsset = incident.assets.find((a) => a.crown_jewel);

  return (
    <div className={`br-app is-${mode} ${sim ? 'is-sim' : ''}`} data-testid="incident-view">
      <TopBar incident={incident} />
      <div className="br-stage">
        <div className="br-graph-wrap" data-testid="incident-graph">
          <IncidentGraph
            incident={incident}
            frame={frame}
            view={viewMode}
            selection={selection}
            speed={speed}
            autoFollow={mode !== 'investigate'}
            onSelect={select}
            fitSignal={fitSignal}
          />

          <div className="br-overlay br-phase" data-testid="phase-indicator">
            <div className={`br-scenario-chip ${sim ? 'is-sim' : ''}`} data-testid="scenario-chip">
              {sim ? (
                <>
                  <ShieldIcon size={12} /> Simulated outcome
                </>
              ) : (
                'Observed evidence'
              )}
            </div>
            <div className="br-eyebrow">Attack phase</div>
            <div className="br-phase-name" style={{ color: frame.current ? phaseColor(frame.phase) : undefined }}>
              {frame.current ? frame.phase : 'Before the incident'}
            </div>
          </div>

          <div className="br-overlay br-graph-tools">
            <div className="br-seg" role="group" aria-label="Graph view">
              <button type="button" className={viewMode === 'focused' ? 'is-on' : ''} onClick={() => setViewMode('focused')} aria-pressed={viewMode === 'focused'}>
                Focused incident path
              </button>
              <button type="button" className={viewMode === 'all' ? 'is-on' : ''} onClick={() => setViewMode('all')} aria-pressed={viewMode === 'all'} data-testid="view-all">
                All observed connections
              </button>
            </div>
            <button type="button" className="br-icon-btn" onClick={() => setFitSignal((n) => n + 1)} aria-label="Fit to incident" title="Fit to incident">
              <FitIcon />
            </button>
            {simulation && (
              <div className="br-seg" role="group" aria-label="Scenario">
                <button type="button" className={scenario === 'observed' ? 'is-on' : ''} onClick={() => useApp.getState().setScenario('observed')}>
                  Observed
                </button>
                <button type="button" className={scenario === 'simulated' ? 'is-on is-green' : ''} onClick={() => useApp.getState().setScenario('simulated')}>
                  Simulated
                </button>
              </div>
            )}
          </div>

          <div className="br-overlay br-legend" aria-hidden>
            <span className="is-normal">Normal</span>
            <span className="is-suspicious">Suspicious</span>
            <span className="is-affected">Affected</span>
            <span className="is-contained">Contained / protected</span>
          </div>

          <div className="br-overlay br-stats" data-testid="incident-summary">
            <div>
              <span className="br-stat-v">{incident.summary.assets_observed}</span>
              <span className="br-stat-k">Assets observed</span>
            </div>
            <div>
              <span className="br-stat-v is-red">{frame.counters.affected}</span>
              <span className="br-stat-k">Affected so far</span>
            </div>
            <div>
              <span className="br-stat-v">{incident.summary.detections}</span>
              <span className="br-stat-k">Detections</span>
            </div>
            <div>
              <span className={`br-stat-v ${frame.crownJewelReached ? 'is-red' : sim && frame.interrupted ? 'is-green' : ''}`} data-testid="crown-status">
                {frame.crownJewelReached ? 'YES' : sim && frame.interrupted && simulation && !simulation.crown_jewel_after ? 'PROTECTED' : 'NO'}
              </span>
              <span className="br-stat-k">Crown jewel reached</span>
            </div>
          </div>

          <AnimatePresence>
            {crownMoment && !sim && (
              <motion.div
                key="crown"
                className="br-moment is-crown"
                initial={{ opacity: 0, y: -12, scale: 0.97 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -8 }}
                transition={{ duration: 0.35 }}
                data-testid="crown-moment"
              >
                <CrownIcon size={18} />
                <div>
                  <div className="br-moment-title">Crown jewel reached</div>
                  <div className="br-moment-sub">
                    {crownName} · {crownAsset?.role}
                  </div>
                </div>
              </motion.div>
            )}
            {interruptMoment && (
              <motion.div
                key="interrupt"
                className="br-moment is-interrupt"
                initial={{ opacity: 0, y: -12, scale: 0.97 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -8 }}
                transition={{ duration: 0.35 }}
                data-testid="interrupt-moment"
              >
                <ShieldIcon size={18} />
                <div>
                  <div className="br-moment-title">{simulation && simulation.crown_jewel_before && !simulation.crown_jewel_after ? 'Breach interrupted' : 'Observed path interrupted'}</div>
                  <div className="br-moment-sub">The observed attack path would have been interrupted here under the simulated control.</div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {!incident.incident_found && (
            <div className="br-noincident" data-testid="no-incident">
              <div className="br-eyebrow">No incident path found</div>
              <p>
                Network activity was analyzed successfully, but BreachReplay did not find enough correlated evidence to reconstruct a meaningful incident path. All
                observed connections are shown for reference.
              </p>
            </div>
          )}
        </div>

        <div className="br-side">
          {mode === 'replay' && (
            <>
              <CurrentEvent incident={incident} frame={frame} />
              <EventFeed incident={incident} timeline={timeline} frame={frame} />
            </>
          )}
          {mode === 'investigate' && <EvidenceDrawer incident={incident} />}
          {mode === 'contain' &&
            (incident.incident_found ? (
              <ContainPanel incident={incident} />
            ) : (
              <div className="br-card br-empty">
                <p className="br-empty-title">Nothing to contain</p>
                <p className="br-muted">No incident path was reconstructed, so there is no observed path to interrupt.</p>
              </div>
            ))}
        </div>
      </div>
      <footer className="br-dock" data-testid="replay-dock">
        <Timeline timeline={timeline} frame={frame} />
        <ReplayControls timeline={timeline} frame={frame} />
      </footer>
      <span hidden data-testid="frame-debug" data-current={frame.current?.event.id ?? ''} data-t={frame.t.toFixed(2)} data-scenario={timeline.scenario} />
    </div>
  );
}

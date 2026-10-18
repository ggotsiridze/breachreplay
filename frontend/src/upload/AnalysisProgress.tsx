import { motion } from 'framer-motion';
import { useEffect, useState } from 'react';

import { LogoMark } from '../graph/icons';
import { useApp } from '../stores/appStore';
import type { AnalysisStep } from '../types/incident';

const STEP_MIN_MS = 380;

const PLACEHOLDER: AnalysisStep[] = [
  'Capture received',
  'File validated',
  'Zeek analysis',
  'Suricata analysis',
  'Normalizing evidence',
  'Correlating incident',
  'Building attack graph',
].map((label) => ({ state: 'UPLOADING', label, status: 'pending', detail: null, started_at: null, finished_at: null }));

export function AnalysisProgress() {
  const analysis = useApp((s) => s.analysis);
  const incident = useApp((s) => s.incident);
  const steps = analysis?.steps.length ? analysis.steps : PLACEHOLDER;
  const [revealed, setRevealed] = useState(0);

  // Reveal completed steps one at a time so fast analyses remain readable.
  const realDone = steps.findIndex((s) => s.status !== 'done' && s.status !== 'skipped');
  const doneCount = realDone === -1 ? steps.length : realDone;
  useEffect(() => {
    if (revealed >= doneCount) return;
    const id = window.setTimeout(() => setRevealed((r) => r + 1), STEP_MIN_MS);
    return () => window.clearTimeout(id);
  }, [revealed, doneCount]);

  const finished = revealed >= steps.length && analysis?.state === 'COMPLETE' && incident !== null;
  useEffect(() => {
    if (!finished) return;
    const id = window.setTimeout(() => useApp.setState({ screen: 'incident', playing: true, t: 0 }), 650);
    return () => window.clearTimeout(id);
  }, [finished]);

  const pct = Math.round((Math.min(revealed, steps.length) / steps.length) * 100);
  const showcase = analysis?.showcase;
  return (
    <main className="br-analyzing" data-testid="analysis-progress">
      <div className="br-landing-bg is-dim" aria-hidden />
      <motion.section className="br-analyzing-card" initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: 0.35 }}>
        <div className="br-analyzing-head">
          <LogoMark size={30} />
          <div>
            <h1 className="br-analyzing-title">{showcase ? 'Loading showcase incident' : 'Analyzing network evidence'}</h1>
            <div className="br-analyzing-file br-mono">{analysis?.filename ?? 'capture.pcap'}</div>
          </div>
        </div>
        {analysis?.demo && (
          <div className="br-synthetic-chip">{showcase ? 'Showcase demo · precomputed synthetic incident' : 'Demo incident · synthetic network traffic'}</div>
        )}
        <ol className="br-steps">
          {steps.map((s, i) => {
            const status = i < revealed ? s.status : i === revealed ? 'running' : 'pending';
            return (
              <li key={s.label} className={`br-step is-${status}`} data-testid={`step-${i}`} data-status={status}>
                <span className="br-step-icon" aria-hidden>
                  {status === 'done' ? '✓' : status === 'skipped' ? '↺' : status === 'failed' ? '!' : status === 'running' ? '' : '○'}
                </span>
                <span className="br-step-label">{s.label}</span>
                <span className="br-step-detail">{i < revealed ? (s.status === 'skipped' ? 'precomputed' : s.detail) : ''}</span>
              </li>
            );
          })}
        </ol>
        <div className="br-progress" aria-label="Analysis progress" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
          <div className="br-progress-fill" style={{ width: `${pct}%` }} />
        </div>
        <p className="br-analyzing-foot">
          {showcase
            ? 'Showcase mode serves an incident precomputed earlier by the full Zeek + Suricata pipeline.'
            : 'Zeek and Suricata run offline against the capture in an isolated, network-less analyzer.'}
        </p>
      </motion.section>
    </main>
  );
}

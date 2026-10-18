import { LogoMark, ShieldIcon } from '../graph/icons';
import { type Mode, useApp } from '../stores/appStore';
import type { Incident } from '../types/incident';

const MODES: { id: Mode; label: string }[] = [
  { id: 'replay', label: 'Replay' },
  { id: 'investigate', label: 'Investigate' },
  { id: 'contain', label: 'Contain' },
];

export function TopBar({ incident }: { incident: Incident }) {
  const { mode, setMode, reset, analysis } = useApp();
  const source = incident.showcase
    ? { cls: 'is-showcase', text: 'Showcase demo · precomputed synthetic incident' }
    : incident.demo
      ? { cls: 'is-demo', text: 'Demo incident · synthetic network traffic' }
      : { cls: 'is-upload', text: `Uploaded capture · ${analysis?.filename ?? 'capture'}` };
  return (
    <header className="br-topbar">
      <button type="button" className="br-topbar-brand" onClick={reset} title="Back to start">
        <LogoMark size={28} />
        <span className="br-topbar-word">BREACHREPLAY</span>
        <span className="br-topbar-tag">Turn network evidence into an attack you can watch.</span>
      </button>
      <div className="br-topbar-mid">
        <span className="br-topbar-incident br-mono">INCIDENT {incident.id.slice(0, 8).toUpperCase()}</span>
        <span className={`br-source-chip ${source.cls}`} data-testid="source-chip">
          {source.text}
        </span>
      </div>
      <nav className="br-modes" aria-label="Mode">
        {MODES.map((m) => (
          <button key={m.id} type="button" className={`br-mode ${mode === m.id ? 'is-on' : ''}`} onClick={() => setMode(m.id)} aria-pressed={mode === m.id} data-testid={`mode-${m.id}`}>
            {m.label}
          </button>
        ))}
      </nav>
      {incident.incident_found && (
        <button type="button" className={`br-stop ${mode === 'contain' ? 'is-on' : ''}`} onClick={() => setMode('contain')} data-testid="stop-the-breach">
          <ShieldIcon size={15} />
          Stop the breach
        </button>
      )}
    </header>
  );
}

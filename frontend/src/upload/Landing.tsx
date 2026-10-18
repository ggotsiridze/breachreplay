import { motion } from 'framer-motion';
import { type DragEvent, useRef, useState } from 'react';

import { GlobeIcon, LogoMark, MonitorIcon, ServerIcon, DatabaseIcon, UploadIcon } from '../graph/icons';
import { useApp } from '../stores/appStore';

const ACCEPT = '.pcap,.pcapng,.cap';

function PathPreview() {
  const steps = [
    { icon: <GlobeIcon size={18} />, name: 'INTERNET', cls: 'is-ext' },
    { icon: <ServerIcon size={18} />, name: 'WEB-01', cls: 'is-hit' },
    { icon: <MonitorIcon size={18} />, name: 'WS-03', cls: 'is-hit' },
    { icon: <DatabaseIcon size={18} />, name: 'DB-01', cls: 'is-jewel' },
  ];
  return (
    <div className="br-preview" aria-hidden>
      {steps.map((s, i) => (
        <div key={s.name} className="br-preview-step">
          <div className={`br-preview-node ${s.cls}`} style={{ animationDelay: `${0.6 + i * 0.9}s` }}>
            {s.icon}
            <span>{s.name}</span>
          </div>
          {i < steps.length - 1 && (
            <div className="br-preview-link">
              <span className="br-preview-packet" style={{ animationDelay: `${0.15 + i * 0.9}s` }} />
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

export function Landing() {
  const { startDemo, upload, service } = useApp();
  const [drag, setDrag] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const uploadsEnabled = service?.uploads_enabled ?? true;
  const showcase = service?.showcase_mode ?? false;

  const take = (file: File | undefined) => {
    if (!file) return;
    if (!/\.(pcap|pcapng|cap)$/i.test(file.name)) {
      setLocalError('Only .pcap and .pcapng packet captures can be analyzed.');
      return;
    }
    setLocalError(null);
    void upload(file);
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDrag(false);
    if (uploadsEnabled) take(e.dataTransfer.files[0]);
  };

  return (
    <main className="br-landing" data-testid="landing">
      <div className="br-landing-bg" aria-hidden />
      <motion.div className="br-landing-inner" initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, ease: 'easeOut' }}>
        <div className="br-brand-lockup">
          <LogoMark size={40} />
          <h1 className="br-wordmark">BREACHREPLAY</h1>
        </div>
        <p className="br-tagline">Turn network evidence into an attack you can watch.</p>
        <p className="br-subtag">
          Upload a packet capture. BreachReplay analyzes it with <strong>Zeek</strong> and <strong>Suricata</strong>, reconstructs the incident, and replays the
          attack step by step.
        </p>

        <PathPreview />

        <div
          className={`br-drop ${drag ? 'is-drag' : ''} ${uploadsEnabled ? '' : 'is-disabled'}`}
          onDragOver={(e) => {
            e.preventDefault();
            if (uploadsEnabled) setDrag(true);
          }}
          onDragLeave={() => setDrag(false)}
          onDrop={onDrop}
          onClick={() => uploadsEnabled && input.current?.click()}
          onKeyDown={(e) => {
            if ((e.key === 'Enter' || e.key === ' ') && uploadsEnabled) input.current?.click();
          }}
          role="button"
          tabIndex={uploadsEnabled ? 0 : -1}
          aria-disabled={!uploadsEnabled}
          aria-label="Drop a PCAP file here or browse"
          data-testid="dropzone"
        >
          <UploadIcon className="br-drop-icon" />
          <div className="br-drop-title">{uploadsEnabled ? 'Drop PCAP here' : 'Uploads disabled in showcase demo'}</div>
          <div className="br-drop-sub">{uploadsEnabled ? `.pcap / .pcapng · up to ${service?.max_upload_mb ?? 50} MB · or click to browse` : 'Run BreachReplay locally to analyze your own captures'}</div>
          <input
            ref={input}
            type="file"
            accept={ACCEPT}
            hidden
            data-testid="file-input"
            onChange={(e) => {
              take(e.target.files?.[0]);
              e.target.value = '';
            }}
          />
        </div>
        {localError && (
          <p className="br-error-inline" role="alert">
            {localError}
          </p>
        )}

        <div className="br-or">
          <span>or</span>
        </div>

        <button type="button" className="br-demo-btn" onClick={() => void startDemo()} data-testid="watch-demo">
          <span className="br-demo-pulse" aria-hidden />
          Watch demo incident
        </button>
        <div className="br-demo-note">{showcase ? 'Showcase demo · precomputed synthetic incident' : 'Synthetic network traffic · analyzed live by Zeek + Suricata'}</div>

        <div className="br-pillars">
          <div className="br-pillar">
            <span className="br-pillar-k is-red">Replay</span>
            <span>Watch the incident unfold.</span>
          </div>
          <div className="br-pillar">
            <span className="br-pillar-k is-cyan">Investigate</span>
            <span>Inspect the evidence behind each step.</span>
          </div>
          <div className="br-pillar">
            <span className="br-pillar-k is-green">Contain</span>
            <span>Simulate where the observed path could have been interrupted.</span>
          </div>
        </div>
      </motion.div>
      <footer className="br-landing-foot">
        Captures are processed server-side in an isolated workspace and deleted after analysis · deterministic evidence correlation · no AI guesswork
      </footer>
    </main>
  );
}

import type { CSSProperties, ReactNode } from 'react';

import type { AssetState, ConfidenceLabel } from '../types/incident';

export function labelClass(label: ConfidenceLabel): string {
  return `is-${label.toLowerCase().replace(' ', '-')}`;
}

export function ConfidenceChip({ label }: { label: ConfidenceLabel }) {
  return <span className={`br-chip br-conf ${labelClass(label)}`}>{label}</span>;
}

export function ConfidenceMeter({ value, label, compact }: { value: number; label: ConfidenceLabel; compact?: boolean }) {
  return (
    <div className={`br-meter ${labelClass(label)} ${compact ? 'is-compact' : ''}`} role="meter" aria-valuenow={value} aria-valuemin={0} aria-valuemax={100} aria-label="Confidence">
      <div className="br-meter-track">
        <div className="br-meter-fill" style={{ width: `${value}%` } as CSSProperties} />
        {[40, 65, 85].map((m) => (
          <span key={m} className="br-meter-tick" style={{ left: `${m}%` }} />
        ))}
      </div>
      {!compact && <span className="br-meter-value br-mono">{value}%</span>}
    </div>
  );
}

const STATE_LABEL: Record<AssetState, string> = {
  NORMAL: 'Normal',
  SUSPICIOUS: 'Suspicious',
  AFFECTED: 'Affected',
  CONTAINED: 'Contained',
  PROTECTED: 'Protected',
};

export function StateBadge({ state, highConfidence }: { state: AssetState; highConfidence?: boolean }) {
  return (
    <span className={`br-chip br-state is-${state.toLowerCase()}`}>
      <span className="br-dot" />
      {state === 'AFFECTED' && highConfidence ? 'High-confidence affected' : STATE_LABEL[state]}
    </span>
  );
}

export function Eyebrow({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`br-eyebrow ${className}`}>{children}</div>;
}

export function TechniqueChip({ id, name, url }: { id: string; name?: string | null; url?: string }) {
  const body = (
    <>
      <span className="br-technique-id br-mono">{id}</span>
      {name && <span className="br-technique-name">{name}</span>}
    </>
  );
  return url ? (
    <a className="br-technique" href={url} target="_blank" rel="noreferrer noopener" title={`${id}${name ? ` ${name}` : ''} (open in MITRE ATT&CK)`}>
      {body}
    </a>
  ) : (
    <span className="br-technique">{body}</span>
  );
}

/** Zeek says "ssl", Suricata says "tls": show one TLS label; hide auth sub-protocols. */
export function serviceNames(services: string[]): string[] {
  const names = services.filter((s) => s && !['ntlm', 'gssapi', 'failed'].includes(s)).map((s) => (s === 'ssl' || s === 'tls' ? 'TLS' : s.toUpperCase()));
  return [...new Set(names)];
}

export function protocolText(service: string | null, protocol: string | null, port: number | null): string {
  const svc = serviceNames((service ?? '').split(',')).join(' / ');
  const transport = protocol ? `${protocol.toUpperCase()} ${port ?? ''}`.trim() : port ? `PORT ${port}` : '';
  return [svc, transport].filter(Boolean).join(' · ');
}

import type { AssetType } from '../types/incident';

type IconProps = { size?: number; className?: string };

const base = (size: number) => ({
  width: size,
  height: size,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.7,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
  'aria-hidden': true,
});

export const GlobeIcon = ({ size = 20, className }: IconProps) => (
  <svg {...base(size)} className={className}>
    <circle cx="12" cy="12" r="9" />
    <path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" />
  </svg>
);
export const ServerIcon = ({ size = 20, className }: IconProps) => (
  <svg {...base(size)} className={className}>
    <rect x="3.5" y="4" width="17" height="6.5" rx="1.6" />
    <rect x="3.5" y="13.5" width="17" height="6.5" rx="1.6" />
    <path d="M7.5 7.25h.01M7.5 16.75h.01M11 7.25h5M11 16.75h5" />
  </svg>
);
export const MonitorIcon = ({ size = 20, className }: IconProps) => (
  <svg {...base(size)} className={className}>
    <rect x="3" y="4" width="18" height="12" rx="1.8" />
    <path d="M8.5 20h7M12 16v4" />
  </svg>
);
export const DatabaseIcon = ({ size = 20, className }: IconProps) => (
  <svg {...base(size)} className={className}>
    <ellipse cx="12" cy="5.5" rx="7.5" ry="2.8" />
    <path d="M4.5 5.5v13c0 1.55 3.36 2.8 7.5 2.8s7.5-1.25 7.5-2.8v-13M4.5 12c0 1.55 3.36 2.8 7.5 2.8s7.5-1.25 7.5-2.8" />
  </svg>
);
export const UserIcon = ({ size = 20, className }: IconProps) => (
  <svg {...base(size)} className={className}>
    <circle cx="12" cy="8" r="4" />
    <path d="M4.5 20.5a7.5 7.5 0 0 1 15 0" />
  </svg>
);
export const RouterIcon = ({ size = 20, className }: IconProps) => (
  <svg {...base(size)} className={className}>
    <rect x="3" y="13" width="18" height="7" rx="1.8" />
    <path d="M7 16.5h.01M11 16.5h.01M12 13V9M8.5 6.5a5 5 0 0 1 7 0M6 4a8.5 8.5 0 0 1 12 0" />
  </svg>
);
export const UnknownIcon = ({ size = 20, className }: IconProps) => (
  <svg {...base(size)} className={className}>
    <rect x="4" y="4" width="16" height="16" rx="3" strokeDasharray="3 2.5" />
    <path d="M9.6 9.6a2.5 2.5 0 1 1 3.4 2.3c-.6.3-1 .8-1 1.4v.4M12 16.6h.01" />
  </svg>
);
export const CrownIcon = ({ size = 14, className }: IconProps) => (
  <svg {...base(size)} className={className}>
    <path d="M3 8l4.5 4L12 5l4.5 7L21 8l-2 11H5L3 8z" fill="currentColor" fillOpacity="0.18" />
  </svg>
);
export const ShieldIcon = ({ size = 14, className }: IconProps) => (
  <svg {...base(size)} className={className}>
    <path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.3-7.5 9.5-4.3-1.2-7.5-4.9-7.5-9.5V6L12 3z" />
    <path d="M9 12l2.2 2.2L15.5 10" />
  </svg>
);
export const AlertIcon = ({ size = 14, className }: IconProps) => (
  <svg {...base(size)} className={className}>
    <path d="M12 4l9 16H3l9-16z" />
    <path d="M12 10v4M12 17h.01" />
  </svg>
);
export const PlayIcon = ({ size = 18 }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden>
    <path d="M7 4.8v14.4a1 1 0 0 0 1.52.85l11.5-7.2a1 1 0 0 0 0-1.7L8.52 3.95A1 1 0 0 0 7 4.8z" fill="currentColor" />
  </svg>
);
export const PauseIcon = ({ size = 18 }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden>
    <rect x="6" y="4.5" width="4" height="15" rx="1.2" fill="currentColor" />
    <rect x="14" y="4.5" width="4" height="15" rx="1.2" fill="currentColor" />
  </svg>
);
export const SkipBackIcon = ({ size = 16 }: IconProps) => (
  <svg {...base(size)}>
    <path d="M19 5v14L9 12l10-7zM5 5v14" />
  </svg>
);
export const SkipForwardIcon = ({ size = 16 }: IconProps) => (
  <svg {...base(size)}>
    <path d="M5 5v14l10-7L5 5zM19 5v14" />
  </svg>
);
export const PrevIcon = ({ size = 16 }: IconProps) => (
  <svg {...base(size)}>
    <path d="M15 18l-6-6 6-6" />
  </svg>
);
export const NextIcon = ({ size = 16 }: IconProps) => (
  <svg {...base(size)}>
    <path d="M9 18l6-6-6-6" />
  </svg>
);
export const RestartIcon = ({ size = 16 }: IconProps) => (
  <svg {...base(size)}>
    <path d="M3.5 12a8.5 8.5 0 1 0 2.6-6.1M3.5 4v4.5H8" />
  </svg>
);
export const FitIcon = ({ size = 16 }: IconProps) => (
  <svg {...base(size)}>
    <path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5" />
  </svg>
);
export const CloseIcon = ({ size = 16 }: IconProps) => (
  <svg {...base(size)}>
    <path d="M6 6l12 12M18 6L6 18" />
  </svg>
);
export const UploadIcon = ({ size = 28, className }: IconProps) => (
  <svg {...base(size)} className={className}>
    <path d="M12 16V4M7 9l5-5 5 5" />
    <path d="M4 15v3.5A1.5 1.5 0 0 0 5.5 20h13a1.5 1.5 0 0 0 1.5-1.5V15" />
  </svg>
);
export const LogoMark = ({ size = 26 }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden>
    <defs>
      <linearGradient id="br-logo" x1="0" y1="1" x2="1" y2="0">
        <stop offset="0" stopColor="#4cc9f0" />
        <stop offset="1" stopColor="#ff4d5e" />
      </linearGradient>
    </defs>
    <rect x="1" y="1" width="30" height="30" rx="8" fill="#0d121b" stroke="rgba(148,163,184,0.25)" />
    <path d="M7 22 L13 10 L19 18 L25 8" fill="none" stroke="url(#br-logo)" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
    <circle cx="25" cy="8" r="2.6" fill="#ff4d5e" />
    <circle cx="7" cy="22" r="2.2" fill="#4cc9f0" />
  </svg>
);

export function AssetIcon({ type, crown, size = 22 }: { type: AssetType; crown?: boolean; size?: number }) {
  if (crown || type === 'DATABASE') return <DatabaseIcon size={size} />;
  switch (type) {
    case 'INTERNET':
      return <GlobeIcon size={size} />;
    case 'SERVER':
      return <ServerIcon size={size} />;
    case 'WORKSTATION':
      return <MonitorIcon size={size} />;
    case 'IDENTITY':
      return <UserIcon size={size} />;
    case 'INFRASTRUCTURE':
      return <RouterIcon size={size} />;
    default:
      return <UnknownIcon size={size} />;
  }
}

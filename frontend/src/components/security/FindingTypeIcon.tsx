import { cn } from '../../lib/utils';

export type FindingTypeIconKind =
  | 'vulnerability'
  | 'semgrep'
  | 'secret'
  | 'malicious'
  | 'license'
  | 'iac'
  | 'container';

interface FindingTypeIconProps {
  type: FindingTypeIconKind;
  size?: number;
  className?: string;
}

export function FindingTypeIcon({ type, size = 18, className }: FindingTypeIconProps) {
  const cls = cn('text-zinc-400 shrink-0', className);
  const dim = { width: size, height: size };

  if (type === 'malicious') {
    return (
      <svg className={cls} style={dim} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 2L4 6v6c0 5 3.5 9 8 10 4.5-1 8-5 8-10V6l-8-4z" />
        <path d="M12 8v4" />
        <circle cx="12" cy="16" r="0.5" fill="currentColor" />
      </svg>
    );
  }
  if (type === 'vulnerability') {
    return (
      <svg className={cls} style={dim} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z" />
        <path d="M3.3 7L12 12l8.7-5" />
        <path d="M12 22V12" />
      </svg>
    );
  }
  if (type === 'secret') {
    return (
      <svg className={cls} style={dim} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
      </svg>
    );
  }
  if (type === 'license') {
    return (
      <svg className={cls} style={dim} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
        <polyline points="14 2 14 8 20 8" />
        <path d="M9 15v-1a3 3 0 0 1 6 0v1" />
        <rect x="8" y="15" width="8" height="5" rx="1" />
      </svg>
    );
  }
  if (type === 'iac') {
    return (
      <svg className={cls} style={dim} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M3 7l9-4 9 4-9 4-9-4z" />
        <path d="M3 12l9 4 9-4" />
        <path d="M3 17l9 4 9-4" />
      </svg>
    );
  }
  if (type === 'container') {
    return (
      <svg className={cls} style={dim} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="8" width="18" height="11" rx="1.5" />
        <rect x="6" y="11" width="3" height="3" />
        <rect x="11" y="11" width="3" height="3" />
        <rect x="16" y="11" width="3" height="3" />
        <path d="M3 8c2 0 3-2 3-2h12s1 2 3 2" />
      </svg>
    );
  }
  // semgrep / fallback
  return (
    <svg className={cls} style={dim} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M8 3C5.5 3 4 5 4 7v4c0 1-1 2-2 2 1 0 2 1 2 2v4c0 2 1.5 4 4 4" />
      <path d="M16 3c2.5 0 4 2 4 4v4c0 1 1 2 2 2-1 0-2 1-2 2v4c0 2-1.5 4-4 4" />
    </svg>
  );
}

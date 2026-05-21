// v2.1c: small pill identifying which DAST engine produced a finding.
// ZAP → blue, Nuclei → purple, merged → neutral.

import { cn } from '../../lib/utils';
import type { DastEngine } from '../../lib/api';

const ENGINE_STYLE: Record<DastEngine, { label: string; className: string }> = {
  zap: { label: 'ZAP', className: 'bg-blue-500/10 text-blue-400 border-blue-500/20' },
  nuclei: { label: 'Nuclei', className: 'bg-purple-500/10 text-purple-400 border-purple-500/20' },
  merged: { label: 'Merged', className: 'bg-background-subtle text-foreground-secondary border-border' },
};

interface EngineChipProps {
  /** Pre-v2.1c rows have no engine — default to ZAP. */
  engine?: DastEngine | null;
  className?: string;
}

export function EngineChip({ engine, className }: EngineChipProps) {
  const key: DastEngine = engine === 'nuclei' || engine === 'merged' ? engine : 'zap';
  const style = ENGINE_STYLE[key];
  return (
    <span
      className={cn(
        'inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium leading-none',
        style.className,
        className,
      )}
    >
      {style.label}
    </span>
  );
}

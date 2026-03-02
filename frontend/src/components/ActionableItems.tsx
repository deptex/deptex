import { useNavigate } from 'react-router-dom';
import { ShieldCheck, AlertTriangle, AlertCircle, ChevronRight, ShieldAlert, Code, FileWarning } from 'lucide-react';
import type { ActionItem } from '../lib/api';

interface ActionableItemsProps {
  items: ActionItem[];
  loading?: boolean;
}

const typeConfig: Record<string, { icon: React.ReactNode; color: string }> = {
  critical_vuln: { icon: <AlertCircle className="h-4 w-4" />, color: 'text-red-400' },
  high_vuln: { icon: <AlertTriangle className="h-4 w-4" />, color: 'text-orange-400' },
  non_compliant: { icon: <ShieldAlert className="h-4 w-4" />, color: 'text-amber-400' },
  policy_violation: { icon: <FileWarning className="h-4 w-4" />, color: 'text-amber-400' },
  outdated_critical: { icon: <AlertTriangle className="h-4 w-4" />, color: 'text-orange-400' },
  code_finding: { icon: <Code className="h-4 w-4" />, color: 'text-blue-400' },
};

export function ActionableItems({ items, loading }: ActionableItemsProps) {
  const navigate = useNavigate();

  if (loading) {
    return (
      <div className="rounded-lg border border-border bg-background-card p-4">
        <h3 className="text-sm font-semibold text-foreground mb-3">Action Items</h3>
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="flex items-center gap-3 animate-pulse">
              <div className="h-4 w-4 rounded bg-muted/60" />
              <div className="flex-1">
                <div className="h-3.5 w-32 rounded bg-muted/60 mb-1" />
                <div className="h-3 w-48 rounded bg-muted/40" />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border bg-background-card p-4">
      <h3 className="text-sm font-semibold text-foreground mb-3">Action Items</h3>
      {items.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-6 text-center">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-emerald-500/15 mb-3">
            <ShieldCheck className="h-5 w-5 text-emerald-400" />
          </div>
          <p className="text-sm font-medium text-foreground">Everything looks good</p>
          <p className="text-xs text-foreground-secondary mt-1">No action items at this time</p>
        </div>
      ) : (
        <div className="space-y-1">
          {items.map((item, i) => {
            const cfg = typeConfig[item.type] ?? { icon: <AlertTriangle className="h-4 w-4" />, color: 'text-zinc-400' };
            return (
              <button
                key={i}
                onClick={() => navigate(item.link)}
                className="flex items-center gap-3 w-full rounded-md px-2 py-2 transition-colors hover:bg-muted/50 text-left"
              >
                <span className={cfg.color}>{cfg.icon}</span>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-foreground truncate">{item.title}</p>
                  <p className="text-xs text-foreground-secondary truncate">{item.description}</p>
                </div>
                <ChevronRight className="h-4 w-4 text-foreground-secondary shrink-0" />
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

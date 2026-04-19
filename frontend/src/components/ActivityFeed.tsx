import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  RefreshCw, Shield, ShieldCheck, AlertTriangle, FileText, Users, Settings, X,
  Loader2, ExternalLink, Clock,
} from 'lucide-react';
import { Button } from './ui/button';
import type { ProjectActivityItem } from '../lib/api';

interface ActivityFeedProps {
  items: ProjectActivityItem[];
  loading?: boolean;
  onRetrySync?: () => void;
  emptyMessage?: string;
  /** Timeline variant: vertical line + dots, for use in a narrow right column */
  variant?: 'table' | 'timeline';
}

const iconMap: Record<string, { icon: React.ReactNode; color: string; bg: string }> = {
  sync_started: { icon: <Loader2 className="h-3.5 w-3.5 animate-spin" />, color: 'text-blue-400', bg: 'bg-blue-500/15' },
  sync_completed: { icon: <RefreshCw className="h-3.5 w-3.5" />, color: 'text-emerald-400', bg: 'bg-emerald-500/15' },
  sync_failed: { icon: <AlertTriangle className="h-3.5 w-3.5" />, color: 'text-red-400', bg: 'bg-red-500/15' },
  vuln_discovered: { icon: <Shield className="h-3.5 w-3.5" />, color: 'text-orange-400', bg: 'bg-orange-500/15' },
  vuln_resolved: { icon: <ShieldCheck className="h-3.5 w-3.5" />, color: 'text-emerald-400', bg: 'bg-emerald-500/15' },
  policy_change: { icon: <FileText className="h-3.5 w-3.5" />, color: 'text-amber-400', bg: 'bg-amber-500/15' },
  team_assignment: { icon: <Users className="h-3.5 w-3.5" />, color: 'text-blue-400', bg: 'bg-blue-500/15' },
  guardrail_update: { icon: <Settings className="h-3.5 w-3.5" />, color: 'text-zinc-400', bg: 'bg-zinc-500/15' },
  other: { icon: <Clock className="h-3.5 w-3.5" />, color: 'text-zinc-400', bg: 'bg-zinc-500/15' },
};

function relativeTime(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diff = now - then;
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

export function ActivityFeed({ items, loading, onRetrySync, emptyMessage, variant = 'table' }: ActivityFeedProps) {
  const navigate = useNavigate();
  const [selectedItem, setSelectedItem] = useState<ProjectActivityItem | null>(null);

  const isTimeline = variant === 'timeline';

  if (loading) {
    if (isTimeline) {
      return (
        <div className="rounded-lg border border-border bg-background-card overflow-hidden h-full min-h-[200px] flex flex-col">
          <h3 className="text-sm font-semibold text-foreground px-4 py-3 border-b border-border shrink-0">Recent activity</h3>
          <div className="flex-1 p-4 space-y-4">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="flex gap-3 animate-pulse">
                <div className="h-3 w-3 rounded-full bg-muted/50 shrink-0 mt-1.5" />
                <div className="flex-1 min-w-0">
                  <div className="h-4 w-24 rounded bg-muted/50 mb-1.5" />
                  <div className="h-3 w-full max-w-[140px] rounded bg-muted/40" />
                </div>
              </div>
            ))}
          </div>
        </div>
      );
    }
    return (
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <h3 className="text-sm font-semibold text-foreground px-4 py-3 border-b border-border">Recent activity</h3>
        <table className="w-full text-sm">
          <thead className="bg-background-card-header border-b border-border">
            <tr>
              <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-9">Event</th>
              <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Details</th>
              <th className="text-right px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-20">Time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {[1, 2, 3, 4].map((i) => (
              <tr key={i} className="animate-pulse">
                <td className="px-4 py-2.5"><div className="h-7 w-7 rounded-full bg-muted/50" /></td>
                <td className="px-4 py-2.5"><div className="h-4 w-32 rounded bg-muted/50 mb-1" /><div className="h-3 w-24 rounded bg-muted/40" /></td>
                <td className="px-4 py-2.5 text-right"><div className="h-3 w-12 rounded bg-muted/40 ml-auto" /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  if (isTimeline) {
    return (
      <div className="rounded-lg border border-border bg-background-card overflow-hidden flex flex-col h-full min-h-[200px] relative">
        <h3 className="text-sm font-semibold text-foreground px-4 py-3 border-b border-border shrink-0">Recent activity</h3>
        {items.length === 0 ? (
          <p className="text-sm text-foreground-secondary py-6 px-4 text-center flex-1">
            {emptyMessage ?? 'Activity will appear here after your first sync.'}
          </p>
        ) : (
          <div className="flex-1 overflow-y-auto py-4 pl-4 pr-4">
            <div className="relative">
              {/* Vertical line */}
              <div className="absolute left-[11px] top-2 bottom-2 w-px bg-border" aria-hidden />
              <ul className="space-y-0">
                {items.map((item) => {
                  const cfg = iconMap[item.type] ?? iconMap.other;
                  return (
                    <li key={item.id} className="relative flex gap-3 pb-4 last:pb-0">
                      <div className={`relative z-10 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border-2 border-background-card ${cfg.bg} shadow-sm`}>
                        <span className={cfg.color}>{cfg.icon}</span>
                      </div>
                      <button
                        type="button"
                        onClick={() => setSelectedItem(item)}
                        className="flex-1 text-left min-w-0 group"
                      >
                        <p className="text-sm font-medium text-foreground truncate group-hover:text-primary transition-colors">{item.title}</p>
                        {item.description && (
                          <p className="text-xs text-foreground-secondary truncate mt-0.5">{item.description}</p>
                        )}
                        <p className="text-xs text-foreground-secondary mt-0.5">{relativeTime(item.created_at)}</p>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          </div>
        )}
        {selectedItem && (
          <ActivityDetailSidebar
            item={selectedItem}
            onClose={() => setSelectedItem(null)}
            onRetrySync={onRetrySync}
            navigate={navigate}
          />
        )}
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border bg-background-card overflow-hidden relative">
      <h3 className="text-sm font-semibold text-foreground px-4 py-3 border-b border-border">Recent activity</h3>

      {items.length === 0 ? (
        <p className="text-sm text-foreground-secondary py-6 px-4 text-center">
          {emptyMessage ?? 'Activity will appear here after your first sync.'}
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-9">Event</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Details</th>
                <th className="text-right px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-20">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {items.map((item) => {
                const cfg = iconMap[item.type] ?? iconMap.other;
                return (
                  <tr
                    key={item.id}
                    onClick={() => setSelectedItem(item)}
                    className="hover:bg-table-hover transition-colors cursor-pointer"
                  >
                    <td className="px-4 py-2.5">
                      <div className={`flex h-7 w-7 items-center justify-center rounded-full ${cfg.bg}`}>
                        <span className={cfg.color}>{cfg.icon}</span>
                      </div>
                    </td>
                    <td className="px-4 py-2.5">
                      <p className="font-medium text-foreground truncate">{item.title}</p>
                      {item.description && (
                        <p className="text-xs text-foreground-secondary truncate max-w-[220px] mt-0.5">{item.description}</p>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-right text-foreground-secondary text-xs whitespace-nowrap">
                      {relativeTime(item.created_at)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {selectedItem && (
        <ActivityDetailSidebar
          item={selectedItem}
          onClose={() => setSelectedItem(null)}
          onRetrySync={onRetrySync}
          navigate={navigate}
        />
      )}
    </div>
  );
}

function ActivityDetailSidebar({
  item,
  onClose,
  onRetrySync,
  navigate,
}: {
  item: ProjectActivityItem;
  onClose: () => void;
  onRetrySync?: () => void;
  navigate: (path: string) => void;
}) {
  const cfg = iconMap[item.type] ?? iconMap.other;

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-md border-l border-border bg-background shadow-xl flex flex-col">
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <div className="flex items-center gap-2">
          <div className={`flex h-7 w-7 items-center justify-center rounded-full ${cfg.bg}`}>
            <span className={cfg.color}>{cfg.icon}</span>
          </div>
          <h3 className="text-sm font-semibold text-foreground">{item.title}</h3>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose} className="h-7 w-7">
          <X className="h-4 w-4" />
        </Button>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary mb-1">Timestamp</p>
          <p className="text-sm text-foreground">{new Date(item.created_at).toLocaleString()}</p>
        </div>

        {item.description && (
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary mb-1">Details</p>
            <p className="text-sm text-foreground">{item.description}</p>
          </div>
        )}

        {/* Type-specific content */}
        {item.type === 'sync_completed' && item.metadata && (
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary mb-1">Extraction</p>
            <p className="text-sm text-foreground">Completed at {item.metadata.completed_at ? new Date(item.metadata.completed_at).toLocaleString() : 'N/A'}</p>
          </div>
        )}

        {item.type === 'sync_failed' && (
          <div className="space-y-2">
            <p className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary mb-1">Error</p>
            <p className="text-sm text-red-400">{item.metadata?.error ?? item.description ?? 'Unknown error'}</p>
            {onRetrySync && (
              <Button variant="outline" size="sm" onClick={onRetrySync} className="mt-2">
                <RefreshCw className="h-3.5 w-3.5 mr-1.5" /> Retry Sync
              </Button>
            )}
          </div>
        )}

        {(item.type === 'vuln_discovered' || item.type === 'vuln_resolved') && item.metadata && (
          <div className="space-y-2">
            {item.metadata.osv_id && (
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary mb-1">OSV ID</p>
                <p className="text-sm text-foreground font-mono">{item.metadata.osv_id}</p>
              </div>
            )}
            {item.metadata.severity && (
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary mb-1">Severity</p>
                <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                  item.metadata.severity === 'critical' ? 'bg-red-500/15 text-red-400' :
                  item.metadata.severity === 'high' ? 'bg-orange-500/15 text-orange-400' :
                  item.metadata.severity === 'medium' ? 'bg-yellow-500/15 text-yellow-400' :
                  'bg-slate-500/15 text-slate-400'
                }`}>{item.metadata.severity}</span>
              </div>
            )}
          </div>
        )}

        {item.type === 'sync_started' && (
          <div className="flex items-center gap-2 text-sm text-blue-400">
            <Loader2 className="h-4 w-4 animate-spin" />
            <span>Extraction in progress…</span>
          </div>
        )}
      </div>
    </div>
  );
}

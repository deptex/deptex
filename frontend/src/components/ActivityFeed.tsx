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

export function ActivityFeed({ items, loading, onRetrySync, emptyMessage }: ActivityFeedProps) {
  const navigate = useNavigate();
  const [selectedItem, setSelectedItem] = useState<ProjectActivityItem | null>(null);

  if (loading) {
    return (
      <div className="rounded-lg border border-border bg-background-card p-4">
        <h3 className="text-sm font-semibold text-foreground mb-3">Recent Activity</h3>
        <div className="space-y-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="flex items-start gap-3 animate-pulse">
              <div className="h-7 w-7 rounded-full bg-muted/40 shrink-0 mt-0.5" />
              <div className="flex-1">
                <div className="h-3.5 w-40 rounded bg-muted/60 mb-1" />
                <div className="h-3 w-24 rounded bg-muted/40" />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border bg-background-card p-4 relative">
      <h3 className="text-sm font-semibold text-foreground mb-3">Recent Activity</h3>

      {items.length === 0 ? (
        <p className="text-sm text-foreground-secondary py-4 text-center">
          {emptyMessage ?? 'Activity will appear here after your first sync.'}
        </p>
      ) : (
        <div className="space-y-1">
          {items.map((item) => {
            const cfg = iconMap[item.type] ?? iconMap.other;
            return (
              <button
                key={item.id}
                onClick={() => setSelectedItem(item)}
                className="flex items-start gap-3 w-full rounded-md px-2 py-2 transition-colors hover:bg-muted/50 text-left"
              >
                <div className={`flex h-7 w-7 items-center justify-center rounded-full ${cfg.bg} shrink-0 mt-0.5`}>
                  <span className={cfg.color}>{cfg.icon}</span>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-foreground truncate">{item.title}</p>
                  {item.description && (
                    <p className="text-xs text-foreground-secondary truncate">{item.description}</p>
                  )}
                </div>
                <span className="text-xs text-foreground-secondary shrink-0 mt-1">{relativeTime(item.created_at)}</span>
              </button>
            );
          })}
        </div>
      )}

      {/* Slide-out sidebar for activity detail */}
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

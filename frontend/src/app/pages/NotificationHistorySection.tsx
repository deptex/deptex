import { useState, useEffect, useCallback } from 'react';
import {
  ChevronDown,
  ChevronRight,
  Loader2,
  RefreshCw,
  Mail,
  Webhook,
  Clock,
  AlertCircle,
  Inbox,
} from 'lucide-react';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../../components/ui/select';
import { useAuth } from '../../contexts/AuthContext';
import { useToast } from '../../hooks/use-toast';
import { cn } from '../../lib/utils';

interface NotificationHistorySectionProps {
  organizationId: string;
}

interface DeliveryAttempt {
  attempted_at: string;
  status: string;
  error_message?: string | null;
  response_code?: number | null;
}

interface NotificationDelivery {
  id: string;
  event_type: string;
  project_name: string | null;
  rule_name: string;
  destination_type: string;
  destination_name: string;
  status: 'delivered' | 'failed' | 'rate_limited' | 'skipped' | 'dry_run' | 'pending';
  message_title: string | null;
  message_body: string | null;
  error_message: string | null;
  attempts: DeliveryAttempt[];
  created_at: string;
}

interface HistoryResponse {
  deliveries: NotificationDelivery[];
  total: number;
  page: number;
  perPage: number;
}

const EVENT_TYPES = [
  'vulnerability_discovered',
  'malicious_package_detected',
  'dependency_added',
  'extraction_completed',
  'extraction_failed',
  'policy_violation',
  'status_changed',
  'pr_check_completed',
] as const;

const EVENT_TYPE_LABELS: Record<string, string> = {
  vulnerability_discovered: 'Vulnerability Discovered',
  malicious_package_detected: 'Malicious Package',
  dependency_added: 'Dependency Added',
  extraction_completed: 'Extraction Completed',
  extraction_failed: 'Extraction Failed',
  policy_violation: 'Policy Violation',
  status_changed: 'Status Changed',
  pr_check_completed: 'PR Check Completed',
};

const EVENT_TYPE_COLORS: Record<string, string> = {
  vulnerability_discovered: 'bg-red-500/10 text-red-400 border-red-500/20',
  malicious_package_detected: 'bg-red-600/10 text-red-500 border-red-600/20',
  dependency_added: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  extraction_completed: 'bg-green-500/10 text-green-400 border-green-500/20',
  extraction_failed: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  policy_violation: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  status_changed: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  pr_check_completed: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20',
};

const STATUS_STYLES: Record<string, string> = {
  delivered: 'bg-green-500/10 text-green-400 border-green-500/20',
  failed: 'bg-red-500/10 text-red-400 border-red-500/20',
  rate_limited: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  skipped: 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20',
  dry_run: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  pending: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
};

const STATUS_LABELS: Record<string, string> = {
  delivered: 'Delivered',
  failed: 'Failed',
  rate_limited: 'Rate Limited',
  skipped: 'Skipped',
  dry_run: 'Dry Run',
  pending: 'Pending',
};

const DESTINATION_TYPES = [
  'slack',
  'discord',
  'email',
  'jira',
  'linear',
  'asana',
  'custom_notification',
  'custom_ticketing',
  'pagerduty',
] as const;

const DESTINATION_LABELS: Record<string, string> = {
  slack: 'Slack',
  discord: 'Discord',
  email: 'Email',
  jira: 'Jira',
  linear: 'Linear',
  asana: 'Asana',
  custom_notification: 'Custom',
  custom_ticketing: 'Custom Ticketing',
  pagerduty: 'PagerDuty',
};

const DESTINATION_ICON_SRC: Record<string, string> = {
  slack: '/images/integrations/slack.png',
  discord: '/images/integrations/discord.png',
  jira: '/images/integrations/jira.png',
  linear: '/images/integrations/linear.png',
  asana: '/images/integrations/asana.png',
};

type Timeframe = '24h' | '7d' | '30d';

const PER_PAGE = 20;

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

function DestinationIcon({ type }: { type: string }) {
  const src = DESTINATION_ICON_SRC[type];
  if (src) {
    return <img src={src} alt="" className="h-4 w-4 rounded-sm flex-shrink-0 object-contain" />;
  }
  if (type === 'email') {
    return <Mail className="h-4 w-4 text-foreground-secondary flex-shrink-0" />;
  }
  return <Webhook className="h-4 w-4 text-foreground-secondary flex-shrink-0" />;
}

export default function NotificationHistorySection({ organizationId }: NotificationHistorySectionProps) {
  const { session } = useAuth();
  const { toast } = useToast();

  const [deliveries, setDeliveries] = useState<NotificationDelivery[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [retrying, setRetrying] = useState<string | null>(null);

  const [eventType, setEventType] = useState('all');
  const [destType, setDestType] = useState('all');
  const [status, setStatus] = useState('all');
  const [timeframe, setTimeframe] = useState<Timeframe>('7d');

  const [expandedId, setExpandedId] = useState<string | null>(null);

  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE));

  const fetchHistory = useCallback(async () => {
    if (!organizationId || !session?.access_token) return;
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: String(page),
        per_page: String(PER_PAGE),
        timeframe,
      });
      if (eventType !== 'all') params.set('event_type', eventType);
      if (destType !== 'all') params.set('destination_type', destType);
      if (status !== 'all') params.set('status', status);

      const res = await fetch(
        `/api/organizations/${organizationId}/notification-history?${params.toString()}`,
        { headers: { Authorization: `Bearer ${session.access_token}` } }
      );
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(err.error || `HTTP ${res.status}`);
      }
      const data: HistoryResponse = await res.json();
      setDeliveries(data.deliveries);
      setTotal(data.total);
    } catch (err: any) {
      toast({ title: 'Failed to load history', description: err.message, variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  }, [organizationId, session?.access_token, page, eventType, destType, status, timeframe, toast]);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  useEffect(() => {
    setPage(1);
  }, [eventType, destType, status, timeframe]);

  const handleRetry = async (deliveryId: string) => {
    if (!session?.access_token) return;
    setRetrying(deliveryId);
    try {
      const res = await fetch(
        `/api/organizations/${organizationId}/notification-history/${deliveryId}/retry`,
        {
          method: 'POST',
          headers: { Authorization: `Bearer ${session.access_token}` },
        }
      );
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: 'Retry failed' }));
        throw new Error(err.error || `HTTP ${res.status}`);
      }
      toast({ title: 'Retry queued', description: 'The notification will be re-delivered shortly.' });
      fetchHistory();
    } catch (err: any) {
      toast({ title: 'Retry failed', description: err.message, variant: 'destructive' });
    } finally {
      setRetrying(null);
    }
  };

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <Select value={eventType} onValueChange={setEventType}>
          <SelectTrigger className="w-[200px] h-8 text-xs">
            <SelectValue placeholder="Event type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Events</SelectItem>
            {EVENT_TYPES.map((t) => (
              <SelectItem key={t} value={t}>
                {EVENT_TYPE_LABELS[t] ?? t}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={destType} onValueChange={setDestType}>
          <SelectTrigger className="w-[180px] h-8 text-xs">
            <SelectValue placeholder="Destination" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Destinations</SelectItem>
            {DESTINATION_TYPES.map((d) => (
              <SelectItem key={d} value={d}>
                {DESTINATION_LABELS[d] ?? d}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={status} onValueChange={setStatus}>
          <SelectTrigger className="w-[160px] h-8 text-xs">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="delivered">Delivered</SelectItem>
            <SelectItem value="failed">Failed</SelectItem>
            <SelectItem value="rate_limited">Rate Limited</SelectItem>
            <SelectItem value="skipped">Skipped</SelectItem>
            <SelectItem value="pending">Pending</SelectItem>
            <SelectItem value="dry_run">Dry Run</SelectItem>
          </SelectContent>
        </Select>

        {/* Timeframe toggle */}
        <div className="flex items-center rounded-md border border-border bg-background-card overflow-hidden ml-auto">
          {(['24h', '7d', '30d'] as Timeframe[]).map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => setTimeframe(t)}
              className={cn(
                'px-3 py-1.5 text-xs font-medium transition-colors',
                timeframe === t
                  ? 'bg-foreground text-background'
                  : 'text-foreground-secondary hover:text-foreground hover:bg-background-subtle'
              )}
            >
              {t.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="bg-background-card border border-border rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[14%]">Time</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[18%]">Event</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[14%]">Project</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[16%]">Rule</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[16%]">Destination</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[12%]">Status</th>
                <th className="text-right px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[10%]" />
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {loading && (
                <>
                  {Array.from({ length: 6 }).map((_, i) => (
                    <tr key={i} className="animate-pulse">
                      <td className="px-4 py-3"><div className="h-4 bg-muted rounded w-16" /></td>
                      <td className="px-4 py-3"><div className="h-5 bg-muted rounded w-28" /></td>
                      <td className="px-4 py-3"><div className="h-4 bg-muted rounded w-20" /></td>
                      <td className="px-4 py-3"><div className="h-4 bg-muted rounded w-24" /></td>
                      <td className="px-4 py-3"><div className="h-4 bg-muted rounded w-20" /></td>
                      <td className="px-4 py-3"><div className="h-5 bg-muted rounded w-16" /></td>
                      <td className="px-4 py-3"><div className="h-4 bg-muted rounded w-8 ml-auto" /></td>
                    </tr>
                  ))}
                </>
              )}

              {!loading && deliveries.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-12 text-center">
                    <div className="flex flex-col items-center gap-2">
                      <Inbox className="h-8 w-8 text-foreground-secondary" />
                      <span className="text-sm text-foreground-secondary">No delivery history found</span>
                      <span className="text-xs text-foreground-muted">Notifications will appear here once rules are triggered.</span>
                    </div>
                  </td>
                </tr>
              )}

              {!loading && deliveries.map((d) => {
                const isExpanded = expandedId === d.id;
                return (
                  <tr
                    key={d.id}
                    className="group"
                  >
                    <td colSpan={7} className="p-0">
                      <div>
                        {/* Main row */}
                        <button
                          type="button"
                          onClick={() => setExpandedId(isExpanded ? null : d.id)}
                          className="w-full flex items-center px-4 py-3 text-left hover:bg-table-hover transition-colors"
                        >
                          {/* Time */}
                          <div className="w-[14%] flex items-center gap-1.5 pr-2">
                            <Clock className="h-3.5 w-3.5 text-foreground-secondary flex-shrink-0" />
                            <span className="text-xs text-foreground-secondary whitespace-nowrap" title={new Date(d.created_at).toLocaleString()}>
                              {relativeTime(d.created_at)}
                            </span>
                          </div>

                          {/* Event type */}
                          <div className="w-[18%] pr-2">
                            <Badge className={cn('text-[11px] whitespace-nowrap', EVENT_TYPE_COLORS[d.event_type] ?? 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20')}>
                              {EVENT_TYPE_LABELS[d.event_type] ?? d.event_type.replaceAll('_', ' ')}
                            </Badge>
                          </div>

                          {/* Project */}
                          <div className="w-[14%] pr-2">
                            <span className="text-sm text-foreground truncate block">
                              {d.project_name ?? '—'}
                            </span>
                          </div>

                          {/* Rule name */}
                          <div className="w-[16%] pr-2">
                            <span className="text-sm text-foreground truncate block">{d.rule_name}</span>
                          </div>

                          {/* Destination */}
                          <div className="w-[16%] pr-2">
                            <div className="flex items-center gap-1.5 min-w-0">
                              <DestinationIcon type={d.destination_type} />
                              <span className="text-sm text-foreground truncate">
                                {d.destination_name || DESTINATION_LABELS[d.destination_type] || d.destination_type}
                              </span>
                            </div>
                          </div>

                          {/* Status */}
                          <div className="w-[12%] pr-2">
                            <Badge className={cn('text-[11px]', STATUS_STYLES[d.status] ?? STATUS_STYLES.pending)}>
                              {STATUS_LABELS[d.status] ?? d.status}
                            </Badge>
                          </div>

                          {/* Expand indicator */}
                          <div className="w-[10%] flex items-center justify-end gap-1">
                            {d.status === 'failed' && (
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-7 px-2 text-xs text-foreground-secondary hover:text-foreground"
                                disabled={retrying === d.id}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleRetry(d.id);
                                }}
                              >
                                {retrying === d.id ? (
                                  <Loader2 className="h-3 w-3 animate-spin" />
                                ) : (
                                  <RefreshCw className="h-3 w-3" />
                                )}
                              </Button>
                            )}
                            {isExpanded ? (
                              <ChevronDown className="h-4 w-4 text-foreground-secondary" />
                            ) : (
                              <ChevronRight className="h-4 w-4 text-foreground-secondary" />
                            )}
                          </div>
                        </button>

                        {/* Expanded details */}
                        {isExpanded && (
                          <div className="px-4 pb-4 pt-1 border-t border-border/50 bg-background-subtle/30">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                              {/* Message */}
                              <div className="space-y-1.5">
                                <span className="text-xs font-medium text-foreground-secondary uppercase tracking-wider">Message</span>
                                {d.message_title ? (
                                  <div>
                                    <p className="text-sm font-medium text-foreground">{d.message_title}</p>
                                    {d.message_body && (
                                      <p className="text-xs text-foreground-secondary mt-1 whitespace-pre-wrap line-clamp-6">{d.message_body}</p>
                                    )}
                                  </div>
                                ) : (
                                  <p className="text-xs text-foreground-muted italic">No message content</p>
                                )}
                              </div>

                              {/* Error / Attempts */}
                              <div className="space-y-1.5">
                                {d.error_message && (
                                  <div>
                                    <span className="text-xs font-medium text-foreground-secondary uppercase tracking-wider">Error</span>
                                    <div className="mt-1 flex items-start gap-1.5 rounded-md bg-red-500/5 border border-red-500/10 px-3 py-2">
                                      <AlertCircle className="h-3.5 w-3.5 text-red-400 flex-shrink-0 mt-0.5" />
                                      <p className="text-xs text-red-400 break-all">{d.error_message}</p>
                                    </div>
                                  </div>
                                )}

                                {d.attempts && d.attempts.length > 0 && (
                                  <div>
                                    <span className="text-xs font-medium text-foreground-secondary uppercase tracking-wider">
                                      Delivery Attempts ({d.attempts.length})
                                    </span>
                                    <div className="mt-1 space-y-1">
                                      {d.attempts.map((a, idx) => (
                                        <div key={idx} className="flex items-center gap-2 text-xs">
                                          <span className={cn(
                                            'inline-block h-1.5 w-1.5 rounded-full flex-shrink-0',
                                            a.status === 'delivered' ? 'bg-green-400' : 'bg-red-400'
                                          )} />
                                          <span className="text-foreground-secondary">
                                            {relativeTime(a.attempted_at)}
                                          </span>
                                          {a.response_code && (
                                            <span className="text-foreground-muted">HTTP {a.response_code}</span>
                                          )}
                                          {a.error_message && (
                                            <span className="text-red-400 truncate">{a.error_message}</span>
                                          )}
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                )}

                                {!d.error_message && (!d.attempts || d.attempts.length === 0) && (
                                  <p className="text-xs text-foreground-muted italic">No additional details</p>
                                )}
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {!loading && total > PER_PAGE && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-border bg-background-card-header">
            <span className="text-xs text-foreground-secondary">
              {((page - 1) * PER_PAGE) + 1}–{Math.min(page * PER_PAGE, total)} of {total}
            </span>
            <div className="flex items-center gap-1">
              <Button
                variant="ghost"
                size="sm"
                className="h-7 px-2 text-xs"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                Previous
              </Button>
              {Array.from({ length: Math.min(totalPages, 5) }, (_, i) => {
                let pageNum: number;
                if (totalPages <= 5) {
                  pageNum = i + 1;
                } else if (page <= 3) {
                  pageNum = i + 1;
                } else if (page >= totalPages - 2) {
                  pageNum = totalPages - 4 + i;
                } else {
                  pageNum = page - 2 + i;
                }
                return (
                  <button
                    key={pageNum}
                    type="button"
                    onClick={() => setPage(pageNum)}
                    className={cn(
                      'h-7 w-7 rounded-md text-xs font-medium transition-colors',
                      page === pageNum
                        ? 'bg-foreground text-background'
                        : 'text-foreground-secondary hover:text-foreground hover:bg-background-subtle'
                    )}
                  >
                    {pageNum}
                  </button>
                );
              })}
              <Button
                variant="ghost"
                size="sm"
                className="h-7 px-2 text-xs"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              >
                Next
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

import { useCallback, useEffect, useMemo, useState } from 'react';
import { ChevronDown, ChevronRight, Loader2 } from 'lucide-react';
import { Button } from '../../../components/ui/button';
import { Input } from '../../../components/ui/input';
import { Badge } from '../../../components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../../../components/ui/select';
import { useToast } from '../../../hooks/use-toast';
import {
  apiAdminListExtractionFailures,
  apiAdminFleetMetrics,
  type ExtractionFailure,
  type FleetMetrics,
} from '../../../lib/api';

const PER_PAGE = 50;
const MESSAGE_PREVIEW_LIMIT = 120;

type SeverityFilter = 'all' | 'warn' | 'error';

function formatDate(s: string | null): string {
  if (!s) return '—';
  const d = new Date(s);
  return d.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function truncate(s: string, n: number): string {
  if (!s) return '';
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

function Stat({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded-lg border border-border bg-background p-3">
      <div className="text-xs text-foreground-secondary">{label}</div>
      <div className="text-xl font-semibold text-foreground tabular-nums">{value}</div>
      {sub ? <div className="text-xs text-foreground-secondary mt-0.5">{sub}</div> : null}
    </div>
  );
}

/**
 * Live fleet-dispatcher metrics. Polls every 5s — "watch the autoscaler react
 * to load." Inflight vs MAX_FLEET shows the hard cap; queue-wait percentiles +
 * throughput show drain health.
 */
function FleetPanel() {
  const [m, setM] = useState<FleetMetrics | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const data = await apiAdminFleetMetrics('extraction');
        if (alive) {
          setM(data);
          setError(false);
        }
      } catch {
        if (alive) setError(true);
      }
    };
    tick();
    const id = setInterval(tick, 5000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  if (error && !m) return null; // fleet metrics unavailable (CE / Fly not configured) — hide silently
  if (!m) {
    return (
      <div className="rounded-lg border border-border bg-background-card p-4 mb-4">
        <div className="h-5 w-32 bg-muted rounded animate-pulse mb-3" />
        <div className="grid gap-3 grid-cols-2 sm:grid-cols-3 lg:grid-cols-6">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="h-16 bg-muted/40 rounded-lg animate-pulse" />
          ))}
        </div>
      </div>
    );
  }

  const fleetPct = m.maxFleet > 0 ? Math.min(100, Math.round((m.inflight / m.maxFleet) * 100)) : 0;
  const fmtSec = (s: number | null) => (s == null ? '—' : s >= 60 ? `${Math.round(s / 60)}m` : `${s}s`);

  return (
    <div className="rounded-lg border border-border bg-background-card p-4 mb-4">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-semibold text-foreground">Extraction fleet</h2>
        <div className="flex items-center gap-2">
          {m.spendBlocked ? (
            <Badge variant="destructive">spend cap reached</Badge>
          ) : (
            <span className="inline-flex items-center gap-1 text-xs text-foreground-secondary">
              <span className="h-1.5 w-1.5 rounded-full bg-green-500 animate-pulse" /> live
            </span>
          )}
        </div>
      </div>
      <div className="grid gap-3 grid-cols-2 sm:grid-cols-3 lg:grid-cols-6">
        <Stat label="Queue depth" value={String(m.queued)} />
        <Stat label="Running" value={String(m.running)} sub={`${m.starting} starting`} />
        <Stat label="Inflight / max" value={`${m.inflight} / ${m.maxFleet}`} sub={`${fleetPct}% of cap`} />
        <Stat label="Throughput" value={`${m.throughputPerHour}/hr`} />
        <Stat label="Queue wait p50 / p95" value={`${fmtSec(m.p50QueueSeconds)} / ${fmtSec(m.p95QueueSeconds)}`} />
        <Stat
          label="Spend (this hour)"
          value={`$${m.spendThisHourUsd.toFixed(2)}`}
          sub={m.spendCapUsd != null ? `cap $${m.spendCapUsd.toFixed(2)}` : 'no cap'}
        />
      </div>
      <div className="mt-3 h-1.5 w-full rounded-full bg-muted overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-300 ${fleetPct >= 100 ? 'bg-amber-500' : 'bg-primary'}`}
          style={{ width: `${fleetPct}%` }}
        />
      </div>
    </div>
  );
}

function SkeletonRows({ rows }: { rows: number }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, i) => (
        <tr key={i} className="animate-pulse border-b border-border last:border-0">
          <td className="px-4 py-3"><div className="h-4 w-4 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-32 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-40 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-20 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-24 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-14 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-16 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-56 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-24 bg-muted rounded" /></td>
        </tr>
      ))}
    </>
  );
}

export default function ExtractionFailuresPage() {
  const { toast } = useToast();

  // Applied filters (sent to the API).
  const [appliedStep, setAppliedStep] = useState('');
  const [appliedCode, setAppliedCode] = useState('');
  const [appliedProjectId, setAppliedProjectId] = useState('');
  const [appliedSeverity, setAppliedSeverity] = useState<SeverityFilter>('all');

  // Draft filters bound to the inputs.
  const [stepInput, setStepInput] = useState('');
  const [codeInput, setCodeInput] = useState('');
  const [projectIdInput, setProjectIdInput] = useState('');
  const [severityInput, setSeverityInput] = useState<SeverityFilter>('all');

  const [page, setPage] = useState(1);
  const [rows, setRows] = useState<ExtractionFailure[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const resp = await apiAdminListExtractionFailures({
        page,
        per_page: PER_PAGE,
        step: appliedStep || undefined,
        code: appliedCode || undefined,
        project_id: appliedProjectId || undefined,
        severity: appliedSeverity === 'all' ? undefined : appliedSeverity,
      });
      setRows(resp.data);
      setTotal(resp.total);
    } catch (e: unknown) {
      toast({
        title: 'Failed to load failures',
        description: e instanceof Error ? e.message : 'Unknown error',
        variant: 'destructive',
      });
      setRows([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [page, appliedStep, appliedCode, appliedProjectId, appliedSeverity, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const totalPages = useMemo(() => Math.max(1, Math.ceil(total / PER_PAGE)), [total]);

  const applyFilters = () => {
    setAppliedStep(stepInput.trim());
    setAppliedCode(codeInput.trim());
    setAppliedProjectId(projectIdInput.trim());
    setAppliedSeverity(severityInput);
    setPage(1);
    setExpanded(new Set());
  };

  const clearFilters = () => {
    setStepInput('');
    setCodeInput('');
    setProjectIdInput('');
    setSeverityInput('all');
    setAppliedStep('');
    setAppliedCode('');
    setAppliedProjectId('');
    setAppliedSeverity('all');
    setPage(1);
    setExpanded(new Set());
  };

  const toggleRow = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const hasActiveFilters =
    !!appliedStep || !!appliedCode || !!appliedProjectId || appliedSeverity !== 'all';

  return (
    <div className="container mx-auto py-8 px-4 max-w-7xl">
      <h1 className="text-2xl font-semibold mb-6">Extraction Failures</h1>

      {/* Live fleet dispatcher metrics */}
      <FleetPanel />

      {/* Filter bar */}
      <div className="rounded-lg border border-border bg-background-card p-4 mb-4">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          <div>
            <label className="text-xs font-medium text-foreground-secondary mb-1 block">
              Step
            </label>
            <Input
              value={stepInput}
              onChange={(e) => setStepInput(e.target.value)}
              placeholder="e.g. clone, sbom, dep_scan"
              onKeyDown={(e) => {
                if (e.key === 'Enter') applyFilters();
              }}
            />
          </div>
          <div>
            <label className="text-xs font-medium text-foreground-secondary mb-1 block">
              Code
            </label>
            <Input
              value={codeInput}
              onChange={(e) => setCodeInput(e.target.value)}
              placeholder="e.g. timeout, oom"
              onKeyDown={(e) => {
                if (e.key === 'Enter') applyFilters();
              }}
            />
          </div>
          <div>
            <label className="text-xs font-medium text-foreground-secondary mb-1 block">
              Project ID
            </label>
            <Input
              value={projectIdInput}
              onChange={(e) => setProjectIdInput(e.target.value)}
              placeholder="uuid"
              onKeyDown={(e) => {
                if (e.key === 'Enter') applyFilters();
              }}
            />
          </div>
          <div>
            <label className="text-xs font-medium text-foreground-secondary mb-1 block">
              Severity
            </label>
            <Select
              value={severityInput}
              onValueChange={(v) => setSeverityInput(v as SeverityFilter)}
            >
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="error">Error</SelectItem>
                <SelectItem value="warn">Warn</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="flex items-end gap-2">
            <Button onClick={applyFilters} className="flex-1">
              Apply
            </Button>
            <Button
              variant="outline"
              onClick={clearFilters}
              disabled={!hasActiveFilters && severityInput === 'all' && !stepInput && !codeInput && !projectIdInput}
            >
              Clear
            </Button>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-background-card-header">
            <tr className="border-b border-border">
              <th className="w-8 px-4 py-3" />
              <th className="text-left font-medium px-4 py-3 text-foreground">Created</th>
              <th className="text-left font-medium px-4 py-3 text-foreground">Project</th>
              <th className="text-left font-medium px-4 py-3 text-foreground">Step</th>
              <th className="text-left font-medium px-4 py-3 text-foreground">Code</th>
              <th className="text-left font-medium px-4 py-3 text-foreground">Severity</th>
              <th className="text-right font-medium px-4 py-3 text-foreground">Duration</th>
              <th className="text-left font-medium px-4 py-3 text-foreground">Message</th>
              <th className="text-left font-medium px-4 py-3 text-foreground">Machine</th>
            </tr>
          </thead>
          <tbody>
            {loading && rows.length === 0 ? (
              <SkeletonRows rows={8} />
            ) : rows.length === 0 ? (
              <tr>
                <td colSpan={9} className="px-4 py-16 text-center text-foreground-secondary">
                  No extraction failures found
                </td>
              </tr>
            ) : (
              rows.map((row) => {
                const isExpanded = expanded.has(row.id);
                const preview = truncate(row.message ?? '', MESSAGE_PREVIEW_LIMIT);
                const messageTruncated = (row.message ?? '').length > MESSAGE_PREVIEW_LIMIT;
                return (
                  <>
                    <tr
                      key={row.id}
                      className="border-b border-border last:border-0 hover:bg-muted/30 cursor-pointer"
                      onClick={() => toggleRow(row.id)}
                    >
                      <td className="px-4 py-3 align-top text-foreground-secondary">
                        {isExpanded ? (
                          <ChevronDown className="h-4 w-4" />
                        ) : (
                          <ChevronRight className="h-4 w-4" />
                        )}
                      </td>
                      <td className="px-4 py-3 align-top whitespace-nowrap text-foreground-secondary">
                        {formatDate(row.created_at)}
                      </td>
                      <td className="px-4 py-3 align-top text-foreground">
                        {row.project_name || (
                          <span className="font-mono text-xs text-foreground-secondary">
                            {row.project_id.slice(0, 8)}…
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 align-top font-mono text-xs text-foreground">
                        {row.step}
                      </td>
                      <td className="px-4 py-3 align-top font-mono text-xs text-foreground">
                        {row.code}
                      </td>
                      <td className="px-4 py-3 align-top">
                        <Badge
                          variant={row.severity === 'error' ? 'destructive' : 'warning'}
                        >
                          {row.severity}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 align-top text-right tabular-nums text-foreground-secondary whitespace-nowrap">
                        {row.duration_ms != null ? `${row.duration_ms} ms` : '—'}
                      </td>
                      <td className="px-4 py-3 align-top text-foreground">
                        <span className="block max-w-xl">
                          {preview}
                          {messageTruncated && !isExpanded ? (
                            <span className="ml-1 text-xs text-foreground-secondary">
                              (expand)
                            </span>
                          ) : null}
                        </span>
                      </td>
                      <td className="px-4 py-3 align-top font-mono text-xs text-foreground-secondary">
                        {row.machine_id || '—'}
                      </td>
                    </tr>
                    {isExpanded ? (
                      <tr key={`${row.id}-detail`} className="border-b border-border last:border-0 bg-muted/20">
                        <td />
                        <td colSpan={8} className="px-4 py-4">
                          <div className="space-y-3">
                            <div>
                              <div className="text-xs font-medium text-foreground-secondary mb-1">
                                Message
                              </div>
                              <pre className="text-xs text-foreground bg-background rounded border border-border p-3 whitespace-pre-wrap break-words">
                                {row.message || '(empty)'}
                              </pre>
                            </div>
                            {row.stack ? (
                              <div>
                                <div className="text-xs font-medium text-foreground-secondary mb-1">
                                  Stack
                                </div>
                                <pre className="text-xs text-foreground bg-background rounded border border-border p-3 whitespace-pre-wrap break-words max-h-96 overflow-auto">
                                  {row.stack}
                                </pre>
                              </div>
                            ) : null}
                            <div className="grid grid-cols-2 gap-3 text-xs text-foreground-secondary">
                              <div>
                                <span className="font-medium text-foreground">Project ID:</span>{' '}
                                <span className="font-mono">{row.project_id}</span>
                              </div>
                              <div>
                                <span className="font-medium text-foreground">Job ID:</span>{' '}
                                <span className="font-mono">{row.extraction_job_id}</span>
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    ) : null}
                  </>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between mt-4">
        <div className="text-xs text-foreground-secondary">
          {loading ? (
            <span className="inline-flex items-center gap-1">
              <Loader2 className="h-3 w-3 animate-spin" /> Loading…
            </span>
          ) : total === 0 ? (
            '0 results'
          ) : (
            `Showing ${(page - 1) * PER_PAGE + 1}–${Math.min(page * PER_PAGE, total)} of ${total}`
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1 || loading}
          >
            Previous
          </Button>
          <span className="text-xs text-foreground-secondary tabular-nums">
            Page {page} of {totalPages}
          </span>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages || loading}
          >
            Next
          </Button>
        </div>
      </div>
    </div>
  );
}

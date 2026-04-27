import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Search, ChevronLeft, ChevronRight, Loader2, MoreHorizontal, Eye,
  Trash2, Power, RefreshCw, Inbox,
} from 'lucide-react';
import {
  api,
  type GeneratedRuleStatus,
  type GeneratedRuleSummary,
  type ReachabilitySettings,
} from '../../lib/api';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from '../ui/dropdown-menu';
import { useToast } from '../../hooks/use-toast';
import { cn } from '../../lib/utils';
import GeneratedRuleDetailModal from './GeneratedRuleDetailModal';

interface GeneratedRulesTableProps {
  organizationId: string;
  settings: ReachabilitySettings | null;
  canManage: boolean;
}

const PER_PAGE = 25;
const STATUS_FILTERS: { value: GeneratedRuleStatus | 'all'; label: string }[] = [
  { value: 'all', label: 'All statuses' },
  { value: 'validated', label: 'Validated' },
  { value: 'pending', label: 'Pending' },
  { value: 'failed_validation', label: 'Validation failed' },
  { value: 'manual_override', label: 'Manual override' },
];

function formatDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  } catch {
    return iso;
  }
}

function statusVariant(status: string): 'success' | 'warning' | 'destructive' | 'default' {
  switch (status) {
    case 'validated': return 'success';
    case 'pending': return 'warning';
    case 'failed_validation': return 'destructive';
    case 'manual_override': return 'default';
    default: return 'default';
  }
}

function statusLabel(status: string): string {
  switch (status) {
    case 'validated': return 'Validated';
    case 'pending': return 'Pending';
    case 'failed_validation': return 'Failed';
    case 'manual_override': return 'Override';
    default: return status;
  }
}

function packageDisplay(purl: string): string {
  // Reduce noise: pkg:npm/lodash@4.17.20 → lodash@4.17.20
  const m = /^pkg:[^/]+\/(.*)$/.exec(purl);
  return m ? m[1] : purl;
}

export default function GeneratedRulesTable({
  organizationId,
  settings,
  canManage,
}: GeneratedRulesTableProps) {
  const { toast } = useToast();
  const [rules, setRules] = useState<GeneratedRuleSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [statusFilter, setStatusFilter] = useState<GeneratedRuleStatus | 'all'>('all');
  const [detailRuleId, setDetailRuleId] = useState<string | null>(null);
  const [busyRuleId, setBusyRuleId] = useState<string | null>(null);

  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE));

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.listGeneratedRules(organizationId, {
        page,
        perPage: PER_PAGE,
        status: statusFilter !== 'all' ? statusFilter : undefined,
        search: search.trim() || undefined,
      });
      setRules(result.rules);
      setTotal(result.pagination.total);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to load rules';
      toast({ title: 'Failed to load generated rules', description: message, variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  }, [organizationId, page, statusFilter, search, toast]);

  useEffect(() => { load(); }, [load]);

  // Debounce the search input (300ms) so we don't hit the API on each keystroke.
  useEffect(() => {
    const t = window.setTimeout(() => {
      if (searchInput !== search) {
        setSearch(searchInput);
        setPage(1);
      }
    }, 300);
    return () => window.clearTimeout(t);
  }, [searchInput, search]);

  const handleToggleEnabled = async (rule: GeneratedRuleSummary) => {
    setBusyRuleId(rule.id);
    try {
      await api.updateGeneratedRule(organizationId, rule.id, { enabled: !rule.enabled });
      toast({ title: rule.enabled ? 'Rule disabled' : 'Rule enabled' });
      await load();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to update rule';
      toast({ title: 'Update failed', description: message, variant: 'destructive' });
    } finally {
      setBusyRuleId(null);
    }
  };

  const handleDelete = async (rule: GeneratedRuleSummary) => {
    if (!window.confirm(`Delete the generated rule for ${rule.cve_id}? This is permanent.`)) return;
    setBusyRuleId(rule.id);
    try {
      await api.deleteGeneratedRule(organizationId, rule.id);
      toast({ title: 'Rule deleted' });
      await load();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to delete rule';
      toast({ title: 'Delete failed', description: message, variant: 'destructive' });
    } finally {
      setBusyRuleId(null);
    }
  };

  const handleQuickRegenerate = async (rule: GeneratedRuleSummary) => {
    if (!settings) {
      toast({ title: 'Settings not loaded yet', variant: 'destructive' });
      return;
    }
    setBusyRuleId(rule.id);
    try {
      await api.regenerateGeneratedRule(organizationId, rule.id, {
        provider: settings.ai_provider,
        model: settings.ai_model,
      });
      toast({
        title: 'Regeneration queued',
        description: 'Will run on the next extraction scan.',
      });
      await load();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to queue regeneration';
      toast({ title: 'Regeneration failed', description: message, variant: 'destructive' });
    } finally {
      setBusyRuleId(null);
    }
  };

  const showEmpty = !loading && rules.length === 0;
  const filtersActive = statusFilter !== 'all' || search.trim().length > 0;

  const skeletonRows = useMemo(() => Array.from({ length: 6 }, (_, i) => i), []);

  return (
    <div className="space-y-4">
      <div>
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <h3 className="text-base font-semibold text-foreground">Generated rules</h3>
            <p className="text-xs text-foreground-secondary mt-0.5">
              AI-generated Semgrep taint rules for your organization. Validated rules run during reachability analysis.
            </p>
          </div>
        </div>

        {/* Filters */}
        <div className="mt-4 flex items-center gap-2 flex-wrap">
          <div className="relative flex-1 min-w-[220px] max-w-sm">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-foreground-secondary pointer-events-none" />
            <Input
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              placeholder="Search by CVE or package…"
              className="pl-8 h-9 text-sm"
            />
          </div>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" className="text-xs gap-1.5">
                {STATUS_FILTERS.find((s) => s.value === statusFilter)?.label}
                <ChevronRight className="h-3 w-3 rotate-90 opacity-50" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start">
              {STATUS_FILTERS.map((s) => (
                <DropdownMenuItem
                  key={s.value}
                  onClick={() => { setStatusFilter(s.value); setPage(1); }}
                >
                  {s.label}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
          {filtersActive && (
            <button
              type="button"
              onClick={() => {
                setSearchInput('');
                setSearch('');
                setStatusFilter('all');
                setPage(1);
              }}
              className="text-xs text-foreground-secondary hover:text-foreground px-2"
            >
              Clear filters
            </button>
          )}
        </div>
      </div>

      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header">
              <tr className="border-b border-border">
                <th className="text-left px-5 py-2.5 text-xs font-medium text-foreground-secondary">CVE</th>
                <th className="text-left px-5 py-2.5 text-xs font-medium text-foreground-secondary">Package</th>
                <th className="text-left px-5 py-2.5 text-xs font-medium text-foreground-secondary">Status</th>
                <th className="text-left px-5 py-2.5 text-xs font-medium text-foreground-secondary">Model</th>
                <th className="text-right px-5 py-2.5 text-xs font-medium text-foreground-secondary">Cost</th>
                <th className="text-left px-5 py-2.5 text-xs font-medium text-foreground-secondary">Generated</th>
                <th className="text-right px-5 py-2.5 text-xs font-medium text-foreground-secondary">Used</th>
                <th className="px-3 py-2.5 w-[40px]"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {loading ? (
                skeletonRows.map((i) => (
                  <tr key={`sk-${i}`}>
                    <td colSpan={8} className="px-5 py-3">
                      <div className="h-4 w-full bg-muted/40 animate-pulse rounded" />
                    </td>
                  </tr>
                ))
              ) : showEmpty ? (
                <tr>
                  <td colSpan={8} className="px-5 py-12 text-center">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <div className="h-12 w-12 rounded-full bg-background-subtle flex items-center justify-center">
                        <Inbox className="h-5 w-5 text-foreground-secondary" />
                      </div>
                      <p className="text-sm font-medium text-foreground">
                        {filtersActive ? 'No rules match your filters' : 'No generated rules yet'}
                      </p>
                      <p className="text-xs text-foreground-secondary max-w-[320px]">
                        {filtersActive
                          ? 'Try clearing filters to see all rules.'
                          : 'Rules are generated automatically during extraction when vulnerabilities match your trigger policy.'}
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                rules.map((r) => (
                  <tr
                    key={r.id}
                    className="hover:bg-table-hover transition-colors cursor-pointer"
                    onClick={() => setDetailRuleId(r.id)}
                  >
                    <td className="px-5 py-2.5 font-mono text-xs text-foreground whitespace-nowrap">{r.cve_id}</td>
                    <td className="px-5 py-2.5 max-w-[260px]">
                      <div className="truncate text-foreground" title={r.package_purl}>{packageDisplay(r.package_purl)}</div>
                      <div className="text-xs text-foreground-secondary capitalize mt-0.5">{r.ecosystem}</div>
                    </td>
                    <td className="px-5 py-2.5">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <Badge variant={statusVariant(r.validation_status)}>
                          {statusLabel(r.validation_status)}
                        </Badge>
                        {!r.enabled && <Badge variant="muted">Off</Badge>}
                      </div>
                    </td>
                    <td className="px-5 py-2.5 text-xs text-foreground-secondary whitespace-nowrap">
                      <span className="capitalize">{r.generated_with_provider}</span>
                      <span className="mx-1 opacity-50">/</span>
                      <span className="font-mono">{r.generated_with_model}</span>
                    </td>
                    <td className="px-5 py-2.5 text-right text-xs text-foreground tabular-nums whitespace-nowrap">
                      ${r.generation_cost_usd.toFixed(4)}
                    </td>
                    <td className="px-5 py-2.5 text-xs text-foreground-secondary whitespace-nowrap">
                      {formatDate(r.generated_at)}
                    </td>
                    <td className="px-5 py-2.5 text-right text-xs text-foreground tabular-nums whitespace-nowrap">{r.use_count}</td>
                    <td
                      className="px-3 py-2.5 text-right"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <button
                            type="button"
                            className="h-7 w-7 rounded-md flex items-center justify-center text-foreground-secondary hover:text-foreground hover:bg-background-subtle disabled:opacity-50"
                            disabled={busyRuleId === r.id}
                            aria-label="Actions"
                          >
                            {busyRuleId === r.id
                              ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                              : <MoreHorizontal className="h-3.5 w-3.5" />}
                          </button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => setDetailRuleId(r.id)}>
                            <Eye className="h-3.5 w-3.5 mr-2" /> View details
                          </DropdownMenuItem>
                          {canManage && (
                            <>
                              <DropdownMenuItem onClick={() => handleQuickRegenerate(r)}>
                                <RefreshCw className="h-3.5 w-3.5 mr-2" /> Regenerate (default model)
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => handleToggleEnabled(r)}>
                                <Power className="h-3.5 w-3.5 mr-2" />
                                {r.enabled ? 'Disable' : 'Enable'}
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem
                                onClick={() => handleDelete(r)}
                                className="text-destructive focus:text-destructive"
                              >
                                <Trash2 className="h-3.5 w-3.5 mr-2" /> Delete
                              </DropdownMenuItem>
                            </>
                          )}
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {!loading && rules.length > 0 && (
          <div className="flex items-center justify-between px-5 py-3 border-t border-border bg-background-card-header">
            <p className="text-xs text-foreground-secondary">
              {total} {total === 1 ? 'rule' : 'rules'}
            </p>
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className={cn(
                  'h-7 w-7 rounded-md border border-border flex items-center justify-center',
                  'text-foreground-secondary hover:text-foreground hover:bg-background-subtle',
                  'disabled:opacity-40 disabled:cursor-not-allowed',
                )}
              >
                <ChevronLeft className="h-3.5 w-3.5" />
              </button>
              <span className="text-xs text-foreground-secondary px-2 tabular-nums">
                {page}/{totalPages}
              </span>
              <button
                type="button"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className={cn(
                  'h-7 w-7 rounded-md border border-border flex items-center justify-center',
                  'text-foreground-secondary hover:text-foreground hover:bg-background-subtle',
                  'disabled:opacity-40 disabled:cursor-not-allowed',
                )}
              >
                <ChevronRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>

      <GeneratedRuleDetailModal
        organizationId={organizationId}
        ruleId={detailRuleId}
        settings={settings}
        onClose={() => setDetailRuleId(null)}
        onChanged={load}
        canManage={canManage}
      />
    </div>
  );
}

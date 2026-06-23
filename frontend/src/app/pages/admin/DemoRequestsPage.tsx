import { useCallback, useEffect, useMemo, useState } from 'react';
import { ChevronDown, ChevronRight, Loader2 } from 'lucide-react';
import { Button } from '../../../components/ui/button';
import { useToast } from '../../../hooks/use-toast';
import { apiAdminListDemoRequests, type DemoRequestLead } from '../../../lib/api';

const PER_PAGE = 50;
const DETAILS_PREVIEW_LIMIT = 100;

function formatDate(s: string | null): string {
  if (!s) return '—';
  return new Date(s).toLocaleString(undefined, {
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

function fullName(r: DemoRequestLead): string {
  return `${r.first_name} ${r.last_name}`.trim() || '—';
}

function SkeletonRows({ rows }: { rows: number }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, i) => (
        <tr key={i} className="animate-pulse border-b border-border last:border-0">
          <td className="px-4 py-3"><div className="h-4 w-4 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-32 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-28 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-40 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-24 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-48 bg-muted rounded" /></td>
        </tr>
      ))}
    </>
  );
}

export default function DemoRequestsPage() {
  const { toast } = useToast();
  const [page, setPage] = useState(1);
  const [rows, setRows] = useState<DemoRequestLead[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const resp = await apiAdminListDemoRequests({ page, per_page: PER_PAGE });
      setRows(resp.data);
      setTotal(resp.total);
    } catch (e: unknown) {
      toast({
        title: 'Failed to load demo requests',
        description: e instanceof Error ? e.message : 'Unknown error',
        variant: 'destructive',
      });
      setRows([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [page, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const totalPages = useMemo(() => Math.max(1, Math.ceil(total / PER_PAGE)), [total]);

  const toggleRow = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <div className="mx-auto w-full max-w-7xl px-4 sm:px-6 lg:px-8 py-8 space-y-3">
      <div>
        <h2 className="text-sm font-semibold text-foreground">Demo requests</h2>
        <p className="mt-0.5 text-xs text-foreground-secondary">
          Leads submitted from the public Get Demo page, newest first.
        </p>
      </div>

      <div className="overflow-hidden rounded-lg border border-border bg-background-card">
        <table className="w-full text-sm">
          <thead className="bg-background-card-header">
            <tr className="border-b border-border text-xs font-semibold uppercase tracking-wider text-foreground-secondary">
              <th className="w-8 px-4 py-2.5" />
              <th className="text-left px-4 py-2.5">Created</th>
              <th className="text-left px-4 py-2.5">Name</th>
              <th className="text-left px-4 py-2.5">Email</th>
              <th className="text-left px-4 py-2.5">Company</th>
              <th className="text-left px-4 py-2.5">Details</th>
            </tr>
          </thead>
          <tbody>
            {loading && rows.length === 0 ? (
              <SkeletonRows rows={8} />
            ) : rows.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-16 text-center text-foreground-secondary">
                  No demo requests yet
                </td>
              </tr>
            ) : (
              rows.map((row) => {
                const hasDetails = !!(row.details && row.details.trim());
                const isExpanded = expanded.has(row.id);
                const preview = truncate(row.details ?? '', DETAILS_PREVIEW_LIMIT);
                const detailsTruncated = (row.details ?? '').length > DETAILS_PREVIEW_LIMIT;
                return (
                  <>
                    <tr
                      key={row.id}
                      className={`border-b border-border last:border-0 ${hasDetails ? 'hover:bg-table-hover cursor-pointer' : ''}`}
                      onClick={hasDetails ? () => toggleRow(row.id) : undefined}
                    >
                      <td className="px-4 py-3 align-top text-foreground-secondary">
                        {hasDetails ? (
                          isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />
                        ) : null}
                      </td>
                      <td className="px-4 py-3 align-top whitespace-nowrap text-foreground-secondary">
                        {formatDate(row.created_at)}
                      </td>
                      <td className="px-4 py-3 align-top text-foreground">{fullName(row)}</td>
                      <td className="px-4 py-3 align-top">
                        <a
                          href={`mailto:${row.email}`}
                          onClick={(e) => e.stopPropagation()}
                          className="text-foreground hover:text-accent-text hover:underline"
                        >
                          {row.email}
                        </a>
                      </td>
                      <td className="px-4 py-3 align-top text-foreground">
                        {row.company_name || <span className="text-foreground-secondary">—</span>}
                      </td>
                      <td className="px-4 py-3 align-top text-foreground">
                        {hasDetails ? (
                          <span className="block max-w-md">
                            {preview}
                            {detailsTruncated && !isExpanded ? (
                              <span className="ml-1 text-xs text-foreground-secondary">(expand)</span>
                            ) : null}
                          </span>
                        ) : (
                          <span className="text-foreground-secondary">—</span>
                        )}
                      </td>
                    </tr>
                    {hasDetails && isExpanded ? (
                      <tr key={`${row.id}-detail`} className="border-b border-border last:border-0 bg-muted/20">
                        <td />
                        <td colSpan={5} className="px-4 py-4">
                          <div className="text-xs font-medium text-foreground-secondary mb-1">Details</div>
                          <pre className="text-xs text-foreground bg-background rounded border border-border p-3 whitespace-pre-wrap break-words">
                            {row.details}
                          </pre>
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

      <div className="flex items-center justify-between">
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

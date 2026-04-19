import { useState, useMemo } from 'react';
import { Loader2 } from 'lucide-react';
import { Button } from '../ui/button';
import { Checkbox } from '../ui/checkbox';
import type { SlaComplianceResponse } from '../../lib/api';
import { api } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';

interface SLAViolationsTableProps {
  organizationId: string;
  violations: SlaComplianceResponse['violations'];
  onFixTriggered?: () => void;
}

function formatDate(s: string | null): string {
  if (!s) return '—';
  const d = new Date(s);
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function hoursOverdue(deadline: string | null): number | null {
  if (!deadline) return null;
  const diff = Date.now() - new Date(deadline).getTime();
  return diff > 0 ? Math.round(diff / (1000 * 60 * 60) * 10) / 10 : 0;
}

export default function SLAViolationsTable({ organizationId, violations, onFixTriggered }: SLAViolationsTableProps) {
  const { toast } = useToast();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [fixing, setFixing] = useState(false);

  const sortedViolations = useMemo(() => {
    return [...violations].sort((a, b) => {
      const aOver = hoursOverdue(a.deadline) ?? -1;
      const bOver = hoursOverdue(b.deadline) ?? -1;
      return bOver - aOver;
    });
  }, [violations]);

  const toggleOne = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleAll = () => {
    if (selected.size === sortedViolations.length) setSelected(new Set());
    else setSelected(new Set(sortedViolations.map((v) => v.id)));
  };

  const handleFixSelected = async () => {
    const toFix = sortedViolations.filter((v) => selected.has(v.id));
    if (toFix.length === 0) {
      toast({ title: 'No selection', description: 'Select at least one violation.', variant: 'destructive' });
      return;
    }
    setFixing(true);
    try {
      let ok = 0;
      let err = 0;
      for (const row of toFix) {
        const res = await api.requestFix(organizationId, row.project_id, {
          strategy: 'patch',
          vulnerabilityOsvId: row.osv_id,
        });
        if (res.success) ok++;
        else err++;
      }
      if (ok > 0) toast({ title: 'Fix requested', description: `${ok} fix job(s) queued.${err > 0 ? ` ${err} failed.` : ''}` });
      if (err > 0 && ok === 0) toast({ title: 'Fix failed', description: 'Could not request fix for selected items.', variant: 'destructive' });
      setSelected(new Set());
      onFixTriggered?.();
    } catch (e: unknown) {
      toast({ title: 'Error', description: e instanceof Error ? e.message : 'Failed to trigger fix.', variant: 'destructive' });
    } finally {
      setFixing(false);
    }
  };

  if (violations.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-muted/30 px-4 py-6 text-center text-sm text-muted-foreground">
        No current SLA violations.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Button size="sm" variant="outline" onClick={handleFixSelected} disabled={selected.size === 0 || fixing}>
          {fixing ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
          Fix selected with AI ({selected.size})
        </Button>
      </div>
      <div className="rounded-lg border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/50">
              <th className="w-10 px-2 py-2">
                <Checkbox
                  checked={selected.size === sortedViolations.length && sortedViolations.length > 0}
                  onCheckedChange={toggleAll}
                  aria-label="Select all"
                />
              </th>
              <th className="text-left font-medium px-4 py-2.5 text-foreground">Project</th>
              <th className="text-left font-medium px-4 py-2.5 text-foreground">Vulnerability</th>
              <th className="text-left font-medium px-4 py-2.5 text-foreground">Severity</th>
              <th className="text-left font-medium px-4 py-2.5 text-foreground">Detected</th>
              <th className="text-left font-medium px-4 py-2.5 text-foreground">Deadline</th>
              <th className="text-right font-medium px-4 py-2.5 text-foreground">Overdue (h)</th>
            </tr>
          </thead>
          <tbody>
            {sortedViolations.map((row) => {
              const over = hoursOverdue(row.deadline);
              return (
                <tr key={row.id} className="border-b border-border last:border-0 hover:bg-muted/30">
                  <td className="w-10 px-2 py-2">
                    <Checkbox
                      checked={selected.has(row.id)}
                      onCheckedChange={() => toggleOne(row.id)}
                      aria-label={`Select ${row.osv_id}`}
                    />
                  </td>
                  <td className="px-4 py-2.5 text-foreground">{row.project_name}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-foreground">{row.osv_id}</td>
                  <td className="px-4 py-2.5">
                    <span className={row.severity === 'critical' ? 'text-red-500' : row.severity === 'high' ? 'text-orange-500' : 'text-foreground'}>
                      {row.severity}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-muted-foreground">{formatDate(row.detected_at)}</td>
                  <td className="px-4 py-2.5 text-muted-foreground">{formatDate(row.deadline)}</td>
                  <td className="px-4 py-2.5 text-right tabular-nums">
                    {over != null && over > 0 ? <span className="text-red-500">{over.toFixed(1)}</span> : over === 0 ? '0' : '—'}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

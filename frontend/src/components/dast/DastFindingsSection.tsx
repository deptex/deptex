// Phase 23b PR 5: Project Security tab DAST surface.
//
// Renders three pieces stacked below the SCA vulnerabilities table:
//   1. Last-scan strip — status + relative time, mirroring the extraction
//      run-history affordance the user expects on the Settings tab.
//   2. Empty state — when the project has never run a DAST scan, point them
//      at the Scanning settings tab.
//   3. Findings table — flat list with severity, endpoint, vuln type, and
//      the Confirmed Exploitable badge on cross-linked rows (PR 6 lights
//      that badge up; the markup is here so PR 6 is a 1-line wire-up).

import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, ChevronRight, Globe, Loader2, Radar, ShieldAlert, Star } from 'lucide-react';
import { Badge } from '../ui/badge';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
import { EngineChip } from './EngineChip';
import { api, type DastFindingDTO, type DastJobDTO, type DastSeverity } from '../../lib/api';

interface DastFindingsSectionProps {
  organizationId: string;
  projectId: string;
}

const SEVERITY_RANK: Record<DastSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function severityBadge(sev: DastSeverity) {
  const variant: 'destructive' | 'warning' | 'secondary' | 'muted' | 'outline' =
    sev === 'critical' || sev === 'high' ? 'destructive' :
    sev === 'medium' ? 'warning' :
    sev === 'low' ? 'muted' :
    'outline';
  return (
    <Badge variant={variant} className="capitalize text-[11px] px-1.5 py-0">
      {sev}
    </Badge>
  );
}

function formatRelative(iso: string | null | undefined): string {
  if (!iso) return '';
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return 'just now';
  const m = Math.floor(diff / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d ago`;
  return `${Math.floor(d / 30)}mo ago`;
}

export function DastFindingsSection({ organizationId, projectId }: DastFindingsSectionProps) {
  const [jobs, setJobs] = useState<DastJobDTO[] | null>(null);
  const [findings, setFindings] = useState<DastFindingDTO[] | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    (async () => {
      try {
        const [j, f] = await Promise.all([
          api.getDastJobs(projectId, { limit: 5 }),
          api.getDastFindings(projectId, { limit: 200 }),
        ]);
        if (cancelled) return;
        setJobs(j);
        setFindings(f);
      } catch (e) {
        console.error('[dast] section load failed', e);
        if (!cancelled) {
          setJobs([]);
          setFindings([]);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [projectId]);

  if (loading) {
    return (
      <div className="border border-border rounded-lg overflow-hidden bg-background-card animate-pulse">
        <div className="px-4 py-3 border-b border-border h-12" />
        <div className="px-4 py-6 h-24" />
      </div>
    );
  }

  const lastJob = jobs && jobs.length > 0 ? jobs[0] : null;
  const hasFindings = findings && findings.length > 0;
  const sortedFindings = [...(findings ?? [])].sort(
    (a, b) => (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99)
  );

  // Never-scanned: show empty state and stop.
  if (!lastJob) {
    return <DastEmptyState organizationId={organizationId} projectId={projectId} />;
  }

  return (
    <div className="space-y-3">
      <DastLastScanStrip job={lastJob} organizationId={organizationId} projectId={projectId} />

      {hasFindings ? (
        <div className="border border-border rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">Severity</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">Engine</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">Endpoint</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">Finding</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">Linked</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {sortedFindings.map((f) => (
                <DastFindingRow key={f.id} finding={f} />
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="py-6 text-center text-sm text-foreground-secondary border border-border rounded-lg bg-background-subtle/50">
          No DAST findings on the latest scan — the target appears clean.
        </div>
      )}
    </div>
  );
}

interface DastLastScanStripProps {
  job: DastJobDTO;
  organizationId: string;
  projectId: string;
}

export function DastLastScanStrip({ job, organizationId, projectId }: DastLastScanStripProps) {
  const isActive = job.status === 'queued' || job.status === 'processing';
  const isFailed = job.status === 'failed';

  return (
    <div className="border border-border rounded-lg bg-background-card px-4 py-3 flex items-center justify-between gap-4">
      <div className="flex items-center gap-3 min-w-0">
        <div className="h-7 w-7 rounded-md bg-background-subtle/50 flex items-center justify-center shrink-0">
          <Radar className="h-3.5 w-3.5 text-foreground-secondary" />
        </div>
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-foreground">DAST</span>
            {isActive ? (
              <span className="inline-flex items-center gap-1 text-xs text-foreground-secondary">
                <Loader2 className="h-3 w-3 animate-spin" />
                Scanning
              </span>
            ) : isFailed ? (
              <span className="inline-flex items-center gap-1 text-xs text-destructive">
                <AlertTriangle className="h-3 w-3" />
                Last scan failed
              </span>
            ) : (
              <span className="text-xs text-foreground-secondary">
                Last scan {formatRelative(job.completed_at ?? job.created_at)}
              </span>
            )}
          </div>
          {job.target_url ? (
            <div className="flex items-center gap-1 text-xs text-foreground-secondary mt-0.5 min-w-0">
              <Globe className="h-3 w-3 shrink-0" />
              <span className="truncate" title={job.target_url}>{job.target_url}</span>
            </div>
          ) : null}
        </div>
      </div>
      <Link
        to={`/organizations/${organizationId}/projects/${projectId}/settings/scanning`}
        className="inline-flex items-center gap-1 text-xs text-foreground-secondary hover:text-foreground shrink-0"
      >
        Configure <ChevronRight className="h-3 w-3" />
      </Link>
    </div>
  );
}

interface DastEmptyStateProps {
  organizationId: string;
  projectId: string;
}

export function DastEmptyState({ organizationId, projectId }: DastEmptyStateProps) {
  return (
    <div className="border border-border rounded-lg bg-background-card px-4 py-5 flex items-center gap-4">
      <div className="h-10 w-10 rounded-md bg-background-subtle/50 flex items-center justify-center shrink-0">
        <Radar className="h-5 w-5 text-foreground-secondary" />
      </div>
      <div className="flex-1 min-w-0">
        <h4 className="text-sm font-medium text-foreground">DAST not configured</h4>
        <p className="text-xs text-foreground-secondary mt-0.5">
          Add a target URL on the Scanning tab to run dynamic application security tests.
          Findings cross-link to vulnerable dependencies via the reachability graph.
        </p>
      </div>
      <Link
        to={`/organizations/${organizationId}/projects/${projectId}/settings/scanning`}
        className="text-xs text-foreground-secondary hover:text-foreground border border-border rounded-md px-3 py-1.5 bg-background hover:bg-background-subtle shrink-0"
      >
        Configure DAST
      </Link>
    </div>
  );
}

function DastFindingRow({ finding }: { finding: DastFindingDTO }) {
  return (
    <tr className="hover:bg-background-subtle/50">
      <td className="px-4 py-2.5 align-middle">
        <div className="flex items-center gap-1.5">
          {severityBadge(finding.severity)}
          {finding.kev ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <Star className="h-3 w-3 fill-amber-400 text-amber-400" aria-label="Known Exploited Vulnerability" />
              </TooltipTrigger>
              <TooltipContent>Known Exploited Vulnerability — CISA KEV catalog.</TooltipContent>
            </Tooltip>
          ) : null}
        </div>
      </td>
      <td className="px-4 py-2.5 align-middle">
        <EngineChip engine={finding.engine} />
      </td>
      <td className="px-4 py-2.5 align-middle text-sm text-foreground min-w-0">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-[10px] font-mono uppercase text-foreground-secondary border border-border rounded px-1 py-0.5 shrink-0">
            {finding.http_method}
          </span>
          <span className="truncate" title={finding.endpoint_url}>{finding.endpoint_url}</span>
        </div>
        {finding.handler_file_path ? (
          <div className="text-xs text-foreground-secondary mt-0.5 truncate">
            {finding.handler_function_name ? `${finding.handler_function_name}() · ` : ''}
            {finding.handler_file_path}{finding.handler_line ? `:${finding.handler_line}` : ''}
          </div>
        ) : null}
      </td>
      <td className="px-4 py-2.5 align-middle text-sm text-foreground">
        <div>{finding.vulnerability_type}</div>
        {finding.cwe_id ? (
          <div className="text-xs text-foreground-secondary mt-0.5">CWE-{finding.cwe_id}{finding.owasp_top10_ref ? ` · ${finding.owasp_top10_ref}` : ''}</div>
        ) : null}
      </td>
      <td className="px-4 py-2.5 align-middle">
        {finding.confirmed_exploitable && finding.linked_sca_osv_id ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="inline-flex items-center gap-1.5">
                <Badge variant="warning" className="text-[10px] px-1.5 py-0 inline-flex items-center gap-1">
                  <ShieldAlert className="h-3 w-3" />
                  Confirmed Exploitable
                </Badge>
                <span className="text-xs text-foreground-secondary">SCA · {finding.linked_sca_osv_id}</span>
              </span>
            </TooltipTrigger>
            <TooltipContent className="max-w-md">
              This DAST hit reaches a known vulnerable dependency through the same handler. Cross-linked via tree-sitter reachability graph.
            </TooltipContent>
          </Tooltip>
        ) : (
          <span className="text-xs text-foreground-secondary">—</span>
        )}
      </td>
    </tr>
  );
}

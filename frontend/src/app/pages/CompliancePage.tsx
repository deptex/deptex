import { Fragment, useState, useEffect, useMemo, useCallback } from 'react';
import { useOutletContext, useParams, useNavigate } from 'react-router-dom';
import { Download, Loader2 } from 'lucide-react';
import { Button } from '../../components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogTitle,
} from '../../components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../../components/ui/select';
import { api, Project, ProjectDependency, ProjectPullRequest } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { Toaster } from '../../components/ui/toaster';
import { ComplianceSidepanel } from '../../components/ComplianceSidepanel';
import { FrameworkIcon } from '../../components/framework-icon';
import { ProjectStatusBadge } from '../../components/ProjectStatusBadge';
import { isExtractionOngoing } from '../../lib/extractionStatus';

function formatDisplayDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  } catch {
    return '—';
  }
}

type ComplianceExpandDetail = {
  loading: boolean;
  error: string | null;
  lastExtractedAt: string | null;
  blockedDeps: ProjectDependency[];
  blockedPrs: ProjectPullRequest[];
};

interface OrganizationContextType {
  organization: { id: string; name?: string } | null;
  reloadOrganization?: () => Promise<void>;
}

export default function CompliancePage() {
  const { id: organizationId, section: urlSection } = useParams<{ id: string; section?: string }>();
  useOutletContext<OrganizationContextType>();
  const navigate = useNavigate();
  const { toast } = useToast();

  const [projects, setProjects] = useState<Project[]>([]);
  const [expandedProjectId, setExpandedProjectId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [exportNoticeModalOpen, setExportNoticeModalOpen] = useState(false);
  const [exportSBOMModalOpen, setExportSBOMModalOpen] = useState(false);
  const [exportNoticeProjectId, setExportNoticeProjectId] = useState<string>('');
  const [exportSBOMProjectId, setExportSBOMProjectId] = useState<string>('');
  const [exportingNotice, setExportingNotice] = useState(false);
  const [exportingSBOM, setExportingSBOM] = useState(false);
  const [expandByProject, setExpandByProject] = useState<Record<string, ComplianceExpandDetail>>({});
  const [inlineExport, setInlineExport] = useState<{ projectId: string; kind: 'notice' | 'sbom' } | null>(null);

  const activeSection = urlSection === 'overview' || !urlSection ? 'overview' as const : 'overview' as const;

  const loadData = useCallback(async () => {
    if (!organizationId) return;
    try {
      setLoading(true);
      setError(null);
      const projectsData = await api.getProjects(organizationId);
      setProjects(projectsData);
    } catch (err: any) {
      setError(err.message || 'Failed to load compliance data');
    } finally {
      setLoading(false);
    }
  }, [organizationId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  useEffect(() => {
    if (!organizationId) return;
    if (!urlSection || urlSection !== 'overview') {
      navigate(`/organizations/${organizationId}/compliance/overview`, { replace: true });
    }
  }, [organizationId, urlSection, navigate]);

  const compliantCount = useMemo(
    () => projects.filter((p) => p.is_compliant !== false).length,
    [projects]
  );
  const compliantPct = projects.length ? Math.round((compliantCount / projects.length) * 100) : 100;

  const isProjectExtracting = (p: Project) =>
    isExtractionOngoing(p.repo_status ?? '', p.extraction_step ?? null);

  useEffect(() => {
    if (!organizationId || !expandedProjectId) return;
    const pid = expandedProjectId;
    let cancelled = false;

    setExpandByProject((prev) => ({
      ...prev,
      [pid]: { loading: true, error: null, lastExtractedAt: null, blockedDeps: [], blockedPrs: [] },
    }));

    (async () => {
      try {
        const [reposRes, deps, prRes] = await Promise.all([
          api.getProjectRepositories(organizationId, pid).catch(() => null),
          api.getProjectDependencies(organizationId, pid),
          api.getProjectPullRequests(organizationId, pid, { status: 'open', perPage: 50 }),
        ]);
        if (cancelled) return;
        const lastExtractedAt = reposRes?.connectedRepository?.last_extracted_at ?? null;
        const blockedDeps = deps.filter(
          (d) => d.policy_result?.allowed === false || d.is_current_version_banned === true
        );
        const blockedPrs = (prRes.data ?? []).filter((pr) => {
          if (pr.check_result === 'failed') return true;
          const b = pr.blocked_by;
          if (b == null) return false;
          if (typeof b === 'object') return Object.keys(b as object).length > 0;
          return String(b).length > 0;
        });
        setExpandByProject((prev) => ({
          ...prev,
          [pid]: { loading: false, error: null, lastExtractedAt, blockedDeps, blockedPrs },
        }));
      } catch (e: any) {
        if (cancelled) return;
        setExpandByProject((prev) => ({
          ...prev,
          [pid]: {
            loading: false,
            error: e?.message || 'Failed to load details',
            lastExtractedAt: null,
            blockedDeps: [],
            blockedPrs: [],
          },
        }));
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [organizationId, expandedProjectId]);

  const downloadLegalNoticeForProject = useCallback(
    async (projectId: string) => {
      if (!organizationId) return;
      setInlineExport({ projectId, kind: 'notice' });
      try {
        const blob = await api.downloadProjectLegalNotice(organizationId, projectId);
        const name = projects.find((p) => p.id === projectId)?.name ?? 'project';
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${name}-THIRD-PARTY-NOTICES.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        toast({ title: 'Legal notice downloaded', description: `${name}` });
      } catch (e: any) {
        toast({ title: 'Export failed', description: e.message || 'Failed to export.', variant: 'destructive' });
      } finally {
        setInlineExport(null);
      }
    },
    [organizationId, projects, toast]
  );

  const downloadSbomForProject = useCallback(
    async (projectId: string) => {
      if (!organizationId) return;
      setInlineExport({ projectId, kind: 'sbom' });
      try {
        const blob = await api.downloadProjectSBOM(organizationId, projectId);
        const name = projects.find((p) => p.id === projectId)?.name ?? 'project';
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${name}-sbom.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        toast({ title: 'SBOM downloaded', description: `${name}` });
      } catch (e: any) {
        toast({ title: 'Export failed', description: e.message || 'Failed to export.', variant: 'destructive' });
      } finally {
        setInlineExport(null);
      }
    },
    [organizationId, projects, toast]
  );

  const handleExportNoticeFromModal = useCallback(async () => {
    if (!organizationId || !exportNoticeProjectId) return;
    setExportingNotice(true);
    try {
      const blob = await api.downloadProjectLegalNotice(organizationId, exportNoticeProjectId);
      const project = projects.find((p) => p.id === exportNoticeProjectId);
      const name = project?.name ?? 'project';
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${name}-THIRD-PARTY-NOTICES.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast({ title: 'Legal Notice Downloaded', description: `${name} notice downloaded.` });
      setExportNoticeModalOpen(false);
      setExportNoticeProjectId('');
    } catch (e: any) {
      toast({ title: 'Export failed', description: e.message || 'Failed to export.', variant: 'destructive' });
    } finally {
      setExportingNotice(false);
    }
  }, [organizationId, exportNoticeProjectId, projects, toast]);

  const handleExportSBOMFromModal = useCallback(async () => {
    if (!organizationId || !exportSBOMProjectId) return;
    setExportingSBOM(true);
    try {
      const blob = await api.downloadProjectSBOM(organizationId, exportSBOMProjectId);
      const project = projects.find((p) => p.id === exportSBOMProjectId);
      const name = project?.name ?? 'project';
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${name}-sbom.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast({ title: 'SBOM Downloaded', description: `${name} SBOM downloaded.` });
      setExportSBOMModalOpen(false);
      setExportSBOMProjectId('');
    } catch (e: any) {
      toast({ title: 'Export failed', description: e.message || 'Failed to export.', variant: 'destructive' });
    } finally {
      setExportingSBOM(false);
    }
  }, [organizationId, exportSBOMProjectId, projects, toast]);

  const handleSectionSelect = useCallback(
    (section: 'overview') => {
      if (!organizationId) return;
      navigate(`/organizations/${organizationId}/compliance/${section}`);
    },
    [organizationId, navigate]
  );

  if (error) {
    return (
      <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <div className="bg-destructive/10 border border-destructive/30 rounded-lg p-4 text-sm text-destructive">
          {error}
        </div>
      </main>
    );
  }

  const complianceLoadingSkeleton = (
    <div className="flex-1 min-w-0 overflow-auto px-4 sm:px-6 lg:px-8 py-6 mx-auto max-w-7xl space-y-8">
      <div className="flex flex-wrap items-center gap-8">
        <div className="flex items-baseline gap-3">
          <div className="h-10 w-20 bg-muted rounded animate-pulse" />
          <div className="h-3 w-24 bg-muted rounded animate-pulse" />
        </div>
      </div>
      <div className="bg-background-card border border-border rounded-lg overflow-hidden">
        <div className="border-b border-border px-4 py-3 flex gap-4">
          <div className="h-3 w-24 bg-muted rounded animate-pulse" />
          <div className="h-3 w-28 bg-muted rounded animate-pulse" />
        </div>
        {[1, 2, 3, 4, 5, 6].map((row) => (
          <div key={row} className="px-4 py-2.5 flex gap-4 items-center border-b border-border last:border-0">
            <div className="flex items-center gap-2">
              <div className="h-4 w-4 bg-muted rounded animate-pulse shrink-0" />
              <div className="h-4 w-32 bg-muted rounded animate-pulse" />
            </div>
            <div className="h-4 w-12 bg-muted rounded animate-pulse" />
          </div>
        ))}
      </div>
    </div>
  );

  return (
    <>
      <div className="flex min-h-[calc(100vh-3rem)] overflow-hidden">
        <ComplianceSidepanel
          mode="organization"
          activeSection={activeSection}
          onSelect={handleSectionSelect}
          canViewSettings={true}
          disabledExports={!projects.length}
          onExportNoticeClick={() => setExportNoticeModalOpen(true)}
          onExportSBOMClick={() => setExportSBOMModalOpen(true)}
        />

        <div className="flex-1 min-w-0 overflow-auto">
          {loading ? (
            complianceLoadingSkeleton
          ) : (
            <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-6 space-y-8">
              {/* Aggregate: percent of projects passing policy (binary compliant/not) */}
              <div className="flex flex-wrap items-center gap-8">
                <div className="flex items-baseline gap-3">
                  <span className="text-4xl font-semibold tabular-nums text-foreground">
                    {compliantPct}%
                  </span>
                  <span className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary">
                    Compliance
                  </span>
                </div>
                <p className="text-sm text-foreground-secondary">
                  {compliantCount} of {projects.length} project{projects.length !== 1 ? 's' : ''} compliant
                </p>
              </div>

              {/* Per row: package-level policy pass %; header label on each row */}
              <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                <table className="w-full">
                  <thead className="bg-background-card-header border-b border-border">
                    <tr>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                        Project
                      </th>
                      <th className="text-right px-4 py-3 w-44 min-w-[11rem]" aria-hidden="true" />
                    </tr>
                  </thead>
                  <tbody>
                    {projects.length === 0 ? (
                      <tr>
                        <td colSpan={2} className="px-4 py-8 text-center text-sm text-foreground-secondary">
                          No projects in this organization.
                        </td>
                      </tr>
                    ) : (
                      projects.map((project) => {
                        const expand = expandByProject[project.id];
                        const showExpandLoading =
                          expandedProjectId === project.id && (!expand || expand.loading);
                        const depLimit = 12;
                        const prLimit = 10;
                        const blockedDepsShown = expand?.blockedDeps.slice(0, depLimit) ?? [];
                        const blockedPrsShown = expand?.blockedPrs.slice(0, prLimit) ?? [];
                        const depOverflow = (expand?.blockedDeps.length ?? 0) - blockedDepsShown.length;
                        const prOverflow = (expand?.blockedPrs.length ?? 0) - blockedPrsShown.length;

                        return (
                        <Fragment key={project.id}>
                          <tr
                            className="hover:bg-background-subtle/50 transition-colors cursor-pointer border-b border-border"
                            onClick={() =>
                              setExpandedProjectId((prev) => (prev === project.id ? null : project.id))
                            }
                            aria-expanded={expandedProjectId === project.id}
                          >
                            <td className="px-4 py-2.5">
                              <div className="flex items-center gap-2 min-w-0">
                                <FrameworkIcon
                                  frameworkId={project.framework?.toLowerCase()}
                                  size={18}
                                  className="text-foreground-secondary shrink-0"
                                />
                                <span className="text-sm font-medium text-foreground truncate min-w-0 flex-1">
                                  {project.name}
                                </span>
                                <ProjectStatusBadge project={project} className="shrink-0" />
                              </div>
                            </td>
                            <td className="px-4 py-2.5 text-sm tabular-nums text-foreground text-right whitespace-nowrap">
                              {isProjectExtracting(project) ? (
                                <span className="inline-flex items-center justify-end gap-1.5 text-foreground-secondary">
                                  <Loader2 className="h-3.5 w-3.5 animate-spin shrink-0" />
                                  Extracting
                                </span>
                              ) : project.compliance_score_pct != null ? (
                                `${project.compliance_score_pct}% compliance`
                              ) : (
                                '—'
                              )}
                            </td>
                          </tr>
                          <tr>
                            <td colSpan={2} className="px-0 py-0">
                              <div
                                className="overflow-hidden transition-[max-height,opacity] duration-300 ease-in-out"
                                style={{
                                  maxHeight: expandedProjectId === project.id ? 1800 : 0,
                                  opacity: expandedProjectId === project.id ? 1 : 0,
                                }}
                              >
                                <div className="px-4 py-4 border-b border-border bg-background-subtle/30">
                                  <div className="max-h-[min(70vh,56rem)] overflow-y-auto space-y-6">
                                    <div>
                                      <div className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary">
                                        Compliance summary
                                      </div>
                                      <div className="mt-2 grid grid-cols-1 md:grid-cols-12 gap-4 gap-y-6">
                                        <div className="min-w-0 md:col-span-3">
                                          <div className="text-xs text-foreground-secondary">Policy status</div>
                                          <div className="mt-0.5 min-h-9 flex items-center text-sm font-medium text-foreground">
                                            {project.status_name ?? (project.is_compliant !== false ? 'Compliant' : 'Non-compliant')}
                                          </div>
                                        </div>
                                        <div className="min-w-0 md:col-span-3">
                                          <div className="text-xs text-foreground-secondary">Packages passing policy</div>
                                          <div className="mt-0.5 min-h-9 flex items-center text-sm font-medium text-foreground tabular-nums">
                                            {project.compliance_score_pct != null ? `${project.compliance_score_pct}%` : '—'}
                                          </div>
                                        </div>
                                        <div className="flex w-full min-w-0 items-stretch gap-3 md:col-span-6">
                                          <div className="min-w-0 flex-1">
                                            <div className="text-xs text-foreground-secondary">Last sync</div>
                                            <div className="mt-0.5 text-sm font-medium text-foreground tabular-nums break-words leading-snug">
                                              {showExpandLoading && !project.policy_evaluated_at
                                                ? '…'
                                                : formatDisplayDate(
                                                    project.policy_evaluated_at ?? expand?.lastExtractedAt
                                                  )}
                                            </div>
                                          </div>
                                          <div className="flex shrink-0 items-center justify-end self-stretch">
                                            <div className="flex flex-wrap justify-end gap-2">
                                              <Button
                                                type="button"
                                                variant="outline"
                                                size="sm"
                                                className="shrink-0 h-9 gap-2 px-3"
                                                title="Download SBOM"
                                                aria-label="Download SBOM"
                                                disabled={
                                                  Boolean(inlineExport && inlineExport.projectId === project.id) ||
                                                  showExpandLoading
                                                }
                                                onClick={(e) => {
                                                  e.stopPropagation();
                                                  downloadSbomForProject(project.id);
                                                }}
                                              >
                                                {inlineExport?.projectId === project.id && inlineExport.kind === 'sbom' ? (
                                                  <Loader2 className="h-4 w-4 shrink-0 animate-spin" />
                                                ) : (
                                                  <Download className="h-4 w-4 shrink-0" />
                                                )}
                                                <span className="text-xs font-semibold tracking-wide">SBOM</span>
                                              </Button>
                                              <Button
                                                type="button"
                                                variant="outline"
                                                size="sm"
                                                className="shrink-0 h-9 gap-2 px-3"
                                                title="Download legal notice"
                                                aria-label="Download legal notice"
                                                disabled={
                                                  Boolean(inlineExport && inlineExport.projectId === project.id) ||
                                                  showExpandLoading
                                                }
                                                onClick={(e) => {
                                                  e.stopPropagation();
                                                  downloadLegalNoticeForProject(project.id);
                                                }}
                                              >
                                                {inlineExport?.projectId === project.id && inlineExport.kind === 'notice' ? (
                                                  <Loader2 className="h-4 w-4 shrink-0 animate-spin" />
                                                ) : (
                                                  <Download className="h-4 w-4 shrink-0" />
                                                )}
                                                <span className="text-xs font-semibold tracking-wide">LEGAL NOTICE</span>
                                              </Button>
                                            </div>
                                          </div>
                                        </div>
                                      </div>

                                      {project.status_violations && project.status_violations.length > 0 ? (
                                        <div className="mt-4">
                                          <div className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary">
                                            Project status violations
                                          </div>
                                          <div className="mt-2 text-sm text-foreground-secondary">
                                            {project.status_violations.length} issue{project.status_violations.length !== 1 ? 's' : ''}{' '}
                                            from project status policy
                                          </div>
                                          <div className="mt-2 space-y-1">
                                            {project.status_violations.slice(0, 3).map((v) => (
                                              <div key={v} className="text-sm text-foreground-secondary truncate">
                                                {v}
                                              </div>
                                            ))}
                                            {project.status_violations.length > 3 ? (
                                              <div className="text-sm text-foreground-secondary">
                                                +{project.status_violations.length - 3} more
                                              </div>
                                            ) : null}
                                          </div>
                                        </div>
                                      ) : null}
                                    </div>

                                    {expand?.error ? (
                                      <div className="text-sm text-destructive">{expand.error}</div>
                                    ) : (
                                      <>
                                        <div>
                                          <div className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary">
                                            Blocked packages
                                          </div>
                                          <p className="mt-1 text-xs text-foreground-secondary">
                                            Direct/transitive dependencies that fail package policy or use a banned version.
                                          </p>
                                          {showExpandLoading ? (
                                            <div className="mt-3 rounded-md border border-border overflow-hidden">
                                              <table className="w-full text-sm">
                                                <thead className="bg-background-card-header border-b border-border">
                                                  <tr>
                                                    <th className="text-left px-3 py-2 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                                                      Package
                                                    </th>
                                                    <th className="text-left px-3 py-2 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-24">
                                                      Version
                                                    </th>
                                                    <th className="text-left px-3 py-2 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                                                      Reason
                                                    </th>
                                                  </tr>
                                                </thead>
                                                <tbody className="divide-y divide-border bg-background-card">
                                                  {[1, 2, 3].map((row) => (
                                                    <tr key={row}>
                                                      <td className="px-3 py-2">
                                                        <div className="h-4 w-40 bg-muted/70 rounded animate-pulse" />
                                                      </td>
                                                      <td className="px-3 py-2">
                                                        <div className="h-4 w-16 bg-muted/70 rounded animate-pulse" />
                                                      </td>
                                                      <td className="px-3 py-2">
                                                        <div className="h-4 w-full max-w-[26rem] bg-muted/70 rounded animate-pulse" />
                                                      </td>
                                                    </tr>
                                                  ))}
                                                </tbody>
                                              </table>
                                            </div>
                                          ) : blockedDepsShown.length === 0 ? (
                                            <p className="mt-2 text-sm text-foreground-secondary">None</p>
                                          ) : (
                                            <div className="mt-3 rounded-md border border-border overflow-hidden">
                                              <table className="w-full text-sm">
                                                <thead className="bg-background-card-header border-b border-border">
                                                  <tr>
                                                    <th className="text-left px-3 py-2 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                                                      Package
                                                    </th>
                                                    <th className="text-left px-3 py-2 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-24">
                                                      Version
                                                    </th>
                                                    <th className="text-left px-3 py-2 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                                                      Reason
                                                    </th>
                                                  </tr>
                                                </thead>
                                                <tbody className="divide-y divide-border bg-background-card">
                                                  {blockedDepsShown.map((d) => {
                                                    const reasons =
                                                      d.policy_result?.reasons?.length &&
                                                      d.policy_result?.allowed === false
                                                        ? d.policy_result.reasons.join('; ')
                                                        : d.is_current_version_banned
                                                          ? 'Org/team banned version'
                                                          : 'Policy blocked';
                                                    return (
                                                      <tr key={d.id}>
                                                        <td className="px-3 py-2 font-medium text-foreground">{d.name}</td>
                                                        <td className="px-3 py-2 tabular-nums text-foreground-secondary">{d.version}</td>
                                                        <td className="px-3 py-2 text-foreground-secondary">{reasons}</td>
                                                      </tr>
                                                    );
                                                  })}
                                                </tbody>
                                              </table>
                                              {depOverflow > 0 ? (
                                                <div className="px-3 py-2 text-xs text-foreground-secondary border-t border-border">
                                                  +{depOverflow} more
                                                </div>
                                              ) : null}
                                            </div>
                                          )}
                                        </div>

                                        <div>
                                          <div className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary">
                                            Blocked pull requests
                                          </div>
                                          <p className="mt-1 text-xs text-foreground-secondary">
                                            Open PRs with a failed Deptex check or an active merge block.
                                          </p>
                                          {showExpandLoading ? (
                                            <div className="mt-3 rounded-md border border-border overflow-hidden">
                                              <table className="w-full text-sm">
                                                <thead className="bg-background-card-header border-b border-border">
                                                  <tr>
                                                    <th className="text-left px-3 py-2 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                                                      Pull request
                                                    </th>
                                                    <th className="text-left px-3 py-2 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-28">
                                                      Check
                                                    </th>
                                                    <th className="text-left px-3 py-2 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                                                      Detail
                                                    </th>
                                                  </tr>
                                                </thead>
                                                <tbody className="divide-y divide-border bg-background-card">
                                                  {[1, 2, 3].map((row) => (
                                                    <tr key={row}>
                                                      <td className="px-3 py-2">
                                                        <div className="h-4 w-56 bg-muted/70 rounded animate-pulse" />
                                                      </td>
                                                      <td className="px-3 py-2">
                                                        <div className="h-4 w-16 bg-muted/70 rounded animate-pulse" />
                                                      </td>
                                                      <td className="px-3 py-2">
                                                        <div className="h-4 w-full max-w-[22rem] bg-muted/70 rounded animate-pulse" />
                                                      </td>
                                                    </tr>
                                                  ))}
                                                </tbody>
                                              </table>
                                            </div>
                                          ) : blockedPrsShown.length === 0 ? (
                                            <p className="mt-2 text-sm text-foreground-secondary">None</p>
                                          ) : (
                                            <div className="mt-3 rounded-md border border-border overflow-hidden">
                                              <table className="w-full text-sm">
                                                <thead className="bg-background-card-header border-b border-border">
                                                  <tr>
                                                    <th className="text-left px-3 py-2 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                                                      Pull request
                                                    </th>
                                                    <th className="text-left px-3 py-2 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-28">
                                                      Check
                                                    </th>
                                                    <th className="text-left px-3 py-2 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                                                      Detail
                                                    </th>
                                                  </tr>
                                                </thead>
                                                <tbody className="divide-y divide-border bg-background-card">
                                                  {blockedPrsShown.map((pr) => {
                                                    const blockHint =
                                                      pr.check_summary ||
                                                      (pr.blocked_by
                                                        ? typeof pr.blocked_by === 'object'
                                                          ? JSON.stringify(pr.blocked_by)
                                                          : String(pr.blocked_by)
                                                        : null) ||
                                                      '—';
                                                    return (
                                                      <tr key={pr.id}>
                                                        <td className="px-3 py-2">
                                                          {pr.provider_url ? (
                                                            <a
                                                              href={pr.provider_url}
                                                              target="_blank"
                                                              rel="noreferrer"
                                                              className="font-medium text-primary hover:underline"
                                                              onClick={(e) => e.stopPropagation()}
                                                            >
                                                              #{pr.pr_number}
                                                              {pr.title ? ` ${pr.title}` : ''}
                                                            </a>
                                                          ) : (
                                                            <span className="font-medium text-foreground">
                                                              #{pr.pr_number}
                                                              {pr.title ? ` ${pr.title}` : ''}
                                                            </span>
                                                          )}
                                                        </td>
                                                        <td className="px-3 py-2 text-foreground-secondary">
                                                          {pr.check_result ?? '—'}
                                                        </td>
                                                        <td className="px-3 py-2 text-foreground-secondary max-w-md truncate" title={blockHint}>
                                                          {blockHint}
                                                        </td>
                                                      </tr>
                                                    );
                                                  })}
                                                </tbody>
                                              </table>
                                              {prOverflow > 0 ? (
                                                <div className="px-3 py-2 text-xs text-foreground-secondary border-t border-border">
                                                  +{prOverflow} more
                                                </div>
                                              ) : null}
                                            </div>
                                          )}
                                        </div>
                                      </>
                                    )}
                                  </div>
                                </div>
                              </div>
                            </td>
                          </tr>
                        </Fragment>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Export Legal Notice modal */}
      <Dialog open={exportNoticeModalOpen} onOpenChange={(open) => !open && setExportNoticeModalOpen(false)}>
        <DialogContent className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-visible max-h-[90vh] flex flex-col">
          <div className="px-6 pt-6 pb-4 border-b border-border flex-shrink-0">
            <DialogTitle>Export Legal Notice</DialogTitle>
            <DialogDescription className="mt-1">
              Select a project to download its third-party legal notice.
            </DialogDescription>
          </div>
          <div className="px-6 py-4 grid gap-4 bg-background overflow-y-auto max-h-[60vh] min-h-0">
            <Select
              value={exportNoticeProjectId}
              onValueChange={setExportNoticeProjectId}
            >
              <SelectTrigger className="w-full">
                <SelectValue placeholder="Select project" />
              </SelectTrigger>
              <SelectContent className="p-0.5">
                {projects.map((p) => (
                  <SelectItem key={p.id} value={p.id} className="py-1.5 pl-2 pr-2 gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <FrameworkIcon frameworkId={p.framework?.toLowerCase()} size={16} className="text-foreground-secondary shrink-0" />
                      <span className="truncate">{p.name}</span>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <DialogFooter className="px-6 py-4 bg-background">
            <Button variant="outline" onClick={() => setExportNoticeModalOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleExportNoticeFromModal}
              disabled={!exportNoticeProjectId || exportingNotice}
              className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
            >
              {exportingNotice ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : null}
              Export
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Export SBOM modal */}
      <Dialog open={exportSBOMModalOpen} onOpenChange={(open) => !open && setExportSBOMModalOpen(false)}>
        <DialogContent className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-visible max-h-[90vh] flex flex-col">
          <div className="px-6 pt-6 pb-4 border-b border-border flex-shrink-0">
            <DialogTitle>Export SBOM</DialogTitle>
            <DialogDescription className="mt-1">
              Select a project to download its SBOM (Software Bill of Materials).
            </DialogDescription>
          </div>
          <div className="px-6 py-4 grid gap-4 bg-background overflow-y-auto max-h-[60vh] min-h-0">
            <Select
              value={exportSBOMProjectId}
              onValueChange={setExportSBOMProjectId}
            >
              <SelectTrigger className="w-full">
                <SelectValue placeholder="Select project" />
              </SelectTrigger>
              <SelectContent className="p-0.5">
                {projects.map((p) => (
                  <SelectItem key={p.id} value={p.id} className="py-1.5 pl-2 pr-2 gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <FrameworkIcon frameworkId={p.framework?.toLowerCase()} size={16} className="text-foreground-secondary shrink-0" />
                      <span className="truncate">{p.name}</span>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <DialogFooter className="px-6 py-4 bg-background">
            <Button variant="outline" onClick={() => setExportSBOMModalOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleExportSBOMFromModal}
              disabled={!exportSBOMProjectId || exportingSBOM}
              className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
            >
              {exportingSBOM ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : null}
              Export
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Toaster position="bottom-right" />
    </>
  );
}

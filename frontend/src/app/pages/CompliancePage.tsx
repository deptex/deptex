import { useState, useEffect, useMemo, useCallback } from 'react';
import { useOutletContext, useParams, useNavigate } from 'react-router-dom';
import { Loader2 } from 'lucide-react';
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
import { api, Project } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { Toaster } from '../../components/ui/toaster';
import { ComplianceSidepanel } from '../../components/ComplianceSidepanel';
import { FrameworkIcon } from '../../components/framework-icon';

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
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [exportNoticeModalOpen, setExportNoticeModalOpen] = useState(false);
  const [exportSBOMModalOpen, setExportSBOMModalOpen] = useState(false);
  const [exportNoticeProjectId, setExportNoticeProjectId] = useState<string>('');
  const [exportSBOMProjectId, setExportSBOMProjectId] = useState<string>('');
  const [exportingNotice, setExportingNotice] = useState(false);
  const [exportingSBOM, setExportingSBOM] = useState(false);

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

  const EXTRACTING_STATUSES = ['initializing', 'extracting', 'analyzing', 'finalizing'];
  const isProjectExtracting = (p: Project) =>
    p.repo_status != null && EXTRACTING_STATUSES.includes(p.repo_status);

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

  const goToProjectCompliance = useCallback(
    (project: Project) => {
      if (!organizationId) return;
      navigate(`/organizations/${organizationId}/projects/${project.id}/compliance/project`);
    },
    [organizationId, navigate]
  );

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
    <div className="flex-1 min-w-0 overflow-auto px-6 py-6 mx-auto max-w-5xl space-y-8">
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
            <div className="mx-auto max-w-5xl px-6 py-6 space-y-8">
              {/* Aggregate compliance score */}
              <div className="flex flex-wrap items-center gap-8">
                <div className="flex items-baseline gap-3">
                  <span className="text-4xl font-semibold tabular-nums text-foreground">
                    {compliantPct}%
                  </span>
                  <span className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary">
                    Compliance score
                  </span>
                </div>
                <p className="text-sm text-foreground-secondary">
                  {compliantCount} of {projects.length} project{projects.length !== 1 ? 's' : ''} compliant
                </p>
              </div>

              {/* Projects table */}
              <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                <table className="w-full">
                  <thead className="bg-background-card-header border-b border-border">
                    <tr>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                        Project
                      </th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-44 min-w-[11rem]">
                        Compliance score
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {projects.length === 0 ? (
                      <tr>
                        <td colSpan={2} className="px-4 py-8 text-center text-sm text-foreground-secondary">
                          No projects in this organization.
                        </td>
                      </tr>
                    ) : (
                      projects.map((project) => (
                        <tr
                          key={project.id}
                          className="hover:bg-background-subtle/50 transition-colors cursor-pointer"
                          onClick={() => goToProjectCompliance(project)}
                        >
                          <td className="px-4 py-2.5">
                            <div className="flex items-center gap-2 min-w-0">
                              <FrameworkIcon frameworkId={project.framework?.toLowerCase()} size={18} className="text-foreground-secondary shrink-0" />
                              <span className="text-sm font-medium text-foreground truncate">
                                {project.name}
                              </span>
                            </div>
                          </td>
                          <td className="px-4 py-2.5 text-sm tabular-nums text-foreground">
                            {isProjectExtracting(project) ? (
                              <span className="inline-flex items-center gap-1.5 text-foreground-secondary">
                                <Loader2 className="h-3.5 w-3.5 animate-spin shrink-0" />
                                Extracting
                              </span>
                            ) : project.health_score != null ? (
                              `${project.health_score}%`
                            ) : (
                              '—'
                            )}
                          </td>
                        </tr>
                      ))
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
              variant="default"
              onClick={handleExportNoticeFromModal}
              disabled={!exportNoticeProjectId || exportingNotice}
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
              variant="default"
              onClick={handleExportSBOMFromModal}
              disabled={!exportSBOMProjectId || exportingSBOM}
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

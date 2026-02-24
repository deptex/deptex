import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { useOutletContext, useParams, useNavigate } from 'react-router-dom';
import {
  Shield,
  AlertTriangle,
  ClipboardList,
  Download,
  FileText,
  BookOpen,
  X,
  ChevronDown,
  Scale,
  Lock,
  ExternalLink,
  Package,
  CheckCircle2,
} from 'lucide-react';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Switch } from '../../components/ui/switch';
import { Card, CardContent } from '../../components/ui/card';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from '../../components/ui/dropdown-menu';
import { api, Project, ProjectPolicyException, OrganizationPolicies } from '../../lib/api';
import {
  generateSBOM,
  generateLegalNotice,
  generateOrgSBOM,
  generateOrgLegalNotice,
  downloadFile,
  getComplianceStatus,
  getIssueLabel,
  getIssueBadgeVariant,
  getSlsaEnforcementLabel,
  type SbomNoticeItem,
} from '../../lib/compliance-utils';
import { useToast } from '../../hooks/use-toast';
import { Toaster } from '../../components/ui/toaster';

interface OrganizationContextType {
  organization: { id: string; name?: string } | null;
  reloadOrganization?: () => Promise<void>;
}

// Mock issue summary for projects (until backend provides)
function getMockIssueSummary(projectId: string, projectIndex: number): string {
  const mock: Record<string, string> = {
    // First two "failing" projects get mock text; key by index for stability
    '0': '1 GPL License',
    '1': '2 CVEs',
  };
  return mock[String(projectIndex)] ?? '—';
}

const formatDate = (dateString: string): string => {
  const d = new Date(dateString);
  const day = d.getDate().toString().padStart(2, '0');
  const month = d.toLocaleDateString('en-US', { month: 'short' });
  const year = d.getFullYear().toString().slice(2);
  return `${day} ${month} ${year}`;
};

export default function CompliancePage() {
  const { id: organizationId } = useParams<{ id: string }>();
  const { organization } = useOutletContext<OrganizationContextType>();
  const navigate = useNavigate();
  const { toast } = useToast();
  const tableSectionRef = useRef<HTMLDivElement>(null);

  const [projects, setProjects] = useState<Project[]>([]);
  const [pendingExceptions, setPendingExceptions] = useState<ProjectPolicyException[]>([]);
  const [orgPolicies, setOrgPolicies] = useState<OrganizationPolicies | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showFailingOnly, setShowFailingOnly] = useState(true);
  const [selectedProject, setSelectedProject] = useState<Project | null>(null);
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const [showPoliciesPanel, setShowPoliciesPanel] = useState(false);
  const [exporting, setExporting] = useState(false);

  const loadData = useCallback(async () => {
    if (!organizationId) return;
    try {
      setLoading(true);
      setError(null);
      const [projectsData, pendingData, policiesData] = await Promise.all([
        api.getProjects(organizationId),
        api.getOrganizationPolicyExceptions(organizationId, 'pending'),
        api.getOrganizationPolicies(organizationId),
      ]);
      setProjects(projectsData);
      setPendingExceptions(pendingData);
      setOrgPolicies(policiesData);
    } catch (err: any) {
      setError(err.message || 'Failed to load compliance data');
    } finally {
      setLoading(false);
    }
  }, [organizationId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const compliantCount = useMemo(
    () => projects.filter((p) => p.is_compliant !== false).length,
    [projects]
  );
  const violationCount = useMemo(
    () => projects.filter((p) => p.is_compliant === false).length,
    [projects]
  );
  const compliantPct = projects.length ? Math.round((compliantCount / projects.length) * 100) : 100;

  const failingProjectIndexMap = useMemo(() => {
    const map: Record<string, number> = {};
    let idx = 0;
    projects.forEach((p) => {
      if (p.is_compliant === false) {
        map[p.id] = idx++;
      }
    });
    return map;
  }, [projects]);

  const filteredProjects = useMemo(() => {
    if (showFailingOnly) {
      return projects.filter((p) => p.is_compliant === false);
    }
    return projects;
  }, [projects, showFailingOnly]);

  const handleReviewTriage = () => {
    setShowFailingOnly(true);
    tableSectionRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const handleExportSBOMOrg = async () => {
    if (!organizationId || !projects.length) {
      toast({ title: 'No projects', description: 'No projects to export.', variant: 'destructive' });
      return;
    }
    setExporting(true);
    try {
      const projectData: { projectName: string; items: SbomNoticeItem[] }[] = [];
      for (const p of projects) {
        const deps = await api.getProjectDependencies(organizationId, p.id);
        const items: SbomNoticeItem[] = deps.map((d) => ({
          name: d.name,
          version: d.version,
          license: d.license,
        }));
        projectData.push({ projectName: p.name, items });
      }
      const content = generateOrgSBOM(projectData);
      downloadFile(content, `${organization?.name || 'org'}-sbom.json`, 'application/json');
      toast({ title: 'SBOM Exported', description: 'Organization SBOM has been downloaded.' });
    } catch (e: any) {
      toast({ title: 'Export failed', description: e.message || 'Failed to export SBOM.', variant: 'destructive' });
    } finally {
      setExporting(false);
    }
  };

  const handleExportNoticeOrg = async () => {
    if (!organizationId || !projects.length) {
      toast({ title: 'No projects', description: 'No projects to export.', variant: 'destructive' });
      return;
    }
    setExporting(true);
    try {
      const projectData: { projectName: string; items: SbomNoticeItem[] }[] = [];
      for (const p of projects) {
        const deps = await api.getProjectDependencies(organizationId, p.id);
        const items: SbomNoticeItem[] = deps.map((d) => ({
          name: d.name,
          version: d.version,
          license: d.license,
        }));
        projectData.push({ projectName: p.name, items });
      }
      const content = generateOrgLegalNotice(projectData);
      downloadFile(content, `${organization?.name || 'org'}-NOTICE.txt`, 'text/plain');
      toast({ title: 'Notice Exported', description: 'Organization notice has been downloaded.' });
    } catch (e: any) {
      toast({ title: 'Export failed', description: e.message || 'Failed to export notice.', variant: 'destructive' });
    } finally {
      setExporting(false);
    }
  };

  const handleExportSBOMProject = async (project: Project) => {
    if (!organizationId) return;
    setExporting(true);
    try {
      const deps = await api.getProjectDependencies(organizationId, project.id);
      const items: SbomNoticeItem[] = deps.map((d) => ({
        name: d.name,
        version: d.version,
        license: d.license,
      }));
      const content = generateSBOM(items, project.name);
      downloadFile(content, `${project.name}-sbom.json`, 'application/json');
      toast({ title: 'SBOM Exported', description: `${project.name} SBOM downloaded.` });
    } catch (e: any) {
      toast({ title: 'Export failed', description: e.message || 'Failed to export SBOM.', variant: 'destructive' });
    } finally {
      setExporting(false);
    }
  };

  const handleExportNoticeProject = async (project: Project) => {
    if (!organizationId) return;
    setExporting(true);
    try {
      const deps = await api.getProjectDependencies(organizationId, project.id);
      const items: SbomNoticeItem[] = deps.map((d) => ({
        name: d.name,
        version: d.version,
        license: d.license,
      }));
      const content = generateLegalNotice(items, project.name);
      downloadFile(content, `${project.name}-NOTICE.txt`, 'text/plain');
      toast({ title: 'Notice Exported', description: `${project.name} notice downloaded.` });
    } catch (e: any) {
      toast({ title: 'Export failed', description: e.message || 'Failed to export notice.', variant: 'destructive' });
    } finally {
      setExporting(false);
    }
  };

  const openInspector = (project: Project) => {
    setSelectedProject(project);
    setInspectorOpen(true);
  };

  const goToProjectCompliance = () => {
    if (!organizationId || !selectedProject) return;
    setInspectorOpen(false);
    setSelectedProject(null);
    navigate(`/organizations/${organizationId}/projects/${selectedProject.id}/compliance`);
  };

  if (error) {
    return (
      <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-foreground">Compliance</h1>
          <p className="text-foreground-secondary mt-1">View and manage organization compliance status.</p>
        </div>
        <div className="bg-destructive/10 border border-destructive/30 rounded-lg p-4 text-sm text-destructive">
          {error}
        </div>
      </main>
    );
  }

  return (
    <>
      <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-6 flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground">Compliance</h1>
            <p className="text-foreground-secondary mt-1">
              View and manage organization compliance status across all projects.
            </p>
          </div>
          <div className="flex items-center gap-2">
            {orgPolicies && (
              <Button variant="outline" onClick={() => setShowPoliciesPanel(true)}>
                <BookOpen className="h-4 w-4 mr-2" />
                View Org Policies
              </Button>
            )}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" disabled={exporting}>
                  <Download className="h-4 w-4 mr-2" />
                  Export
                  <ChevronDown className="h-4 w-4 ml-2" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-56">
                <DropdownMenuLabel>Download SBOM</DropdownMenuLabel>
                <DropdownMenuItem onClick={handleExportSBOMOrg} disabled={!projects.length || exporting}>
                  Org (all projects)
                </DropdownMenuItem>
                <DropdownMenuSub>
                  <DropdownMenuSubTrigger disabled={!projects.length || exporting}>
                    By project…
                  </DropdownMenuSubTrigger>
                  <DropdownMenuSubContent>
                    {projects.map((p) => (
                      <DropdownMenuItem
                        key={p.id}
                        onClick={() => handleExportSBOMProject(p)}
                        disabled={exporting}
                      >
                        {p.name}
                      </DropdownMenuItem>
                    ))}
                  </DropdownMenuSubContent>
                </DropdownMenuSub>
                <DropdownMenuSeparator />
                <DropdownMenuLabel>Export Notice</DropdownMenuLabel>
                <DropdownMenuItem onClick={handleExportNoticeOrg} disabled={!projects.length || exporting}>
                  Org (all projects)
                </DropdownMenuItem>
                <DropdownMenuSub>
                  <DropdownMenuSubTrigger disabled={!projects.length || exporting}>
                    By project…
                  </DropdownMenuSubTrigger>
                  <DropdownMenuSubContent>
                    {projects.map((p) => (
                      <DropdownMenuItem
                        key={p.id}
                        onClick={() => handleExportNoticeProject(p)}
                        disabled={exporting}
                      >
                        {p.name}
                      </DropdownMenuItem>
                    ))}
                  </DropdownMenuSubContent>
                </DropdownMenuSub>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>

        {loading ? (
          <>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              {[1, 2, 3].map((i) => (
                <Card key={i}>
                  <CardContent className="p-4">
                    <div className="h-4 w-24 bg-muted rounded animate-pulse mb-2" />
                    <div className="h-8 w-16 bg-muted rounded animate-pulse" />
                  </CardContent>
                </Card>
              ))}
            </div>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="h-6 w-32 bg-muted rounded animate-pulse" />
                <div className="h-5 w-36 bg-muted rounded animate-pulse" />
              </div>
              <div className="rounded-lg border border-border overflow-hidden">
                <div className="h-10 bg-muted/50 border-b border-border flex">
                  <div className="w-[36%] px-4 flex items-center" />
                  <div className="w-[14%] px-4 flex items-center" />
                  <div className="w-[18%] px-4 flex items-center" />
                  <div className="w-[18%] px-4 flex items-center" />
                  <div className="w-[14%] px-4 flex items-center" />
                </div>
                {[1, 2, 3, 4].map((i) => (
                  <div key={i} className="h-10 border-b border-border last:border-0 flex items-center">
                    <div className="w-[36%] px-4 flex items-center gap-2 shrink-0">
                      <div className="h-4 w-28 bg-muted rounded animate-pulse" />
                    </div>
                    <div className="w-[14%] px-4">
                      <div className="h-4 w-16 bg-muted rounded animate-pulse" />
                    </div>
                    <div className="w-[18%] px-4">
                      <div className="h-4 w-24 bg-muted rounded animate-pulse" />
                    </div>
                    <div className="w-[18%] px-4">
                      <div className="h-4 w-20 bg-muted rounded animate-pulse" />
                    </div>
                    <div className="w-[14%] px-4">
                      <div className="h-6 w-16 bg-muted rounded animate-pulse" />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </>
        ) : (
          <>
            {/* KPI Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mb-8">
              {/* Org Health */}
              <Card className="overflow-hidden border-border">
                <CardContent className="p-5">
                  <div className="flex items-center gap-2 mb-3">
                    <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
                      <Shield className="h-4 w-4" />
                    </div>
                    <span className="text-xs font-medium uppercase tracking-wider text-foreground-secondary">
                      Org Health
                    </span>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="relative h-16 w-16 flex-shrink-0 flex items-center justify-center">
                      <svg className="absolute inset-0 h-16 w-16 -rotate-90" viewBox="0 0 36 36">
                        <circle
                          cx="18"
                          cy="18"
                          r="15.5"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="2"
                          className="text-border"
                        />
                        <circle
                          cx="18"
                          cy="18"
                          r="15.5"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="2"
                          strokeLinecap="round"
                          strokeDasharray={`${compliantPct} 100`}
                          className="text-primary"
                        />
                      </svg>
                      <span className="relative z-10 text-sm font-bold text-foreground tabular-nums">
                        {compliantPct}%
                      </span>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-foreground">Compliant</p>
                      <p className="text-xs text-foreground-secondary">
                        {compliantCount} of {projects.length} project{projects.length !== 1 ? 's' : ''}
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
              {/* Active Violations */}
              <Card className={`overflow-hidden transition-colors ${violationCount > 0 ? 'border-destructive/20 bg-destructive/5' : 'border-border'}`}>
                <CardContent className="p-5">
                  <div className="flex items-center gap-2 mb-3">
                    <div className={`flex h-8 w-8 items-center justify-center rounded-lg ${violationCount > 0 ? 'bg-destructive/15 text-destructive' : 'bg-background-subtle text-foreground-secondary'}`}>
                      <AlertTriangle className="h-4 w-4" />
                    </div>
                    <span className="text-xs font-medium uppercase tracking-wider text-foreground-secondary">
                      Active Violations
                    </span>
                  </div>
                  <p className={`text-2xl font-bold tabular-nums ${violationCount > 0 ? 'text-destructive' : 'text-foreground'}`}>
                    {violationCount} Critical {violationCount === 1 ? 'Issue' : 'Issues'}
                  </p>
                  {violationCount > 0 && (
                    <p className="text-xs text-foreground-secondary mt-1">
                      Projects requiring attention
                    </p>
                  )}
                </CardContent>
              </Card>
              {/* Triage Queue */}
              <Card className="overflow-hidden border-border">
                <CardContent className="p-5">
                  <div className="flex items-center gap-2 mb-3">
                    <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-background-subtle text-foreground-secondary">
                      <ClipboardList className="h-4 w-4" />
                    </div>
                    <span className="text-xs font-medium uppercase tracking-wider text-foreground-secondary">
                      Triage Queue
                    </span>
                  </div>
                  <p className="text-2xl font-bold text-foreground tabular-nums mb-4">
                    {pendingExceptions.length} Pending
                  </p>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleReviewTriage}
                    className="w-full border-border hover:bg-background-subtle"
                  >
                    Review exceptions
                  </Button>
                </CardContent>
              </Card>
            </div>

            {/* Policy Matrix */}
            <div ref={tableSectionRef} className="space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold text-foreground">Policy Matrix</h2>
                <div className="flex items-center gap-2 text-sm">
                  <span className="text-foreground-secondary">Show Failing Only</span>
                  <Switch checked={showFailingOnly} onCheckedChange={setShowFailingOnly} />
                </div>
              </div>

              <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                <table className="w-full table-fixed">
                  <colgroup>
                    <col style={{ width: '36%' }} />
                    <col style={{ width: '14%' }} />
                    <col style={{ width: '18%' }} />
                    <col style={{ width: '18%' }} />
                    <col style={{ width: '14%' }} />
                  </colgroup>
                  <thead className="bg-background-subtle/50 border-b border-border">
                    <tr>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                        Project
                      </th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                        Status
                      </th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                        Issues
                      </th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                        Last Scan
                      </th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                        Action
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {filteredProjects.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="px-4 py-8 text-center">
                          {showFailingOnly && violationCount === 0 && projects.length > 0 ? (
                            <div className="flex flex-col items-center gap-2">
                              <CheckCircle2 className="h-10 w-10 text-green-500" />
                              <p className="text-sm font-medium text-foreground">No failing projects</p>
                              <p className="text-sm text-foreground-secondary">All projects are compliant.</p>
                            </div>
                          ) : (
                            <p className="text-sm text-foreground-secondary">
                              {showFailingOnly ? 'No failing projects.' : 'No projects in this organization.'}
                            </p>
                          )}
                        </td>
                      </tr>
                    ) : (
                      filteredProjects.map((project, index) => {
                        const isPassing = project.is_compliant !== false;
                        const issueSummary = getMockIssueSummary(
                          project.id,
                          failingProjectIndexMap[project.id] ?? index
                        );
                        return (
                          <tr
                            key={project.id}
                            className="hover:bg-background-subtle/50 transition-colors cursor-pointer"
                            onClick={() => openInspector(project)}
                          >
                            <td className="px-4 py-2 min-w-0">
                              <div className="flex items-center gap-2 min-w-0">
                                <span className="text-sm font-medium text-foreground truncate">{project.name}</span>
                                {(project.owner_team_name || project.team_names?.[0]) && (
                                  <Badge variant="outline" className="text-xs font-medium shrink-0">
                                    {project.owner_team_name || project.team_names?.[0]}
                                  </Badge>
                                )}
                              </div>
                            </td>
                            <td className="px-4 py-2">
                              <Badge variant={isPassing ? 'success' : 'destructive'}>
                                {isPassing ? 'Passing' : 'Failing'}
                              </Badge>
                            </td>
                            <td className="px-4 py-2 text-sm text-foreground-secondary">
                              {isPassing ? '—' : issueSummary}
                            </td>
                            <td className="px-4 py-2 text-sm text-foreground-secondary">
                              {formatDate(project.updated_at)}
                            </td>
                            <td className="px-4 py-2" onClick={(e) => e.stopPropagation()}>
                              <Button variant="outline" size="sm" className="h-7 text-xs px-2" onClick={() => openInspector(project)}>
                                Inspect
                              </Button>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}
      </main>

      {/* Inspector drawer */}
      {inspectorOpen && selectedProject && organizationId && (
        <InspectorDrawer
          organizationId={organizationId}
          project={selectedProject}
          onClose={() => {
            setInspectorOpen(false);
            setSelectedProject(null);
          }}
          onOpenProjectCompliance={goToProjectCompliance}
          toast={toast}
        />
      )}

      {/* Org policies panel */}
      {showPoliciesPanel && orgPolicies && (
        <div className="fixed inset-0 z-50">
          <div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm"
            onClick={() => setShowPoliciesPanel(false)}
          />
          <div
            className="fixed right-0 top-0 h-full w-full max-w-lg bg-background border-l border-border shadow-2xl flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 py-5 border-b border-border flex items-center justify-between flex-shrink-0">
              <h2 className="text-xl font-semibold text-foreground">Organization Policies</h2>
              <button
                onClick={() => setShowPoliciesPanel(false)}
                className="text-foreground-secondary hover:text-foreground"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto px-6 py-6 space-y-6">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <Scale className="h-5 w-5 text-foreground-secondary" />
                  <h3 className="text-lg font-semibold text-foreground">Accepted Licenses</h3>
                </div>
                <p className="text-sm text-foreground-secondary mb-2">
                  Dependencies with these licenses are allowed org-wide.
                </p>
                {(orgPolicies.accepted_licenses ?? []).length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {(orgPolicies.accepted_licenses ?? []).map((license) => (
                      <Badge key={license} variant="outline">
                        {license}
                      </Badge>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-foreground-secondary italic">No licenses configured.</p>
                )}
              </div>
              {(orgPolicies.rejected_licenses ?? []).length > 0 && (
                <div>
                  <h3 className="text-lg font-semibold text-foreground mb-2">Rejected Licenses</h3>
                  <div className="flex flex-wrap gap-2">
                    {(orgPolicies.rejected_licenses ?? []).map((license) => (
                      <Badge key={license} variant="destructive">
                        {license}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
              <div className="pt-4 border-t border-border">
                <div className="flex items-center gap-2 mb-1">
                  <Lock className="h-5 w-5 text-foreground-secondary" />
                  <h3 className="text-lg font-semibold text-foreground">SLSA</h3>
                </div>
                <p className="text-sm text-foreground-secondary mb-2">
                  {getSlsaEnforcementLabel(orgPolicies.slsa_enforcement)}
                </p>
                {orgPolicies.slsa_level != null && (
                  <p className="text-sm text-foreground-secondary">Level: {orgPolicies.slsa_level}</p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      <Toaster position="bottom-right" />
    </>
  );
}

function InspectorDrawer({
  organizationId,
  project,
  onClose,
  onOpenProjectCompliance,
  toast,
}: {
  organizationId: string;
  project: Project;
  onClose: () => void;
  onOpenProjectCompliance: () => void;
  toast: ReturnType<typeof useToast>['toast'];
}) {
  const [deps, setDeps] = useState<Awaited<ReturnType<typeof api.getProjectDependencies>>>([]);
  const [policies, setPolicies] = useState<Awaited<ReturnType<typeof api.getProjectPolicies>> | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [d, p] = await Promise.all([
          api.getProjectDependencies(organizationId, project.id),
          api.getProjectPolicies(organizationId, project.id),
        ]);
        if (!cancelled) {
          setDeps(d);
          setPolicies(p);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [organizationId, project.id]);

  const violations = useMemo(() => {
    return deps
      .map((dep) => {
        const { status, issueType } = getComplianceStatus(dep, policies);
        return { dep, status, issueType };
      })
      .filter((x) => x.status === 'VIOLATION' || x.status === 'UNKNOWN');
  }, [deps, policies]);

  const handleGrantException = () => {
    toast({
      title: 'Request Exception',
      description: 'To grant an exception, go to project Settings → Policies.',
    });
  };

  const handleBlock = () => {
    toast({
      title: 'Block',
      description: 'To block a package, use the project Dependencies or Compliance tab.',
    });
  };

  return (
    <div className="fixed inset-0 z-50">
      <div className="fixed inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div
        className="fixed right-0 top-0 h-full w-full max-w-lg bg-background border-l border-border shadow-2xl flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-6 py-5 border-b border-border flex items-center justify-between flex-shrink-0">
          <h2 className="text-xl font-semibold text-foreground">
            Compliance Details: {project.name}
          </h2>
          <button onClick={onClose} className="text-foreground-secondary hover:text-foreground">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4">
          {loading ? (
            <div className="space-y-2">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-12 bg-muted rounded animate-pulse" />
              ))}
            </div>
          ) : violations.length === 0 ? (
            <p className="text-sm text-foreground-secondary">No violations for this project.</p>
          ) : (
            <ul className="space-y-2">
              {violations.map(({ dep, status, issueType }) => (
                <li
                  key={dep.id}
                  className="flex items-center justify-between gap-2 p-3 rounded-lg border border-border bg-background-card"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <Package className="h-4 w-4 text-foreground-secondary flex-shrink-0" />
                    <div className="min-w-0">
                      <span className="text-sm font-medium text-foreground truncate block">
                        {dep.name}@{dep.version}
                      </span>
                      <span className="text-xs text-foreground-secondary">
                        {getIssueLabel(issueType)} {dep.license ? `· ${dep.license}` : ''}
                      </span>
                    </div>
                  </div>
                  <Badge variant={getIssueBadgeVariant(issueType)}>{getIssueLabel(issueType)}</Badge>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="px-6 py-4 border-t border-border flex flex-wrap gap-2 flex-shrink-0">
          <Button variant="outline" size="sm" onClick={handleGrantException}>
            Grant Exception
          </Button>
          <Button variant="outline" size="sm" onClick={handleBlock}>
            Block
          </Button>
          <Button size="sm" onClick={onOpenProjectCompliance} className="ml-auto">
            <ExternalLink className="h-4 w-4 mr-1" />
            Open project compliance
          </Button>
        </div>
      </div>
    </div>
  );
}

import { useState, useEffect, useMemo, useCallback } from 'react';
import { useOutletContext, useParams, useNavigate } from 'react-router-dom';
import {
  useReactTable,
  getCoreRowModel,
  getFilteredRowModel,
  flexRender,
  createColumnHelper,
  ColumnDef,
} from '@tanstack/react-table';
import { CheckCircle2, AlertTriangle, HelpCircle, Package, GitPullRequest, GitCommit, ChevronDown } from 'lucide-react';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Input } from '../../components/ui/input';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from '../../components/ui/dropdown-menu';
import { Avatar, AvatarFallback, AvatarImage } from '../../components/ui/avatar';
import { ComplianceSidepanel, type ComplianceSection } from '../../components/ComplianceSidepanel';
import { api, ProjectWithRole, ProjectPermissions, ProjectDependency, ProjectEffectivePolicies } from '../../lib/api';
import {
  getComplianceStatus,
  getIssueLabel,
  getIssueBadgeVariant,
  generateSBOM,
  generateLegalNotice,
  downloadFile,
  type ComplianceStatus,
  type IssueType,
} from '../../lib/compliance-utils';
import { useToast } from '../../hooks/use-toast';
import { Toaster } from '../../components/ui/toaster';
import { cn } from '../../lib/utils';

// Types
interface ComplianceItem {
  id: string;
  name: string;
  version: string;
  license: string | null;
  status: ComplianceStatus;
  issueType?: IssueType;
  manuallyAssignedLicense?: string | null;
  originalDependency: ProjectDependency;
}

interface ProjectContextType {
  project: ProjectWithRole | null;
  reloadProject: () => Promise<void>;
  organizationId: string;
  userPermissions: ProjectPermissions | null;
}

type PullRequestStatus = 'OPEN' | 'BLOCKED' | 'MERGED';

type CommitComplianceStatus = 'COMPLIANT' | 'NON_COMPLIANT' | 'UNKNOWN';

interface CompliancePullRequest {
  id: string;
  title: string;
  branch: string;
  author: {
    name: string;
    avatarUrl: string;
    handle: string;
  };
  status: PullRequestStatus;
  packageChanges: {
    added: number;
    removed: number;
    updated: number;
  };
  complianceImpact: string;
  updatedAt: string;
}

interface ComplianceCommit {
  id: string;
  message: string;
  shortSha: string;
  committer: {
    name: string;
    avatarUrl: string;
    handle: string;
  };
  status: CommitComplianceStatus;
  packageChanges: {
    added: number;
    removed: number;
    updated: number;
  };
  committedAt: string;
}

const getInitials = (name: string) => {
  const parts = name.split(' ').filter(Boolean);
  if (parts.length === 0) return '??';
  if (parts.length === 1) return parts[0]!.slice(0, 2).toUpperCase();
  return (parts[0]![0] + parts[1]![0]).toUpperCase();
};

const formatDateTime = (dateString: string) => {
  const d = new Date(dateString);
  return d.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
};

const formatDate = (dateString: string) => {
  const d = new Date(dateString);
  return d.toLocaleDateString(undefined, {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
  });
};

// Column helper
const columnHelper = createColumnHelper<ComplianceItem>();

const VALID_SECTIONS: ComplianceSection[] = ['project', 'updates', 'export-notice', 'export-sbom'];
function isValidSection(s: string | undefined): s is ComplianceSection {
  return !!s && VALID_SECTIONS.includes(s as ComplianceSection);
}

export default function ProjectCompliancePage() {
  const { project, organizationId, userPermissions } = useOutletContext<ProjectContextType>();
  const { projectId, section: urlSection } = useParams<{ projectId: string; section?: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();

  // Section derived from URL; default to 'project'
  const activeSection = isValidSection(urlSection) ? urlSection : 'project';
  const [projectTab, setProjectTab] = useState<'issues' | 'all'>('issues');
  const [updatesTab, setUpdatesTab] = useState<'pull-requests' | 'commits'>('pull-requests');

  const [prStatusFilter, setPrStatusFilter] = useState<'ALL' | PullRequestStatus>('ALL');
  const [prTimeframe, setPrTimeframe] = useState<'24H' | '7D' | '30D' | 'ALL'>('7D');
  const [prSearch, setPrSearch] = useState('');

  const [commitStatusFilter, setCommitStatusFilter] = useState<'ALL' | CommitComplianceStatus>('ALL');
  const [commitTimeframe, setCommitTimeframe] = useState<'24H' | '7D' | '30D' | 'ALL'>('30D');
  const [commitSearch, setCommitSearch] = useState('');

  // Data state
  const [dependencies, setDependencies] = useState<ProjectDependency[]>([]);
  const [policies, setPolicies] = useState<ProjectEffectivePolicies | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const canViewSettings = userPermissions?.view_settings === true;

  // Mock PR data
  const mockPullRequests: CompliancePullRequest[] = useMemo(
    () => [
      {
        id: '1',
        title: 'Add GPL-3.0 licensed dependency',
        branch: 'feature/add-gpl-lib',
        author: {
          name: 'Alex Rivera',
          avatarUrl: 'https://avatars.githubusercontent.com/u/000001?v=4',
          handle: '@alex',
        },
        status: 'BLOCKED',
        packageChanges: { added: 2, removed: 0, updated: 1 },
        complianceImpact: 'Introduces GPL-3.0 · 1 violation',
        updatedAt: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
      },
      {
        id: '2',
        title: 'Bump dependencies for security patch',
        branch: 'chore/deps-bump',
        author: {
          name: 'Jordan Lee',
          avatarUrl: 'https://avatars.githubusercontent.com/u/000002?v=4',
          handle: '@jordan',
        },
        status: 'OPEN',
        packageChanges: { added: 0, removed: 0, updated: 5 },
        complianceImpact: 'Resolves 2 high severity CVEs',
        updatedAt: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(),
      },
      {
        id: '3',
        title: 'Refactor build pipeline',
        branch: 'refactor/build-pipeline',
        author: {
          name: 'Samira Patel',
          avatarUrl: 'https://avatars.githubusercontent.com/u/000003?v=4',
          handle: '@samira',
        },
        status: 'MERGED',
        packageChanges: { added: 0, removed: 0, updated: 2 },
        complianceImpact: 'No license changes',
        updatedAt: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
      },
      {
        id: '4',
        title: 'Introduce internal logging package',
        branch: 'feature/internal-logging',
        author: {
          name: 'Chris Young',
          avatarUrl: 'https://avatars.githubusercontent.com/u/000004?v=4',
          handle: '@chris',
        },
        status: 'OPEN',
        packageChanges: { added: 1, removed: 0, updated: 0 },
        complianceImpact: 'Internal package · no external license impact',
        updatedAt: new Date(Date.now() - 26 * 60 * 60 * 1000).toISOString(),
      },
      {
        id: '5',
        title: 'Remove unsupported license',
        branch: 'fix/remove-unsupported-license',
        author: {
          name: 'Taylor Kim',
          avatarUrl: 'https://avatars.githubusercontent.com/u/000005?v=4',
          handle: '@taylor',
        },
        status: 'MERGED',
        packageChanges: { added: 0, removed: 1, updated: 1 },
        complianceImpact: 'Removes GPL-3.0 dependency',
        updatedAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
      },
    ],
    []
  );

  // Mock commit data
  const mockCommits: ComplianceCommit[] = useMemo(
    () => [
      {
        id: '8f3c2a1b9d',
        shortSha: '8f3c2a1',
        message: 'Add gpl-utils helper and wire into build',
        committer: {
          name: 'Alex Rivera',
          avatarUrl: 'https://avatars.githubusercontent.com/u/000001?v=4',
          handle: '@alex',
        },
        status: 'NON_COMPLIANT',
        packageChanges: { added: 1, removed: 0, updated: 0 },
        committedAt: new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString(),
      },
      {
        id: '1b9d4e2c7a',
        shortSha: '1b9d4e2',
        message: 'Bump openssl dependency to patched version',
        committer: {
          name: 'Jordan Lee',
          avatarUrl: 'https://avatars.githubusercontent.com/u/000002?v=4',
          handle: '@jordan',
        },
        status: 'COMPLIANT',
        packageChanges: { added: 0, removed: 0, updated: 2 },
        committedAt: new Date(Date.now() - 8 * 60 * 60 * 1000).toISOString(),
      },
      {
        id: 'c7a2b1d9f4',
        shortSha: 'c7a2b1d',
        message: 'Refactor dependency injection for SBOM generator',
        committer: {
          name: 'Samira Patel',
          avatarUrl: 'https://avatars.githubusercontent.com/u/000003?v=4',
          handle: '@samira',
        },
        status: 'COMPLIANT',
        packageChanges: { added: 0, removed: 0, updated: 1 },
        committedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
      },
      {
        id: 'd4f9a2c7b1',
        shortSha: 'd4f9a2c',
        message: 'Introduce experimental analytics package',
        committer: {
          name: 'Chris Young',
          avatarUrl: 'https://avatars.githubusercontent.com/u/000004?v=4',
          handle: '@chris',
        },
        status: 'UNKNOWN',
        packageChanges: { added: 1, removed: 0, updated: 0 },
        committedAt: new Date(Date.now() - 6 * 24 * 60 * 60 * 1000).toISOString(),
      },
      {
        id: 'aa3e9b7c2d',
        shortSha: 'aa3e9b7',
        message: 'Remove deprecated crypto library',
        committer: {
          name: 'Taylor Kim',
          avatarUrl: 'https://avatars.githubusercontent.com/u/000005?v=4',
          handle: '@taylor',
        },
        status: 'COMPLIANT',
        packageChanges: { added: 0, removed: 1, updated: 0 },
        committedAt: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString(),
      },
    ],
    []
  );

  // Load data
  const loadData = useCallback(async () => {
    if (!organizationId || !projectId) return;

    try {
      setLoading(true);
      setError(null);

      const [depsData, policiesData] = await Promise.all([
        api.getProjectDependencies(organizationId, projectId),
        api.getProjectPolicies(organizationId, projectId),
      ]);

      setDependencies(depsData);
      setPolicies(policiesData);
    } catch (err: any) {
      setError(err.message || 'Failed to load compliance data');
    } finally {
      setLoading(false);
    }
  }, [organizationId, projectId]);

  useEffect(() => {
    if (project && organizationId && projectId) {
      loadData();
    }
  }, [project, organizationId, projectId, loadData]);

  // Redirect /compliance, /compliance/policies, or export-only to /compliance/project
  useEffect(() => {
    if (!organizationId || !projectId) return;
    if (!urlSection || !isValidSection(urlSection) || urlSection === 'export-notice' || urlSection === 'export-sbom') {
      navigate(`/organizations/${organizationId}/projects/${projectId}/compliance/project`, { replace: true });
    }
  }, [urlSection, navigate, organizationId, projectId]);

  // Transform dependencies into compliance items (must be before export handlers that use it)
  const complianceData = useMemo<ComplianceItem[]>(() => {
    return dependencies.map((dep) => {
      const { status, issueType } = getComplianceStatus(dep, policies);
      return {
        id: dep.id,
        name: dep.name,
        version: dep.version,
        license: dep.license,
        status,
        issueType,
        manuallyAssignedLicense: null,
        originalDependency: dep,
      };
    });
  }, [dependencies, policies]);

  // Dedupe by package name for display - same package can appear as direct + transitive. Keep worst status.
  const statusRank = (s: ComplianceStatus) => (s === 'VIOLATION' ? 2 : s === 'UNKNOWN' ? 1 : 0);
  const complianceDataDeduped = useMemo<ComplianceItem[]>(() => {
    const byName = new Map<string, ComplianceItem>();
    for (const item of complianceData) {
      const existing = byName.get(item.name);
      if (!existing || statusRank(item.status) > statusRank(existing.status)) {
        byName.set(item.name, item);
      }
    }
    return Array.from(byName.values());
  }, [complianceData]);

  // Export handlers
  const handleExportSBOM = useCallback(() => {
    if (!project) return;
    const sbom = generateSBOM(complianceData, project.name || 'Project');
    downloadFile(sbom, `${project.name || 'project'}-sbom.json`, 'application/json');
    toast({ title: 'SBOM Exported', description: 'CycloneDX SBOM has been downloaded.' });
  }, [project, complianceData, toast]);

  const handleExportNotice = useCallback(() => {
    if (!project) return;
    const notice = generateLegalNotice(complianceData, project.name || 'Project');
    downloadFile(notice, `${project.name || 'project'}-NOTICE.txt`, 'text/plain');
    toast({ title: 'Notice Exported', description: 'Legal attribution notice has been downloaded.' });
  }, [project, complianceData, toast]);

  // Navigate for Project/Policies; Export Notice/SBOM just trigger download without changing tab
  const handleSectionSelect = useCallback(
    (section: ComplianceSection) => {
      if (section === 'export-notice') {
        handleExportNotice();
        return;
      }
      if (section === 'export-sbom') {
        handleExportSBOM();
        return;
      }
      navigate(`/organizations/${organizationId}/projects/${projectId}/compliance/${section}`, { replace: true });
    },
    [navigate, organizationId, projectId, handleExportNotice, handleExportSBOM]
  );

  // Filter deduped data based on tab
  const filteredData = useMemo(() => {
    if (projectTab === 'all') return complianceDataDeduped;
    return complianceDataDeduped.filter((item) => item.status === 'VIOLATION' || item.status === 'UNKNOWN');
  }, [complianceDataDeduped, projectTab]);

  const violationCount = complianceDataDeduped.filter((item) => item.status === 'VIOLATION').length;
  const unknownCount = complianceDataDeduped.filter((item) => item.status === 'UNKNOWN').length;
  const issueCount = violationCount + unknownCount;

  const now = useMemo(() => new Date(), []);

  const isWithinTimeframe = useCallback(
    (dateString: string, timeframe: '24H' | '7D' | '30D' | 'ALL') => {
      if (timeframe === 'ALL') return true;
      const date = new Date(dateString);
      const diffMs = now.getTime() - date.getTime();
      const oneHour = 60 * 60 * 1000;
      if (timeframe === '24H') return diffMs <= 24 * oneHour;
      if (timeframe === '7D') return diffMs <= 7 * 24 * oneHour;
      return diffMs <= 30 * 24 * oneHour;
    },
    [now]
  );

  const filteredPullRequests = useMemo(() => {
    const statusRank: Record<PullRequestStatus, number> = {
      BLOCKED: 2,
      OPEN: 1,
      MERGED: 0,
    };

    return mockPullRequests
      .filter((pr) => (prStatusFilter === 'ALL' ? true : pr.status === prStatusFilter))
      .filter((pr) => isWithinTimeframe(pr.updatedAt, prTimeframe))
      .filter((pr) => {
        if (!prSearch.trim()) return true;
        const query = prSearch.toLowerCase();
        return (
          pr.title.toLowerCase().includes(query) ||
          pr.author.name.toLowerCase().includes(query) ||
          pr.author.handle.toLowerCase().includes(query)
        );
      })
      .sort((a, b) => {
        const statusDiff = statusRank[b.status] - statusRank[a.status];
        if (statusDiff !== 0) return statusDiff;
        return new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime();
      });
  }, [mockPullRequests, prStatusFilter, prTimeframe, prSearch, isWithinTimeframe]);

  const filteredCommits = useMemo(() => {
    const statusRank: Record<CommitComplianceStatus, number> = {
      NON_COMPLIANT: 2,
      UNKNOWN: 1,
      COMPLIANT: 0,
    };

    return mockCommits
      .filter((commit) => (commitStatusFilter === 'ALL' ? true : commit.status === commitStatusFilter))
      .filter((commit) => isWithinTimeframe(commit.committedAt, commitTimeframe))
      .filter((commit) => {
        if (!commitSearch.trim()) return true;
        const query = commitSearch.toLowerCase();
        return (
          commit.message.toLowerCase().includes(query) ||
          commit.committer.name.toLowerCase().includes(query) ||
          commit.committer.handle.toLowerCase().includes(query)
        );
      })
      .sort((a, b) => new Date(b.committedAt).getTime() - new Date(a.committedAt).getTime())
      .slice(0, 50);
  }, [mockCommits, commitStatusFilter, commitTimeframe, commitSearch, isWithinTimeframe]);

  // Table columns
  const columns = useMemo<ColumnDef<ComplianceItem, any>[]>(
    () => [
      columnHelper.accessor('name', {
        id: 'package',
        header: 'Package',
        cell: ({ row }) => (
          <div className="flex items-center gap-2 min-w-0">
            <Package className="h-4 w-4 text-foreground-secondary shrink-0" />
            <span className="text-sm font-medium text-foreground truncate">{row.original.name}</span>
          </div>
        ),
      }),
      columnHelper.accessor((row) => row.originalDependency.parent_package ?? null, {
        id: 'parent',
        header: 'Parent',
        cell: ({ row }) => {
          const parent = row.original.originalDependency.parent_package;
          if (row.original.originalDependency.is_direct || !parent) {
            return <span className="text-sm text-foreground-secondary">—</span>;
          }
          return (
            <span className="text-sm text-foreground-secondary truncate block" title={parent}>
              {parent}
            </span>
          );
        },
      }),
      columnHelper.accessor('issueType', {
        header: 'Issue',
        cell: ({ row }) => {
          const { status, issueType } = row.original;
          if (status === 'COMPLIANT') {
            return (
              <Badge variant="success" className="gap-1">
                <CheckCircle2 className="h-3 w-3" />
                Compliant
              </Badge>
            );
          }
          return (
            <Badge variant={getIssueBadgeVariant(issueType)} className="gap-1">
              {status === 'UNKNOWN' ? <HelpCircle className="h-3 w-3" /> : <AlertTriangle className="h-3 w-3" />}
              {getIssueLabel(issueType)}
            </Badge>
          );
        },
      }),
      columnHelper.accessor('license', {
        header: 'License',
        cell: ({ row }) => {
          const item = row.original;
          const { license, manuallyAssignedLicense } = item;
          const displayLicense = manuallyAssignedLicense || license;
          const showRequestException = canViewSettings && item.status === 'VIOLATION';
          return (
            <div className="flex items-center justify-between gap-2">
              <span className="text-sm text-foreground-secondary min-w-0 truncate">
                {displayLicense || <span className="italic">None</span>}
                {manuallyAssignedLicense && <span className="ml-1 text-xs text-primary">(assigned)</span>}
              </span>
              {showRequestException && (
                <Button
                  variant="outline"
                  size="sm"
                  className="opacity-0 group-hover:opacity-100 transition-opacity shrink-0 h-7 text-xs px-2"
                  onClick={() => navigate(`/organizations/${organizationId}/projects/${projectId}/settings`, { state: { section: 'policies' } })}
                  title="Go to Settings → Policies to request an exception"
                >
                  Request Exception
                </Button>
              )}
            </div>
          );
        },
      }),
    ],
    [navigate, organizationId, projectId, canViewSettings]
  );

  const table = useReactTable({
    data: filteredData,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
  });

  const loadingSection: ComplianceSection = isValidSection(urlSection) ? urlSection : 'project';

  // Loading state
  if (!project || loading) {
    return (
      <div className="flex min-h-[calc(100vh-3rem)]">
        <ComplianceSidepanel
          activeSection={loadingSection}
          onSelect={handleSectionSelect}
          canViewSettings={canViewSettings}
          disabledExports
        />
        <div className="flex-1 min-w-0 px-6 py-6 overflow-auto">
          <div className="mx-auto max-w-7xl">
            <>
              <div className="mb-4">
                <h1 className="text-2xl font-bold text-foreground">Licenses</h1>
              </div>
              <div className="flex gap-6 border-b border-border mb-4">
                <button
                  onClick={() => setProjectTab('issues')}
                  className={cn(
                    'pb-3 text-sm font-medium border-b-2 -mb-px transition-colors',
                    projectTab === 'issues'
                      ? 'text-foreground border-foreground'
                      : 'text-foreground-secondary border-transparent hover:text-foreground'
                  )}
                >
                  Issues
                </button>
                <button
                  onClick={() => setProjectTab('all')}
                  className={cn(
                    'pb-3 text-sm font-medium border-b-2 -mb-px transition-colors',
                    projectTab === 'all'
                      ? 'text-foreground border-foreground'
                      : 'text-foreground-secondary border-transparent hover:text-foreground'
                  )}
                >
                  All packages
                </button>
              </div>
              <div className="bg-background-card border border-border rounded-lg max-h-[600px] overflow-hidden">
                <table className="w-full table-fixed">
                  <colgroup>
                    <col style={{ width: '32%' }} />
                    <col style={{ width: '22%' }} />
                    <col style={{ width: '22%' }} />
                    <col style={{ width: '24%' }} />
                  </colgroup>
                  <thead className="bg-[#141618] border-b border-border">
                    <tr>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Package</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Parent</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Issue</th>
                      <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">License</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {[1, 2, 3, 4, 5].map((i) => (
                      <tr key={i} className="animate-pulse">
                        <td className="px-4 py-2"><div className="h-4 w-28 bg-muted rounded" /></td>
                        <td className="px-4 py-2"><div className="h-4 w-16 bg-muted rounded" /></td>
                        <td className="px-4 py-2"><div className="h-5 w-20 bg-muted rounded" /></td>
                        <td className="px-4 py-2"><div className="h-4 w-14 bg-muted rounded" /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          </div>
        </div>
        <Toaster position="bottom-right" />
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="flex min-h-[calc(100vh-3rem)]">
        <ComplianceSidepanel
          activeSection={loadingSection}
          onSelect={handleSectionSelect}
          canViewSettings={canViewSettings}
          disabledExports={complianceData.length === 0}
        />
        <div className="flex-1 min-w-0 px-6 py-6 overflow-auto">
          <div className="mx-auto max-w-7xl">
            <h1 className="text-2xl font-bold text-foreground">Compliance</h1>
            <div className="bg-destructive/10 border border-destructive/30 rounded-lg p-4 text-sm text-destructive mt-4">
              {error}
            </div>
          </div>
        </div>
        <Toaster position="bottom-right" />
      </div>
    );
  }

  return (
    <>
      <div className="flex min-h-[calc(100vh-3rem)]">
        <ComplianceSidepanel
          activeSection={activeSection}
          onSelect={handleSectionSelect}
          canViewSettings={canViewSettings}
          disabledExports={complianceData.length === 0}
        />

        <div className="flex-1 min-w-0 px-6 py-6 overflow-auto">
          <div className="mx-auto max-w-7xl">
            {activeSection === 'project' && (
              <>
                <div className="mb-4">
                  <h1 className="text-2xl font-bold text-foreground">Licenses</h1>
                </div>

                <div className="flex gap-6 border-b border-border mb-4">
                  <button
                    onClick={() => setProjectTab('issues')}
                    className={cn(
                      'pb-3 text-sm font-medium border-b-2 -mb-px transition-colors',
                      projectTab === 'issues'
                        ? 'text-foreground border-foreground'
                        : 'text-foreground-secondary border-transparent hover:text-foreground'
                    )}
                  >
                    Issues
                  </button>
                  <button
                    onClick={() => setProjectTab('all')}
                    className={cn(
                      'pb-3 text-sm font-medium border-b-2 -mb-px transition-colors',
                      projectTab === 'all'
                        ? 'text-foreground border-foreground'
                        : 'text-foreground-secondary border-transparent hover:text-foreground'
                    )}
                  >
                    All packages
                  </button>
                </div>

                <div className="bg-background-card border border-border rounded-lg max-h-[600px] overflow-y-auto custom-scrollbar">
                  <table className="w-full table-fixed">
                    <colgroup>
                      <col style={{ width: '32%' }} />
                      <col style={{ width: '22%' }} />
                      <col style={{ width: '22%' }} />
                      <col style={{ width: '24%' }} />
                    </colgroup>
                    <thead className="sticky top-0 bg-[#141618] z-10">
                      {table.getHeaderGroups().map((headerGroup) => (
                        <tr key={headerGroup.id} className="border-b border-border">
                          {headerGroup.headers.map((header) => (
                            <th
                              key={header.id}
                              className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider"
                            >
                              {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                            </th>
                          ))}
                        </tr>
                      ))}
                    </thead>
                    <tbody className="divide-y divide-border">
                      {complianceData.length === 0 ? (
                        <tr>
                          <td colSpan={4} className="px-4 py-6 text-sm text-foreground-secondary">
                            No dependencies found yet.
                          </td>
                        </tr>
                      ) : table.getRowModel().rows.length === 0 ? (
                        <tr>
                          <td colSpan={4} className="px-4 py-6 text-center">
                            <p className="text-sm text-foreground-secondary">
                              {issueCount === 0 ? 'No compliance issues found.' : 'No items to display.'}
                            </p>
                          </td>
                        </tr>
                      ) : (
                        table.getRowModel().rows.map((row) => (
                          <tr key={row.id} className="group hover:bg-table-hover transition-colors">
                            {row.getVisibleCells().map((cell) => (
                              <td key={cell.id} className="px-4 py-2">
                                {flexRender(cell.column.columnDef.cell, cell.getContext())}
                              </td>
                            ))}
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </>
            )}

            {activeSection === 'updates' && (
              <>
                <div className="mb-4">
                  <h1 className="text-2xl font-bold text-foreground">Updates</h1>
                </div>

                <div className="flex gap-6 border-b border-border mb-4">
                  <button
                    onClick={() => setUpdatesTab('pull-requests')}
                    className={cn(
                      'pb-3 text-sm font-medium border-b-2 -mb-px transition-colors',
                      updatesTab === 'pull-requests'
                        ? 'text-foreground border-foreground'
                        : 'text-foreground-secondary border-transparent hover:text-foreground'
                    )}
                  >
                    Pull Requests
                  </button>
                  <button
                    onClick={() => setUpdatesTab('commits')}
                    className={cn(
                      'pb-3 text-sm font-medium border-b-2 -mb-px transition-colors',
                      updatesTab === 'commits'
                        ? 'text-foreground border-foreground'
                        : 'text-foreground-secondary border-transparent hover:text-foreground'
                    )}
                  >
                    Commits
                  </button>
                </div>

                {updatesTab === 'pull-requests' && (
                  <div className="space-y-4">
                    <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button
                              variant="outline"
                              size="sm"
                              className="h-9 px-3 text-xs font-medium text-foreground-secondary flex items-center gap-2"
                            >
                              <span>Status</span>
                              <span className="text-foreground">
                                {prStatusFilter === 'ALL'
                                  ? 'All'
                                  : prStatusFilter === 'OPEN'
                                  ? 'Open'
                                  : prStatusFilter === 'BLOCKED'
                                  ? 'Blocked'
                                  : 'Merged'}
                              </span>
                              <ChevronDown className="h-3.5 w-3.5 text-foreground-secondary" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="start" className="w-40">
                            <DropdownMenuLabel className="text-xs">Status</DropdownMenuLabel>
                            <DropdownMenuItem onClick={() => setPrStatusFilter('ALL')}>All</DropdownMenuItem>
                            <DropdownMenuItem onClick={() => setPrStatusFilter('OPEN')}>Open</DropdownMenuItem>
                            <DropdownMenuItem onClick={() => setPrStatusFilter('BLOCKED')}>Blocked</DropdownMenuItem>
                            <DropdownMenuItem onClick={() => setPrStatusFilter('MERGED')}>Merged</DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>

                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button
                              variant="outline"
                              size="sm"
                              className="h-9 px-3 text-xs font-medium text-foreground-secondary flex items-center gap-2"
                            >
                              <span>Timeframe</span>
                              <span className="text-foreground">
                                {prTimeframe === '24H'
                                  ? 'Last 24h'
                                  : prTimeframe === '7D'
                                  ? 'Last 7 days'
                                  : prTimeframe === '30D'
                                  ? 'Last 30 days'
                                  : 'All time'}
                              </span>
                              <ChevronDown className="h-3.5 w-3.5 text-foreground-secondary" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="start" className="w-44">
                            <DropdownMenuLabel className="text-xs">Timeframe</DropdownMenuLabel>
                            <DropdownMenuItem onClick={() => setPrTimeframe('24H')}>Last 24 hours</DropdownMenuItem>
                            <DropdownMenuItem onClick={() => setPrTimeframe('7D')}>Last 7 days</DropdownMenuItem>
                            <DropdownMenuItem onClick={() => setPrTimeframe('30D')}>Last 30 days</DropdownMenuItem>
                            <DropdownMenuItem onClick={() => setPrTimeframe('ALL')}>All time</DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>

                      <div className="w-full md:w-64">
                        <Input
                          placeholder="Search by title or author..."
                          value={prSearch}
                          onChange={(e) => setPrSearch(e.target.value)}
                          className="h-9"
                        />
                      </div>
                    </div>

                    <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                      <table className="w-full table-fixed">
                        <colgroup>
                          <col style={{ width: '34%' }} />
                          <col style={{ width: '22%' }} />
                          <col style={{ width: '14%' }} />
                          <col style={{ width: '16%' }} />
                          <col style={{ width: '14%' }} />
                        </colgroup>
                        <thead className="bg-background-card-header border-b border-border">
                          <tr>
                            <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                              Pull Request
                            </th>
                            <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                              Author
                            </th>
                            <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                              Status
                            </th>
                            <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                              Packages
                            </th>
                            <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                              Updated
                            </th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                          {filteredPullRequests.length === 0 ? (
                            <tr>
                              <td colSpan={5} className="px-4 py-6 text-sm text-foreground-secondary text-center">
                                No pull requests match the current filters.
                              </td>
                            </tr>
                          ) : (
                            filteredPullRequests.map((pr) => (
                              <tr key={pr.id} className="hover:bg-table-hover transition-colors">
                                <td className="px-4 py-3 align-top">
                                  <div className="flex flex-col gap-1 min-w-0">
                                    <div className="flex items-center gap-2 min-w-0">
                                      <GitPullRequest className="h-4 w-4 text-foreground-secondary shrink-0" />
                                      <span className="text-sm font-medium text-foreground truncate">{pr.title}</span>
                                    </div>
                                    <div className="flex items-center gap-2 text-xs text-foreground-secondary">
                                      <span className="px-1.5 py-0.5 rounded-full border border-border/80 bg-background-subtle/60 truncate max-w-[180px]">
                                        {pr.branch}
                                      </span>
                                      <span className="text-foreground-muted">#{pr.id}</span>
                                    </div>
                                    <p className="text-xs text-foreground-secondary truncate">
                                      {pr.complianceImpact}
                                    </p>
                                  </div>
                                </td>
                                <td className="px-4 py-3 align-top">
                                  <div className="flex items-center gap-2 min-w-0">
                                    <Avatar className="h-7 w-7">
                                      <AvatarImage src={pr.author.avatarUrl} alt={pr.author.name} />
                                      <AvatarFallback>{getInitials(pr.author.name)}</AvatarFallback>
                                    </Avatar>
                                    <div className="min-w-0">
                                      <div className="text-sm text-foreground truncate">{pr.author.name}</div>
                                      <div className="text-xs text-foreground-secondary truncate">
                                        {pr.author.handle}
                                      </div>
                                    </div>
                                  </div>
                                </td>
                                <td className="px-4 py-3 align-top">
                                  <Badge
                                    variant={
                                      pr.status === 'BLOCKED'
                                        ? 'destructive'
                                        : pr.status === 'MERGED'
                                        ? 'success'
                                        : 'outline'
                                    }
                                  >
                                    {pr.status === 'BLOCKED'
                                      ? 'Blocked'
                                      : pr.status === 'MERGED'
                                      ? 'Merged'
                                      : 'Open'}
                                  </Badge>
                                </td>
                                <td className="px-4 py-3 align-top">
                                  <div className="text-sm text-foreground-secondary">
                                    <span className="text-foreground">+{pr.packageChanges.added}</span> / -
                                    {pr.packageChanges.removed} / {pr.packageChanges.updated} updated
                                  </div>
                                </td>
                                <td className="px-4 py-3 align-top">
                                  <div className="flex flex-col gap-1 items-start">
                                    <span className="text-sm text-foreground-secondary">
                                      {formatDateTime(pr.updatedAt)}
                                    </span>
                                    {pr.status === 'BLOCKED' && (
                                      <Button
                                        variant="outline"
                                        size="sm"
                                        className="h-7 text-xs px-2"
                                        onClick={() =>
                                          navigate(
                                            `/organizations/${organizationId}/projects/${projectId}/settings`,
                                            { state: { section: 'policies' } }
                                          )
                                        }
                                      >
                                        Allow exception
                                      </Button>
                                    )}
                                  </div>
                                </td>
                              </tr>
                            ))
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {updatesTab === 'commits' && (
                  <div className="space-y-4">
                    <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button
                              variant="outline"
                              size="sm"
                              className="h-9 px-3 text-xs font-medium text-foreground-secondary flex items-center gap-2"
                            >
                              <span>Status</span>
                              <span className="text-foreground">
                                {commitStatusFilter === 'ALL'
                                  ? 'All'
                                  : commitStatusFilter === 'COMPLIANT'
                                  ? 'Compliant'
                                  : commitStatusFilter === 'NON_COMPLIANT'
                                  ? 'Non-compliant'
                                  : 'Unknown'}
                              </span>
                              <ChevronDown className="h-3.5 w-3.5 text-foreground-secondary" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="start" className="w-44">
                            <DropdownMenuLabel className="text-xs">Status</DropdownMenuLabel>
                            <DropdownMenuItem onClick={() => setCommitStatusFilter('ALL')}>All</DropdownMenuItem>
                            <DropdownMenuItem onClick={() => setCommitStatusFilter('COMPLIANT')}>
                              Compliant
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => setCommitStatusFilter('NON_COMPLIANT')}>
                              Non-compliant
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => setCommitStatusFilter('UNKNOWN')}>
                              Unknown
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>

                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button
                              variant="outline"
                              size="sm"
                              className="h-9 px-3 text-xs font-medium text-foreground-secondary flex items-center gap-2"
                            >
                              <span>Timeframe</span>
                              <span className="text-foreground">
                                {commitTimeframe === '24H'
                                  ? 'Last 24h'
                                  : commitTimeframe === '7D'
                                  ? 'Last 7 days'
                                  : commitTimeframe === '30D'
                                  ? 'Last 30 days'
                                  : 'All time'}
                              </span>
                              <ChevronDown className="h-3.5 w-3.5 text-foreground-secondary" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="start" className="w-44">
                            <DropdownMenuLabel className="text-xs">Timeframe</DropdownMenuLabel>
                            <DropdownMenuItem onClick={() => setCommitTimeframe('24H')}>Last 24 hours</DropdownMenuItem>
                            <DropdownMenuItem onClick={() => setCommitTimeframe('7D')}>Last 7 days</DropdownMenuItem>
                            <DropdownMenuItem onClick={() => setCommitTimeframe('30D')}>Last 30 days</DropdownMenuItem>
                            <DropdownMenuItem onClick={() => setCommitTimeframe('ALL')}>All time</DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>

                      <div className="w-full md:w-64">
                        <Input
                          placeholder="Search by message or committer..."
                          value={commitSearch}
                          onChange={(e) => setCommitSearch(e.target.value)}
                          className="h-9"
                        />
                      </div>
                    </div>

                    <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                      <table className="w-full table-fixed">
                        <colgroup>
                          <col style={{ width: '40%' }} />
                          <col style={{ width: '22%' }} />
                          <col style={{ width: '14%' }} />
                          <col style={{ width: '12%' }} />
                          <col style={{ width: '12%' }} />
                        </colgroup>
                        <thead className="bg-background-card-header border-b border-border">
                          <tr>
                            <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                              Commit
                            </th>
                            <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                              Committer
                            </th>
                            <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                              Status
                            </th>
                            <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                              Packages
                            </th>
                            <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                              Date
                            </th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                          {filteredCommits.length === 0 ? (
                            <tr>
                              <td colSpan={5} className="px-4 py-6 text-sm text-foreground-secondary text-center">
                                No commits match the current filters.
                              </td>
                            </tr>
                          ) : (
                            filteredCommits.map((commit) => (
                              <tr key={commit.id} className="hover:bg-table-hover transition-colors">
                                <td className="px-4 py-3 align-top">
                                  <div className="flex items-start gap-2 min-w-0">
                                    <GitCommit className="h-4 w-4 text-foreground-secondary shrink-0 mt-0.5" />
                                    <div className="min-w-0">
                                      <div className="text-sm font-medium text-foreground truncate">
                                        {commit.message}
                                      </div>
                                      <div className="text-xs text-foreground-secondary mt-0.5">
                                        {commit.shortSha}
                                      </div>
                                    </div>
                                  </div>
                                </td>
                                <td className="px-4 py-3 align-top">
                                  <div className="flex items-center gap-2 min-w-0">
                                    <Avatar className="h-7 w-7">
                                      <AvatarImage src={commit.committer.avatarUrl} alt={commit.committer.name} />
                                      <AvatarFallback>{getInitials(commit.committer.name)}</AvatarFallback>
                                    </Avatar>
                                    <div className="min-w-0">
                                      <div className="text-sm text-foreground truncate">{commit.committer.name}</div>
                                      <div className="text-xs text-foreground-secondary truncate">
                                        {commit.committer.handle}
                                      </div>
                                    </div>
                                  </div>
                                </td>
                                <td className="px-4 py-3 align-top">
                                  <Badge
                                    variant={
                                      commit.status === 'NON_COMPLIANT'
                                        ? 'destructive'
                                        : commit.status === 'COMPLIANT'
                                        ? 'success'
                                        : 'outline'
                                    }
                                  >
                                    {commit.status === 'NON_COMPLIANT'
                                      ? 'Non-compliant'
                                      : commit.status === 'COMPLIANT'
                                      ? 'Compliant'
                                      : 'Unknown'}
                                  </Badge>
                                </td>
                                <td className="px-4 py-3 align-top">
                                  <div className="text-sm text-foreground-secondary">
                                    <span className="text-foreground">+{commit.packageChanges.added}</span> / -
                                    {commit.packageChanges.removed} / {commit.packageChanges.updated} updated
                                  </div>
                                </td>
                                <td className="px-4 py-3 align-top">
                                  <span className="text-sm text-foreground-secondary">
                                    {formatDate(commit.committedAt)}
                                  </span>
                                </td>
                              </tr>
                            ))
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </>
            )}

          </div>
        </div>
      </div>

      <Toaster position="bottom-right" />
    </>
  );
}

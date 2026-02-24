import { useParams, useOutletContext } from 'react-router-dom';
import { useMemo, useState, useEffect, useCallback } from 'react';
import PackageOverview from '../../components/PackageOverview';
import { PackageOverviewSkeleton } from '../../components/PackageOverviewSkeleton';
import { api, type ProjectDependency, type ProjectEffectivePolicies, type LatestSafeVersionResponse } from '../../lib/api';
import type { DependencyContextType } from './DependencyLayout';

// Build ProjectDependency for overview – real fields from overview API, rest placeholder
function buildDependencyFromOverview(
  projectId: string,
  projectDependencyId: string,
  overview: {
    dependency_id: string | null;
    name: string | null;
    version: string | null;
    score: number | null;
    critical_vulns: number;
    high_vulns: number;
    medium_vulns: number;
    low_vulns: number;
    github_url: string | null;
    license: string | null;
    weekly_downloads: number | null;
    latest_release_date: string | null;
    latest_version: string | null;
    last_published_at: string | null;
    releases_last_12_months?: number | null;
    openssf_score?: number | null;
    openssf_penalty?: number | null;
    popularity_penalty?: number | null;
    maintenance_penalty?: number | null;
    files_importing_count?: number;
    imported_functions?: string[];
    imported_file_paths?: string[];
    ai_usage_summary?: string | null;
    ai_usage_analyzed_at?: string | null;
    other_projects_using_count?: number;
    other_projects_using_names?: string[];
    description?: string | null;
  } | null
): ProjectDependency {
  return {
    id: projectDependencyId,
    project_id: projectId,
    dependency_id: overview?.dependency_id ?? '',
    name: overview?.name ?? 'example-package',
    version: overview?.version ?? '9.9.9',
    license: overview?.license ?? 'MIT',
    github_url: overview?.github_url ?? null,
    is_direct: true,
    source: 'dependencies',
    is_watching: false,
    files_importing_count: overview?.files_importing_count ?? 0,
    imported_functions: overview?.imported_functions ?? [],
    imported_file_paths: overview?.imported_file_paths ?? [],
    ai_usage_summary: overview?.ai_usage_summary ?? null,
    ai_usage_analyzed_at: overview?.ai_usage_analyzed_at ?? null,
    other_projects_using_count: overview?.other_projects_using_count ?? 0,
    other_projects_using_names: overview?.other_projects_using_names ?? [],
    description: overview?.description ?? null,
    created_at: new Date().toISOString(),
    analysis: {
      status: 'ready',
      score: overview?.score ?? null,
      score_breakdown: {
        openssf_penalty: overview?.openssf_penalty ?? null,
        popularity_penalty: overview?.popularity_penalty ?? null,
        maintenance_penalty: overview?.maintenance_penalty ?? null,
      },
      critical_vulns: overview?.critical_vulns ?? 0,
      high_vulns: overview?.high_vulns ?? 0,
      medium_vulns: overview?.medium_vulns ?? 0,
      low_vulns: overview?.low_vulns ?? 0,
      openssf_score: overview?.openssf_score ?? null,
      openssf_data: undefined,
      weekly_downloads: overview?.weekly_downloads ?? null,
      last_published_at: overview?.last_published_at ?? null,
      latest_release_date: overview?.latest_release_date ?? null,
      releases_last_12_months: overview?.releases_last_12_months ?? null,
      analyzed_at: new Date().toISOString(),
    },
  };
}

export default function DependencyOverviewPage() {
  const { orgId, projectId, dependencyId } = useParams<{ orgId: string; projectId: string; dependencyId: string }>();
  const { organization, dependency: layoutDependency } = useOutletContext<DependencyContextType>();
  const otherProjectsScopeIsOrg = organization?.permissions?.manage_teams_and_projects ?? false;
  const [overview, setOverview] = useState<{
    dependency_id: string | null;
    name: string | null;
    version: string | null;
    score: number | null;
    critical_vulns: number;
    high_vulns: number;
    medium_vulns: number;
    low_vulns: number;
    github_url: string | null;
    license: string | null;
    weekly_downloads: number | null;
    latest_release_date: string | null;
    latest_version: string | null;
    last_published_at: string | null;
    releases_last_12_months: number | null;
    openssf_score: number | null;
    openssf_penalty: number | null;
    popularity_penalty: number | null;
    maintenance_penalty: number | null;
    files_importing_count: number;
    imported_functions: string[];
    imported_file_paths?: string[];
    ai_usage_summary: string | null;
    ai_usage_analyzed_at: string | null;
    other_projects_using_count: number;
    other_projects_using_names: string[];
    description: string | null;
    remove_pr_url: string | null;
  } | null>(null);
  const [deprecation, setDeprecation] = useState<{
    recommended_alternative: string;
    deprecated_by: string | null;
    created_at: string;
    scope?: 'organization' | 'team';
    team_id?: string;
  } | null>(null);
  const [policies, setPolicies] = useState<ProjectEffectivePolicies | null>(null);
  const [bumpScope, setBumpScope] = useState<'org' | 'team' | 'project'>('project');
  const [bumpTeamId, setBumpTeamId] = useState<string | undefined>(undefined);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [safeVersionData, setSafeVersionData] = useState<LatestSafeVersionResponse | null>(null);
  const [safeVersionSeverity, setSafeVersionSeverity] = useState<string>('high');
  const [safeVersionLoading, setSafeVersionLoading] = useState(false);

  // Can manage deprecations when org or team scope (same as ban permission)
  const canManageDeprecations = bumpScope === 'org' || bumpScope === 'team';

  // Fetch bump scope for permission checks
  useEffect(() => {
    if (!orgId || !projectId) return;
    api.getBumpScope(orgId, projectId)
      .then((res) => {
        setBumpScope(res.scope);
        if (res.team_id) setBumpTeamId(res.team_id);
      })
      .catch(() => setBumpScope('project'));
  }, [orgId, projectId]);

  useEffect(() => {
    if (!orgId || !projectId || !dependencyId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    const prefetched = api.consumePrefetchedOverview(orgId, projectId, dependencyId);
    const applyOverview = (res: { dependency_id?: string | null; name: string | null; version: string | null; score: number | null; critical_vulns?: number; high_vulns?: number; medium_vulns?: number; low_vulns?: number; github_url?: string | null; license?: string | null; weekly_downloads?: number | null; latest_release_date?: string | null; latest_version?: string | null; last_published_at?: string | null; releases_last_12_months?: number | null; openssf_score?: number | null; openssf_penalty?: number | null; popularity_penalty?: number | null; maintenance_penalty?: number | null; files_importing_count?: number; imported_functions?: string[]; imported_file_paths?: string[]; ai_usage_summary?: string | null; ai_usage_analyzed_at?: string | null; other_projects_using_count?: number; other_projects_using_names?: string[]; description?: string | null; remove_pr_url?: string | null; deprecation?: unknown }) => {
      setOverview({
        dependency_id: res.dependency_id ?? null,
        name: res.name,
        version: res.version,
        score: res.score,
        critical_vulns: res.critical_vulns ?? 0,
        high_vulns: res.high_vulns ?? 0,
        medium_vulns: res.medium_vulns ?? 0,
        low_vulns: res.low_vulns ?? 0,
        github_url: res.github_url ?? null,
        license: res.license ?? null,
        weekly_downloads: res.weekly_downloads ?? null,
        latest_release_date: res.latest_release_date ?? null,
        latest_version: res.latest_version ?? null,
        last_published_at: res.last_published_at ?? null,
        releases_last_12_months: res.releases_last_12_months ?? null,
        openssf_score: res.openssf_score ?? null,
        openssf_penalty: res.openssf_penalty ?? null,
        popularity_penalty: res.popularity_penalty ?? null,
        maintenance_penalty: res.maintenance_penalty ?? null,
        files_importing_count: res.files_importing_count ?? 0,
        imported_functions: res.imported_functions ?? [],
        imported_file_paths: res.imported_file_paths ?? [],
        ai_usage_summary: res.ai_usage_summary ?? null,
        ai_usage_analyzed_at: res.ai_usage_analyzed_at ?? null,
        other_projects_using_count: res.other_projects_using_count ?? 0,
        other_projects_using_names: res.other_projects_using_names ?? [],
        description: res.description ?? null,
        remove_pr_url: res.remove_pr_url ?? null,
      });
      setDeprecation((res.deprecation ?? null) as { recommended_alternative: string; deprecated_by: string | null; created_at: string; scope?: 'organization' | 'team'; team_id?: string } | null);
    };

    if (prefetched) {
      prefetched
        .then(([res, policiesData]) => {
          if (res == null) {
            // Prefetch failed (returned [null, null]) - fall back to fresh fetch
            return Promise.all([
              api.getDependencyOverview(orgId, projectId, dependencyId),
              api.getProjectPolicies(orgId, projectId).catch(() => null),
            ]).then(([overviewRes, policiesRes]) => {
              applyOverview(overviewRes);
              setPolicies(policiesRes);
            });
          }
          applyOverview(res);
          setPolicies(policiesData);
        })
        .catch((err) => setError(err.message ?? 'Failed to load dependency'))
        .finally(() => setLoading(false));
    } else {
      api
        .getDependencyOverview(orgId, projectId, dependencyId)
        .then((res) => {
          applyOverview(res);
          setLoading(false);
          api.getProjectPolicies(orgId, projectId).then(setPolicies).catch(() => setPolicies(null));
        })
        .catch((err) => setError(err.message ?? 'Failed to load dependency'))
        .finally(() => setLoading(false));
    }
  }, [orgId, projectId, dependencyId]);

  // Fetch latest safe version (refresh=true so Watchtower check results in DB are always reflected)
  useEffect(() => {
    if (!orgId || !projectId || !dependencyId) return;
    setSafeVersionLoading(true);
    api.getLatestSafeVersion(orgId, projectId, dependencyId, safeVersionSeverity, true, { refresh: true })
      .then((data) => {
        setSafeVersionData(data);
      })
      .catch((err) => {
        console.error('Failed to fetch latest safe version:', err);
        setSafeVersionData(null);
      })
      .finally(() => {
        setSafeVersionLoading(false);
      });
  }, [orgId, projectId, dependencyId, safeVersionSeverity]);

  const handleDeprecate = useCallback(async (alternativeName: string) => {
    if (!orgId || !overview?.dependency_id) return;
    if (bumpScope === 'org') {
      await api.deprecateDependency(orgId, overview.dependency_id, alternativeName);
      setDeprecation({
        recommended_alternative: alternativeName,
        deprecated_by: null,
        created_at: new Date().toISOString(),
        scope: 'organization',
      });
    } else if (bumpScope === 'team' && bumpTeamId) {
      await api.deprecateDependencyTeam(orgId, bumpTeamId, overview.dependency_id, alternativeName);
      setDeprecation({
        recommended_alternative: alternativeName,
        deprecated_by: null,
        created_at: new Date().toISOString(),
        scope: 'team',
        team_id: bumpTeamId,
      });
    }
  }, [orgId, overview?.dependency_id, bumpScope, bumpTeamId]);

  const handleRemoveDeprecation = useCallback(async () => {
    if (!orgId || !overview?.dependency_id) return;
    if (deprecation?.scope === 'team' && deprecation?.team_id) {
      await api.removeDeprecationTeam(orgId, deprecation.team_id, overview.dependency_id);
    } else {
      await api.removeDeprecation(orgId, overview.dependency_id);
    }
    setDeprecation(null);
  }, [orgId, overview?.dependency_id, deprecation?.scope, deprecation?.team_id]);

  const handleSeverityChange = useCallback((severity: string) => {
    setSafeVersionSeverity(severity);
  }, []);

  const [bumpPrUrl, setBumpPrUrl] = useState<string | null>(null);
  const [bumpPrCheckLoading, setBumpPrCheckLoading] = useState(false);
  const [bumping, setBumping] = useState(false);

  const dependency = useMemo(
    () => (projectId && dependencyId ? buildDependencyFromOverview(projectId, dependencyId, overview) : null),
    [projectId, dependencyId, overview]
  );

  const handleBumpVersion = useCallback(async () => {
    if (!orgId || !projectId || !dependencyId || !safeVersionData?.safeVersion || bumping) return;
    setBumping(true);
    try {
      const result = await api.createWatchtowerBumpPR(orgId, projectId, dependencyId, safeVersionData.safeVersion);
      if (result.pr_url) {
        setBumpPrUrl(result.pr_url);
        window.open(result.pr_url, '_blank');
      }
    } catch (err: any) {
      console.error('Failed to create bump PR:', err);
    } finally {
      setBumping(false);
    }
  }, [orgId, projectId, dependencyId, safeVersionData?.safeVersion, bumping]);

  // Check for existing bump PR when safe version data changes (show View PR if any bump PR exists)
  useEffect(() => {
    if (!overview?.name || !dependencyId || !safeVersionData?.safeVersion) {
      setBumpPrUrl(null);
      setBumpPrCheckLoading(false);
      return;
    }
    setBumpPrCheckLoading(true);
    api.getWatchtowerSummary(overview.name, dependencyId)
      .then((summary) => {
        setBumpPrUrl(summary.bump_pr_url ?? null);
      })
      .catch(() => {
        setBumpPrUrl(null);
      })
      .finally(() => {
        setBumpPrCheckLoading(false);
      });
  }, [overview?.name, dependencyId, safeVersionData?.safeVersion]);

  if (!orgId || !projectId || !dependencyId) {
    return (
      <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <p className="text-foreground-secondary">Missing org, project, or dependency in URL.</p>
      </main>
    );
  }

  if (loading) {
    return (
      <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8 bg-background-content min-h-[calc(100vh-3rem)]">
        <PackageOverviewSkeleton />
      </main>
    );
  }

  if (error || !dependency) {
    return (
      <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8 bg-background-content min-h-[calc(100vh-3rem)]">
        <p className="text-destructive">{error ?? 'Missing dependency'}</p>
      </main>
    );
  }

  return (
    <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8 bg-background-content min-h-[calc(100vh-3rem)]">
      <PackageOverview
        dependency={dependency}
        organizationId={orgId}
        projectId={projectId}
        latestVersion={overview?.latest_version ?? null}
        policies={policies}
        deprecation={deprecation}
        canManageDeprecations={canManageDeprecations}
        onDeprecate={handleDeprecate}
        onRemoveDeprecation={handleRemoveDeprecation}
        removePrUrlFromOverview={overview?.remove_pr_url ?? null}
        safeVersionData={safeVersionData}
        safeVersionSeverity={safeVersionSeverity}
        onSeverityChange={handleSeverityChange}
        onBumpVersion={handleBumpVersion}
        safeVersionLoading={safeVersionLoading}
        bumpPrUrl={bumpPrUrl}
        bumpPrCheckLoading={bumpPrCheckLoading}
        bumping={bumping}
        otherProjectsScopeIsOrg={otherProjectsScopeIsOrg}
        isDevDependency={layoutDependency?.source === 'devDependencies'}
      />
    </main>
  );
}

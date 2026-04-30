import { jsonSchema } from 'ai';
import { calculateLatestSafeVersion } from '../../latest-safe-version';
import type { AegisToolEntry } from '../tool-types';

const checkCisaKev: AegisToolEntry<{ cveOrOsvId: string }> = {
  name: 'check_cisa_kev',
  description:
    'Check whether a CVE or OSV id is on the CISA Known Exploited Vulnerabilities (KEV) list. KEV status is cached on each vulnerability row in the org.',
  danger: 'safe',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      cveOrOsvId: { type: 'string', minLength: 1 },
    },
    required: ['cveOrOsvId'],
    additionalProperties: false,
  }),
  execute: async ({ cveOrOsvId }, ctx) => {
    const { data: orgProjects } = await ctx.supabase
      .from('projects')
      .select('id')
      .eq('organization_id', ctx.orgId);
    const projectIds = (orgProjects ?? []).map((p: any) => p.id);
    if (projectIds.length === 0) return { error: 'No projects in this organization' };

    let query = ctx.supabase
      .from('project_dependency_vulnerabilities')
      .select('osv_id, cisa_kev, aliases')
      .in('project_id', projectIds);

    if (cveOrOsvId.startsWith('CVE-')) query = (query as any).contains('aliases', [cveOrOsvId]);
    else query = query.eq('osv_id', cveOrOsvId);

    const { data: rows, error } = await query.limit(5);
    if (error) return { error: error.message };
    if (!rows || rows.length === 0) {
      return { queryId: cveOrOsvId, isKev: false, note: 'Not present in the org vulnerability cache.' };
    }

    return {
      queryId: cveOrOsvId,
      isKev: rows.some((r: any) => r.cisa_kev === true),
      osvId: rows[0].osv_id,
    };
  },
};

const getEpssScore: AegisToolEntry<{ cveOrOsvId: string }> = {
  name: 'get_epss_score',
  description:
    'EPSS exploit probability score (0.0–1.0) for a CVE or OSV id. EPSS is cached per-project on each vulnerability row; this returns the highest observed score across the org.',
  danger: 'safe',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      cveOrOsvId: {
        type: 'string',
        minLength: 1,
        description: 'CVE id (CVE-YYYY-NNNN) or OSV id (GHSA-xxxx).',
      },
    },
    required: ['cveOrOsvId'],
    additionalProperties: false,
  }),
  execute: async ({ cveOrOsvId }, ctx) => {
    const { data: orgProjects } = await ctx.supabase
      .from('projects')
      .select('id')
      .eq('organization_id', ctx.orgId);
    const projectIds = (orgProjects ?? []).map((p: any) => p.id);
    if (projectIds.length === 0) return { error: 'No projects in this organization' };

    let query = ctx.supabase
      .from('project_dependency_vulnerabilities')
      .select('osv_id, epss_score, aliases')
      .in('project_id', projectIds);

    if (cveOrOsvId.startsWith('CVE-')) query = (query as any).contains('aliases', [cveOrOsvId]);
    else query = query.eq('osv_id', cveOrOsvId);

    const { data: rows, error } = await query.limit(20);
    if (error) return { error: error.message };
    if (!rows || rows.length === 0) {
      return { error: `No EPSS data found for ${cveOrOsvId} in this organization's vulnerability cache.` };
    }

    const best = rows.reduce((acc: any, r: any) =>
      (r.epss_score ?? -1) > (acc.epss_score ?? -1) ? r : acc,
    );

    return {
      queryId: cveOrOsvId,
      osvId: best.osv_id,
      epssScore: best.epss_score,
      epssPercentile: best.epss_score != null ? Math.round(best.epss_score * 100) : null,
    };
  },
};

const getPackageReputation: AegisToolEntry<{ packageName: string }> = {
  name: 'get_package_reputation',
  description:
    'Package reputation data: OpenSSF Scorecard, weekly downloads, last published date, maintenance signals, and whether the package is flagged malicious. Input is the package name as stored (e.g. lodash, express, requests).',
  danger: 'safe',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      packageName: { type: 'string', minLength: 1, description: 'Package name as stored.' },
    },
    required: ['packageName'],
    additionalProperties: false,
  }),
  execute: async ({ packageName }, ctx) => {
    const { data, error } = await ctx.supabase
      .from('dependencies')
      .select(
        'id, name, status, score, openssf_score, openssf_penalty, popularity_penalty, maintenance_penalty, weekly_downloads, last_published_at, releases_last_12_months, github_url, latest_version, latest_release_date, description, is_malicious, license',
      )
      .eq('name', packageName)
      .maybeSingle();

    if (error) return { error: error.message };
    if (!data) return { error: `Package "${packageName}" not found in the Deptex reputation cache.` };

    return {
      name: data.name,
      analysisStatus: data.status,
      reputationScore: data.score,
      openssfScore: data.openssf_score,
      scorePenalties: {
        openssf: data.openssf_penalty ?? 0,
        popularity: data.popularity_penalty ?? 0,
        maintenance: data.maintenance_penalty ?? 0,
      },
      weeklyDownloads: data.weekly_downloads,
      lastPublishedAt: data.last_published_at,
      releasesLast12Months: data.releases_last_12_months,
      githubUrl: data.github_url,
      description: data.description,
      latestVersion: data.latest_version,
      latestReleaseDate: data.latest_release_date,
      license: data.license,
      isMalicious: !!data.is_malicious,
    };
  },
};

const analyzeUpgradePath: AegisToolEntry<{
  projectDependencyId: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
}> = {
  name: 'analyze_upgrade_path',
  description:
    'Analyze the safest upgrade target for a project dependency. Given a project_dependency_id, returns the latest version that has no vulnerabilities (direct + transitive) above the chosen severity threshold.',
  danger: 'safe',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      projectDependencyId: {
        type: 'string',
        format: 'uuid',
        description: 'project_dependencies.id (from list_project_dependencies).',
      },
      severity: {
        type: 'string',
        enum: ['critical', 'high', 'medium', 'low'],
        description: 'Highest severity to tolerate (default "high").',
      },
    },
    required: ['projectDependencyId'],
    additionalProperties: false,
  }),
  execute: async ({ projectDependencyId, severity }, ctx) => {
    const { data: pd } = await ctx.supabase
      .from('project_dependencies')
      .select('id, project_id, name, version')
      .eq('id', projectDependencyId)
      .single();
    if (!pd) return { error: 'Project dependency not found' };

    const { data: project } = await ctx.supabase
      .from('projects')
      .select('id, organization_id')
      .eq('id', pd.project_id)
      .single();
    if (!project || project.organization_id !== ctx.orgId) {
      return { error: 'Project not in current organization' };
    }

    try {
      const result = await calculateLatestSafeVersion({
        organizationId: ctx.orgId,
        projectId: pd.project_id,
        projectDependencyId: pd.id,
        severity: severity ?? 'high',
      });
      return {
        packageName: pd.name,
        currentVersion: pd.version,
        safeVersion: result.safeVersion,
        isCurrent: result.isCurrent,
        severityThreshold: result.severity,
        versionsChecked: result.versionsChecked,
        message: result.message,
      };
    } catch (err: any) {
      return { error: err?.message ?? 'Upgrade analysis failed' };
    }
  },
};

export const intelligenceTools: AegisToolEntry[] = [
  checkCisaKev,
  getEpssScore,
  getPackageReputation,
  analyzeUpgradePath,
];

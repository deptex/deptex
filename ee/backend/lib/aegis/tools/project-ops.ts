import { tool } from 'ai';
import { z } from 'zod';
import { registerAegisTool } from './registry';
import { supabase } from '../../../../../backend/src/lib/supabase';
import { queueExtractionJob } from '../../../redis';

const safeProjectOpsMeta = {
  category: 'project_ops' as const,
  permissionLevel: 'safe' as const,
  requiredRbacPermissions: [] as string[],
};

const moderateProjectOpsMeta = {
  category: 'project_ops' as const,
  permissionLevel: 'moderate' as const,
  requiredRbacPermissions: ['manage_teams_and_projects'] as string[],
};

// 1. listProjects
registerAegisTool(
  'listProjects',
  safeProjectOpsMeta,
  tool({
    description: 'List all projects in the organization with basic stats (health_score, status, framework). Optionally filter by team.',
    parameters: z.object({
      organizationId: z.string().uuid(),
      teamId: z.string().uuid().optional(),
    }),
    execute: async ({ organizationId, teamId }) => {
      let query = supabase
        .from('projects')
        .select(`
          id,
          name,
          health_score,
          status_id,
          framework,
          organization_statuses(name),
          project_repositories(status, repo_full_name)
        `)
        .eq('organization_id', organizationId);

      if (teamId) {
        const { data: pt } = await supabase
          .from('project_teams')
          .select('project_id')
          .eq('team_id', teamId);
        const projectIds = (pt || []).map((r: { project_id: string }) => r.project_id);
        if (projectIds.length === 0) return JSON.stringify({ projects: [] });
        query = query.in('id', projectIds);
      }

      const { data, error } = await query.order('created_at', { ascending: false });
      if (error) return JSON.stringify({ error: error.message });
      const projects = (data || []).map((p: any) => ({
        id: p.id,
        name: p.name,
        health_score: p.health_score,
        status: p.organization_statuses?.name ?? null,
        framework: p.framework,
        repo_status: p.project_repositories?.[0]?.status ?? null,
        repo_full_name: p.project_repositories?.[0]?.repo_full_name ?? null,
      }));
      return JSON.stringify({ projects });
    },
  })
);

// 2. getProjectSummary
registerAegisTool(
  'getProjectSummary',
  safeProjectOpsMeta,
  tool({
    description: 'Get detailed project info including dep count, vuln count, semgrep findings.',
    parameters: z.object({
      projectId: z.string().uuid(),
    }),
    execute: async ({ projectId }) => {
      const { data: project, error: projError } = await supabase
        .from('projects')
        .select(`
          id,
          name,
          health_score,
          status_id,
          framework,
          organization_statuses(name),
          project_repositories(status, repo_full_name, default_branch, ecosystem)
        `)
        .eq('id', projectId)
        .single();

      if (projError || !project) {
        return JSON.stringify({ error: projError?.message ?? 'Project not found' });
      }

      const [{ count: depCount }, { count: vulnCount }, { count: semgrepCount }] = await Promise.all([
        supabase.from('project_dependencies').select('id', { count: 'exact', head: true }).eq('project_id', projectId),
        supabase
          .from('project_dependency_vulnerabilities')
          .select('id', { count: 'exact', head: true })
          .eq('project_id', projectId)
          .eq('suppressed', false),
        supabase.from('project_semgrep_findings').select('id', { count: 'exact', head: true }).eq('project_id', projectId),
      ]);

      const result = {
        id: project.id,
        name: project.name,
        health_score: project.health_score,
        status: (project as any).organization_statuses?.name ?? null,
        framework: project.framework,
        repository: (project as any).project_repositories?.[0]
          ? {
              status: (project as any).project_repositories[0].status,
              repo_full_name: (project as any).project_repositories[0].repo_full_name,
              default_branch: (project as any).project_repositories[0].default_branch,
              ecosystem: (project as any).project_repositories[0].ecosystem,
            }
          : null,
        counts: {
          dependencies: depCount ?? 0,
          vulnerabilities: vulnCount ?? 0,
          semgrep_findings: semgrepCount ?? 0,
        },
      };
      return JSON.stringify(result);
    },
  })
);

// 3. getProjectDependencies
registerAegisTool(
  'getProjectDependencies',
  safeProjectOpsMeta,
  tool({
    description: 'List project dependencies with name, version, license, is_direct.',
    parameters: z.object({
      projectId: z.string().uuid(),
      isDirect: z.boolean().optional(),
      limit: z.number().min(1).max(200).default(50),
    }),
    execute: async ({ projectId, isDirect, limit = 50 }) => {
      let query = supabase
        .from('project_dependencies')
        .select(`
          id,
          name,
          version,
          license,
          is_direct,
          source,
          files_importing_count,
          dependencies(name, ecosystem),
          dependency_versions(vuln_critical_count, vuln_high_count)
        `)
        .eq('project_id', projectId)
        .limit(limit);

      if (isDirect !== undefined) {
        query = query.eq('is_direct', isDirect);
      }

      const { data, error } = await query.order('name');
      if (error) return JSON.stringify({ error: error.message });
      const deps = (data || []).map((d: any) => ({
        id: d.id,
        name: d.name,
        version: d.version,
        license: d.license,
        is_direct: d.is_direct,
        source: d.source,
        files_importing_count: d.files_importing_count,
        ecosystem: d.dependencies?.ecosystem,
        vuln_critical: d.dependency_versions?.vuln_critical_count ?? 0,
        vuln_high: d.dependency_versions?.vuln_high_count ?? 0,
      }));
      return JSON.stringify({ dependencies: deps });
    },
  })
);

// 4. getProjectVulnerabilities
registerAegisTool(
  'getProjectVulnerabilities',
  safeProjectOpsMeta,
  tool({
    description: 'List vulnerabilities for a project sorted by depscore. Optional filters: severity, reachabilityLevel.',
    parameters: z.object({
      projectId: z.string().uuid(),
      severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
      reachabilityLevel: z.enum(['unreachable', 'module', 'function', 'data_flow', 'confirmed']).optional(),
      limit: z.number().min(1).max(100).default(50),
    }),
    execute: async ({ projectId, severity, reachabilityLevel, limit = 50 }) => {
      let query = supabase
        .from('project_dependency_vulnerabilities')
        .select(`
          id,
          osv_id,
          severity,
          depscore,
          epss_score,
          cisa_kev,
          reachability_level,
          project_dependencies(dependencies(name), version)
        `)
        .eq('project_id', projectId)
        .eq('suppressed', false)
        .eq('risk_accepted', false)
        .order('depscore', { ascending: false })
        .limit(limit);

      if (severity) query = query.eq('severity', severity);
      if (reachabilityLevel) query = query.eq('reachability_level', reachabilityLevel);

      const { data, error } = await query;
      if (error) return JSON.stringify({ error: error.message });
      const vulns = (data || []).map((v: any) => ({
        id: v.id,
        osv_id: v.osv_id,
        severity: v.severity,
        depscore: v.depscore,
        epss_score: v.epss_score,
        cisa_kev: v.cisa_kev,
        reachability_level: v.reachability_level,
        summary: null,
        package: v.project_dependencies?.dependencies?.name,
        version: v.project_dependencies?.version,
      }));
      if (vulns.length > 0) {
        const osvIds = [...new Set(vulns.map((v: { osv_id: string }) => v.osv_id))];
        const { data: dvData } = await supabase
          .from('dependency_vulnerabilities')
          .select('osv_id, summary')
          .in('osv_id', osvIds);
        const summaryMap = new Map((dvData || []).map((d: any) => [d.osv_id, d.summary]));
        vulns.forEach((v: any) => { v.summary = summaryMap.get(v.osv_id) ?? null; });
      }
      return JSON.stringify({ vulnerabilities: vulns });
    },
  })
);

// 5. getDependencyGraph
registerAegisTool(
  'getDependencyGraph',
  safeProjectOpsMeta,
  tool({
    description: "Get dependency graph edges for a project's dependencies. Optionally filter by dependencyId.",
    parameters: z.object({
      projectId: z.string().uuid(),
      dependencyId: z.string().uuid().optional(),
    }),
    execute: async ({ projectId, dependencyId }) => {
      let pdQuery = supabase
        .from('project_dependencies')
        .select('dependency_version_id')
        .eq('project_id', projectId);
      if (dependencyId) {
        pdQuery = pdQuery.eq('dependency_id', dependencyId);
      }
      const { data: pds, error: pdError } = await pdQuery;
      if (pdError) return JSON.stringify({ error: pdError.message });
      const versionIds = [...new Set((pds || []).map((r: any) => r.dependency_version_id).filter(Boolean))];
      if (versionIds.length === 0) return JSON.stringify({ edges: [] });

      const [parentEdges, childEdges] = await Promise.all([
        supabase
          .from('dependency_version_edges')
          .select('parent_version_id, child_version_id')
          .in('parent_version_id', versionIds),
        supabase
          .from('dependency_version_edges')
          .select('parent_version_id, child_version_id')
          .in('child_version_id', versionIds),
      ]);
      const edgesSet = new Map<string, { parent_version_id: string; child_version_id: string }>();
      for (const e of parentEdges.data || []) {
        edgesSet.set(`${e.parent_version_id}-${e.child_version_id}`, e);
      }
      for (const e of childEdges.data || []) {
        edgesSet.set(`${e.parent_version_id}-${e.child_version_id}`, e);
      }
      const edges = Array.from(edgesSet.values());
      const error = parentEdges.error || childEdges.error;

      if (error) return JSON.stringify({ error: error.message });

      const dvIds = [...new Set((edges || []).flatMap((e: any) => [e.parent_version_id, e.child_version_id]))];
      const { data: vers } = await supabase
        .from('dependency_versions')
        .select('id, version, dependencies(name)')
        .in('id', dvIds);
      const versMap = new Map((vers || []).map((v: any) => [v.id, { version: v.version, name: v.dependencies?.name }]));

      const resultEdges = (edges || []).map((e: any) => ({
        parent_version_id: e.parent_version_id,
        child_version_id: e.child_version_id,
        parent: versMap.get(e.parent_version_id),
        child: versMap.get(e.child_version_id),
      }));
      return JSON.stringify({ edges: resultEdges });
    },
  })
);

// 6. getReachabilityFlows
registerAegisTool(
  'getReachabilityFlows',
  safeProjectOpsMeta,
  tool({
    description: 'Get reachability data-flow paths for a project. Optionally filter by dependencyId.',
    parameters: z.object({
      projectId: z.string().uuid(),
      dependencyId: z.string().uuid().optional(),
      limit: z.number().min(1).max(100).default(20),
    }),
    execute: async ({ projectId, dependencyId, limit = 20 }) => {
      let query = supabase
        .from('project_reachable_flows')
        .select('id, purl, dependency_id, flow_nodes, entry_point_file, entry_point_method, sink_file, sink_method, flow_length')
        .eq('project_id', projectId)
        .limit(limit);
      if (dependencyId) query = query.eq('dependency_id', dependencyId);
      const { data, error } = await query.order('created_at', { ascending: false });
      if (error) return JSON.stringify({ error: error.message });
      const flows = (data || []).map((f: any) => ({
        id: f.id,
        purl: f.purl,
        dependency_id: f.dependency_id,
        entry_point_file: f.entry_point_file,
        entry_point_method: f.entry_point_method,
        sink_file: f.sink_file,
        sink_method: f.sink_method,
        flow_length: f.flow_length,
        flow_nodes_count: Array.isArray(f.flow_nodes) ? f.flow_nodes.length : 0,
      }));
      return JSON.stringify({ flows });
    },
  })
);

// 7. getProjectSecurityPosture
registerAegisTool(
  'getProjectSecurityPosture',
  safeProjectOpsMeta,
  tool({
    description: 'Get comprehensive security posture: vuln counts by severity, semgrep findings, secrets, compliance rate.',
    parameters: z.object({
      projectId: z.string().uuid(),
    }),
    execute: async ({ projectId }) => {
      const [vulnRes, semgrepRes, secretRes, depRes, complRes] = await Promise.all([
        supabase
          .from('project_dependency_vulnerabilities')
          .select('severity')
          .eq('project_id', projectId)
          .eq('suppressed', false)
          .eq('risk_accepted', false),
        supabase.from('project_semgrep_findings').select('severity').eq('project_id', projectId),
        supabase
          .from('project_secret_findings')
          .select('id')
          .eq('project_id', projectId)
          .eq('is_current', true),
        supabase.from('project_dependencies').select('id, policy_result').eq('project_id', projectId),
      ]);

      const vulns = vulnRes.data || [];
      const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
      vulns.forEach((v: any) => {
        if (v.severity && bySeverity[v.severity] !== undefined) bySeverity[v.severity]++;
      });

      const semgrep = semgrepRes.data || [];
      const semgrepBySev = { ERROR: 0, WARNING: 0, INFO: 0 };
      semgrep.forEach((s: any) => {
        const k = (s.severity || 'INFO').toUpperCase();
        if (semgrepBySev[k] !== undefined) semgrepBySev[k]++;
        else semgrepBySev.INFO++;
      });

      const deps = depRes.data || [];
      const compliant = deps.filter((d: any) => d.policy_result?.allowed !== false).length;
      const complianceRate = deps.length > 0 ? Math.round((compliant / deps.length) * 100) : 100;

      const result = {
        vulnerabilities: { total: vulns.length, by_severity: bySeverity },
        semgrep_findings: { total: semgrep.length, by_severity: semgrepBySev },
        secret_exposures: (secretRes.data || []).length,
        compliance: { compliant, total: deps.length, rate_percent: complianceRate },
      };
      return JSON.stringify(result);
    },
  })
);

// 8. triggerExtraction
registerAegisTool(
  'triggerExtraction',
  moderateProjectOpsMeta,
  tool({
    description: 'Trigger a re-extraction for a project. Requires manage_teams_and_projects permission.',
    parameters: z.object({
      projectId: z.string().uuid(),
    }),
    execute: async ({ projectId }) => {
      const { data: project } = await supabase
        .from('projects')
        .select('organization_id')
        .eq('id', projectId)
        .single();
      if (!project) return JSON.stringify({ error: 'Project not found' });

      const { data: repo, error: repoError } = await supabase
        .from('project_repositories')
        .select('repo_full_name, installation_id, default_branch, package_json_path, ecosystem, provider, integration_id')
        .eq('project_id', projectId)
        .single();

      if (repoError || !repo) {
        return JSON.stringify({ error: repoError?.message ?? 'No repository connected to this project' });
      }

      const result = await queueExtractionJob(projectId, project.organization_id, {
        repo_full_name: repo.repo_full_name,
        installation_id: repo.installation_id,
        default_branch: repo.default_branch,
        package_json_path: repo.package_json_path ?? '',
        ecosystem: repo.ecosystem ?? 'npm',
        provider: repo.provider ?? 'github',
        integration_id: repo.integration_id ?? undefined,
      });

      if (!result.success) {
        return JSON.stringify({ error: result.error });
      }
      return JSON.stringify({ success: true, run_id: result.run_id, message: 'Extraction job queued successfully' });
    },
  })
);

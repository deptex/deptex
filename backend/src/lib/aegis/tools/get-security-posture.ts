import { dynamicTool, jsonSchema } from 'ai';
import { supabase } from '../../supabase';

export function getSecurityPostureTool(ctx: { organizationId: string }) {
  return dynamicTool({
    description:
      'Org-wide aggregate. Returns project count, vulnerability totals by severity (incl. reachable and KEV), average health score, and a count of projects in violation.',
    inputSchema: jsonSchema({ type: 'object', properties: {}, additionalProperties: false }),
    execute: async () => {
      const { data: projects, error } = await supabase
        .from('projects')
        .select('id, health_score, status_violations, status_id')
        .eq('organization_id', ctx.organizationId);
      if (error) return { error: error.message };
      if (!projects || projects.length === 0) return { projectCount: 0, vulnCounts: null };

      const projectIds = projects.map((p: any) => p.id);
      const { data: vulns } = await supabase
        .from('project_dependency_vulnerabilities')
        .select('severity, is_reachable, cisa_kev, depscore')
        .in('project_id', projectIds);

      const vulnCounts = { critical: 0, high: 0, medium: 0, low: 0 };
      let reachable = 0;
      let kev = 0;
      let critReachable = 0;
      let highestDepscore = 0;
      for (const v of vulns ?? []) {
        const sev = (v.severity ?? 'low').toLowerCase();
        if (sev in vulnCounts) (vulnCounts as any)[sev]++;
        if (v.is_reachable) reachable++;
        if (v.cisa_kev) kev++;
        if (v.is_reachable && sev === 'critical') critReachable++;
        if (typeof v.depscore === 'number' && v.depscore > highestDepscore) highestDepscore = v.depscore;
      }

      let healthSum = 0;
      let healthCount = 0;
      let projectsInViolation = 0;
      for (const p of projects) {
        if (typeof p.health_score === 'number') {
          healthSum += p.health_score;
          healthCount++;
        }
        if (Array.isArray(p.status_violations) && p.status_violations.length > 0) {
          projectsInViolation++;
        }
      }

      return {
        projectCount: projects.length,
        vulnCounts,
        reachableVulnCount: reachable,
        kevVulnCount: kev,
        criticalReachableCount: critReachable,
        highestDepscore,
        averageHealthScore: healthCount > 0 ? Math.round(healthSum / healthCount) : null,
        projectsInViolation,
      };
    },
  });
}

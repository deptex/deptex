import { dynamicTool, jsonSchema } from 'ai';
import { supabase } from '../../supabase';

export function getEpssScoreTool(ctx: { organizationId: string }) {
  return dynamicTool({
    description:
      'EPSS exploit probability score (0.0–1.0) for a CVE or OSV id. EPSS is cached per-project on each vulnerability row; this returns the highest observed score across the org.',
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
    execute: async (input) => {
      const { cveOrOsvId } = input as { cveOrOsvId: string };

      const { data: orgProjects } = await supabase
        .from('projects')
        .select('id')
        .eq('organization_id', ctx.organizationId);
      const projectIds = (orgProjects ?? []).map((p: any) => p.id);
      if (projectIds.length === 0) return { error: 'No projects in this organization' };

      let query = supabase
        .from('project_dependency_vulnerabilities')
        .select('osv_id, epss_score, aliases')
        .in('project_id', projectIds);

      if (cveOrOsvId.startsWith('CVE-')) query = query.contains('aliases', [cveOrOsvId]);
      else query = query.eq('osv_id', cveOrOsvId);

      const { data: rows, error } = await query.limit(20);
      if (error) return { error: error.message };
      if (!rows || rows.length === 0) {
        return { error: `No EPSS data found for ${cveOrOsvId} in this organization's vulnerability cache.` };
      }

      const best = rows.reduce((acc: any, r: any) => (
        (r.epss_score ?? -1) > (acc.epss_score ?? -1) ? r : acc
      ));

      return {
        queryId: cveOrOsvId,
        osvId: best.osv_id,
        epssScore: best.epss_score,
        epssPercentile: best.epss_score != null ? Math.round(best.epss_score * 100) : null,
      };
    },
  });
}

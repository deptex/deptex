import { dynamicTool, jsonSchema } from 'ai';
import { supabase } from '../../supabase';

export function checkCisaKevTool(ctx: { organizationId: string }) {
  return dynamicTool({
    description:
      'Check whether a CVE or OSV id is on the CISA Known Exploited Vulnerabilities (KEV) list. KEV status is cached on each vulnerability row in the org.',
    inputSchema: jsonSchema({
      type: 'object',
      properties: {
        cveOrOsvId: { type: 'string', minLength: 1 },
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
        .from('project_dependency_findings')
        .select('osv_id, cisa_kev, aliases')
        .in('project_id', projectIds);

      if (cveOrOsvId.startsWith('CVE-')) query = query.contains('aliases', [cveOrOsvId]);
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
  });
}

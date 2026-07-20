import { dynamicTool, jsonSchema } from 'ai';
import { supabase } from '../../supabase';

export function getReachabilityFlowsTool(ctx: { organizationId: string }) {
  return dynamicTool({
    description:
      'Return reachability flow paths (entry point → sink) for a vulnerability. Input is a project_dependency_findings.id. Each flow has an entry point file/method/line, a sink file/method/line, and a chain of nodes.',
    inputSchema: jsonSchema({
      type: 'object',
      properties: {
        vulnerabilityId: {
          type: 'string',
          format: 'uuid',
          description: 'project_dependency_findings.id (from get_project_vulnerabilities).',
        },
      },
      required: ['vulnerabilityId'],
      additionalProperties: false,
    }),
    execute: async (input) => {
      const { vulnerabilityId } = input as { vulnerabilityId: string };

      const { data: vuln } = await supabase
        .from('project_dependency_findings')
        .select('id, project_id, osv_id, reachability_level, reachability_details, project_dependency_id')
        .eq('id', vulnerabilityId)
        .single();
      if (!vuln) return { error: 'Vulnerability not found' };

      const { data: project } = await supabase
        .from('projects')
        .select('id, organization_id')
        .eq('id', vuln.project_id)
        .single();
      if (!project || project.organization_id !== ctx.organizationId) {
        return { error: 'Project not in current organization' };
      }

      const { data: pd } = await supabase
        .from('project_dependencies')
        .select('name, version')
        .eq('id', vuln.project_dependency_id)
        .single();

      const { data: flows } = await supabase
        .from('project_reachable_flows')
        .select(
          'id, purl, entry_point_file, entry_point_method, entry_point_line, sink_file, sink_method, sink_line, flow_length, flow_nodes',
        )
        .eq('project_id', vuln.project_id)
        .limit(10);

      const packageMatch = pd?.name
        ? (flows ?? []).filter((f: any) => f.purl && f.purl.includes(pd.name))
        : flows ?? [];

      return {
        vulnerabilityId: vuln.id,
        osvId: vuln.osv_id,
        reachabilityLevel: vuln.reachability_level,
        reachabilityDetails: vuln.reachability_details ?? null,
        dependency: pd ? { name: pd.name, version: pd.version } : null,
        flows: packageMatch.map((f: any) => ({
          id: f.id,
          purl: f.purl,
          entryPoint: {
            file: f.entry_point_file,
            method: f.entry_point_method,
            line: f.entry_point_line,
          },
          sink: { file: f.sink_file, method: f.sink_method, line: f.sink_line },
          flowLength: f.flow_length,
          flowNodes: f.flow_nodes,
        })),
        flowCount: packageMatch.length,
      };
    },
  });
}

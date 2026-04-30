import { dynamicTool, jsonSchema } from 'ai';
import { supabase } from '../../supabase';
import { calculateLatestSafeVersion } from '../../latest-safe-version';

export function analyzeUpgradePathTool(ctx: { organizationId: string }) {
  return dynamicTool({
    description:
      'Analyze the safest upgrade target for a project dependency. Given a project_dependency_id, returns the latest version that has no vulnerabilities (direct + transitive) above the chosen severity threshold.',
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
    execute: async (input) => {
      const { projectDependencyId, severity } = input as {
        projectDependencyId: string;
        severity?: 'critical' | 'high' | 'medium' | 'low';
      };

      const { data: pd } = await supabase
        .from('project_dependencies')
        .select('id, project_id, name, version')
        .eq('id', projectDependencyId)
        .single();
      if (!pd) return { error: 'Project dependency not found' };

      const { data: project } = await supabase
        .from('projects')
        .select('id, organization_id')
        .eq('id', pd.project_id)
        .single();
      if (!project || project.organization_id !== ctx.organizationId) {
        return { error: 'Project not in current organization' };
      }

      try {
        const result = await calculateLatestSafeVersion({
          organizationId: ctx.organizationId,
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
  });
}

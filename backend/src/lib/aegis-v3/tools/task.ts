import { jsonSchema } from 'ai';
import type { SupabaseClient } from '@supabase/supabase-js';
import type { AegisToolEntry, AegisToolContext } from '../tool-types';
import { getActiveExtractionId, NO_ACTIVE_RUN } from '../../active-extraction';
import { resolveProject } from './resolvers';
import { createProposedTask } from '../tasks';
import {
  AEGIS_TASK_FINDING_TYPES,
  AEGIS_TASK_MAX_TARGETS,
  type AegisTaskFindingType,
  type AegisTaskTarget,
} from '../task-types';

interface RawTarget {
  findingType: AegisTaskFindingType;
  findingHandle: string;
  projectName: string;
}

// Resolve a chat-supplied finding handle to the STABLE task target identity
// (finding_key + osv_id), the same handle shape request_fix accepts. Vulnerability
// handles are OSV ids; semgrep / secret handles are `file:line`.
async function resolveTaskTarget(
  t: RawTarget,
  ctx: AegisToolContext,
): Promise<{ target: AegisTaskTarget } | { error: string }> {
  const resolved = await resolveProject(t.projectName, ctx.orgId, ctx.supabase);
  if ('error' in resolved) return { error: resolved.error };
  const projectId = resolved.id;
  const activeRun =
    (await getActiveExtractionId(ctx.supabase as SupabaseClient, projectId)) ?? NO_ACTIVE_RUN;

  if (t.findingType === 'vulnerability') {
    const { data } = await ctx.supabase
      .from('project_dependency_vulnerabilities')
      .select('osv_id, finding_key, project_dependencies!inner(name, version)')
      .eq('project_id', projectId)
      .eq('osv_id', t.findingHandle)
      .eq('extraction_run_id', activeRun)
      .order('depscore', { ascending: false, nullsFirst: false })
      .limit(1)
      .maybeSingle();
    if (!data || !(data as any).finding_key) {
      return { error: `No vulnerability ${t.findingHandle} on '${t.projectName}' in the latest scan. Re-run list_project_issues.` };
    }
    const dep = (data as any).project_dependencies;
    const label = dep?.name ? `${t.findingHandle} in ${dep.name}@${dep.version ?? '?'}` : t.findingHandle;
    return {
      target: {
        findingType: 'vulnerability',
        findingKey: (data as any).finding_key,
        osvId: (data as any).osv_id ?? t.findingHandle,
        projectId,
        label,
      },
    };
  }

  // semgrep / secret: handle is `file:line`.
  const colon = t.findingHandle.lastIndexOf(':');
  const filePath = colon > 0 ? t.findingHandle.slice(0, colon) : '';
  const line = colon > 0 ? parseInt(t.findingHandle.slice(colon + 1), 10) : NaN;
  if (!filePath || !Number.isFinite(line)) {
    return { error: `Invalid finding handle '${t.findingHandle}'. Re-run list_project_issues to get a current handle.` };
  }
  const table = t.findingType === 'semgrep' ? 'project_semgrep_findings' : 'project_secret_findings';
  let query = ctx.supabase
    .from(table)
    .select('id, finding_key')
    .eq('project_id', projectId)
    .eq('file_path', filePath)
    .eq('start_line', line)
    .eq('extraction_run_id', activeRun)
    .eq('status', 'open');
  if (t.findingType === 'secret') query = query.eq('is_current', true);
  const { data: rows } = await query;
  if (!rows || rows.length === 0) {
    return { error: `No open ${t.findingType} finding at ${filePath}:${line}. Re-run list_project_issues.` };
  }
  if (rows.length > 1) {
    return { error: `Multiple ${t.findingType} findings at ${filePath}:${line}. Ask the user which one before retrying.` };
  }
  const row = rows[0] as { id: string; finding_key: string };
  return {
    target: {
      findingType: t.findingType,
      findingKey: row.finding_key,
      // Location handle — the per-finding identity for semgrep/secret (their
      // finding_key is per-rule, shared across occurrences).
      findingHandle: `${filePath}:${line}`,
      projectId,
      label: `${t.findingType} finding at ${filePath}:${line}`,
    },
  };
}

const createTask: AegisToolEntry<
  {
    description: string;
    targets: RawTarget[];
  },
  {
    taskId?: string;
    description?: string;
    targets?: Array<{ findingType: string; label: string }>;
    error?: string;
  }
> = {
  name: 'create_task',
  description:
    "Propose an Aegis Task to fix one or more security findings end-to-end (generate fixes -> open draft PRs). Use this when the user asks you to fix / remediate a set of findings as a unit of work, rather than walking a single plan. Always call `list_project_issues` first and pass each finding's `handle` exactly as `findingHandle` (OSV id for vulnerabilities, `file:line` for semgrep / secret) plus the `projectName`. Returns a Create-Task card the user accepts or declines; accepting authorizes the whole job (fixes auto-approve, draft PRs open — the merge is the human gate). v1 only fixes vulnerability / semgrep / secret findings. Does NOT open a PR by itself; nothing runs until the user accepts.",
  permission: 'trigger_fix',
  danger: 'medium',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      description: {
        type: 'string',
        minLength: 4,
        maxLength: 2000,
        description: "One-line summary of the goal, e.g. 'Fix the 3 reachable CVEs in api-server'.",
      },
      targets: {
        type: 'array',
        minItems: 1,
        maxItems: AEGIS_TASK_MAX_TARGETS,
        items: {
          type: 'object',
          properties: {
            findingType: { type: 'string', enum: [...AEGIS_TASK_FINDING_TYPES] },
            findingHandle: { type: 'string', minLength: 1, description: 'The `handle` from list_project_issues. Opaque — never paraphrase.' },
            projectName: { type: 'string', minLength: 1, description: 'Project name as the user said it.' },
          },
          required: ['findingType', 'findingHandle', 'projectName'],
          additionalProperties: false,
        },
      },
    },
    required: ['description', 'targets'],
    additionalProperties: false,
  }),
  execute: async ({ description, targets }, ctx) => {
    if (!Array.isArray(targets) || targets.length === 0) {
      return { error: 'A task needs at least one finding to fix.' };
    }
    if (targets.length > AEGIS_TASK_MAX_TARGETS) {
      return { error: `A task can target at most ${AEGIS_TASK_MAX_TARGETS} findings. Split the work.` };
    }

    const resolvedTargets: AegisTaskTarget[] = [];
    for (const t of targets) {
      const r = await resolveTaskTarget(t, ctx);
      if ('error' in r) return { error: r.error };
      resolvedTargets.push(r.target);
    }

    // A task's project_id is the single common project, else null (multi-project).
    const projectIds = new Set(resolvedTargets.map((t) => t.projectId));
    const projectId = projectIds.size === 1 ? resolvedTargets[0].projectId : null;

    const { taskId } = await createProposedTask({
      orgId: ctx.orgId,
      projectId,
      createdBy: ctx.userId,
      description,
      targets: resolvedTargets,
      source: 'chat',
    });

    return {
      taskId,
      description,
      targets: resolvedTargets.map((t) => ({ findingType: t.findingType, label: t.label })),
    };
  },
};

export const taskTools: AegisToolEntry[] = [createTask];

/**
 * Aegis Task runner — dev harness for slice 1 (narrate).
 *
 * Drives `runTaskAgent` directly against the configured Supabase (your local
 * dev backend points at prod), bypassing HTTP auth so you can watch a task
 * narrate without grabbing a JWT. Two modes:
 *
 *   Run an existing task row:
 *     npx tsx scripts/run-task.ts <taskId>
 *
 *   Create a task and run it in one shot:
 *     npx tsx scripts/run-task.ts --create --org <orgId> --project <projectId> --auto
 *       --auto         pick the top-depscore vulnerability in the project's active run
 *       --osv <id> --key <findingKey> [--label "..."]   target a specific vuln instead
 *       --title "..."  override the task title
 *       --user <id>    creator (defaults to any member of the org)
 *
 * After it prints the threadId, open /organizations/<org>/aegis/<threadId> and
 * watch the beats land live (the task thread realtime-subscribes).
 */
import 'dotenv/config';
import { supabase } from '../src/lib/supabase';
import { getActiveExtractionId } from '../src/lib/active-extraction';
import { runTaskAgent } from '../src/lib/aegis-v3/task-runner';
import { ensureTaskThread } from '../src/lib/aegis-v3/tasks';
import type { AegisTaskTarget, AegisTaskFindingType } from '../src/lib/aegis-v3/task-types';

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function pickTopVuln(projectId: string): Promise<AegisTaskTarget | null> {
  const run = await getActiveExtractionId(supabase, projectId);
  if (!run) return null;
  // Package name/version live on project_dependencies (joined via
  // project_dependency_id), not on the vuln row.
  const { data: v, error } = await supabase
    .from('project_dependency_vulnerabilities')
    .select('finding_key, osv_id, project_dependency_id')
    .eq('project_id', projectId)
    .eq('extraction_run_id', run)
    .order('depscore', { ascending: false, nullsFirst: false })
    .limit(1)
    .maybeSingle();
  if (error) {
    console.error('pickTopVuln query failed:', error.message);
    return null;
  }
  if (!v) return null;

  let label = ((v as any).osv_id as string) ?? ((v as any).finding_key as string);
  if ((v as any).project_dependency_id) {
    const { data: dep } = await supabase
      .from('project_dependencies')
      .select('name, version')
      .eq('id', (v as any).project_dependency_id)
      .maybeSingle();
    if (dep) label = `${(dep as any).name}@${(dep as any).version} — ${(v as any).osv_id}`;
  }
  return {
    findingType: 'vulnerability',
    findingKey: (v as any).finding_key,
    osvId: (v as any).osv_id ?? undefined,
    projectId,
    label,
  };
}

async function main() {
  const create = process.argv.includes('--create');
  let taskId =
    process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2] : undefined;

  if (create) {
    const org = arg('org');
    const project = arg('project');
    if (!org) throw new Error('--create requires --org <orgId>');

    // Prefer the org OWNER (the founder/admin who'd actually delegate) so the
    // task-chat belongs to them and they can see it — the task thread is
    // participant-gated to its creator. Fall back to any member.
    let createdBy = arg('user');
    if (!createdBy) {
      const { data: owner } = await supabase
        .from('organization_members')
        .select('user_id')
        .eq('organization_id', org)
        .eq('role', 'owner')
        .limit(1)
        .maybeSingle();
      createdBy = (owner as any)?.user_id;
    }
    if (!createdBy) {
      const { data: anyMember } = await supabase
        .from('organization_members')
        .select('user_id')
        .eq('organization_id', org)
        .limit(1)
        .maybeSingle();
      createdBy = (anyMember as any)?.user_id;
    }
    if (!createdBy) throw new Error('No member found for org — pass --user <userId>');

    const targets: AegisTaskTarget[] = [];
    if (process.argv.includes('--auto')) {
      if (!project) throw new Error('--auto requires --project <projectId>');
      const t = await pickTopVuln(project);
      if (!t) throw new Error('No vulnerability finding in the active run for that project');
      targets.push(t);
      console.log('Auto-picked target:', t.label);
    } else if (arg('osv') && arg('key')) {
      targets.push({
        findingType: 'vulnerability',
        findingKey: arg('key')!,
        osvId: arg('osv'),
        projectId: project!,
        label: arg('label') ?? arg('osv')!,
      });
    } else if (arg('type') && arg('key') && arg('handle')) {
      // A code finding: --type semgrep|secret --key <findingKey> --handle <file:line>
      const ft = arg('type') as AegisTaskFindingType;
      targets.push({
        findingType: ft,
        findingKey: arg('key')!,
        findingHandle: arg('handle'),
        projectId: project!,
        label: arg('label') ?? `${ft} at ${arg('handle')}`,
      });
    }

    const title =
      arg('title') ?? (targets[0]?.label ? `Fix ${targets[0].label}` : 'Aegis test task');
    const { data, error } = await supabase
      .from('aegis_agent_tasks')
      .insert({
        organization_id: org,
        project_id: project ?? null,
        created_by: createdBy,
        kind: 'fix',
        status: 'working',
        source: 'chat',
        title,
        description: arg('desc') ?? null,
        targets,
      })
      .select('id')
      .single();
    if (error || !data) throw new Error(error?.message ?? 'Task insert failed');
    taskId = (data as any).id as string;
    console.log('Created task', taskId, `(${targets.length} target${targets.length === 1 ? '' : 's'})`);
  }

  if (!taskId) {
    throw new Error(
      'Usage: tsx scripts/run-task.ts <taskId>   |   --create --org <id> [--project <id>] [--auto]',
    );
  }

  // Resolve org + ensure the thread BEFORE running, so you can open the URL and
  // watch the beats land live while the loop runs.
  const { data: trow } = await supabase
    .from('aegis_agent_tasks')
    .select('organization_id')
    .eq('id', taskId)
    .maybeSingle();
  const orgId = (trow as any)?.organization_id;
  const threadId = await ensureTaskThread(taskId);
  console.log(`\n▶ Open this NOW and watch it narrate live:\n  /organizations/${orgId}/aegis/${threadId}\n`);

  console.log('Running task', taskId, '…');
  const res = await runTaskAgent(taskId);
  console.log('Result:', res);
  process.exit(res.ok ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

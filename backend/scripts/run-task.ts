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
 *       --auto                pick the top finding in the project's active run
 *       --auto --type <type>  pick the top finding of a specific type. type is one of:
 *                             vulnerability | semgrep | secret | iac | container |
 *                             base_image | dataflow | dast
 *       --osv <id> --key <findingKey> [--label "..."]              target a specific vuln
 *       --type <type> --key <findingKey> --handle <file:line>      target a specific code finding
 *       --title "..."  override the task title
 *       --user <id>    creator (defaults to any member of the org)
 *
 * After it prints the threadId, open /organizations/<org>/aegis/<threadId> and
 * watch the beats land live (the task thread realtime-subscribes).
 */
import 'dotenv/config';
import { supabase } from '../src/lib/supabase';
import { getActiveExtractionId } from '../src/lib/active-extraction';
import { acceptTask } from '../src/lib/aegis-v3/tasks';
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
    .from('project_dependency_findings')
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

// Pick the top finding of any type in a project's active run, and shape it into
// the AegisTaskTarget that resolveTargetFindingId() expects for that type. Used
// by `--auto --type <type>` to dogfood every finding type without hand-copying
// finding keys.
async function pickTopFinding(
  projectId: string,
  type: AegisTaskFindingType,
): Promise<AegisTaskTarget | null> {
  if (type === 'vulnerability') return pickTopVuln(projectId);

  // DAST is dast_run-scoped, not extraction-run scoped → resolve by row id.
  if (type === 'dast') {
    const { data } = await supabase
      .from('project_dast_findings')
      .select('id, endpoint_url, http_method, vulnerability_type')
      .eq('project_id', projectId)
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();
    if (!data) return null;
    const d = data as any;
    return {
      findingType: 'dast',
      findingKey: d.id,
      findingHandle: d.id,
      projectId,
      label: `${d.vulnerability_type} at ${d.http_method} ${d.endpoint_url}`,
    };
  }

  const run = await getActiveExtractionId(supabase, projectId);
  if (!run) return null;

  if (type === 'base_image') {
    const { data } = await supabase
      .from('project_base_image_recommendations')
      .select('dockerfile_path, current_image, recommended_image, cve_delta')
      .eq('project_id', projectId)
      .eq('extraction_run_id', run)
      .not('recommended_image', 'is', null)
      .order('cve_delta', { ascending: false, nullsFirst: false })
      .limit(1)
      .maybeSingle();
    if (!data) return null;
    const d = data as any;
    return {
      findingType: 'base_image',
      findingKey: d.dockerfile_path,
      projectId,
      label: `${d.current_image} → ${d.recommended_image} (${d.dockerfile_path})`,
    };
  }

  if (type === 'container') {
    const { data } = await supabase
      .from('project_container_findings')
      .select('finding_key, cve_id, osv_id, os_package_name, image_reference, image_source')
      .eq('project_id', projectId)
      .eq('extraction_run_id', run)
      .eq('status', 'open')
      .eq('image_source', 'dockerfile_base')
      .order('depscore', { ascending: false, nullsFirst: false })
      .limit(1)
      .maybeSingle();
    if (!data) return null;
    const d = data as any;
    return {
      findingType: 'container',
      findingKey: d.finding_key,
      projectId,
      label: `${d.cve_id ?? d.osv_id} in ${d.os_package_name} (${d.image_reference})`,
    };
  }

  if (type === 'dataflow') {
    const { data } = await supabase
      .from('project_reachable_flows')
      .select('flow_signature_hash, osv_id, vuln_class, entry_point_file, sink_file, sink_line')
      .eq('project_id', projectId)
      .eq('extraction_run_id', run)
      .not('vuln_class', 'is', null)
      .not('sink_file', 'is', null)
      // A sink inside a test/spec file isn't a meaningful "fix" — prefer real source.
      .not('sink_file', 'ilike', '%test%')
      .not('sink_file', 'ilike', '%spec%')
      .order('flow_length', { ascending: false, nullsFirst: false })
      .limit(1)
      .maybeSingle();
    if (!data) return null;
    const d = data as any;
    return {
      findingType: 'dataflow',
      findingKey: d.flow_signature_hash,
      osvId: d.osv_id ?? undefined,
      projectId,
      label: `${d.vuln_class} → ${d.sink_file}:${d.sink_line}`,
    };
  }

  // semgrep / secret / iac: location-based (file:line).
  const table =
    type === 'semgrep'
      ? 'project_semgrep_findings'
      : type === 'iac'
        ? 'project_iac_findings'
        : 'project_secret_findings';
  const cols =
    type === 'secret'
      ? 'id, finding_key, file_path, start_line, detector_type'
      : 'id, finding_key, file_path, start_line, rule_id';
  let q = supabase
    .from(table)
    .select(cols)
    .eq('project_id', projectId)
    .eq('extraction_run_id', run)
    .eq('status', 'open')
    .order('depscore', { ascending: false, nullsFirst: false })
    .limit(1);
  if (type === 'secret') q = q.eq('is_current', true);
  const { data } = await q.maybeSingle();
  if (!data) return null;
  const d = data as any;
  const ruleOrDetector = type === 'secret' ? d.detector_type : d.rule_id;
  return {
    findingType: type,
    findingKey: d.finding_key,
    findingHandle: `${d.file_path}:${d.start_line}`,
    projectId,
    label: `${ruleOrDetector} at ${d.file_path}:${d.start_line}`,
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
      // --auto [--type <type>] picks the top finding of that type (default:
      // vulnerability) and shapes the right target for it.
      const autoType = (arg('type') as AegisTaskFindingType) ?? 'vulnerability';
      const t = await pickTopFinding(project, autoType);
      if (!t) throw new Error(`No ${autoType} finding available for that project`);
      targets.push(t);
      console.log('Auto-picked target:', t.findingType, '—', t.label);
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
        // 'proposed' so acceptTask fans out the agent fix rows (it no-ops on
        // any other status).
        status: 'proposed',
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

  // Resolve org + accepting user, then accept: this fans out one AGENT fix row
  // per target (strategy='agent', already 'approved') and boots a fix-worker
  // machine that claims + runs the autonomous agent loop. Open the printed URL
  // to watch the agent narrate its real tool calls live.
  const { data: trow } = await supabase
    .from('aegis_agent_tasks')
    .select('organization_id, created_by')
    .eq('id', taskId)
    .maybeSingle();
  const orgId = (trow as any)?.organization_id;
  let acceptUserId = (trow as any)?.created_by as string | undefined;
  if (!acceptUserId) {
    const { data: member } = await supabase
      .from('organization_members')
      .select('user_id')
      .eq('organization_id', orgId)
      .limit(1)
      .maybeSingle();
    acceptUserId = (member as any)?.user_id;
  }
  if (!acceptUserId) throw new Error('Could not resolve an accepting user for the task');

  const { threadId } = await acceptTask({ taskId, userId: acceptUserId, organizationId: orgId });
  console.log(`\n▶ Open this NOW and watch the agent narrate live:\n  /organizations/${orgId}/aegis/${threadId}\n`);
  console.log(
    'Accepted — the fix-worker will claim the queued agent fix(es) and run the autonomous loop.\n' +
      '(Run the fix-worker locally, or let the Fly machine boot, to process them.)',
  );
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

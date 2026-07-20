/**
 * Aegis Task follow-up sender — dev harness for the wake path.
 *
 * Companion to run-task.ts: drives `sendTaskFollowup` directly against the
 * configured Supabase (bypassing HTTP auth), exactly what the
 * POST /api/aegis/tasks/:taskId/message route does. Persists the message to the
 * task thread, then wakes the task's agent fix row (terminal → 'approved',
 * run_seq++, machine boot) or reports it queued if a run is active.
 *
 *   npx tsx scripts/send-task-followup.ts <taskId> --message "Also update the README"
 *     --user <id>   sender (defaults to the task's creator, then any org member)
 */
import 'dotenv/config';
import { supabase } from '../src/lib/supabase';
import { sendTaskFollowup } from '../src/lib/aegis-v3/tasks';

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function main() {
  const taskId = process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2] : undefined;
  const message = arg('message');
  if (!taskId || !message) {
    throw new Error('Usage: tsx scripts/send-task-followup.ts <taskId> --message "..." [--user <id>]');
  }

  const { data: trow } = await supabase
    .from('aegis_agent_tasks')
    .select('organization_id, created_by')
    .eq('id', taskId)
    .maybeSingle();
  if (!trow) throw new Error('Task not found');
  const organizationId = (trow as any).organization_id as string;

  let userId = arg('user') ?? ((trow as any).created_by as string | undefined);
  if (!userId) {
    const { data: member } = await supabase
      .from('organization_members')
      .select('user_id')
      .eq('organization_id', organizationId)
      .limit(1)
      .maybeSingle();
    userId = (member as any)?.user_id;
  }
  if (!userId) throw new Error('Could not resolve a sending user — pass --user <userId>');

  const result = await sendTaskFollowup({ taskId, userId, organizationId, message });
  console.log(result);
  if (result.woke) {
    console.log('\n▶ Woke the task agent — a fix-worker machine is booting to resume it.');
  } else if (result.queued) {
    console.log('\n▶ A run is active — the message is queued; the worker drains it when the run ends.');
  }
  console.log(`Watch: /organizations/${organizationId}/aegis/${result.threadId}`);
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

/**
 * Aegis Task cancel — dev harness for the Stop path.
 *
 * Drives `cancelTask` directly against the configured Supabase (bypassing HTTP
 * auth), exactly what the POST /api/aegis/tasks/:taskId/cancel route does:
 * rejects the task's in-flight agent fix rows (so the worker aborts) and lands
 * the task on 'cancelled' (a neutral stop, not an error).
 *
 *   npx tsx scripts/cancel-task.ts <taskId> [--user <id>]
 */
import 'dotenv/config';
import { supabase } from '../src/lib/supabase';
import { cancelTask } from '../src/lib/aegis-v3/tasks';

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function main() {
  const taskId = process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2] : undefined;
  if (!taskId) throw new Error('Usage: tsx scripts/cancel-task.ts <taskId> [--user <id>]');

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
  if (!userId) throw new Error('Could not resolve a user — pass --user <userId>');

  const result = await cancelTask({ taskId, userId, organizationId });
  console.log(result);
  console.log(`\n▶ Stopped ${result.cancelled} in-flight fix row(s); the worker aborts silently.`);
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

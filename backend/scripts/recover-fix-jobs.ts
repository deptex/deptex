/**
 * Aegis fix-recovery — dev harness for the machine-crash path.
 *
 * Mirrors POST /api/internal/recovery/fix-jobs' terminal path: requeue stuck
 * jobs, fail exhausted ones, and post the honest "Something went wrong" beat to
 * each crashed agent task's chat. Drives the real RPCs + postCrashFailureToChat.
 *
 *   npx tsx scripts/recover-fix-jobs.ts
 */
import 'dotenv/config';
import { supabase } from '../src/lib/supabase';
import { postCrashFailureToChat } from '../src/routes/fix-recovery';

async function main() {
  const { data: requeued } = await supabase.rpc('recover_stuck_fix_jobs');
  const { data: failed } = await supabase.rpc('fail_exhausted_fix_jobs');
  const rq = Array.isArray(requeued) ? requeued : [];
  const fl = Array.isArray(failed) ? failed : [];
  console.log(`requeued ${rq.length}, failed ${fl.length}`);

  for (const job of fl as Array<{ id: string; thread_id?: string; strategy?: string }>) {
    if (job.strategy === 'agent' && job.thread_id) {
      await postCrashFailureToChat(supabase as any, { id: job.id, thread_id: job.thread_id });
      console.log(`posted crash beat for fix ${job.id}`);
    }
  }
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

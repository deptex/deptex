import { supabase } from '../../src/lib/supabase';

/**
 * Tear down everything the harness wrote for a single thread. Order matters
 * because `aegis_chat_threads.context_id` is the only thing pointing at fix
 * rows, but `project_security_fixes.thread_id` points at the thread — we wipe
 * children first, then the thread row itself. Each delete is best-effort: a
 * failure prints a warning but doesn't crash the run, so a flaky cleanup
 * doesn't poison the next case.
 */
export async function cleanupThread(threadId: string): Promise<void> {
  const tables: Array<{ name: string; col: string }> = [
    { name: 'aegis_tool_executions', col: 'thread_id' },
    { name: 'aegis_chat_messages', col: 'thread_id' },
    { name: 'aegis_chat_participants', col: 'thread_id' },
    { name: 'aegis_chat_user_state', col: 'thread_id' },
    { name: 'project_security_fixes', col: 'thread_id' },
    { name: 'aegis_chat_threads', col: 'id' },
  ];
  for (const { name, col } of tables) {
    const { error } = await supabase.from(name).delete().eq(col, threadId);
    if (error && !error.message?.includes('does not exist')) {
      console.warn(`  cleanup warn: ${name}.${col}=${threadId} → ${error.message}`);
    }
  }
}

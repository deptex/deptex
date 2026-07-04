// Replay reconstruction for a resumed task agent: the thread's chat rows fold
// back into compact user/assistant turns, the (never-persisted) finding brief
// is seeded as the first user turn, and the char budget trims from the head
// while keeping the brief + the tail + a "PR exists" breadcrumb.

import { reconstructAgentMessages } from '../agent/replay';

/**
 * The stub takes rows in CHRONOLOGICAL order and serves them the way PostgREST
 * would answer the real query — newest-first, capped by .limit(n) — while
 * recording the order/limit args so the fetch shape itself is assertable.
 */
function stubThread(rows: any[], error: any = null) {
  const calls: { orderArgs?: any[]; limitArg?: number } = {};
  const supabase = {
    _calls: calls,
    from: () => ({
      select: () => ({
        eq: () => ({
          order: (...orderArgs: any[]) => {
            calls.orderArgs = orderArgs;
            return {
              limit: async (n: number) => {
                calls.limitArg = n;
                return { data: rows.slice().reverse().slice(0, n), error };
              },
            };
          },
        }),
      }),
    }),
  } as any;
  return supabase;
}

const at = (i: number) => `2026-07-03T00:00:${String(i).padStart(2, '0')}Z`;

describe('reconstructAgentMessages', () => {
  test('maps user turns, assistant text, step rows, and cards; brief first; watermark = last row', async () => {
    const rows = [
      { role: 'user', content: 'fix this CVE', metadata: { parts: [{ type: 'text', text: 'fix this CVE' }] }, created_at: at(1) },
      { role: 'assistant', content: 'Looking at the manifest', metadata: { parts: [{ type: 'text', text: 'Looking at the manifest' }] }, created_at: at(2) },
      { role: 'assistant', content: 'Read package.json', metadata: { parts: [{ type: 'step', icon: 'read', label: 'Read package.json' }] }, created_at: at(3) },
      { role: 'assistant', content: 'Regenerate the lockfile', metadata: { parts: [{ type: 'step', icon: 'verify', label: 'Regenerate the lockfile', command: 'npm install', output: 'lots of output' }] }, created_at: at(4) },
      { role: 'assistant', content: 'PR is up', metadata: { parts: [{ type: 'tool-result', toolCallId: 'f1', toolName: 'apply_fix', result: {} }] }, created_at: at(5) },
      { role: 'assistant', content: 'raw beat with no parts', metadata: null, created_at: at(6) },
      { role: 'user', content: 'now bump to 4.2 instead', metadata: { parts: [{ type: 'text', text: 'now bump to 4.2 instead' }] }, created_at: at(7) },
    ];
    const { messages, replayedThrough } = await reconstructAgentMessages(stubThread(rows), 'thread-1', {
      brief: 'THE BRIEF',
    });
    expect(messages).toEqual([
      { role: 'user', content: 'THE BRIEF' },
      { role: 'user', content: 'fix this CVE' },
      { role: 'assistant', content: 'Looking at the manifest' },
      { role: 'assistant', content: '[read] Read package.json' },
      // Step rows fold to one line: icon + label + command; output/diff omitted.
      { role: 'assistant', content: '[verify] Regenerate the lockfile — $ npm install' },
      { role: 'assistant', content: '[showed the pull request change card to the user]' },
      { role: 'assistant', content: 'raw beat with no parts' },
      { role: 'user', content: 'now bump to 4.2 instead' },
    ]);
    expect(replayedThrough).toBe(at(7));
  });

  test('appends a continue-user turn when the thread ends on an assistant row', async () => {
    const rows = [
      { role: 'user', content: 'do the thing', metadata: null, created_at: at(1) },
      { role: 'assistant', content: 'done, here is why', metadata: { parts: [{ type: 'text', text: 'done, here is why' }] }, created_at: at(2) },
    ];
    const { messages } = await reconstructAgentMessages(stubThread(rows), 'thread-1', { brief: 'B' });
    expect(messages[messages.length - 1]).toEqual({
      role: 'user',
      content: '(Continue with my latest request above.)',
    });
  });

  test('over-budget trim keeps the brief + tail, inserts the omission marker, and re-injects the PR line', async () => {
    const rows = [
      { role: 'assistant', content: 'x', metadata: { parts: [{ type: 'text', text: 'I opened pull request #7 for you' }] }, created_at: at(1) },
      { role: 'assistant', content: 'x', metadata: { parts: [{ type: 'text', text: 'y'.repeat(300) }] }, created_at: at(2) },
      { role: 'user', content: 'please bump to 4.2', metadata: null, created_at: at(3) },
    ];
    const brief = 'B'.repeat(50);
    const { messages } = await reconstructAgentMessages(stubThread(rows), 'thread-1', {
      brief,
      charBudget: 120,
    });
    expect(messages).toEqual([
      { role: 'user', content: brief },
      { role: 'assistant', content: '[… earlier work omitted …]' },
      { role: 'assistant', content: '[earlier: opened pull request #7]' },
      { role: 'user', content: 'please bump to 4.2' },
    ]);
  });

  test('over-budget trim without a PR mention injects only the marker', async () => {
    const rows = [
      { role: 'assistant', content: 'x', metadata: { parts: [{ type: 'text', text: 'z'.repeat(300) }] }, created_at: at(1) },
      { role: 'user', content: 'try again', metadata: null, created_at: at(2) },
    ];
    const { messages } = await reconstructAgentMessages(stubThread(rows), 'thread-1', {
      brief: 'B',
      charBudget: 40,
    });
    expect(messages).toEqual([
      { role: 'user', content: 'B' },
      { role: 'assistant', content: '[… earlier work omitted …]' },
      { role: 'user', content: 'try again' },
    ]);
  });

  test('an empty thread yields just the brief with a null watermark', async () => {
    const { messages, replayedThrough } = await reconstructAgentMessages(stubThread([]), 'thread-1', {
      brief: 'B',
    });
    expect(messages).toEqual([{ role: 'user', content: 'B' }]);
    expect(replayedThrough).toBeNull();
  });

  test('a fetch error THROWS (the loop resolves it as system_error)', async () => {
    await expect(
      reconstructAgentMessages(stubThread([], { message: 'db down' }), 'thread-1', { brief: 'B' }),
    ).rejects.toThrow(/replay fetch failed/);
  });

  test('fetches NEWEST-first with an explicit cap and reverses back to chronological order', async () => {
    // An unbounded ascending select would be truncated by PostgREST's row cap
    // keeping the OLDEST rows — a stale replayedThrough would make the drain
    // re-wake (and re-bill) forever. The fetch must be desc + limit + reverse.
    const rows = [
      { role: 'user', content: 'first', metadata: null, created_at: at(1) },
      { role: 'assistant', content: 'middle', metadata: null, created_at: at(2) },
      { role: 'user', content: 'latest', metadata: null, created_at: at(3) },
    ];
    const supabase = stubThread(rows);
    const { messages, replayedThrough } = await reconstructAgentMessages(supabase, 'thread-1', { brief: 'B' });
    expect(supabase._calls.orderArgs).toEqual(['created_at', { ascending: false }]);
    expect(supabase._calls.limitArg).toBe(1000);
    // Chronological order restored; the watermark is the NEWEST row.
    expect(messages).toEqual([
      { role: 'user', content: 'B' },
      { role: 'user', content: 'first' },
      { role: 'assistant', content: 'middle' },
      { role: 'user', content: 'latest' },
    ]);
    expect(replayedThrough).toBe(at(3));
  });

  test('a failure card replays as a failure card, not a PR card', async () => {
    const rows = [
      {
        role: 'assistant',
        content: 'failed',
        metadata: { parts: [{ type: 'tool-result', toolCallId: 'f1', toolName: 'apply_fix', result: { fixId: 'f1', failed: true } }] },
        created_at: at(1),
      },
      { role: 'user', content: 'why did it fail?', metadata: null, created_at: at(2) },
    ];
    const { messages } = await reconstructAgentMessages(stubThread(rows), 'thread-1', { brief: 'B' });
    expect(messages).toEqual([
      { role: 'user', content: 'B' },
      { role: 'assistant', content: '[showed the failure card to the user]' },
      { role: 'user', content: 'why did it fail?' },
    ]);
  });
});

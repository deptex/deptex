// The end-of-run drain (a user message that arrived DURING a run re-queues the
// fix row so the next run replays it; anything ambiguous returns false and the
// body never throws) + the zombie-run fences: isJobCancelled aborts on a
// machine_id mismatch, and the terminal writers scope their UPDATE to this
// machine so a stale run can't clobber a woken/reclaimed row.

import { maybeRequeueFollowup, isJobCancelled, markFailed, markAnswered, markCompleted } from '../job-db';

function stubSupabase(opts: {
  agentRowCount?: number;
  agentRowStatuses?: string[];
  hasNewerMessage?: boolean;
}) {
  const rpc = jest.fn(async () => ({ data: 'fix-1', error: null }));
  const supabase: any = {
    rpc,
    from: (table: string) => {
      const rows =
        table === 'project_security_fixes'
          ? Array.from({ length: opts.agentRowCount ?? 1 }, (_, i) => ({
              id: `f${i}`,
              // Default to an ACTIVE run so a multi-row task skips (a sibling is
              // still working); tests that want the all-terminal case pass
              // explicit statuses.
              status: opts.agentRowStatuses?.[i] ?? 'executing',
            }))
          : opts.hasNewerMessage
            ? [{ id: 'm1' }]
            : [];
      const builder: any = {
        select: () => builder,
        eq: () => builder,
        gt: () => builder,
        limit: async (n: number) => ({ data: rows.slice(0, n), error: null }),
      };
      return builder;
    },
  };
  return { supabase, rpc };
}

describe('maybeRequeueFollowup', () => {
  test('wakes (rpc called) when a newer user message exists', async () => {
    const { supabase, rpc } = stubSupabase({ agentRowCount: 1, hasNewerMessage: true });
    const woke = await maybeRequeueFollowup(supabase, 'fix-1', 'thread-1', 'task-1', '2026-07-03T00:00:00Z');
    expect(woke).toBe(true);
    expect(rpc).toHaveBeenCalledWith('wake_agent_fix', { p_fix_id: 'fix-1' });
  });

  test('returns false without waking when no newer message exists', async () => {
    const { supabase, rpc } = stubSupabase({ agentRowCount: 1, hasNewerMessage: false });
    const woke = await maybeRequeueFollowup(supabase, 'fix-1', 'thread-1', 'task-1', '2026-07-03T00:00:00Z');
    expect(woke).toBe(false);
    expect(rpc).not.toHaveBeenCalled();
  });

  test('multi-target: skips while a sibling is still active (avoids N wakes for one message)', async () => {
    const { supabase, rpc } = stubSupabase({
      agentRowCount: 2,
      agentRowStatuses: ['completed', 'executing'], // one sibling still running
      hasNewerMessage: true,
    });
    const woke = await maybeRequeueFollowup(supabase, 'fix-1', 'thread-1', 'task-1', '2026-07-03T00:00:00Z');
    expect(woke).toBe(false);
    expect(rpc).not.toHaveBeenCalled();
  });

  test('multi-target: the LAST sibling to finish (all terminal) delivers the queued message', async () => {
    const { supabase, rpc } = stubSupabase({
      agentRowCount: 2,
      agentRowStatuses: ['completed', 'failed'], // all terminal now
      hasNewerMessage: true,
    });
    const woke = await maybeRequeueFollowup(supabase, 'fix-1', 'thread-1', 'task-1', '2026-07-03T00:00:00Z');
    expect(woke).toBe(true);
    expect(rpc).toHaveBeenCalledWith('wake_agent_fix', { p_fix_id: 'fix-1' });
  });

  test('a task-less fix with a newer message still wakes (no multi-row guard needed)', async () => {
    const { supabase, rpc } = stubSupabase({ hasNewerMessage: true });
    const woke = await maybeRequeueFollowup(supabase, 'fix-1', 'thread-1', null, '2026-07-03T00:00:00Z');
    expect(woke).toBe(true);
    expect(rpc).toHaveBeenCalledTimes(1);
  });

  test('returns false when the watermark is null', async () => {
    const { supabase, rpc } = stubSupabase({ agentRowCount: 1, hasNewerMessage: true });
    const woke = await maybeRequeueFollowup(supabase, 'fix-1', 'thread-1', 'task-1', null);
    expect(woke).toBe(false);
    expect(rpc).not.toHaveBeenCalled();
  });

  test('returns false when there is no thread', async () => {
    const { supabase, rpc } = stubSupabase({ agentRowCount: 1, hasNewerMessage: true });
    const woke = await maybeRequeueFollowup(supabase, 'fix-1', null, 'task-1', '2026-07-03T00:00:00Z');
    expect(woke).toBe(false);
    expect(rpc).not.toHaveBeenCalled();
  });

  test('never throws — a failing query resolves to false', async () => {
    const supabase: any = {
      rpc: jest.fn(),
      from: () => {
        throw new Error('db down');
      },
    };
    await expect(
      maybeRequeueFollowup(supabase, 'fix-1', 'thread-1', 'task-1', '2026-07-03T00:00:00Z'),
    ).resolves.toBe(false);
  });
});

function stubStatusRow(row: { status: string; machine_id: string | null } | null) {
  return {
    from: () => ({
      select: () => ({
        eq: () => ({ maybeSingle: async () => ({ data: row }) }),
      }),
    }),
  } as any;
}

describe('isJobCancelled — zombie-run fence', () => {
  test('true on a user Stop (status=rejected), with or without a machine id', async () => {
    expect(await isJobCancelled(stubStatusRow({ status: 'rejected', machine_id: 'me' }), 'f')).toBe(true);
    expect(await isJobCancelled(stubStatusRow({ status: 'rejected', machine_id: 'me' }), 'f', 'me')).toBe(true);
  });

  test('true on a machine mismatch — the row was re-woken and reassigned', async () => {
    expect(await isJobCancelled(stubStatusRow({ status: 'executing', machine_id: 'other' }), 'f', 'me')).toBe(true);
    // A wake resets machine_id to NULL before the next claim — also a mismatch.
    expect(await isJobCancelled(stubStatusRow({ status: 'approved', machine_id: null }), 'f', 'me')).toBe(true);
  });

  test('false while this machine still holds the lease', async () => {
    expect(await isJobCancelled(stubStatusRow({ status: 'executing', machine_id: 'me' }), 'f', 'me')).toBe(false);
  });

  test('without a machine id only status=rejected cancels (legacy call sites unchanged)', async () => {
    expect(await isJobCancelled(stubStatusRow({ status: 'executing', machine_id: 'other' }), 'f')).toBe(false);
  });

  test('a missing row is not treated as cancelled', async () => {
    expect(await isJobCancelled(stubStatusRow(null), 'f', 'me')).toBe(false);
  });
});

/** Thenable update builder that records every .eq() filter. */
function stubUpdate() {
  const eqCalls: Array<[string, unknown]> = [];
  const updates: Array<Record<string, unknown>> = [];
  const builder: any = {
    update: (patch: Record<string, unknown>) => {
      updates.push(patch);
      return builder;
    },
    eq: (col: string, val: unknown) => {
      eqCalls.push([col, val]);
      return builder;
    },
    then: (resolve: any, reject: any) => Promise.resolve({ data: null, error: null }).then(resolve, reject),
  };
  const supabase: any = { from: () => builder };
  return { supabase, eqCalls, updates };
}

describe('terminal writers — machine-id fence', () => {
  test('markFailed with a machine id scopes the update to id AND machine_id', async () => {
    const { supabase, eqCalls } = stubUpdate();
    await markFailed(supabase, 'fix-1', 'boom', 'system_error', null, 'me');
    expect(eqCalls).toEqual([
      ['id', 'fix-1'],
      ['machine_id', 'me'],
    ]);
  });

  test('markFailed without a machine id keeps the legacy id-only update', async () => {
    const { supabase, eqCalls } = stubUpdate();
    await markFailed(supabase, 'fix-1', 'boom');
    expect(eqCalls).toEqual([['id', 'fix-1']]);
  });

  test('markAnswered is machine-fenced and touches ONLY status/completed_at', async () => {
    const { supabase, eqCalls, updates } = stubUpdate();
    await markAnswered(supabase, 'fix-1', 'me');
    expect(eqCalls).toEqual([
      ['id', 'fix-1'],
      ['machine_id', 'me'],
    ]);
    expect(Object.keys(updates[0]).sort()).toEqual(['completed_at', 'status']);
    expect(updates[0].status).toBe('completed');
  });

  test('markCompleted is machine-fenced when a machine id is provided', async () => {
    const { supabase, eqCalls } = stubUpdate();
    await markCompleted(
      supabase,
      'fix-1',
      { prUrl: 'u', prNumber: 1, prBranch: 'b', prRepoFullName: 'o/r', diffSummary: 'd' },
      'me',
    );
    expect(eqCalls).toEqual([
      ['id', 'fix-1'],
      ['machine_id', 'me'],
    ]);
  });
});

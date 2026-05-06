/**
 * Verifies that `insertFindingsBatch` passes optional reachability fields
 * through to the RPC payload unchanged. Without this round-trip, M1a.3's
 * reachability assignment would silently drop at the TS-to-JSONB boundary.
 */
import { insertFindingsBatch, type PendingFinding } from '../malicious/insert-finding';

describe('insertFindingsBatch — JSONB payload round-trip', () => {
  it('passes reachability_level + reachability_details through to the RPC', async () => {
    const captured: { fnName: string | null; payload: unknown } = { fnName: null, payload: null };

    const fakeStorage = {
      rpc: async (fn: string, args: { p_findings: unknown }) => {
        captured.fnName = fn;
        captured.payload = args.p_findings;
        return { data: 1, error: null };
      },
    } as unknown as Parameters<typeof insertFindingsBatch>[0];

    const finding: PendingFinding = {
      project_id: 'p-1',
      organization_id: 'o-1',
      extraction_run_id: 'run-1',
      project_dependency_id: 'pd-1',
      dependency_id: 'd-1',
      rule_id: 'feed:GHSA-xxxx',
      scanner: 'feed',
      severity: 'critical',
      message: 'malware',
      depscore: null,
      reachability_level: 'function',
      reachability_details: {
        entry_points: ['handleRequest'],
        call_chain: ['src/handler.js:22 (handleRequest)'],
        sink_file: 'src/handler.js',
        sink_line: 22,
      },
    };

    const result = await insertFindingsBatch(fakeStorage, [finding]);
    expect(result).toEqual({ inserted: 1, rpcError: null });
    expect(captured.fnName).toBe('insert_malicious_findings_with_recompute');
    const arr = captured.payload as PendingFinding[];
    expect(arr).toHaveLength(1);
    expect(arr[0].reachability_level).toBe('function');
    expect(arr[0].reachability_details).toMatchObject({
      sink_file: 'src/handler.js',
      sink_line: 22,
      entry_points: ['handleRequest'],
    });
  });

  it('accepts scanner="maintainer" without TypeScript narrowing complaints', async () => {
    const fakeStorage = {
      rpc: async (_fn: string, _args: unknown) => ({ data: 0, error: null }),
    } as unknown as Parameters<typeof insertFindingsBatch>[0];

    const finding: PendingFinding = {
      project_id: 'p-1',
      organization_id: 'o-1',
      extraction_run_id: 'maintainer-cron:2026-05-05',
      project_dependency_id: 'pd-1',
      dependency_id: 'd-1',
      rule_id: 'maintainer:email_changed',
      scanner: 'maintainer',
      severity: 'high',
      message: 'maintainer email changed in last 30d',
      depscore: null,
    };

    const result = await insertFindingsBatch(fakeStorage, [finding]);
    expect(result).toEqual({ inserted: 0, rpcError: null });
  });

  it('returns inserted=0 with no RPC call when the array is empty', async () => {
    let called = false;
    const fakeStorage = {
      rpc: async () => {
        called = true;
        return { data: 0, error: null };
      },
    } as unknown as Parameters<typeof insertFindingsBatch>[0];

    const result = await insertFindingsBatch(fakeStorage, []);
    expect(result).toEqual({ inserted: 0, rpcError: null });
    expect(called).toBe(false);
  });

  it('surfaces the RPC error on the return value', async () => {
    const fakeStorage = {
      rpc: async () => ({ data: null, error: { message: 'boom' } }),
    } as unknown as Parameters<typeof insertFindingsBatch>[0];

    const finding: PendingFinding = {
      project_id: 'p-1',
      organization_id: 'o-1',
      extraction_run_id: 'run-1',
      project_dependency_id: 'pd-1',
      dependency_id: 'd-1',
      rule_id: 'feed:GHSA-xxxx',
      scanner: 'feed',
      severity: 'critical',
      message: 'malware',
      depscore: null,
    };

    const result = await insertFindingsBatch(fakeStorage, [finding]);
    expect(result).toEqual({ inserted: 0, rpcError: 'boom' });
  });
});

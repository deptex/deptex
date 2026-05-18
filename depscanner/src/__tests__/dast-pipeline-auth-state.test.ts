// Phase 24a (v2.1a): pipeline auth_state state machine end-to-end.
//
// Drives runDastPipeline through the full happy path with a fake spawn that
// drops a deterministic zap-report.json next to the YAML path the pipeline
// passes in. Covers:
//   - anonymous (no cred) → all findings auth_state='anonymous'
//   - cred + 0 logged_out hits → all findings auth_state='authenticated'
//   - cred + ≥4 AUTH_LOST stderr lines → all findings 'authentication_lost'
//     AND scan_jobs.error_category='auth_failed' AND NO synthetic finding row
//
// We intentionally do NOT exercise OS-level group-kill or real-Docker ZAP
// here — those land in Task 10's real-Docker e2e against Juice Shop. This
// file proves the auth_state values get attached to the rows we INSERT and
// that auth-lost is recorded as JOB STATE rather than a synthetic finding,
// which is the structural correctness gate the plan §"auth_state state
// machine" calls out.

import { EventEmitter } from 'events';
import { Readable } from 'stream';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';

import { runDastPipeline } from '../dast/pipeline';
import type { ExtractionJobRow } from '../job-db';

// Depscanner only ships decryptCredential (encryption lives in the API
// package). Mirror the encrypt format here so the pipeline's decrypt can
// round-trip our test plaintext.
function encryptForTest(plaintext: string): { encrypted: string } {
  const ALGORITHM = 'aes-256-gcm';
  const key = Buffer.from(process.env.DAST_CREDENTIAL_KEY ?? '', 'hex');
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, key, nonce, { authTagLength: 16 });
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    encrypted: `${nonce.toString('base64')}:${ciphertext.toString('base64')}:${authTag.toString('base64')}`,
  };
}

// ---------------------------------------------------------------------------
// supabase mock — extends the dast-pipeline-v2 shape with insert capture so
// we can assert what was written to project_dast_findings.
// ---------------------------------------------------------------------------

type SupabaseResp = { data: unknown; error: unknown };

interface RecordedInsert {
  table: string;
  rows: unknown[];
}

interface MockSupabase {
  pushTableResponse: (table: string, resp: SupabaseResp) => void;
  setTableResponse: (table: string, resp: SupabaseResp) => void;
  setRpcResponse: (resp: SupabaseResp) => void;
  recordedUpdates: Array<{ table: string; values: Record<string, unknown> }>;
  recordedInserts: RecordedInsert[];
  recordedRpcs: Array<{ name: string; args: Record<string, unknown> }>;
  client: {
    from: (table: string) => unknown;
    rpc: (name: string, args: Record<string, unknown>) => unknown;
    storage: { from: (b: string) => unknown };
  };
}

function makeMockSupabase(): MockSupabase {
  const tableQueues = new Map<string, SupabaseResp[]>();
  const tableDefaults = new Map<string, SupabaseResp>();
  let rpcDefault: SupabaseResp = { data: null, error: null };
  const recordedUpdates: MockSupabase['recordedUpdates'] = [];
  const recordedInserts: RecordedInsert[] = [];
  const recordedRpcs: MockSupabase['recordedRpcs'] = [];

  function nextForTable(table: string): SupabaseResp {
    const q = tableQueues.get(table);
    if (q && q.length) return q.shift()!;
    return tableDefaults.get(table) ?? { data: null, error: null };
  }

  function makeChain(table: string) {
    const chain: any = {
      select: () => chain,
      eq: () => chain,
      in: () => chain,
      limit: () => chain,
      insert: (rows: unknown) => {
        recordedInserts.push({ table, rows: Array.isArray(rows) ? rows : [rows] });
        // insert without RETURNING resolves directly to { data: null, error: null }.
        return Promise.resolve({ data: null, error: null });
      },
      update: (values: Record<string, unknown>) => {
        recordedUpdates.push({ table, values });
        return chain;
      },
      upsert: () => chain,
      delete: () => chain,
      single: () => Promise.resolve(nextForTable(table)),
      maybeSingle: () => Promise.resolve(nextForTable(table)),
      then: (resolve: (v: unknown) => void) => {
        resolve(nextForTable(table));
        return Promise.resolve(nextForTable(table));
      },
    };
    return chain;
  }

  return {
    pushTableResponse(table, resp) {
      const q = tableQueues.get(table) ?? [];
      q.push(resp);
      tableQueues.set(table, q);
    },
    setTableResponse(table, resp) {
      tableDefaults.set(table, resp);
    },
    setRpcResponse(resp) {
      rpcDefault = resp;
    },
    recordedUpdates,
    recordedInserts,
    recordedRpcs,
    client: {
      from(table: string) {
        return makeChain(table);
      },
      rpc(name: string, args: Record<string, unknown>) {
        recordedRpcs.push({ name, args });
        return Promise.resolve(rpcDefault);
      },
      storage: { from: () => ({ upload: async () => ({ data: null, error: null }) }) },
    },
  };
}

// ---------------------------------------------------------------------------
// Fake spawn — finds the YAML path in args, writes a deterministic zap report
// next to it, optionally emits AUTH_LOST stderr lines, and exits cleanly.
// ---------------------------------------------------------------------------

interface FakeSpawnOptions {
  /** Number of AUTH_LOST stderr lines to emit before close. */
  authLostHits?: number;
  /** Number of fake findings to emit in the report. */
  findingCount?: number;
}

function makeFakeSpawn(opts: FakeSpawnOptions = {}) {
  return ((_command: string, args: readonly string[]) => {
    const ee = new EventEmitter() as any;
    ee.pid = 99_999;
    ee.killed = false;
    ee.killCalls = [] as Array<NodeJS.Signals | number | undefined>;
    ee.stdout = new Readable({ read() {} });
    ee.stderr = new Readable({ read() {} });
    ee.kill = (signal?: NodeJS.Signals | number) => {
      ee.killed = true;
      ee.killCalls.push(signal);
      return true;
    };

    // The pipeline invokes /zap/zap.sh with `-cmd -autorun <yamlPath>` — pull
    // the YAML path off args[1] (or last arg) and derive the tmpDir.
    const yamlPath = args[args.length - 1];
    const tmpDir = path.dirname(yamlPath);

    const findingCount = opts.findingCount ?? 2;
    const fakeReport = {
      site: [
        {
          '@name': 'https://example.com',
          alerts: [
            {
              alert: 'Cross Site Scripting (Reflected)',
              name: 'Cross Site Scripting (Reflected)',
              riskcode: '3',
              confidence: '2',
              cweid: '79',
              alertRef: '40012',
              pluginid: '40012',
              desc: 'Reflected XSS test fixture',
              instances: Array.from({ length: findingCount }, (_, i) => ({
                uri: `https://example.com/page${i}`,
                method: 'GET',
                evidence: '<script>alert(1)</script>',
                attack: '<script>',
              })),
            },
          ],
        },
      ],
    };

    // Schedule the report write + close on the next tick so the pipeline has
    // time to attach its `done` handler before we settle.
    setImmediate(() => {
      try {
        fs.writeFileSync(path.join(tmpDir, 'zap-report.json'), JSON.stringify(fakeReport));
      } catch {
        /* tmpDir cleanup raced us; not a big deal — pipeline will see 0 findings */
      }
      const hits = opts.authLostHits ?? 0;
      for (let i = 0; i < hits; i++) {
        ee.stderr.push(Buffer.from(`AUTH_LOST status=200 url=/page${i}\n`, 'utf-8'));
      }
      ee.emit('close', 0, null);
    });

    return ee;
  }) as unknown as typeof import('child_process').spawn;
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ORG_ID = '00000000-0000-4000-8000-000000000001';
const PROJECT_ID = '00000000-0000-4000-8000-000000000010';
const TARGET_ID = '00000000-0000-4000-8000-000000000020';
const CRED_ID = '00000000-0000-4000-8000-000000000030';
const JOB_ID = '00000000-0000-4000-8000-000000000040';

function makeJobRow(overrides: Partial<ExtractionJobRow> = {}): ExtractionJobRow {
  return {
    id: JOB_ID,
    project_id: PROJECT_ID,
    organization_id: ORG_ID,
    type: 'dast',
    status: 'processing',
    run_id: 'run-1',
    machine_id: 'machine-1',
    payload: { target_url: 'https://example.com', scan_profile: 'auto', scan_timeout_minutes: 1 },
    attempts: 1,
    max_attempts: 3,
    error: null,
    started_at: null,
    heartbeat_at: null,
    completed_at: null,
    created_at: new Date().toISOString(),
    ...overrides,
  };
}

function makeScanJobRow(overrides: Record<string, unknown> = {}) {
  return {
    id: JOB_ID,
    organization_id: ORG_ID,
    project_id: PROJECT_ID,
    target_id: TARGET_ID,
    credential_id: null,
    credential_payload_hash: null,
    ...overrides,
  };
}

function makeTargetRow(overrides: Record<string, unknown> = {}) {
  return {
    id: TARGET_ID,
    project_id: PROJECT_ID,
    organization_id: ORG_ID,
    target_url: 'https://example.com',
    detected_runtime: 'classic',
    enabled: true,
    ...overrides,
  };
}

function makeProjectRow(overrides: Record<string, unknown> = {}) {
  return {
    id: PROJECT_ID,
    organization_id: ORG_ID,
    active_extraction_run_id: null,
    ...overrides,
  };
}

function primeAnonymousHappyPath(mock: MockSupabase) {
  mock.pushTableResponse('scan_jobs', { data: makeScanJobRow(), error: null });
  mock.pushTableResponse('project_dast_targets', { data: makeTargetRow(), error: null });
  mock.pushTableResponse('projects', { data: makeProjectRow(), error: null });
  mock.pushTableResponse('project_dast_credentials', { data: null, error: null });
  // getActiveExtractionRunId — read from projects again, return null run id.
  mock.pushTableResponse('projects', { data: makeProjectRow(), error: null });
  // isJobCancelled poll — return non-cancelled.
  mock.setTableResponse('scan_jobs', { data: { status: 'processing' }, error: null });
  // commit_dast_target_run RPC + heartbeat updates — defaults are { data: null, error: null }.
  mock.setRpcResponse({ data: null, error: null });
}

function primeAuthenticatedHappyPath(mock: MockSupabase, encryptedPayload: string) {
  const credentialPayloadHash = crypto.createHash('sha256').update(encryptedPayload).digest('hex');
  mock.pushTableResponse('scan_jobs', {
    data: makeScanJobRow({
      credential_id: CRED_ID,
      credential_payload_hash: credentialPayloadHash,
    }),
    error: null,
  });
  mock.pushTableResponse('project_dast_targets', { data: makeTargetRow(), error: null });
  mock.pushTableResponse('projects', { data: makeProjectRow(), error: null });
  mock.pushTableResponse('project_dast_credentials', {
    data: {
      id: CRED_ID,
      target_id: TARGET_ID,
      organization_id: ORG_ID,
      auth_strategy: 'cookie',
      encrypted_payload: encryptedPayload,
      encryption_key_version: 1,
      logged_in_indicator: 'Sign out',
      logged_out_indicator: 'Login',
    },
    error: null,
  });
  mock.pushTableResponse('projects', { data: makeProjectRow(), error: null });
  mock.setTableResponse('scan_jobs', { data: { status: 'processing' }, error: null });
  mock.setRpcResponse({ data: null, error: null });
}

// ---------------------------------------------------------------------------
// auth_state state machine
// ---------------------------------------------------------------------------

describe('runDastPipeline — auth_state state machine', () => {
  // Use a private temp dir per test so the YAML/report writes don't clash.
  let zapWorkDir: string;
  beforeEach(() => {
    zapWorkDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dast-auth-state-test-'));
  });
  afterEach(() => {
    try {
      fs.rmSync(zapWorkDir, { recursive: true, force: true });
    } catch {
      /* swallow — Windows occasionally holds the dir for a few ms */
    }
  });

  it('anonymous (no credential) → every finding gets auth_state=anonymous', async () => {
    delete process.env.DAST_CREDENTIAL_KEY;
    const mock = makeMockSupabase();
    const job = makeJobRow();
    primeAnonymousHappyPath(mock);

    const result = await runDastPipeline(job, mock.client as never, {
      cancellationPollMs: 25,
      zapWorkDir,
      spawnImpl: makeFakeSpawn({ findingCount: 3 }),
    });

    expect(result.auth_state_summary).toBe('anonymous');

    // Every inserted row carries auth_state='anonymous'.
    const findingInserts = mock.recordedInserts.filter((i) => i.table === 'project_dast_findings');
    expect(findingInserts.length).toBeGreaterThan(0);
    const allRows = findingInserts.flatMap((i) => i.rows as Array<Record<string, unknown>>);
    expect(allRows.length).toBe(3);
    for (const row of allRows) {
      expect(row.auth_state).toBe('anonymous');
      expect(row.engine).toBe('zap');
    }

    // Job is finalized as completed — NOT auth_failed.
    const finalize = mock.recordedUpdates.find(
      (u) => u.table === 'scan_jobs' && u.values.status === 'completed',
    );
    expect(finalize).toBeDefined();
    expect(finalize!.values.findings_count).toBe(3);

    // commit_dast_target_run was invoked.
    const commitRpc = mock.recordedRpcs.find((r) => r.name === 'commit_dast_target_run');
    expect(commitRpc).toBeDefined();
  });

  it('authenticated (cred + 0 AUTH_LOST hits) → every finding gets auth_state=authenticated', async () => {
    process.env.DAST_CREDENTIAL_KEY = '0'.repeat(64);
    const mock = makeMockSupabase();
    const job = makeJobRow();

    // Real encryptCredential so the pipeline's decrypt path succeeds end-to-end.
    const plaintext = JSON.stringify({
      kind: 'cookie',
      cookies: [{ name: 'sid', value: 's3cr3t' }],
    });
    const { encrypted } = encryptForTest(plaintext);
    primeAuthenticatedHappyPath(mock, encrypted);

    const result = await runDastPipeline(job, mock.client as never, {
      cancellationPollMs: 25,
      zapWorkDir,
      spawnImpl: makeFakeSpawn({ findingCount: 2, authLostHits: 0 }),
    });

    expect(result.auth_state_summary).toBe('authenticated');

    const findingInserts = mock.recordedInserts.filter((i) => i.table === 'project_dast_findings');
    const allRows = findingInserts.flatMap((i) => i.rows as Array<Record<string, unknown>>);
    expect(allRows.length).toBe(2);
    for (const row of allRows) {
      expect(row.auth_state).toBe('authenticated');
    }

    // Job finalized as completed — NOT auth_failed.
    const finalize = mock.recordedUpdates.find(
      (u) => u.table === 'scan_jobs' && u.values.status === 'completed',
    );
    expect(finalize).toBeDefined();
    const authFailed = mock.recordedUpdates.find(
      (u) => u.table === 'scan_jobs' && u.values.error_category === 'auth_failed',
    );
    expect(authFailed).toBeUndefined();
  });

  it('cred + ≥4 AUTH_LOST hits → auth_failed JOB STATE + findings tagged authentication_lost + NO synthetic finding', async () => {
    process.env.DAST_CREDENTIAL_KEY = '0'.repeat(64);
    const mock = makeMockSupabase();
    const job = makeJobRow();

    const plaintext = JSON.stringify({
      kind: 'cookie',
      cookies: [{ name: 'sid', value: 'session' }],
    });
    const { encrypted } = encryptForTest(plaintext);
    primeAuthenticatedHappyPath(mock, encrypted);

    const result = await runDastPipeline(job, mock.client as never, {
      cancellationPollMs: 25,
      zapWorkDir,
      // 4 hits trips the watcher with default threshold=4, gateStatusCodes
      // includes 200, so the AUTH_LOST status=200 lines from the fake spawn
      // all count.
      spawnImpl: makeFakeSpawn({ findingCount: 2, authLostHits: 4 }),
    });

    expect(result.auth_state_summary).toBe('authentication_lost');

    // Findings collected before the abort still ship — but every row carries
    // 'authentication_lost' (run-level summary, per plan §"auth_state state
    // machine" — rule_state stays a run-level summary in v2.1a).
    const findingInserts = mock.recordedInserts.filter((i) => i.table === 'project_dast_findings');
    const allRows = findingInserts.flatMap((i) => i.rows as Array<Record<string, unknown>>);
    expect(allRows.length).toBe(2);
    for (const row of allRows) {
      expect(row.auth_state).toBe('authentication_lost');
    }

    // CRITICAL invariant: NO synthetic 'authentication_lost' finding row was
    // inserted on top of the real ones. Every inserted row must come from the
    // ZAP report — none are pipeline-fabricated.
    expect(allRows.every((r) => typeof r.endpoint_url === 'string' && r.endpoint_url.startsWith('https://example.com/page'))).toBe(true);

    // auth_failed was recorded as JOB STATE on scan_jobs.
    const authFailed = mock.recordedUpdates.find(
      (u) => u.table === 'scan_jobs' && u.values.error_category === 'auth_failed',
    );
    expect(authFailed).toBeDefined();
    expect(authFailed!.values.status).toBe('failed');
    const errorPayload = authFailed!.values.error_payload as {
      consecutive_lost_count: number;
      last_logged_out_url: string;
      findings_count: number;
    };
    expect(errorPayload.consecutive_lost_count).toBeGreaterThanOrEqual(4);
    expect(typeof errorPayload.last_logged_out_url).toBe('string');
    expect(errorPayload.findings_count).toBe(2);
  });
});

// Phase 24a (v2.1a): DAST pipeline rewrite — tenant guard + credential load.
//
// We exercise the abort paths with a hand-rolled supabase mock that returns
// deterministic rows per table. The actual ZAP spawn is NOT exercised here
// (control-plane has its own tests); the pipeline is forced to abort BEFORE
// the spawn step in every test.

import crypto from 'crypto';
import { EventEmitter } from 'events';
import { runDastPipeline, DastPipelineAbortError } from '../dast/pipeline';
import type { ExtractionJobRow } from '../job-db';

// ---------------------------------------------------------------------------
// supabase mock: per-table response queue. Each .from(table) call pops the
// next response for that table from the queue.
// ---------------------------------------------------------------------------

type SupabaseResp = { data: unknown; error: unknown };

interface MockSupabase {
  pushTableResponse: (table: string, resp: SupabaseResp) => void;
  setTableResponse: (table: string, resp: SupabaseResp) => void;
  pushRpcResponse: (resp: SupabaseResp) => void;
  setRpcResponse: (resp: SupabaseResp) => void;
  recordedUpdates: Array<{ table: string; values: Record<string, unknown> }>;
  recordedRpcs: Array<{ name: string; args: Record<string, unknown> }>;
  recordedInserts: Array<{ table: string; rows: unknown }>;
  // narrow Storage shape used by the pipeline; Storage is a duck-typed structural interface.
  client: {
    from: (table: string) => unknown;
    rpc: (name: string, args: Record<string, unknown>) => unknown;
    storage: { from: (b: string) => unknown };
  };
}

function makeMockSupabase(): MockSupabase {
  const tableQueues = new Map<string, SupabaseResp[]>();
  const tableDefaults = new Map<string, SupabaseResp>();
  const rpcQueue: SupabaseResp[] = [];
  let rpcDefault: SupabaseResp = { data: null, error: null };
  const recordedUpdates: MockSupabase['recordedUpdates'] = [];
  const recordedRpcs: MockSupabase['recordedRpcs'] = [];
  const recordedInserts: MockSupabase['recordedInserts'] = [];

  function nextForTable(table: string): SupabaseResp {
    const q = tableQueues.get(table);
    if (q && q.length) return q.shift()!;
    return tableDefaults.get(table) ?? { data: null, error: null };
  }

  function makeChain(table: string) {
    const chain: any = {
      _pendingUpdate: null as Record<string, unknown> | null,
      select(_cols?: string) {
        return chain;
      },
      eq(_col: string, _val: unknown) {
        return chain;
      },
      in(_col: string, _vals: readonly unknown[]) {
        return chain;
      },
      limit(_n: number) {
        return chain;
      },
      insert(rows: unknown) {
        recordedInserts.push({ table, rows });
        return chain;
      },
      update(values: Record<string, unknown>) {
        chain._pendingUpdate = values;
        recordedUpdates.push({ table, values });
        return chain;
      },
      upsert(_rows: unknown) {
        return chain;
      },
      delete() {
        return chain;
      },
      single() {
        return Promise.resolve(nextForTable(table));
      },
      maybeSingle() {
        return Promise.resolve(nextForTable(table));
      },
      then(resolve: (v: unknown) => void) {
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
    pushRpcResponse(resp) {
      rpcQueue.push(resp);
    },
    setRpcResponse(resp) {
      rpcDefault = resp;
    },
    recordedUpdates,
    recordedRpcs,
    recordedInserts,
    client: {
      from(table: string) {
        return makeChain(table);
      },
      rpc(name: string, args: Record<string, unknown>) {
        recordedRpcs.push({ name, args });
        const resp = rpcQueue.shift() ?? rpcDefault;
        return Promise.resolve(resp);
      },
      storage: { from: () => ({ upload: async () => ({ data: null, error: null }) }) },
    },
  };
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ORG_ID = '00000000-0000-4000-8000-000000000001';
const FOREIGN_ORG_ID = '00000000-0000-4000-8000-00000000beef';
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
  return { id: PROJECT_ID, organization_id: ORG_ID, ...overrides };
}

function makeCredRow(encryptedPayload: string, overrides: Record<string, unknown> = {}) {
  return {
    id: CRED_ID,
    target_id: TARGET_ID,
    organization_id: ORG_ID,
    auth_strategy: 'jwt',
    encrypted_payload: encryptedPayload,
    encryption_key_version: 1,
    logged_in_indicator: null,
    logged_out_indicator: null,
    ...overrides,
  };
}

// Build a structurally valid `nonce:ciphertext:tag` credential blob encrypted
// under `keyHex` (aes-256-gcm). decryptCredential's up-front structural checks
// pass; the auth-tag check fails only when the worker holds a different key —
// which is the genuine stale-key scenario (distinct from a corrupt blob).
function makeCredentialBlob(keyHex: string, plaintext = '{"username":"u","password":"p"}'): string {
  const key = Buffer.from(keyHex, 'hex');
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [
    nonce.toString('base64'),
    ciphertext.toString('base64'),
    tag.toString('base64'),
  ].join(':');
}

function primeHappyPath(mock: MockSupabase, job: ExtractionJobRow, withCredential?: { encrypted_payload: string }) {
  // tenant-guard load: scan_jobs.single, project_dast_targets.single (target),
  // projects.single. cred load uses maybeSingle on project_dast_credentials.
  mock.pushTableResponse('scan_jobs', {
    data: makeScanJobRow({ id: job.id, project_id: job.project_id, organization_id: job.organization_id }),
    error: null,
  });
  mock.pushTableResponse('project_dast_targets', { data: makeTargetRow(), error: null });
  mock.pushTableResponse('projects', { data: makeProjectRow(), error: null });
  mock.pushTableResponse('project_dast_credentials', {
    data: withCredential ? makeCredRow(withCredential.encrypted_payload) : null,
    error: null,
  });
}

// ---------------------------------------------------------------------------
// Tenant-drift abort
// ---------------------------------------------------------------------------

describe('runDastPipeline — tenant-drift abort', () => {
  it('aborts BEFORE decrypt with error_category=tenant_drift_detected when target.organization_id mismatches', async () => {
    const mock = makeMockSupabase();
    const job = makeJobRow();

    mock.pushTableResponse('scan_jobs', {
      data: makeScanJobRow({ organization_id: ORG_ID }),
      error: null,
    });
    // Target row's organization_id is the foreign tenant — the worker MUST
    // refuse to proceed regardless of what scan_jobs says.
    mock.pushTableResponse('project_dast_targets', {
      data: makeTargetRow({ organization_id: FOREIGN_ORG_ID }),
      error: null,
    });
    mock.pushTableResponse('projects', { data: makeProjectRow(), error: null });

    await expect(runDastPipeline(job, mock.client as never)).rejects.toBeInstanceOf(
      DastPipelineAbortError,
    );

    // scan_jobs row was updated with the tenant-drift category, BEFORE any
    // credential decrypt was attempted (no project_dast_credentials read in
    // recordedUpdates path — confirm via an absence assertion).
    const errorUpdate = mock.recordedUpdates.find(
      (u) => u.table === 'scan_jobs' && u.values.error_category === 'tenant_drift_detected',
    );
    expect(errorUpdate).toBeDefined();
    expect(errorUpdate!.values.status).toBe('failed');
    expect((errorUpdate!.values.error_payload as { expected_org_id: string }).expected_org_id).toBe(ORG_ID);
  });

  it('aborts when project.organization_id mismatches scan_jobs.organization_id', async () => {
    const mock = makeMockSupabase();
    const job = makeJobRow();

    mock.pushTableResponse('scan_jobs', { data: makeScanJobRow(), error: null });
    mock.pushTableResponse('project_dast_targets', { data: makeTargetRow(), error: null });
    mock.pushTableResponse('projects', {
      data: makeProjectRow({ organization_id: FOREIGN_ORG_ID }),
      error: null,
    });

    const err = await runDastPipeline(job, mock.client as never).catch((e) => e);
    expect(err).toBeInstanceOf(DastPipelineAbortError);
    expect((err as DastPipelineAbortError).errorCategory).toBe('tenant_drift_detected');
  });
});

// ---------------------------------------------------------------------------
// Credential load — missing key, stale key, rotated payload
// ---------------------------------------------------------------------------

describe('runDastPipeline — credential abort paths', () => {
  const originalEnv = { ...process.env };
  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('aborts with dast_credential_key_missing when encrypted credential exists but DAST_CREDENTIAL_KEY is unset', async () => {
    delete process.env.DAST_CREDENTIAL_KEY;
    const mock = makeMockSupabase();
    const job = makeJobRow();
    primeHappyPath(mock, job, { encrypted_payload: 'AAAA:BBBB:CCCC' });

    const err = await runDastPipeline(job, mock.client as never).catch((e) => e);
    expect(err).toBeInstanceOf(DastPipelineAbortError);
    expect((err as DastPipelineAbortError).errorCategory).toBe('dast_credential_key_missing');

    const errorUpdate = mock.recordedUpdates.find(
      (u) => u.table === 'scan_jobs' && u.values.error_category === 'dast_credential_key_missing',
    );
    expect(errorUpdate).toBeDefined();
  });

  it('aborts with dast_credential_key_stale when current+previous keys both reject the ciphertext', async () => {
    // Structurally valid ciphertext, but encrypted under a key the worker does
    // not hold. The auth-tag check fails and no previous key is configured, so
    // this is a stale-key problem — not a corrupt-credential format error.
    process.env.DAST_CREDENTIAL_KEY = '0'.repeat(64);
    delete process.env.DAST_CREDENTIAL_KEY_PREV;

    const mock = makeMockSupabase();
    const job = makeJobRow();
    primeHappyPath(mock, job, { encrypted_payload: makeCredentialBlob('a'.repeat(64)) });

    const err = await runDastPipeline(job, mock.client as never).catch((e) => e);
    expect(err).toBeInstanceOf(DastPipelineAbortError);
    expect((err as DastPipelineAbortError).errorCategory).toBe('dast_credential_key_stale');
  });

  it('aborts with dast_credential_rotated when scan_jobs.credential_payload_hash mismatches current row', async () => {
    process.env.DAST_CREDENTIAL_KEY = '0'.repeat(64);
    const mock = makeMockSupabase();
    const job = makeJobRow();

    const encryptedPayload = 'AAAA:BBBB:CCCC';
    const queueTimeHash = crypto.createHash('sha256').update('STALE:DIFFERENT').digest('hex');

    mock.pushTableResponse('scan_jobs', {
      data: makeScanJobRow({ credential_id: CRED_ID, credential_payload_hash: queueTimeHash }),
      error: null,
    });
    mock.pushTableResponse('project_dast_targets', { data: makeTargetRow(), error: null });
    mock.pushTableResponse('projects', { data: makeProjectRow(), error: null });
    mock.pushTableResponse('project_dast_credentials', {
      data: makeCredRow(encryptedPayload),
      error: null,
    });

    const err = await runDastPipeline(job, mock.client as never).catch((e) => e);
    expect(err).toBeInstanceOf(DastPipelineAbortError);
    expect((err as DastPipelineAbortError).errorCategory).toBe('dast_credential_rotated');

    const errorUpdate = mock.recordedUpdates.find(
      (u) => u.table === 'scan_jobs' && u.values.error_category === 'dast_credential_rotated',
    );
    expect(errorUpdate).toBeDefined();
  });

  it('aborts with dast_credential_rotated when credential_id at queue time differs from current row', async () => {
    process.env.DAST_CREDENTIAL_KEY = '0'.repeat(64);
    const mock = makeMockSupabase();
    const job = makeJobRow();

    mock.pushTableResponse('scan_jobs', {
      data: makeScanJobRow({ credential_id: 'old-credential-id', credential_payload_hash: null }),
      error: null,
    });
    mock.pushTableResponse('project_dast_targets', { data: makeTargetRow(), error: null });
    mock.pushTableResponse('projects', { data: makeProjectRow(), error: null });
    mock.pushTableResponse('project_dast_credentials', {
      data: makeCredRow('AAAA:BBBB:CCCC', { id: CRED_ID }),
      error: null,
    });

    const err = await runDastPipeline(job, mock.client as never).catch((e) => e);
    expect(err).toBeInstanceOf(DastPipelineAbortError);
    expect((err as DastPipelineAbortError).errorCategory).toBe('dast_credential_rotated');
  });
});

// ---------------------------------------------------------------------------
// scope_config propagation regression. The route layer validates and saves
// scope_config to project_dast_config, but the worker never read it back —
// silently dropping every customer's include/exclude paths and header rules.
// ---------------------------------------------------------------------------

import { __test_loadScopeConfig } from '../dast/pipeline';

describe('runDastPipeline — scope_config propagation', () => {
  it('loads scope_config from project_dast_config and shapes it for the YAML builder', async () => {
    const mock = makeMockSupabase();
    mock.pushTableResponse('project_dast_config', {
      data: {
        scope_config: {
          include_patterns: ['^https://example\\.com/api/.*$'],
          exclude_patterns: ['^https://example\\.com/admin/.*$'],
          header_rules: [
            { name: 'X-Tenant-Id', value: 'org-42', scope: 'all' },
            { name: 'X-Trace-Id', value: 'trace-1', scope: 'requests' },
          ],
        },
      },
      error: null,
    });

    const out = await __test_loadScopeConfig(mock.client as never, PROJECT_ID, 'https://example.com');
    expect(out).toBeDefined();
    expect(out!.includePaths).toEqual(['^https://example\\.com/api/.*$']);
    expect(out!.excludePaths).toEqual(['^https://example\\.com/admin/.*$']);
    expect(out!.headerRules).toEqual([
      { name: 'X-Tenant-Id', value: 'org-42', scope: 'all' },
      { name: 'X-Trace-Id', value: 'trace-1', scope: 'requests' },
    ]);
  });

  it('returns undefined when project_dast_config has no scope_config row', async () => {
    const mock = makeMockSupabase();
    mock.pushTableResponse('project_dast_config', { data: null, error: null });
    const out = await __test_loadScopeConfig(mock.client as never, PROJECT_ID);
    expect(out).toBeUndefined();
  });

  it('returns undefined when scope_config is empty {}', async () => {
    const mock = makeMockSupabase();
    mock.pushTableResponse('project_dast_config', {
      data: { scope_config: {} },
      error: null,
    });
    const out = await __test_loadScopeConfig(mock.client as never, PROJECT_ID);
    expect(out).toBeUndefined();
  });

  it('drops malformed entries instead of failing loudly (defense-in-depth)', async () => {
    const mock = makeMockSupabase();
    mock.pushTableResponse('project_dast_config', {
      data: {
        scope_config: {
          // non-strings dropped; include patterns must stay within target origin
          include_patterns: [
            '^https://example\\.com/ok',
            42,
            null,
            '^https://example\\.com/also-ok',
          ],
          header_rules: [
            { name: 'X-Ok', value: 'v' }, // missing scope → defaults 'all'
            { name: 'X-Bad', value: 123 }, // value not string → dropped
            null, // dropped
            { name: 'X-Bad-Scope', value: 'v', scope: 'invalid' }, // bad scope → defaults 'all'
          ],
        },
      },
      error: null,
    });
    const out = await __test_loadScopeConfig(mock.client as never, PROJECT_ID, 'https://example.com');
    expect(out!.includePaths).toEqual([
      '^https://example\\.com/ok',
      '^https://example\\.com/also-ok',
    ]);
    expect(out!.headerRules).toEqual([
      { name: 'X-Ok', value: 'v', scope: 'all' },
      { name: 'X-Bad-Scope', value: 'v', scope: 'all' },
    ]);
  });

  it('caps include/exclude arrays at 32 entries', async () => {
    const mock = makeMockSupabase();
    // include patterns must stay within the target origin; exclude patterns
    // only narrow reach so they are not origin-checked.
    const bigInclude = Array.from({ length: 50 }, (_, i) => `^https://example\\.com/pat-${i}`);
    const bigExclude = Array.from({ length: 50 }, (_, i) => `pat-${i}`);
    mock.pushTableResponse('project_dast_config', {
      data: { scope_config: { include_patterns: bigInclude, exclude_patterns: bigExclude } },
      error: null,
    });
    const out = await __test_loadScopeConfig(mock.client as never, PROJECT_ID, 'https://example.com');
    expect(out!.includePaths).toHaveLength(32);
    expect(out!.excludePaths).toHaveLength(32);
  });
});

// ---------------------------------------------------------------------------
// Anonymous scan path: target with no credential row should NOT abort.
// We don't run the full ZAP spawn (no /zap/zap.sh in tests), so we assert
// the pipeline reaches the spawn step rather than aborting at cred load.
// ---------------------------------------------------------------------------

describe('runDastPipeline — anonymous (no credential) path', () => {
  it('does NOT abort with a credential error when target has no credential row', async () => {
    delete process.env.DAST_CREDENTIAL_KEY;
    const mock = makeMockSupabase();
    const job = makeJobRow();
    primeHappyPath(mock, job /* no credential */);

    // The pipeline will fail at the spawn step (no /zap/wrk on the test
    // host, or spawn ENOENT on /zap/zap.sh). Either way, the abort MUST NOT
    // be a credential-related abort — that's the assertion that matters
    // for the silent-anonymous-fallback prevention guarantee.
    const err = await runDastPipeline(job, mock.client as never, {
      cancellationPollMs: 25,
      zapWorkDir: require('os').tmpdir(),
    }).catch((e) => e);
    if (err instanceof DastPipelineAbortError) {
      expect(err.errorCategory).not.toBe('dast_credential_key_missing');
      expect(err.errorCategory).not.toBe('dast_credential_key_stale');
      expect(err.errorCategory).not.toBe('dast_credential_rotated');
    }
    // Confirm no credential error_category was written to scan_jobs.
    const credErrorWrites = mock.recordedUpdates.filter(
      (u) =>
        typeof u.values.error_category === 'string' &&
        (u.values.error_category as string).startsWith('dast_credential_'),
    );
    expect(credErrorWrites).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Nuclei engine branch (v2.1c): a dast_nuclei job runs runDastPipeline end to
// end with a faked `nuclei` process, and the runtime-confirmation RPC fires
// only when an inserted finding carries CVE ids.
// ---------------------------------------------------------------------------

/** Fake `spawn` that emits `stdout` as one JSONL chunk then exits 0. */
function makeFakeNucleiSpawn(stdout: string): any {
  return () => {
    const child: any = new EventEmitter();
    child.pid = 5151;
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = () => true;
    setTimeout(() => {
      child.stdout.emit('data', Buffer.from(stdout, 'utf-8'));
      child.emit('close', 0, null);
    }, 5);
    return child;
  };
}

const NUCLEI_KEV_LINE = JSON.stringify({
  'template-id': 'CVE-2017-12615',
  info: {
    name: 'Apache Tomcat - Remote Code Execution',
    severity: 'critical',
    tags: ['cve', 'kev', 'rce'],
    classification: { 'cve-id': ['CVE-2017-12615'], 'cwe-id': ['CWE-434'] },
  },
  type: 'http',
  host: 'https://example.com',
  'matched-at': 'https://example.com/evil.jsp',
  request: 'PUT /evil.jsp HTTP/1.1',
});

const NUCLEI_NO_CVE_LINE = JSON.stringify({
  'template-id': 'tech-detect',
  info: { name: 'Technology detection', severity: 'info', tags: ['tech'] },
  type: 'http',
  'matched-at': 'https://example.com/',
});

describe('runDastPipeline — Nuclei engine branch', () => {
  it('runs the Nuclei engine for a dast_nuclei job: engine/kev on inserts, confirm RPC fires', async () => {
    delete process.env.DAST_CREDENTIAL_KEY;
    const mock = makeMockSupabase();
    const job = makeJobRow({ type: 'dast_nuclei' });
    primeHappyPath(mock, job /* no credential — anonymous Nuclei scan */);

    const result = await runDastPipeline(job, mock.client as never, {
      spawnImpl: makeFakeNucleiSpawn(`${NUCLEI_KEV_LINE}\n`),
      cancellationPollMs: 100_000,
      zapWorkDir: require('os').tmpdir(),
    });

    // The dispatch resolved to Nuclei and the finding round-tripped into the
    // insert payload with engine='nuclei' and the KEV flag set.
    const findingInserts = mock.recordedInserts.filter((i) => i.table === 'project_dast_findings');
    expect(findingInserts.length).toBeGreaterThan(0);
    const rows = findingInserts[0].rows as Array<Record<string, unknown>>;
    expect(rows[0].engine).toBe('nuclei');
    expect(rows[0].kev).toBe(true);

    // The finding carried a CVE id, so the runtime-confirmation batch ran.
    const confirmCalls = mock.recordedRpcs.filter((r) => r.name === 'confirm_pdvs_from_dast_run');
    expect(confirmCalls).toHaveLength(1);
    expect(mock.recordedRpcs.filter((r) => r.name === 'commit_dast_target_run')).toHaveLength(1);
    // The RPC mock returns null data → zero flips.
    expect(result.runtime_confirmed_count).toBe(0);
  });

  it('skips the confirm RPC when no Nuclei finding carries a CVE id', async () => {
    delete process.env.DAST_CREDENTIAL_KEY;
    const mock = makeMockSupabase();
    const job = makeJobRow({ type: 'dast_nuclei' });
    primeHappyPath(mock, job);

    const result = await runDastPipeline(job, mock.client as never, {
      spawnImpl: makeFakeNucleiSpawn(`${NUCLEI_NO_CVE_LINE}\n`),
      cancellationPollMs: 100_000,
      zapWorkDir: require('os').tmpdir(),
    });

    // cveSignalCount === 0 → confirm_pdvs_from_dast_run must NOT be called
    // (its tenancy guard would otherwise raise P0001 on every clean run).
    expect(mock.recordedRpcs.filter((r) => r.name === 'confirm_pdvs_from_dast_run')).toHaveLength(0);
    expect(result.runtime_confirmed_count).toBe(0);
  });
});

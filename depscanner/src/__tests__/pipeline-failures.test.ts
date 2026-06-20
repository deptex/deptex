process.env.SUPABASE_URL = 'https://fake.supabase.co';
process.env.SUPABASE_SERVICE_ROLE_KEY = 'fake-key';

let fsExistsSync: (p: string) => boolean = () => true;
let fsReadFileSync: (p: string, enc?: string) => string = () => '[]';
let fsMkdirSync: (p: string, opts?: { recursive?: boolean }) => void = () => {};
let fsReaddirSync: (p: string, opts?: { withFileTypes?: boolean }) => unknown[] = () => [];
// Steps that write intermediate files (e.g. TruffleHog's
// .deptex-trufflehog-excludes) must not touch the real disk under the
// non-existent fake-repo dir — stub writes to a no-op by default.
let fsWriteFileSync: (p: string, data: string, enc?: string) => void = () => {};

jest.mock('fs', () => {
  const actual = jest.requireActual<typeof import('fs')>('fs');
  return {
    ...actual,
    existsSync: (p: string) => fsExistsSync(p),
    readFileSync: (p: string, enc?: string) => fsReadFileSync(p, enc),
    mkdirSync: (p: string, opts?: { recursive?: boolean }) => fsMkdirSync(p, opts),
    readdirSync: (p: string, opts?: { withFileTypes?: boolean }) => fsReaddirSync(p, opts),
    writeFileSync: (p: string, data: string, enc?: string) => fsWriteFileSync(p, data, enc),
  };
});

const supabaseResolves: Array<{ data: unknown; error: unknown }> = [];
function createChain() {
  const chain: Record<string, unknown> = {
    from: jest.fn().mockReturnThis(),
    select: jest.fn().mockReturnThis(),
    eq: jest.fn().mockReturnThis(),
    in: jest.fn().mockReturnThis(),
    update: jest.fn().mockReturnThis(),
    insert: jest.fn().mockReturnThis(),
    upsert: jest.fn().mockReturnThis(),
    delete: jest.fn().mockReturnThis(),
    single: jest.fn().mockImplementation(() => {
      const v = supabaseResolves.shift() ?? { data: null, error: null };
      return Promise.resolve(v);
    }),
    maybeSingle: jest.fn().mockImplementation(() => {
      const v = supabaseResolves.shift() ?? { data: null, error: null };
      return Promise.resolve(v);
    }),
  };
  (chain as any).then = function (resolve: (v: unknown) => void) {
    const v = supabaseResolves.shift() ?? { data: [], error: null };
    resolve(v);
    return Promise.resolve(v);
  };
  return chain;
}

const mockChain = createChain();
const mockSupabase = {
  from: (t: string) => mockChain,
  rpc: jest.fn().mockResolvedValue({ data: { extraction_run_id: 'test-run', deps_removed: 0, vulns_new: 0 }, error: null }),
  storage: {
    from: jest.fn().mockReturnValue({
      upload: jest.fn().mockResolvedValue({}),
    }),
  },
};

jest.mock('@supabase/supabase-js', () => ({
  createClient: jest.fn(() => mockSupabase),
}));

const mockCloneByProvider = jest.fn();
const mockCleanupRepository = jest.fn();
jest.mock('../clone', () => ({
  cloneByProvider: (...args: unknown[]) => mockCloneByProvider(...args),
  cleanupRepository: (...args: unknown[]) => mockCleanupRepository(...args),
}));

const mockExecSync = jest.fn();
const mockSpawnSync = jest.fn();
const mockSpawn = jest.fn();
jest.mock('child_process', () => ({
  execSync: (...args: unknown[]) => mockExecSync(...args),
  spawnSync: (...args: unknown[]) => mockSpawnSync(...args),
  spawn: (...args: unknown[]) => mockSpawn(...args),
}));

jest.mock('../tree-sitter-extractor', () => ({
  extractUsage: jest.fn().mockResolvedValue({ files: [], filesImportingByDep: {} }),
}));

jest.mock('../tree-sitter-extractor/storage', () => ({
  storeUsageExtractionResults: jest.fn().mockResolvedValue({ success: true }),
}));

// IaC/container + malicious are now hard-fail scanners. The tests that exercise
// a LATER scanner's hard-fail (semgrep) need these earlier optional scanners to
// pass cleanly so the run reaches semgrep — stub them to a clean result.
jest.mock('../scanners/orchestrator', () => ({
  runIaCAndContainerScans: jest.fn().mockResolvedValue({ infraTypes: [], failedScanners: [] }),
}));

jest.mock('../malicious-scan', () => ({
  runMaliciousScan: jest.fn().mockResolvedValue({
    status: 'completed', inserted_findings: 0, feed_hits: 0, guarddog_hits: 0,
  }),
  eventDeduplicationKey: jest.fn(() => 'dedup-key'),
}));

const SBOM_WITH_DEPS = JSON.stringify({
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  metadata: { component: { 'bom-ref': 'root' } },
  components: [
    { 'bom-ref': 'pkg:npm/lodash@4.17.21', name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' },
    { 'bom-ref': 'pkg:npm/express@4.18.0', name: 'express', version: '4.18.0', purl: 'pkg:npm/express@4.18.0' },
  ],
  dependencies: [
    { ref: 'root', dependsOn: ['pkg:npm/lodash@4.17.21', 'pkg:npm/express@4.18.0'] },
  ],
});

const baseJob = {
  projectId: 'proj-1',
  organizationId: 'org-1',
  repo_full_name: 'owner/repo',
  installation_id: '123',
  default_branch: 'main',
  ecosystem: 'npm' as const,
  provider: 'github' as const,
};

function pushSupabaseResponses() {
  while (supabaseResolves.length > 0) supabaseResolves.pop();
  supabaseResolves.push(
    { data: [], error: null },
    { data: [], error: null },
    { data: [{ id: 'd1', name: 'lodash' }, { id: 'd2', name: 'express' }], error: null },
    { data: [], error: null },
    { data: [{ id: 'v1', dependency_id: 'd1', version: '4.17.21' }, { id: 'v2', dependency_id: 'd2', version: '4.18.0' }], error: null },
    { data: [], error: null },
    { data: [], error: null },
    { data: [], error: null },
    { data: [{ id: 'pd1', name: 'lodash', version: '4.17.21' }, { id: 'pd2', name: 'express', version: '4.18.0' }], error: null },
    { data: { importance: 1.0 }, error: null },
    { data: [], error: null },
    { data: [], error: null },
    { data: [], error: null },
    { data: [], error: null },
    { data: [], error: null },
    { data: [], error: null },
    { data: [], error: null },
    { data: [], error: null },
    { data: [], error: null },
    { data: [], error: null },
    { data: [], error: null },
  );
}

import * as path from 'path';
import { runPipeline } from '../pipeline';

describe('runPipeline', () => {
  const mockLog = {
    info: jest.fn().mockResolvedValue(undefined),
    success: jest.fn().mockResolvedValue(undefined),
    warn: jest.fn().mockResolvedValue(undefined),
    error: jest.fn().mockResolvedValue(undefined),
  };

  beforeEach(() => {
    jest.clearAllMocks();
    (global as any).fetch = jest.fn().mockResolvedValue({ ok: true, json: async () => ({}), text: async () => '' });
    // binaryAvailable() uses spawnSync(which/where, [name]) and checks
    // .status === 0. Default the mock to "installed" so the semgrep /
    // trufflehog steps run their logic; individual tests can override.
    mockSpawnSync.mockReturnValue({ status: 0, stdout: '', stderr: '' });
  });

  it('clone auth failure (401/403) -> pipeline throws, error message contains "Authentication failed"', async () => {
    mockCloneByProvider.mockRejectedValue(new Error('401 Unauthorized'));
    await expect(runPipeline(baseJob, mockLog)).rejects.toThrow(/Authentication failed/);
  }, 25000);

  it('clone 404 -> pipeline throws, error message contains "Repository not found"', async () => {
    mockCloneByProvider.mockRejectedValue(new Error('404 Repository not found'));
    await expect(runPipeline(baseJob, mockLog)).rejects.toThrow(/Repository not found/);
  }, 25000);

  it('clone succeeds but cdxgen fails -> pipeline throws, error message contains "SBOM"', async () => {
    const repoPath = path.join(process.cwd(), 'fake-repo');
    mockCloneByProvider.mockResolvedValue(repoPath);
    mockExecSync.mockImplementation((cmd: string) => {
      if (String(cmd).includes('cdxgen')) throw new Error('cdxgen command failed');
      return undefined;
    });
    fsExistsSync = () => true;
    await expect(runPipeline(baseJob, mockLog)).rejects.toThrow(/SBOM/);
  }, 25000);

  it('empty SBOM but the npm manifest declares dependencies -> pipeline HARD-FAILS (unresolved dependencies)', async () => {
    // The express-dogfood shape: one unpublished dep (event-stream@3.3.6) aborts
    // `npm install`, so cdxgen emits an empty SBOM. The manifest clearly declared
    // dependencies we couldn't resolve, so the scan must fail loudly rather than
    // report a misleading "0 dependencies, all clear".
    const repoPath = path.join(process.cwd(), 'fake-repo');
    mockCloneByProvider.mockResolvedValue(repoPath);
    mockExecSync.mockReturnValue(undefined);
    fsExistsSync = () => true;
    fsReadFileSync = (p: string) => {
      if (String(p).endsWith('sbom.json')) {
        return JSON.stringify({
          metadata: { component: { 'bom-ref': 'root' } },
          components: [],
          dependencies: [{ ref: 'root', dependsOn: [] }],
        });
      }
      if (String(p).endsWith('package.json')) {
        return JSON.stringify({ name: 'app', dependencies: { express: '4.18.2', 'event-stream': '3.3.6' } });
      }
      throw new Error('unexpected read');
    };
    fsMkdirSync = () => {};
    fsReaddirSync = () => [];
    await expect(runPipeline(baseJob, mockLog)).rejects.toThrow(/Unable to resolve/i);
    expect(mockLog.error).toHaveBeenCalledWith('sbom', expect.stringContaining('Unable to resolve'));
  });

  it('empty SBOM and the manifest declares no dependencies -> pipeline continues (legitimate zero-dep project)', async () => {
    const repoPath = path.join(process.cwd(), 'fake-repo');
    mockCloneByProvider.mockResolvedValue(repoPath);
    mockExecSync.mockReturnValue(undefined);
    // dep-scan exits cleanly (empty VDR) so the vuln scan succeeds on a zero-dep
    // project. Optional scans are skipped so this test stays focused on the
    // sbom-continues path.
    mockSpawn.mockImplementation(() => {
      const child: { stdout: { on: jest.Mock }; stderr: { on: jest.Mock }; on: jest.Mock; kill: jest.Mock } = {
        stdout: { on: jest.fn() }, stderr: { on: jest.fn() }, on: jest.fn(), kill: jest.fn(),
      };
      (child.on as jest.Mock).mockImplementation((ev: string, cb: (code?: number) => void) => {
        if (ev === 'close') setImmediate(() => cb(0));
        return child;
      });
      return child;
    });
    fsExistsSync = () => true;
    fsReadFileSync = (p: string) => {
      if (String(p).endsWith('sbom.json')) {
        return JSON.stringify({
          metadata: { component: { 'bom-ref': 'root' } },
          components: [],
          dependencies: [{ ref: 'root', dependsOn: [] }],
        });
      }
      if (String(p).endsWith('package.json')) return JSON.stringify({ name: 'docs-only', version: '1.0.0' });
      return '{"vulnerabilities":[]}';
    };
    fsMkdirSync = () => {};
    fsReaddirSync = () => [];
    process.env.DEPTEX_SKIP_OPTIONAL_SCANS = '1';
    try {
      const result = await runPipeline(baseJob, mockLog);
      expect(result.finalizeSummary).toBeDefined();
    } finally {
      delete process.env.DEPTEX_SKIP_OPTIONAL_SCANS;
    }
    expect(mockLog.warn).toHaveBeenCalledWith('sbom', expect.stringContaining('No dependencies to analyze'));
  });

  it('dep-scan not installed (ENOENT) -> pipeline HARD-FAILS (vulnerability scan did not run)', async () => {
    const repoPath = path.join(process.cwd(), 'fake-repo');
    mockCloneByProvider.mockResolvedValue(repoPath);
    mockExecSync.mockReturnValue(undefined);
    mockSpawn.mockImplementation(() => {
      const child = { stdout: { on: jest.fn() }, stderr: { on: jest.fn() }, on: jest.fn(), kill: jest.fn() };
      setImmediate(() => {
        const onError = (child as any).on.mock.calls.find((c: unknown[]) => c[0] === 'error')?.[1];
        if (onError) onError({ code: 'ENOENT' });
      });
      return child;
    });
    fsExistsSync = () => true;
    fsReadFileSync = (p: string) => (String(p).endsWith('sbom.json') ? SBOM_WITH_DEPS : '{"vulnerabilities":[]}');
    fsMkdirSync = () => {};
    fsReaddirSync = () => [];
    pushSupabaseResponses();
    // dep-scan crashing (here: not installed) means the CVE picture is unknown,
    // not clean — the scan now hard-fails instead of silently reporting 0 vulns.
    await expect(runPipeline(baseJob, mockLog)).rejects.toThrow(/Vulnerability scan failed/i);
    expect(mockLog.warn).toHaveBeenCalledWith('vuln_scan', expect.stringContaining('dep-scan not installed'));
  });

  it('semgrep OOM (exit 137) with no output -> degrades gracefully, pipeline continues', async () => {
    const repoPath = path.join(process.cwd(), 'fake-repo');
    mockCloneByProvider.mockResolvedValue(repoPath);
    mockExecSync.mockImplementation((cmd: string) => {
      if (String(cmd).includes('semgrep')) {
        const err = new Error('killed') as Error & { status?: number };
        err.status = 137;
        throw err;
      }
      return undefined;
    });
    // dep-scan + every spawned scanner exits cleanly (close 0) so the run
    // reaches semgrep; semgrep then OOMs with no output.
    mockSpawn.mockImplementation(() => {
      const child: { stdout: { on: jest.Mock }; stderr: { on: jest.Mock }; on: jest.Mock; kill: jest.Mock } = {
        stdout: { on: jest.fn() }, stderr: { on: jest.fn() }, on: jest.fn(), kill: jest.fn(),
      };
      (child.on as jest.Mock).mockImplementation((ev: string, cb: (code?: number) => void) => {
        if (ev === 'close') setImmediate(() => cb(0));
        return child;
      });
      return child;
    });
    // semgrep.json is absent — an OOM-killed semgrep wrote no output. SAST is
    // supplementary: rather than discard a scan that already resolved deps,
    // dep-CVEs, secrets, IaC and container findings, a Semgrep crash degrades
    // to "no static-analysis findings this run" and the pipeline continues to
    // completion (reaches finalize). The old "hard-fail" assertion was
    // intentionally inverted when Semgrep was made non-fatal.
    fsExistsSync = (p: string) => !String(p).endsWith('semgrep.json');
    fsReadFileSync = (p: string) => (String(p).endsWith('sbom.json') ? SBOM_WITH_DEPS : '{"vulnerabilities":[]}');
    fsMkdirSync = () => {};
    fsReaddirSync = () => [];
    pushSupabaseResponses();
    const result = await runPipeline(baseJob, mockLog);
    expect(result.finalizeSummary).toBeDefined();
    // The OOM is logged as a warning (degraded), not a hard error.
    expect(mockLog.warn).toHaveBeenCalledWith('semgrep', expect.stringContaining('out of memory'));
    expect(mockLog.error).not.toHaveBeenCalledWith('semgrep', expect.stringContaining('out of memory'));
  });
});

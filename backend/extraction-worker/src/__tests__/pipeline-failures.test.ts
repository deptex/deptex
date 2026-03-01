process.env.SUPABASE_URL = 'https://fake.supabase.co';
process.env.SUPABASE_SERVICE_ROLE_KEY = 'fake-key';

let fsExistsSync: (p: string) => boolean = () => true;
let fsReadFileSync: (p: string, enc?: string) => string = () => '[]';
let fsMkdirSync: (p: string, opts?: { recursive?: boolean }) => void = () => {};
let fsReaddirSync: (p: string, opts?: { withFileTypes?: boolean }) => unknown[] = () => [];

jest.mock('fs', () => {
  const actual = jest.requireActual<typeof import('fs')>('fs');
  return {
    ...actual,
    existsSync: (p: string) => fsExistsSync(p),
    readFileSync: (p: string, enc?: string) => fsReadFileSync(p, enc),
    mkdirSync: (p: string, opts?: { recursive?: boolean }) => fsMkdirSync(p, opts),
    readdirSync: (p: string, opts?: { withFileTypes?: boolean }) => fsReaddirSync(p, opts),
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
jest.mock('child_process', () => ({
  execSync: (...args: unknown[]) => mockExecSync(...args),
  spawnSync: (...args: unknown[]) => mockSpawnSync(...args),
}));

jest.mock('../ast-parser', () => ({
  analyzeRepository: jest.fn().mockReturnValue([]),
}));

jest.mock('../ast-storage', () => ({
  storeAstAnalysisResults: jest.fn().mockResolvedValue({ success: true }),
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
    { data: { asset_tier: 'EXTERNAL' }, error: null },
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
    (global as any).fetch = jest.fn().mockResolvedValue({ ok: true });
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

  it('clone + SBOM succeed but SBOM has 0 deps -> pipeline throws, "No dependencies found"', async () => {
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
      throw new Error('unexpected read');
    };
    fsMkdirSync = () => {};
    fsReaddirSync = () => [];
    await expect(runPipeline(baseJob, mockLog)).rejects.toThrow(/No dependencies found/);
  });

  it('dep-scan not installed (ENOENT) -> pipeline does NOT throw, logs warning', async () => {
    const repoPath = path.join(process.cwd(), 'fake-repo');
    mockCloneByProvider.mockResolvedValue(repoPath);
    mockExecSync.mockReturnValue(undefined);
    mockSpawnSync.mockReturnValue({ error: { code: 'ENOENT' }, status: null, stderr: '' });
    fsExistsSync = () => true;
    fsReadFileSync = (p: string) => (String(p).endsWith('sbom.json') ? SBOM_WITH_DEPS : '{"vulnerabilities":[]}');
    fsMkdirSync = () => {};
    fsReaddirSync = () => [];
    pushSupabaseResponses();
    await expect(runPipeline(baseJob, mockLog)).resolves.toBeUndefined();
    expect(mockLog.warn).toHaveBeenCalledWith('vuln_scan', expect.stringContaining('dep-scan not installed'));
  });

  it('semgrep OOM (exit 137) -> pipeline does NOT throw, logs warning', async () => {
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
    mockSpawnSync.mockReturnValue({ error: null, status: 0, stderr: '' });
    fsExistsSync = () => true;
    fsReadFileSync = (p: string) => (String(p).endsWith('sbom.json') ? SBOM_WITH_DEPS : '{"vulnerabilities":[]}');
    fsMkdirSync = () => {};
    fsReaddirSync = () => [];
    pushSupabaseResponses();
    await expect(runPipeline(baseJob, mockLog)).resolves.toBeUndefined();
    expect(mockLog.warn).toHaveBeenCalledWith('semgrep', expect.stringContaining('out of memory'));
  });
});

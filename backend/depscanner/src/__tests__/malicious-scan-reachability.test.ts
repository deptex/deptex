/**
 * Pipeline-level reachability integration tests.
 *
 * The full `runMaliciousScan` exercise lives in the larger pipeline e2e
 * suite; this file validates the two new public helpers + the soft-fail
 * contract that the per-finding wrapper guarantees.
 */
import {
  attachReachability,
  buildWorkspaceReachabilityIndex,
} from '../malicious-scan';
import {
  buildReachabilityIndex,
  type ReachabilityIndex,
} from '../malicious/reachability';
import type { PendingFinding } from '../malicious/insert-finding';
import type { ExtractedFile, ImportBinding, KnownDep, UsageSlice } from '../tree-sitter-extractor';

const DEPS: KnownDep[] = [{ name: 'evil-pkg', namespace: null }];

function importBinding(source: string, line = 1): ImportBinding {
  return { localName: 'x', importedName: null, source, line, kind: 'default' };
}

function usage(filePath: string, depName: string, targetType: UsageSlice['targetType'], line = 5): UsageSlice {
  return {
    filePath,
    lineNumber: line,
    containingMethod: 'main',
    targetName: depName,
    targetType,
    resolvedMethod: null,
    usageLabel: null,
    depName,
  };
}

function extractedFile(path: string, imports: ImportBinding[], usages: UsageSlice[]): ExtractedFile {
  return { filePath: path, language: 'javascript', imports, usages };
}

const baseFinding: Omit<PendingFinding, 'reachability_level' | 'reachability_details'> = {
  project_id: 'p',
  organization_id: 'o',
  extraction_run_id: 'run',
  project_dependency_id: 'pd',
  dependency_id: 'd',
  rule_id: 'feed:GHSA-xxxx',
  scanner: 'feed',
  severity: 'critical',
  message: 'malware',
  depscore: null,
};

describe('attachReachability', () => {
  it('attaches function-level result when the package is invoked', () => {
    const idx: ReachabilityIndex = buildReachabilityIndex(
      [
        extractedFile(
          'src/index.js',
          [importBinding('evil-pkg')],
          [usage('src/index.js', 'evil-pkg', 'call', 10)],
        ),
      ],
      'npm',
      DEPS,
    );

    const result = attachReachability(baseFinding, idx, 'evil-pkg', 'npm');
    expect(result.reachability_level).toBe('function');
    expect(result.reachability_details).toMatchObject({
      sink_file: 'src/index.js',
      sink_line: 10,
      entry_points: ['main'],
    });
  });

  it('attaches unimported when the package is present transitively but never imported in source', () => {
    // Workspace files don't import evil-pkg even though it's a transitive dep.
    const idx: ReachabilityIndex = buildReachabilityIndex(
      [extractedFile('src/index.js', [importBinding('left-pad')], [])],
      'npm',
      [{ name: 'left-pad', namespace: null }, ...DEPS],
    );
    const result = attachReachability(baseFinding, idx, 'evil-pkg', 'npm');
    expect(result.reachability_level).toBe('unimported');
    expect(result.reachability_details).toEqual({});
  });

  it('passes through with reachability_level=null when index is null (resolver disabled)', () => {
    const result = attachReachability(baseFinding, null, 'evil-pkg', 'npm');
    expect(result.reachability_level).toBeNull();
    expect(result.reachability_details).toBeNull();
  });

  it('soft-fails when the underlying resolver throws — finding stays insertable', () => {
    // Forge an "index" whose Map.get throws, mimicking a corrupt index.
    const corruptIndex = {
      importsByDep: { get: () => { throw new Error('index corrupted'); }, size: 0 } as unknown as ReachabilityIndex['importsByDep'],
      usagesByDep: new Map(),
    } as unknown as ReachabilityIndex;

    const result = attachReachability(baseFinding, corruptIndex, 'evil-pkg', 'npm');
    expect(result.reachability_level).toBeNull();
    expect(result.reachability_details).toMatchObject({
      error: 'compute_failed',
      message: expect.stringContaining('index corrupted'),
    });
    // Critically — the rest of the finding round-trips unchanged.
    expect(result.rule_id).toBe('feed:GHSA-xxxx');
    expect(result.severity).toBe('critical');
  });
});

describe('buildWorkspaceReachabilityIndex', () => {
  const noopLog = {
    info: jest.fn(),
    warn: jest.fn(),
    success: jest.fn(),
    error: jest.fn(),
  };

  it('returns null when workspace info is missing (caller passed nothing)', async () => {
    const result = await buildWorkspaceReachabilityIndex({
      supabase: {} as any,
      projectId: 'p',
      organizationId: 'o',
      extractionRunId: 'run',
      jobId: 'job',
      packages: [],
      log: noopLog,
    });
    expect(result).toBeNull();
  });

  it('returns null when ecosystem is set but workspaceRoot is missing', async () => {
    const result = await buildWorkspaceReachabilityIndex({
      supabase: {} as any,
      projectId: 'p',
      organizationId: 'o',
      extractionRunId: 'run',
      jobId: 'job',
      packages: [],
      workspaceRoot: null,
      workspaceEcosystem: 'npm',
      log: noopLog,
    });
    expect(result).toBeNull();
  });
});

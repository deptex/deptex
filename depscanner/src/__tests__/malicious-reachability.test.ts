import {
  buildReachabilityIndex,
  computeReachability,
  emptyReachabilityIndex,
} from '../malicious/reachability';
import type {
  ExtractedFile,
  ImportBinding,
  KnownDep,
  UsageSlice,
} from '../tree-sitter-extractor';

const NPM_DEPS: KnownDep[] = [
  { name: 'lodash', namespace: null },
  { name: 'left-pad', namespace: null },
  { name: 'is-promise', namespace: null },
];

function importBinding(source: string, line = 1, kind: ImportBinding['kind'] = 'default'): ImportBinding {
  return { localName: '_', importedName: null, source, line, kind };
}

function usage(
  filePath: string,
  depName: string,
  targetType: UsageSlice['targetType'],
  containingMethod: string | null = null,
  lineNumber = 10,
): UsageSlice {
  return {
    filePath,
    lineNumber,
    containingMethod,
    targetName: depName,
    targetType,
    resolvedMethod: null,
    usageLabel: null,
    depName,
  };
}

function file(filePath: string, imports: ImportBinding[], usages: UsageSlice[]): ExtractedFile {
  return { filePath, language: 'javascript', imports, usages };
}

describe('computeReachability — 4-level decision tree', () => {
  it('returns "unimported" when no file imports the package', () => {
    const idx = emptyReachabilityIndex();
    expect(computeReachability(idx, 'lodash', 'npm')).toEqual({
      level: 'unimported',
      details: {},
    });
  });

  it('returns "unimported" when other packages are imported but not the queried one', () => {
    const files = [file('a.js', [importBinding('left-pad')], [usage('a.js', 'left-pad', 'call')])];
    const idx = buildReachabilityIndex(files, 'npm', NPM_DEPS);
    expect(computeReachability(idx, 'lodash', 'npm').level).toBe('unimported');
  });

  it('returns "imported_unused" when the package is imported but never referenced', () => {
    const files = [file('a.js', [importBinding('lodash', 3)], [])];
    const idx = buildReachabilityIndex(files, 'npm', NPM_DEPS);
    const got = computeReachability(idx, 'lodash', 'npm');
    expect(got.level).toBe('imported_unused');
    expect(got.details.sink_file).toBe('a.js');
    expect(got.details.sink_line).toBe(3);
  });

  it('returns "module" when the package is referenced as member-access only (no calls)', () => {
    const files = [
      file(
        'a.js',
        [importBinding('lodash')],
        [usage('a.js', 'lodash', 'member', null, 12)],
      ),
    ];
    const idx = buildReachabilityIndex(files, 'npm', NPM_DEPS);
    const got = computeReachability(idx, 'lodash', 'npm');
    expect(got.level).toBe('module');
    expect(got.details.sink_file).toBe('a.js');
    expect(got.details.sink_line).toBe(12);
    expect(got.details.entry_points).toBeUndefined();
  });

  it('returns "function" when the package is invoked (call)', () => {
    const files = [
      file(
        'src/handler.js',
        [importBinding('lodash')],
        [usage('src/handler.js', 'lodash', 'call', 'handleRequest', 22)],
      ),
    ];
    const idx = buildReachabilityIndex(files, 'npm', NPM_DEPS);
    const got = computeReachability(idx, 'lodash', 'npm');
    expect(got.level).toBe('function');
    expect(got.details.sink_file).toBe('src/handler.js');
    expect(got.details.sink_line).toBe(22);
    expect(got.details.entry_points).toEqual(['handleRequest']);
    expect(got.details.call_chain?.[0]).toContain('src/handler.js:22');
  });

  it('returns "function" for constructor / new / tag invocations too', () => {
    for (const targetType of ['constructor', 'new', 'tag'] as const) {
      const files = [
        file(
          'a.js',
          [importBinding('lodash')],
          [usage('a.js', 'lodash', targetType, 'm')],
        ),
      ];
      const idx = buildReachabilityIndex(files, 'npm', NPM_DEPS);
      expect(computeReachability(idx, 'lodash', 'npm').level).toBe('function');
    }
  });

  it('caps entry_points + call_chain to 5 entries', () => {
    const usages: UsageSlice[] = Array.from({ length: 12 }, (_, i) =>
      usage('a.js', 'lodash', 'call', `fn${i}`, i + 1),
    );
    const files = [file('a.js', [importBinding('lodash')], usages)];
    const idx = buildReachabilityIndex(files, 'npm', NPM_DEPS);
    const got = computeReachability(idx, 'lodash', 'npm');
    expect(got.details.entry_points?.length).toBe(5);
    expect(got.details.call_chain?.length).toBe(5);
  });

  it('upgrades from imported_unused to function when even one invocation exists', () => {
    // Two files import lodash; only one calls it. Should land on `function`.
    const files = [
      file('a.js', [importBinding('lodash')], []),
      file('b.js', [importBinding('lodash')], [usage('b.js', 'lodash', 'call', null, 5)]),
    ];
    const idx = buildReachabilityIndex(files, 'npm', NPM_DEPS);
    expect(computeReachability(idx, 'lodash', 'npm').level).toBe('function');
  });

  it('upgrades from module to function when both member-reads and calls exist', () => {
    const files = [
      file(
        'a.js',
        [importBinding('lodash')],
        [
          usage('a.js', 'lodash', 'member', null, 1),
          usage('a.js', 'lodash', 'call', 'main', 5),
        ],
      ),
    ];
    const idx = buildReachabilityIndex(files, 'npm', NPM_DEPS);
    expect(computeReachability(idx, 'lodash', 'npm').level).toBe('function');
  });
});

describe('buildReachabilityIndex — import resolution dispatch', () => {
  it('groups imports by resolved dep name (sub-path imports map to root pkg)', () => {
    // 'lodash/template' and 'lodash' both resolve to the lodash dep entry.
    const files = [
      file(
        'a.js',
        [importBinding('lodash/template'), importBinding('lodash', 2)],
        [],
      ),
    ];
    const idx = buildReachabilityIndex(files, 'npm', NPM_DEPS);
    const lodashImports = idx.importsByDep.get('lodash');
    expect(lodashImports).toBeDefined();
    expect(lodashImports!.length).toBe(2);
  });

  it('skips imports that do not resolve to any known dep', () => {
    const files = [file('a.js', [importBinding('not-installed')], [])];
    const idx = buildReachabilityIndex(files, 'npm', NPM_DEPS);
    expect(idx.importsByDep.size).toBe(0);
  });

  it('skips usages with no depName populated', () => {
    const u = usage('a.js', '', 'call');
    u.depName = null;
    const files = [file('a.js', [importBinding('lodash')], [u])];
    const idx = buildReachabilityIndex(files, 'npm', NPM_DEPS);
    expect(idx.usagesByDep.size).toBe(0);
  });
});

/**
 * v3 precision arc — npm `usedDependencies` extraction.
 *
 * Pins the two pure helpers that turn a JS/TS callgraph's external CallEdges
 * into the set of npm packages the workspace actually calls into:
 *   - `pkgFromNodeModulesPath` — single-path → package-name conversion.
 *   - `extractNpmUsedDependencies` — full edge-list → Set fan-out.
 *
 * The reachability classifier reads the resulting Set to demote
 * called-but-not-imported transitives from `unreachable` to `module` (the
 * jackson-vs-idna fix on the JS side).
 */

import {
  extractNpmUsedDependencies,
  pkgFromNodeModulesPath,
} from '../taint-engine/callgraph';
import type { CallEdge } from '../taint-engine/types';

function edge(overrides: Partial<CallEdge>): CallEdge {
  return {
    callerId: 'src/index.ts:1:1:main',
    calleeId: null,
    kind: 'static',
    filePath: 'src/index.ts',
    line: 1,
    column: 1,
    calleeText: 'lib.fn',
    argumentCount: 0,
    calleeExternalSourcePath: null,
    ...overrides,
  };
}

describe('pkgFromNodeModulesPath', () => {
  it('returns the package name for a flat dep path', () => {
    expect(
      pkgFromNodeModulesPath('/repo/node_modules/lodash/index.js'),
    ).toBe('lodash');
  });

  it('handles scoped packages (@scope/name)', () => {
    expect(
      pkgFromNodeModulesPath('/repo/node_modules/@scope/name/dist/index.js'),
    ).toBe('@scope/name');
  });

  it('credits the deepest (innermost) node_modules — express → qs', () => {
    // node_modules nesting (npm v2 / yarn classic) puts a dep under its
    // parent's node_modules. The classifier wants to credit the actual
    // transitive (qs), not the parent (express).
    expect(
      pkgFromNodeModulesPath(
        '/repo/node_modules/express/node_modules/qs/lib/parse.js',
      ),
    ).toBe('qs');
  });

  it('normalizes Windows backslashes', () => {
    expect(
      pkgFromNodeModulesPath(
        'C:\\repo\\node_modules\\lodash\\index.js',
      ),
    ).toBe('lodash');
  });

  it('returns null for paths outside node_modules (ambient lib.d.ts)', () => {
    expect(
      pkgFromNodeModulesPath('/usr/lib/node/lib.dom.d.ts'),
    ).toBeNull();
  });

  it('returns null for a malformed path with trailing slash', () => {
    expect(
      pkgFromNodeModulesPath('/repo/node_modules/'),
    ).toBeNull();
  });

  it('returns null for a scoped path missing the name segment', () => {
    // `@scope` with nothing after is junk — refuse rather than emit a
    // half-name that won't match any SBOM purl.
    expect(
      pkgFromNodeModulesPath('/repo/node_modules/@scope'),
    ).toBeNull();
  });
});

describe('extractNpmUsedDependencies', () => {
  it('returns an empty set when no edge has an external source path', () => {
    const edges: CallEdge[] = [
      edge({ calleeExternalSourcePath: null }),
      edge({ calleeExternalSourcePath: undefined }),
    ];
    expect(extractNpmUsedDependencies(edges)).toEqual(new Set());
  });

  it('credits packages from non-null external paths', () => {
    const edges: CallEdge[] = [
      edge({ calleeExternalSourcePath: '/repo/node_modules/lodash/index.js' }),
      edge({ calleeExternalSourcePath: '/repo/node_modules/express/lib/request.js' }),
    ];
    expect(extractNpmUsedDependencies(edges)).toEqual(new Set(['lodash', 'express']));
  });

  it('deduplicates multiple call edges into the same package', () => {
    const edges: CallEdge[] = [
      edge({ calleeExternalSourcePath: '/repo/node_modules/lodash/index.js' }),
      edge({ calleeExternalSourcePath: '/repo/node_modules/lodash/fp/index.js' }),
      edge({ calleeExternalSourcePath: '/repo/node_modules/lodash/array.js' }),
    ];
    expect(extractNpmUsedDependencies(edges)).toEqual(new Set(['lodash']));
  });

  it('handles scoped + nested + workspace-internal in the same edge list', () => {
    const edges: CallEdge[] = [
      edge({ calleeExternalSourcePath: '/repo/node_modules/@scope/name/index.js' }),
      edge({ calleeExternalSourcePath: '/repo/node_modules/express/node_modules/qs/parse.js' }),
      edge({ calleeExternalSourcePath: '/repo/src/internal.ts' }), // workspace-internal, no node_modules
      edge({ calleeExternalSourcePath: null }), // unresolved external
    ];
    expect(extractNpmUsedDependencies(edges)).toEqual(
      new Set(['@scope/name', 'qs']),
    );
  });

  it('skips ambient lib.d.ts and other non-node_modules externals', () => {
    const edges: CallEdge[] = [
      edge({ calleeExternalSourcePath: '/usr/lib/node/lib.dom.d.ts' }),
      edge({ calleeExternalSourcePath: '/usr/include/typescript/lib.es5.d.ts' }),
    ];
    expect(extractNpmUsedDependencies(edges)).toEqual(new Set());
  });

  it('returns an empty set for an empty edge list', () => {
    expect(extractNpmUsedDependencies([])).toEqual(new Set());
  });
});

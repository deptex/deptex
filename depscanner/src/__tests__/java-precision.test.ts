/**
 * v3 precision arc — Java/maven matcher pinning.
 *
 * Two surfaces:
 *   - `depMatchesUsedTransitives`: the bidirectional matcher
 *     `reachability.ts` uses to decide whether the callgraph signal
 *     credits a PDV. Pure function; full unit coverage here.
 *   - `extractJavaUsedDependencies`: the Java callgraph extractor that
 *     produces the Set from per-file import tables. Tested with a
 *     hand-constructed JavaFileIndex shape (fields match exactly).
 *
 * The maven jackson-vs-idna case:
 *   - PDV `jackson-core` namespace `com.fasterxml.jackson.core`
 *   - Workspace imports `com.fasterxml.jackson.databind.ObjectMapper`
 *   - Java extractor emits `com.fasterxml.jackson.databind` PLUS the
 *     ancestor `com.fasterxml.jackson`
 *   - depMatchesUsedTransitives checks `lowerNs.startsWith(used + '.')`
 *     → `com.fasterxml.jackson.core`.startsWith(`com.fasterxml.jackson` + `.`)
 *     → TRUE → jackson-core credited as reached → demoted from
 *     unreachable to module
 */

import { depMatchesUsedTransitives } from '../reachability';
import { extractJavaUsedDependencies } from '../taint-engine/java/callgraph';

describe('depMatchesUsedTransitives — npm path (lowercase exact match)', () => {
  it('matches an npm package name directly', () => {
    expect(depMatchesUsedTransitives('lodash', null, new Set(['lodash']))).toBe(true);
  });

  it('matches case-insensitively', () => {
    expect(depMatchesUsedTransitives('Lodash', null, new Set(['lodash']))).toBe(true);
    expect(depMatchesUsedTransitives('lodash', null, new Set(['Lodash']))).toBe(false); // set is the source of truth — caller lowercases
  });

  it('matches scoped npm packages exactly', () => {
    expect(depMatchesUsedTransitives('@scope/name', null, new Set(['@scope/name']))).toBe(true);
  });

  it('returns false when usedTransitives is empty', () => {
    expect(depMatchesUsedTransitives('lodash', null, new Set())).toBe(false);
  });

  it('returns false when depName is empty/null', () => {
    expect(depMatchesUsedTransitives(null, null, new Set(['lodash']))).toBe(false);
    expect(depMatchesUsedTransitives('', null, new Set(['lodash']))).toBe(false);
  });
});

describe('depMatchesUsedTransitives — maven namespace prefix match', () => {
  it('matches when namespace IS in the set (exact)', () => {
    expect(
      depMatchesUsedTransitives(
        'spring-web',
        'org.springframework.web',
        new Set(['org.springframework.web']),
      ),
    ).toBe(true);
  });

  it('matches via bidirectional ancestor — jackson-core credited by jackson.databind import', () => {
    // PDV: groupId com.fasterxml.jackson.core, artifactId jackson-core.
    // Workspace imports com.fasterxml.jackson.databind.* — the Java
    // extractor emits the ancestor com.fasterxml.jackson, which is a
    // strict prefix of com.fasterxml.jackson.core.
    expect(
      depMatchesUsedTransitives(
        'jackson-core',
        'com.fasterxml.jackson.core',
        new Set(['com.fasterxml.jackson', 'com.fasterxml.jackson.databind']),
      ),
    ).toBe(true);
  });

  it('matches when groupId is a strict prefix of a used FQN', () => {
    // PDV groupId `org.springframework` ⊂ used FQN
    // `org.springframework.boot.autoconfigure`.
    expect(
      depMatchesUsedTransitives(
        'spring-context',
        'org.springframework',
        new Set(['org.springframework.boot.autoconfigure']),
      ),
    ).toBe(true);
  });

  it('does NOT match when namespace shares only a too-shallow ancestor', () => {
    // `org.junit` vs `org.springframework` share only `org` — which the
    // Java extractor never emits (TOO_SHALLOW filter), so the matcher
    // correctly returns false. Simulated here by constructing a Set
    // that the extractor would actually produce.
    expect(
      depMatchesUsedTransitives(
        'junit-jupiter',
        'org.junit.jupiter',
        new Set(['org.springframework', 'org.springframework.web']),
      ),
    ).toBe(false);
  });

  it('matches via artifactId hyphen→dot substring (fallback for shaded jars)', () => {
    // Artifact `jackson-databind`, groupId mismatch (some shaded forks
    // bury jackson under a different groupId). Hyphen→dot fallback:
    // `jackson.databind` is a substring of `com.fasterxml.jackson.databind`.
    expect(
      depMatchesUsedTransitives(
        'jackson-databind',
        'unrelated.shaded.group',
        new Set(['com.fasterxml.jackson.databind']),
      ),
    ).toBe(true);
  });

  it('does NOT match a short token via the hyphen→dot fallback (avoids false positives)', () => {
    // `aws-s3` → `aws.s3` (6 chars) — too generic to substring-match
    // safely against arbitrary FQN packages.
    // The matcher rejects dotted tokens shorter than 5 chars OR without
    // a dot — `aws.s3` is exactly 6 chars w/ a dot so it WOULD match.
    // Verify the lower bound: `a-b` → `a.b` (3 chars) MUST NOT match.
    expect(
      depMatchesUsedTransitives(
        'a-b',
        null,
        new Set(['com.x.a.b.something']),
      ),
    ).toBe(false);
  });
});

describe('extractJavaUsedDependencies', () => {
  // Build a minimal JavaFileIndex shape — we only need imports +
  // wildcardImports + classesBySimpleName for the extractor.
  function mkFile(opts: {
    imports?: Array<[string, string]>;
    wildcards?: string[];
    classes?: string[];
  }): any {
    return {
      filePath: 'src/main.java',
      relativePath: 'src/main.java',
      tree: null,
      source: '',
      packageName: 'com.example.app',
      imports: new Map(opts.imports ?? []),
      wildcardImports: opts.wildcards ?? [],
      classesBySimpleName: new Map((opts.classes ?? []).map((c) => [c, null])),
    };
  }

  function mkClassMap(entries: Array<[string, string]>): Map<string, string> {
    return new Map(entries);
  }

  it('emits package + ancestors for an external import', () => {
    const files = [
      mkFile({
        imports: [
          ['ObjectMapper', 'com.fasterxml.jackson.databind.ObjectMapper'],
        ],
      }),
    ];
    const used = extractJavaUsedDependencies(files, mkClassMap([]));
    expect(used).toContain('com.fasterxml.jackson.databind');
    expect(used).toContain('com.fasterxml.jackson');
    expect(used).toContain('com.fasterxml');
    // Too-shallow root excluded.
    expect(used.has('com')).toBe(false);
  });

  it('skips imports that resolve to a workspace class', () => {
    const files = [
      mkFile({
        imports: [
          // This import resolves to a class we extracted from the workspace.
          ['Helper', 'com.example.app.Helper'],
        ],
      }),
    ];
    const used = extractJavaUsedDependencies(
      files,
      mkClassMap([['Helper', 'com.example.app.Helper']]),
    );
    // None of com.example.app.Helper's ancestors should appear because
    // it's a workspace-internal class.
    expect(used.has('com.example.app')).toBe(false);
  });

  it('handles wildcard imports — emits the wildcard root + ancestors', () => {
    const files = [
      mkFile({
        wildcards: ['org.springframework.web.servlet'],
      }),
    ];
    const used = extractJavaUsedDependencies(files, mkClassMap([]));
    expect(used).toContain('org.springframework.web.servlet');
    expect(used).toContain('org.springframework.web');
    expect(used).toContain('org.springframework');
    expect(used.has('org')).toBe(false);
  });

  it('returns an empty set for files with no external imports', () => {
    const used = extractJavaUsedDependencies([mkFile({})], mkClassMap([]));
    expect(used).toEqual(new Set());
  });

  it('jackson-vs-idna scenario — Spring import in app credits jackson-core via ancestor', () => {
    // The exact scenario the precision arc was designed for.
    const files = [
      mkFile({
        imports: [
          // petclinic-style: Spring source uses Jackson annotations.
          ['JsonIgnore', 'com.fasterxml.jackson.annotation.JsonIgnore'],
          ['ObjectMapper', 'com.fasterxml.jackson.databind.ObjectMapper'],
        ],
      }),
    ];
    const used = extractJavaUsedDependencies(files, mkClassMap([]));
    // jackson-core PDV with groupId com.fasterxml.jackson.core should be
    // credited via the common ancestor.
    const jacksonCoreMatched = depMatchesUsedTransitives(
      'jackson-core',
      'com.fasterxml.jackson.core',
      used,
    );
    expect(jacksonCoreMatched).toBe(true);
    // An unrelated groupId should NOT be credited.
    const idnaStyleMatched = depMatchesUsedTransitives(
      'unrelated-lib',
      'org.unrelated.lib',
      used,
    );
    expect(idnaStyleMatched).toBe(false);
  });
});

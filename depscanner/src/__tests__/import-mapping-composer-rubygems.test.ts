/**
 * Tests for the composer + rubygems import resolvers after the v3
 * follow-up fixes:
 *
 * - composer.ts: build vendor/name lookup key from KnownDep.namespace +
 *   KnownDep.name. cdxgen emits composer SBOM entries with split
 *   name+group, so flat-name lookup never resolves and all
 *   `filesImporting` counters stay at 0 (the symfony-demo 0/105 case
 *   surfaced by the v3-final-8eco corpus run).
 *
 * - rubygems.ts: emit a separators-stripped variant (`active_record` →
 *   `activerecord`) so Rails 5+ split-package names resolve. Also
 *   verify the `mapped + variants` co-emission fallback survives an
 *   out-of-date REQUIRE_TO_GEM entry.
 */

import { resolveComposerImport } from '../tree-sitter-extractor/import-mapping/composer';
import { resolveRubygemsImport } from '../tree-sitter-extractor/import-mapping/rubygems';

describe('resolveComposerImport (vendor/name lookup)', () => {
  it('resolves `Symfony\\Component\\HttpFoundation` against KnownDep with namespace+name', () => {
    const deps = [
      { name: 'http-foundation', namespace: 'symfony' },
      { name: 'console', namespace: 'symfony' },
      { name: 'monolog', namespace: 'monolog' },
    ];
    expect(
      resolveComposerImport('Symfony\\Component\\HttpFoundation\\Request', deps),
    ).toBe('http-foundation');
  });

  it('resolves vendor-only single-package vendors', () => {
    const deps = [
      { name: 'monolog', namespace: 'monolog' },
    ];
    expect(resolveComposerImport('Monolog\\Logger', deps)).toBe('monolog');
  });

  it('skips KNOWN_INTERIOR_SEGMENTS (Component, Contracts, Bundle, Bridge)', () => {
    const deps = [{ name: 'http-foundation', namespace: 'symfony' }];
    // Without skipping `Component`, the lookup key would be
    // `symfony/component-http-foundation` and would miss.
    expect(resolveComposerImport('Symfony\\Component\\HttpFoundation\\Request', deps)).toBe(
      'http-foundation',
    );
  });

  it('returns null when no candidate matches', () => {
    const deps = [{ name: 'console', namespace: 'symfony' }];
    expect(resolveComposerImport('Doctrine\\DBAL\\Connection', deps)).toBeNull();
  });

  it('falls back to bare name when KnownDep has no namespace (vendor-only edge case)', () => {
    const deps = [
      { name: 'monolog', namespace: null },
    ];
    expect(resolveComposerImport('Monolog\\Logger', deps)).toBe('monolog');
  });

  it('returns the first candidate stripped to its name when no knownDeps provided', () => {
    // Probe path, used in tests / standalone callers.
    expect(resolveComposerImport('Symfony\\Component\\Console')).toMatch(/symfony|console/);
  });
});

describe('resolveRubygemsImport (separators-stripped variant)', () => {
  it('resolves `active_record` against `activerecord` via stripped variant', () => {
    const deps = ['activerecord', 'actionpack', 'railties'];
    expect(resolveRubygemsImport('active_record', deps)).toBe('activerecord');
  });

  it('resolves `action_view` against `actionview` (Rails 5+ split)', () => {
    const deps = ['actionview', 'actionpack', 'railties'];
    expect(resolveRubygemsImport('action_view', deps)).toBe('actionview');
  });

  it('resolves `action_view/template/handlers` (subpath require) against `actionview`', () => {
    const deps = ['actionview'];
    expect(resolveRubygemsImport('action_view/template/handlers', deps)).toBe('actionview');
  });

  it('still resolves hyphen↔underscore variants (rest_client → rest-client)', () => {
    const deps = ['rest-client'];
    expect(resolveRubygemsImport('rest_client', deps)).toBe('rest-client');
  });

  it('returns null when no variant matches any known dep', () => {
    expect(resolveRubygemsImport('non_existent', ['actionpack', 'rack'])).toBeNull();
  });

  it('falls back to variants when REQUIRE_TO_GEM target is also not in deps', () => {
    // `rest_client` maps to `rest-client` via REQUIRE_TO_GEM, but the
    // dep list might just have `rest_client` (underscore form). The
    // resolver should ALSO try the natural variants.
    const deps = ['rest_client'];
    expect(resolveRubygemsImport('rest_client', deps)).toBe('rest_client');
  });
});

/**
 * Tests for the composer.lock and Gemfile.lock parsers.
 *
 * Both resolvers are pure file-parse — no subprocess. The resolver
 * function itself reads via fs.readFileSync; we exercise it directly
 * against fixtures written into a tmpdir to keep tests hermetic.
 *
 * These tests cover the v3-final-8eco diagnosis where symfony-demo
 * returned 105 cdxgen deps and discourse returned 208 cdxgen deps —
 * after this work, the corresponding composer.lock and Gemfile.lock
 * should expand both substantially via the new resolvers.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { resolveComposerTransitives } from '../transitive-resolvers/composer';
import { resolveRubygemsTransitives } from '../transitive-resolvers/rubygems';

function withTempRepo(write: (root: string) => void): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'resolver-test-'));
  write(root);
  return root;
}

describe('resolveComposerTransitives', () => {
  it('returns null when composer.lock is absent (soft-fail)', async () => {
    const root = withTempRepo(() => {});
    try {
      const result = await resolveComposerTransitives(root);
      expect(result).toBeNull();
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('parses composer.lock packages + packages-dev into vendor/name deps', async () => {
    const lock = {
      packages: [
        { name: 'symfony/console', version: 'v5.0.1', type: 'library' },
        { name: 'monolog/monolog', version: '2.1.0', type: 'library' },
        { name: 'psr/log', version: '1.1.3', type: 'library' },
      ],
      'packages-dev': [
        { name: 'phpunit/phpunit', version: '9.5.0', type: 'library' },
      ],
    };
    const root = withTempRepo((r) => {
      fs.writeFileSync(path.join(r, 'composer.lock'), JSON.stringify(lock));
    });
    try {
      const result = await resolveComposerTransitives(root);
      expect(result).not.toBeNull();
      expect(result!.deps).toHaveLength(4);
      expect(result!.source).toBe('composer-lock-parse');
      // Verify namespace + name split, with leading v stripped.
      const console = result!.deps.find((d) => d.name === 'console');
      expect(console).toBeDefined();
      expect(console!.namespace).toBe('symfony');
      expect(console!.version).toBe('5.0.1');
      // packages-dev entries must be present (they may still carry CVEs).
      expect(result!.deps.find((d) => d.name === 'phpunit')).toBeDefined();
      // Every emitted dep is non-direct so the classifier's heuristic-unreachable
      // gate (!is_direct) is reachable.
      expect(result!.deps.every((d) => d.is_direct === false)).toBe(true);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('skips composer.lock entries missing name or version', async () => {
    const lock = {
      packages: [
        { name: 'symfony/console', version: '5.0.0' },
        { name: 'broken/missing-version' }, // skip
        { version: '1.0.0' }, // skip
        {}, // skip
      ],
    };
    const root = withTempRepo((r) => {
      fs.writeFileSync(path.join(r, 'composer.lock'), JSON.stringify(lock));
    });
    try {
      const result = await resolveComposerTransitives(root);
      expect(result!.deps).toHaveLength(1);
      expect(result!.deps[0].name).toBe('console');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('throws on malformed composer.lock JSON', async () => {
    const root = withTempRepo((r) => {
      fs.writeFileSync(path.join(r, 'composer.lock'), '{not valid json');
    });
    try {
      await expect(resolveComposerTransitives(root)).rejects.toThrow(
        /composer\.lock parse failed/,
      );
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('resolveRubygemsTransitives', () => {
  it('returns null when Gemfile.lock is absent (soft-fail)', async () => {
    const root = withTempRepo(() => {});
    try {
      const result = await resolveRubygemsTransitives(root);
      expect(result).toBeNull();
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('parses Gemfile.lock specs into deps', async () => {
    const lock = `GEM
  remote: https://rubygems.org/
  specs:
    actionpack (5.2.0)
      actionview (= 5.2.0)
      activesupport (= 5.2.0)
      rack (~> 2.0)
    actionview (5.2.0)
      activesupport (= 5.2.0)
    activesupport (5.2.0)
      i18n (~> 1.0)
    rack (2.2.3)
    i18n (1.8.5)

PLATFORMS
  ruby

DEPENDENCIES
  actionpack

BUNDLED WITH
   2.1.4
`;
    const root = withTempRepo((r) => {
      fs.writeFileSync(path.join(r, 'Gemfile.lock'), lock);
    });
    try {
      const result = await resolveRubygemsTransitives(root);
      expect(result).not.toBeNull();
      expect(result!.source).toBe('gemfile-lock-parse');
      const names = result!.deps.map((d) => d.name).sort();
      expect(names).toEqual(['actionpack', 'actionview', 'activesupport', 'i18n', 'rack']);
      const actionpack = result!.deps.find((d) => d.name === 'actionpack');
      expect(actionpack!.version).toBe('5.2.0');
      expect(actionpack!.is_direct).toBe(false);
      expect(actionpack!.namespace).toBeNull();
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('handles multiple source blocks (GIT + GEM) and dedupes name@version', async () => {
    const lock = `GIT
  remote: https://github.com/user/awesome.git
  revision: abc123
  specs:
    awesome (0.1.0)
      rack (>= 1.0)

GEM
  remote: https://rubygems.org/
  specs:
    awesome (0.1.0)
    rack (2.2.3)

PLATFORMS
  ruby
`;
    const root = withTempRepo((r) => {
      fs.writeFileSync(path.join(r, 'Gemfile.lock'), lock);
    });
    try {
      const result = await resolveRubygemsTransitives(root);
      // `awesome (0.1.0)` appears in both blocks but should dedupe.
      expect(result!.deps.filter((d) => d.name === 'awesome')).toHaveLength(1);
      expect(result!.deps).toHaveLength(2);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('ignores nested constraint lines (4-space-indented) under each spec', async () => {
    const lock = `GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.0)
      actionview (= 7.0.0)
      activesupport (= 7.0.0)
    actionview (7.0.0)
      activesupport (= 7.0.0)

PLATFORMS
  ruby
`;
    const root = withTempRepo((r) => {
      fs.writeFileSync(path.join(r, 'Gemfile.lock'), lock);
    });
    try {
      const result = await resolveRubygemsTransitives(root);
      // 2 specs, NOT 4 — constraint lines should not register as deps.
      expect(result!.deps).toHaveLength(2);
      expect(result!.deps.map((d) => d.name).sort()).toEqual(['actionpack', 'actionview']);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

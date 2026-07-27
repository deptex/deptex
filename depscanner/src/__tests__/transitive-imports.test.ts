/**
 * Arc 2 — transitive import index: pure membership/veto semantics.
 *
 * The load-bearing rules under test:
 *   - descendant-counts-as-imported, ancestor does NOT (per ecosystem separator)
 *   - OWNER EXCLUSION: the finding's own package's self-hits are never evidence
 *   - positive answers valid on any status; `unavailable` answers nothing
 *   - the veto helper is the single pypi entry point (modules OR tokens)
 */

import {
  emptyTransitiveImportIndex,
  transitiveConsumerVeto,
  transitiveModuleImported,
  transitiveTokenHit,
  unionImportedModules,
  type TransitiveImportIndex,
} from '../transitive-imports';

function pypiIndex(
  entries: Record<string, { modules?: string[]; tokens?: string[] }>,
  status: TransitiveImportIndex['status'] = 'partial',
): TransitiveImportIndex {
  const idx = emptyTransitiveImportIndex('pypi');
  idx.status = status;
  for (const [pkg, { modules = [], tokens = [] }] of Object.entries(entries)) {
    idx.perPackage.set(pkg, { modules: new Set(modules), tokenHits: new Set(tokens) });
    idx.extractedPackages.add(pkg);
  }
  return idx;
}

function goIndex(modules: string[], status: TransitiveImportIndex['status'] = 'complete'): TransitiveImportIndex {
  const idx = emptyTransitiveImportIndex('golang');
  idx.status = status;
  idx.perPackage.set('__main__', { modules: new Set(modules), tokenHits: new Set() });
  idx.extractedPackages.add('__main__');
  return idx;
}

const NO_OWNERS = new Set<string>();

describe('transitiveModuleImported — descendant semantics per ecosystem', () => {
  it('pypi: exact and descendant (dot) match; ancestor does not', () => {
    const idx = pypiIndex({ captcha: { modules: ['pil.imagefont.core'] } });
    expect(transitiveModuleImported(idx, 'pil.imagefont', NO_OWNERS)).toBe(true);
    expect(transitiveModuleImported(idx, 'pil.imagefont.core', NO_OWNERS)).toBe(true);
    // ancestor import does not load the submodule
    const anc = pypiIndex({ someapp: { modules: ['pil'] } });
    expect(transitiveModuleImported(anc, 'pil.imagefont', NO_OWNERS)).toBe(false);
    // dotted prefix must be a path boundary, not a string prefix
    const near = pypiIndex({ someapp: { modules: ['pil.imagefontx'] } });
    expect(transitiveModuleImported(near, 'pil.imagefont', NO_OWNERS)).toBe(false);
  });

  it('golang: slash separator', () => {
    const idx = goIndex(['golang.org/x/crypto/ssh/agent']);
    expect(transitiveModuleImported(idx, 'golang.org/x/crypto/ssh', NO_OWNERS)).toBe(true);
    expect(transitiveModuleImported(idx, 'golang.org/x/crypto/ssh/agent', NO_OWNERS)).toBe(true);
    expect(transitiveModuleImported(idx, 'golang.org/x/crypto/ssh/knownhosts', NO_OWNERS)).toBe(false);
    // ancestor import does not pull the child
    const anc = goIndex(['golang.org/x/crypto/ssh']);
    expect(transitiveModuleImported(anc, 'golang.org/x/crypto/ssh/agent', NO_OWNERS)).toBe(false);
  });
});

describe('owner exclusion — self-hits are never evidence', () => {
  it('the owner package importing/mentioning its own submodule is excluded', () => {
    // pillow's own wheel contains ImageFont.py — the classic self-hit.
    const idx = pypiIndex({
      pillow: { modules: ['pil.imagefont'], tokens: ['imagefont'] },
    });
    const owners = new Set(['pillow']);
    expect(transitiveModuleImported(idx, 'pil.imagefont', owners)).toBe(false);
    expect(transitiveTokenHit(idx, ['imagefont'], owners)).toBe(false);
    // ...but a REAL third-party consumer still vetoes.
    idx.perPackage.set('captcha', { modules: new Set(['pil.imagefont']), tokenHits: new Set() });
    expect(transitiveModuleImported(idx, 'pil.imagefont', owners)).toBe(true);
  });
});

describe('transitiveConsumerVeto — the single pypi entry point', () => {
  const question = { modules: ['pil.imagefont'], tokens: ['imagefont', 'truetype('] };

  it('vetoes on a non-owner module import', () => {
    const idx = pypiIndex({ captcha: { modules: ['pil.imagefont'] } });
    expect(transitiveConsumerVeto(idx, question, ['pillow'])).toBe(true);
  });

  it('vetoes on a non-owner token hit (the importlib/dynamic-import hole)', () => {
    const idx = pypiIndex({ weirdlib: { tokens: ['truetype('] } });
    expect(transitiveConsumerVeto(idx, question, ['pillow'])).toBe(true);
  });

  it('owner-self-mention-only does NOT veto (demotions keep firing)', () => {
    const idx = pypiIndex({ pillow: { modules: ['pil.imagefont'], tokens: ['imagefont'] } });
    expect(transitiveConsumerVeto(idx, question, ['pillow'])).toBe(false);
  });

  it('positive evidence is valid on a partial index', () => {
    const idx = pypiIndex({ captcha: { modules: ['pil.imagefont'] } }, 'partial');
    idx.failedPackages.push('somefaileddist');
    expect(transitiveConsumerVeto(idx, question, ['pillow'])).toBe(true);
  });

  it('unavailable index answers nothing; null index answers nothing', () => {
    const idx = pypiIndex({ captcha: { modules: ['pil.imagefont'] } }, 'unavailable');
    expect(transitiveConsumerVeto(idx, question, ['pillow'])).toBe(false);
    expect(transitiveConsumerVeto(null, question, ['pillow'])).toBe(false);
    expect(transitiveConsumerVeto(undefined, question, ['pillow'])).toBe(false);
  });

  it('empty question never vetoes', () => {
    const idx = pypiIndex({ captcha: { modules: ['pil.imagefont'], tokens: ['imagefont'] } });
    expect(transitiveConsumerVeto(idx, {}, [])).toBe(false);
  });
});

describe('unionImportedModules — the Go flat membership set', () => {
  it('unions across packages', () => {
    const idx = emptyTransitiveImportIndex('golang');
    idx.perPackage.set('a', { modules: new Set(['golang.org/x/net/idna']), tokenHits: new Set() });
    idx.perPackage.set('b', { modules: new Set(['golang.org/x/net/http2']), tokenHits: new Set() });
    const union = unionImportedModules(idx);
    expect(union.has('golang.org/x/net/idna')).toBe(true);
    expect(union.has('golang.org/x/net/http2')).toBe(true);
    expect(union.size).toBe(2);
  });
});

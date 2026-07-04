/**
 * Arc 2 — dep-import-graph pipeline step: the pure/fs-level pieces.
 *
 *   - parseGoListOutput / enumerateGoModules (the multi-module MUST-FIX:
 *     `./...` does not cross go.mod boundaries, so nested modules must be
 *     enumerated or the compile set is complete-but-wrong)
 *   - pypiExtractorVersion (registry-hash cache invalidation)
 *   - questionRelevantImports (the cache-row subset predicate)
 *   - extractDistSummary over mkdtemp fake wheels (imports + token hits,
 *     compiled/empty wheel → null = FAILED-not-clean, caps → null)
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  enumerateGoModules,
  extractDistSummary,
  parseGoListOutput,
  pypiExtractorVersion,
  questionRelevantImports,
} from '../pipeline-steps/dep-import-graph';
import { djangoTransitiveQuestionRegistry } from '../reachability-django-preconditions';

describe('parseGoListOutput', () => {
  it('one import path per non-empty line, whitespace-trimmed', () => {
    const out = parseGoListOutput('fmt\ngolang.org/x/net/idna\n\n  github.com/a/b  \n');
    expect(out).toEqual(['fmt', 'golang.org/x/net/idna', 'github.com/a/b']);
  });
});

describe('enumerateGoModules', () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gomods-'));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('finds the root module and NESTED modules, skipping vendor/ and testdata/', () => {
    fs.writeFileSync(path.join(dir, 'go.mod'), 'module example.com/root\n');
    fs.mkdirSync(path.join(dir, 'cli'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'cli', 'go.mod'), 'module example.com/root/cli\n');
    fs.mkdirSync(path.join(dir, 'vendor', 'dep'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'vendor', 'dep', 'go.mod'), 'module vendored\n');
    fs.mkdirSync(path.join(dir, 'testdata', 'fixture'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'testdata', 'fixture', 'go.mod'), 'module fixture\n');

    const mods = enumerateGoModules(dir).map((m) => path.relative(dir, m) || '.');
    expect(mods).toContain('.');
    expect(mods).toContain('cli');
    expect(mods).not.toContain(path.join('vendor', 'dep'));
    expect(mods).not.toContain(path.join('testdata', 'fixture'));
  });

  it('returns empty for a workspace with no go.mod anywhere', () => {
    fs.writeFileSync(path.join(dir, 'main.go'), 'package main\n');
    expect(enumerateGoModules(dir)).toEqual([]);
  });
});

describe('pypiExtractorVersion', () => {
  it('changes when the question registry changes (cache invalidation)', () => {
    const a = pypiExtractorVersion({ modules: ['pil.imagefont'], tokens: ['imagefont'], owners: [] });
    const b = pypiExtractorVersion({ modules: ['pil.imagefont'], tokens: ['imagefont', 'truetype('], owners: [] });
    expect(a).not.toBe(b);
    expect(a).toMatch(/^arc2-v1:/);
    // owners are the trigger list, not extraction behavior — no invalidation
    const c = pypiExtractorVersion({ modules: ['pil.imagefont'], tokens: ['imagefont'], owners: ['pillow'] });
    expect(c).toBe(a);
  });
});

describe('questionRelevantImports', () => {
  it('keeps exact + descendant matches only', () => {
    const kept = questionRelevantImports(
      ['pil.imagefont', 'pil.imagefont.core', 'pil.image', 'pil', 'fonttools.misc', 'requests'],
      ['pil.imagefont', 'fonttools'],
    );
    expect(kept.sort()).toEqual(['fonttools.misc', 'pil.imagefont', 'pil.imagefont.core']);
  });
});

describe('extractDistSummary', () => {
  const registry = djangoTransitiveQuestionRegistry();
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dist-'));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('extracts question-relevant imports and token hits from .py sources', () => {
    fs.mkdirSync(path.join(dir, 'captcha'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'captcha', 'image.py'),
      'from PIL import ImageFont\nfont = ImageFont.truetype("x.ttf", 12)\nimport requests\n',
    );
    const s = extractDistSummary(dir, registry);
    expect(s).not.toBeNull();
    expect(s!.modules).toContain('pil.imagefont');
    expect(s!.tokenHits).toContain('imagefont');
    expect(s!.tokenHits).toContain('truetype(');
    // non-question imports are NOT stored (cache-row subset)
    expect(s!.modules).not.toContain('requests');
  });

  it('catches dotted module strings in non-.py metadata (entry_points plugin registries)', () => {
    fs.mkdirSync(path.join(dir, 'pkg-1.0.dist-info'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'pkg'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'pkg', 'mod.py'), 'x = 1\n');
    fs.writeFileSync(
      path.join(dir, 'pkg-1.0.dist-info', 'entry_points.txt'),
      '[myapp.plugins]\nfonts = pkg.backends:load  # drives tqdm.cli under the hood\n',
    );
    const s = extractDistSummary(dir, registry);
    expect(s).not.toBeNull();
    expect(s!.tokenHits).toContain('tqdm.cli');
  });

  it('a dist with ZERO .py files (compiled/empty wheel) is null — failed, never scanned-clean', () => {
    fs.writeFileSync(path.join(dir, 'native.so'), Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
    expect(extractDistSummary(dir, registry)).toBeNull();
  });

  it('an oversize file trips the cap → null (unknown)', () => {
    fs.writeFileSync(path.join(dir, 'big.py'), 'x = 1\n' + '#'.repeat(2 * 1024 * 1024 + 10));
    expect(extractDistSummary(dir, registry)).toBeNull();
  });

  it('an importlib-style dynamic import is caught by the token scan, not the import parser', () => {
    fs.writeFileSync(
      path.join(dir, 'dyn.py'),
      'import importlib\nmod = importlib.import_module("PIL.ImageFont")\n',
    );
    const s = extractDistSummary(dir, registry);
    expect(s).not.toBeNull();
    expect(s!.modules).not.toContain('pil.imagefont'); // parser can't see it
    expect(s!.tokenHits).toContain('imagefont'); // the token scan can
  });
});

/**
 * Base-image catalog loader + lookup tests. Exercises both the shipped
 * catalog YAML and synthetic malformed YAML written to temp files.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  loadCatalog,
  lookupAlternatives,
  catalogHash,
  normalizeImageRef,
  CatalogValidationError,
  _resetCatalogCacheForTests,
} from '../base-image-catalog';

function writeTempYaml(name: string, body: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `deptex-catalog-${name}-`));
  const file = path.join(dir, 'catalog.yaml');
  fs.writeFileSync(file, body);
  return file;
}

beforeEach(() => {
  _resetCatalogCacheForTests();
});

describe('shipped catalog', () => {
  it('loads and validates the bundled base-image-catalog.yaml', () => {
    const catalog = loadCatalog();
    expect(catalog.families.length).toBeGreaterThan(5);
  });

  it('every alternative in the shipped catalog has well-formed fields', () => {
    const catalog = loadCatalog();
    for (const fam of catalog.families) {
      for (const src of fam.sources) {
        expect(src.alternatives.length).toBeGreaterThan(0);
        for (const alt of src.alternatives) {
          expect(alt.image.length).toBeGreaterThan(0);
          expect(alt.drop_in_score).toBeGreaterThanOrEqual(0);
          expect(alt.drop_in_score).toBeLessThanOrEqual(100);
          expect(alt.cve_count).toBeGreaterThanOrEqual(0);
        }
      }
    }
  });
});

describe('lookupAlternatives', () => {
  it('returns chainguard and dhi alternatives for node:20-bullseye', () => {
    const result = lookupAlternatives('node:20-bullseye');
    expect(result).not.toBeNull();
    const providers = result!.alternatives.map((a) => a.provider);
    expect(providers).toContain('chainguard');
    expect(providers).toContain('dhi');
    expect(result!.family).toBe('node');
  });

  it('returns null for an image not in the catalog', () => {
    expect(lookupAlternatives('acme/internal-app:1.2.3')).toBeNull();
  });

  it('matches case-insensitively', () => {
    expect(lookupAlternatives('NODE:20-Bullseye')).not.toBeNull();
  });

  it('strips a digest before matching', () => {
    const withDigest = `node:20-bullseye@sha256:${'a'.repeat(64)}`;
    expect(lookupAlternatives(withDigest)).not.toBeNull();
  });
});

describe('caching + hashing', () => {
  it('memoizes the catalog across calls within a worker process', () => {
    const a = loadCatalog();
    const b = loadCatalog();
    expect(a).toBe(b); // same object reference
  });

  it('produces a stable hash across repeated loads', () => {
    const h1 = catalogHash(loadCatalog());
    _resetCatalogCacheForTests();
    const h2 = catalogHash(loadCatalog());
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^[a-f0-9]{16}$/);
  });
});

describe('schema validation', () => {
  it('rejects a YAML whose root is not a mapping', () => {
    const file = writeTempYaml('root', '- just\n- a\n- list\n');
    expect(() => loadCatalog(file)).toThrow(CatalogValidationError);
  });

  it('rejects a families entry missing the family name', () => {
    const file = writeTempYaml(
      'no-family',
      'families:\n  - sources: []\n'
    );
    expect(() => loadCatalog(file)).toThrow(CatalogValidationError);
  });

  it('rejects an unknown provider value', () => {
    const file = writeTempYaml(
      'bad-provider',
      [
        'families:',
        '  - family: node',
        '    sources:',
        '      - source_image: node:20',
        '        alternatives:',
        '          - image: example/node:20',
        '            provider: totally-not-a-provider',
        '            has_shell: false',
        '            libc_family: glibc',
        '            drop_in_score: 80',
        '            cve_count: 0',
        '',
      ].join('\n')
    );
    expect(() => loadCatalog(file)).toThrow(/provider/);
  });

  it('rejects a drop_in_score outside 0..100', () => {
    const file = writeTempYaml(
      'bad-score',
      [
        'families:',
        '  - family: node',
        '    sources:',
        '      - source_image: node:20',
        '        alternatives:',
        '          - image: example/node:20',
        '            provider: chainguard',
        '            has_shell: false',
        '            libc_family: glibc',
        '            drop_in_score: 150',
        '            cve_count: 0',
        '',
      ].join('\n')
    );
    expect(() => loadCatalog(file)).toThrow(/drop_in_score/);
  });

  it('rejects a duplicate source_image', () => {
    const dup = [
      'families:',
      '  - family: node',
      '    sources:',
      '      - source_image: node:20',
      '        alternatives:',
      '          - image: a/node:20',
      '            provider: chainguard',
      '            has_shell: false',
      '            libc_family: glibc',
      '            drop_in_score: 80',
      '            cve_count: 0',
      '      - source_image: NODE:20',
      '        alternatives:',
      '          - image: b/node:20',
      '            provider: dhi',
      '            has_shell: true',
      '            libc_family: glibc',
      '            drop_in_score: 70',
      '            cve_count: 1',
      '',
    ].join('\n');
    const file = writeTempYaml('dup', dup);
    expect(() => loadCatalog(file)).toThrow(/duplicate/);
  });
});

describe('normalizeImageRef', () => {
  it('lowercases and strips the digest', () => {
    expect(normalizeImageRef(`  Node:20@sha256:${'b'.repeat(64)}`)).toBe('node:20');
  });
});

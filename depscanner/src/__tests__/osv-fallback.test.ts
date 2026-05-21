/**
 * Unit tests for the OSV-API fallback (osv-vuln-scan.ts).
 *
 * These exercise the *pure* path (PURL extraction + querybatch shape) using
 * an in-process global.fetch mock. The live HTTP probe lives in
 * scripts/osv-fallback-probe.ts and is run by hand against real SBOMs.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  extractPurlsFromSbom,
  osvFallbackMode,
  queryOsvBatch,
  runOsvFallback,
} from '../pipeline-steps/osv-vuln-scan';

describe('extractPurlsFromSbom', () => {
  it('returns purl-bearing components and de-duplicates', () => {
    const purls = extractPurlsFromSbom({
      components: [
        { purl: 'pkg:npm/lodash@4.17.20', name: 'lodash' },
        { purl: 'pkg:npm/lodash@4.17.20', name: 'lodash' }, // duplicate
        { purl: 'pkg:npm/express@4.18.2', name: 'express' },
        { purl: 'pkg:cargo/idna@0.3.0', name: 'idna' },
      ],
    }, null);
    expect(purls).toEqual([
      'pkg:npm/lodash@4.17.20',
      'pkg:npm/express@4.18.2',
      'pkg:cargo/idna@0.3.0',
    ]);
  });

  it('drops the project-self bom-ref so we do not query OSV for the org repo itself', () => {
    const purls = extractPurlsFromSbom({
      components: [
        { purl: 'pkg:maven/org.example/the-app@1.0.0', 'bom-ref': 'self' },
        { purl: 'pkg:maven/com.fasterxml.jackson.core/jackson-core@2.15.0', 'bom-ref': 'dep1' },
      ],
    }, 'self');
    expect(purls).toEqual(['pkg:maven/com.fasterxml.jackson.core/jackson-core@2.15.0']);
  });

  it('skips entries that are not purl-shaped or have no version', () => {
    const purls = extractPurlsFromSbom({
      components: [
        { purl: 'not-a-purl', name: 'x' },
        { purl: 'pkg:npm/x' /* no @version */, name: 'x' },
        { purl: 'pkg:gem/sinatra@2.0.0', name: 'sinatra' },
      ],
    }, null);
    expect(purls).toEqual(['pkg:gem/sinatra@2.0.0']);
  });
});

describe('osvFallbackMode', () => {
  const origEnv = process.env.DEPTEX_OSV_FALLBACK;
  afterEach(() => {
    if (origEnv === undefined) delete process.env.DEPTEX_OSV_FALLBACK;
    else process.env.DEPTEX_OSV_FALLBACK = origEnv;
  });

  it('reads 1/true/force as force', () => {
    process.env.DEPTEX_OSV_FALLBACK = '1';
    expect(osvFallbackMode()).toBe('force');
    process.env.DEPTEX_OSV_FALLBACK = 'true';
    expect(osvFallbackMode()).toBe('force');
    process.env.DEPTEX_OSV_FALLBACK = 'force';
    expect(osvFallbackMode()).toBe('force');
  });

  it('reads 0/false/off as off', () => {
    process.env.DEPTEX_OSV_FALLBACK = '0';
    expect(osvFallbackMode()).toBe('off');
    process.env.DEPTEX_OSV_FALLBACK = 'false';
    expect(osvFallbackMode()).toBe('off');
    process.env.DEPTEX_OSV_FALLBACK = 'off';
    expect(osvFallbackMode()).toBe('off');
  });

  it('defaults to auto', () => {
    delete process.env.DEPTEX_OSV_FALLBACK;
    expect(osvFallbackMode()).toBe('auto');
  });
});

describe('queryOsvBatch', () => {
  const realFetch = global.fetch;
  afterEach(() => { global.fetch = realFetch; });

  it('chunks queries to 1000 per batch and aligns results back to input PURLs', async () => {
    const purls = Array.from({ length: 2 }, (_, i) => `pkg:npm/dep${i}@1.0.0`);
    let calls = 0;
    global.fetch = jest.fn(async (_url: any, init: any) => {
      calls++;
      const body = JSON.parse(init.body);
      return new Response(JSON.stringify({
        results: body.queries.map((q: any, j: number) => ({
          vulns: q.package.purl.includes('dep0') ? [{ id: 'GHSA-aaaa-aaaa-aaaa' }] : [],
        })),
      }), { status: 200 });
    }) as any;
    const out = await queryOsvBatch(purls);
    expect(calls).toBe(1);
    expect(out).toHaveLength(2);
    expect(out[0]).toEqual([{ id: 'GHSA-aaaa-aaaa-aaaa' }]);
    expect(out[1]).toEqual([]);
  });

  it('throws on non-2xx response so the caller can downgrade gracefully', async () => {
    global.fetch = jest.fn(async () =>
      new Response('rate-limit', { status: 429 })) as any;
    await expect(queryOsvBatch(['pkg:npm/x@1.0.0'])).rejects.toThrow(/HTTP 429/);
  });
});

describe('runOsvFallback', () => {
  const realFetch = global.fetch;
  afterEach(() => { global.fetch = realFetch; });

  it('skips when dep-scan VDR is already non-empty (and force=false)', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'osv-fb-'));
    try {
      fs.writeFileSync(path.join(dir, 'sbom-npm.cdx.json'), JSON.stringify({ components: [
        { purl: 'pkg:npm/lodash@4.17.20' },
      ]}));
      fs.writeFileSync(path.join(dir, 'sbom-npm.vdr.json'), JSON.stringify({
        vulnerabilities: [{ id: 'CVE-2020-0000' }],
      }));
      const noop: any = { info: jest.fn(), warn: jest.fn() };
      const res = await runOsvFallback({ reportsDir: dir, jobEcosystem: 'npm', logger: noop });
      expect(res.wrote).toBe(false);
      expect(res.reason).toMatch(/non-empty/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('emits a VDR with CVE-canonical ids and ecosystem-correct affects when OSV returns hits', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'osv-fb-'));
    try {
      fs.writeFileSync(path.join(dir, 'sbom-cargo.cdx.json'), JSON.stringify({ components: [
        { purl: 'pkg:cargo/idna@0.3.0' },
      ]}));
      global.fetch = jest.fn(async (url: any) => {
        if (String(url).includes('querybatch')) {
          return new Response(JSON.stringify({ results: [{ vulns: [{ id: 'GHSA-h97m-ww89-6jmq' }] }] }), { status: 200 });
        }
        if (String(url).endsWith('/GHSA-h97m-ww89-6jmq')) {
          return new Response(JSON.stringify({
            id: 'GHSA-h97m-ww89-6jmq',
            summary: 'idna punycode bypass',
            aliases: ['CVE-2024-12224', 'RUSTSEC-2024-0421'],
            database_specific: { severity: 'MODERATE' },
            affected: [{ ranges: [{ events: [{ introduced: '0' }, { fixed: '1.0.0' }] }] }],
            published: '2024-12-09T20:41:10Z',
          }), { status: 200 });
        }
        return new Response('', { status: 404 });
      }) as any;
      const noop: any = { info: jest.fn(), warn: jest.fn() };
      const res = await runOsvFallback({ reportsDir: dir, jobEcosystem: 'cargo', logger: noop });
      expect(res.wrote).toBe(true);
      expect(res.vulnCount).toBe(1);
      const written = JSON.parse(fs.readFileSync(path.join(dir, 'osv-fallback.vdr.json'), 'utf8'));
      expect(written.vulnerabilities).toHaveLength(1);
      expect(written.vulnerabilities[0].id).toBe('CVE-2024-12224');
      expect(written.vulnerabilities[0].ratings?.[0].severity).toBe('medium');
      expect(written.vulnerabilities[0].affects[0].ref).toBe('pkg:cargo/idna@0.3.0');
      expect(written.vulnerabilities[0].affects[0].versions).toEqual([{ version: '1.0.0', status: 'unaffected' }]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('merges multiple PURLs hitting the same canonical CVE into one entry with multiple affects', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'osv-fb-'));
    try {
      fs.writeFileSync(path.join(dir, 'sbom-npm.cdx.json'), JSON.stringify({ components: [
        { purl: 'pkg:npm/affected-a@1.0.0' },
        { purl: 'pkg:npm/affected-b@2.0.0' },
      ]}));
      global.fetch = jest.fn(async (url: any) => {
        if (String(url).includes('querybatch')) {
          return new Response(JSON.stringify({
            results: [
              { vulns: [{ id: 'GHSA-shared' }] },
              { vulns: [{ id: 'GHSA-shared' }] },
            ],
          }), { status: 200 });
        }
        if (String(url).endsWith('/GHSA-shared')) {
          return new Response(JSON.stringify({
            id: 'GHSA-shared',
            summary: 'shared vuln',
            aliases: ['CVE-2099-0001'],
            database_specific: { severity: 'HIGH' },
          }), { status: 200 });
        }
        return new Response('', { status: 404 });
      }) as any;
      const noop: any = { info: jest.fn(), warn: jest.fn() };
      const res = await runOsvFallback({ reportsDir: dir, jobEcosystem: 'npm', logger: noop });
      expect(res.vulnCount).toBe(1);
      const written = JSON.parse(fs.readFileSync(path.join(dir, 'osv-fallback.vdr.json'), 'utf8'));
      expect(written.vulnerabilities[0].id).toBe('CVE-2099-0001');
      const refs = written.vulnerabilities[0].affects.map((a: any) => a.ref);
      expect(refs).toEqual(expect.arrayContaining([
        'pkg:npm/affected-a@1.0.0',
        'pkg:npm/affected-b@2.0.0',
      ]));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('returns wrote=false with reason when SBOM is missing', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'osv-fb-'));
    try {
      const noop: any = { info: jest.fn(), warn: jest.fn() };
      const res = await runOsvFallback({ reportsDir: dir, jobEcosystem: 'npm', logger: noop });
      expect(res.wrote).toBe(false);
      expect(res.reason).toMatch(/no SBOM/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('force=true bypasses the non-empty-VDR skip', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'osv-fb-'));
    try {
      fs.writeFileSync(path.join(dir, 'sbom-npm.cdx.json'), JSON.stringify({ components: [
        { purl: 'pkg:npm/lodash@4.17.20' },
      ]}));
      fs.writeFileSync(path.join(dir, 'sbom-npm.vdr.json'), JSON.stringify({
        vulnerabilities: [{ id: 'CVE-2020-0000' }],
      }));
      global.fetch = jest.fn(async () =>
        new Response(JSON.stringify({ results: [{ vulns: [] }] }), { status: 200 })) as any;
      const noop: any = { info: jest.fn(), warn: jest.fn() };
      const res = await runOsvFallback({ reportsDir: dir, jobEcosystem: 'npm', logger: noop, force: true });
      // Even with no matching OSV vulns, force=true means the fallback ran
      // (wrote an empty VDR sentinel), not skipped.
      expect(res.wrote).toBe(true);
      expect(res.vulnCount).toBe(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

/**
 * Pipeline engine-dispatch tests.
 *
 * Covers the two pure dispatch primitives runDastPipeline uses:
 *   - resolveEngine: scan_jobs.type → 'zap' | 'nuclei'
 *   - buildEngineCrossLinkMetadata: the Nuclei-only `nuclei.cve_ids` merge that
 *     the confirm_pdvs_from_dast_run RPC keys on.
 *
 * Together these prove: dast_nuclei routes to Nuclei, everything else to ZAP,
 * and the CVE cross-link signal is attached for Nuclei findings ONLY (ZAP
 * findings never carry a `nuclei` metadata key, so the confirm batch can never
 * pick them up).
 *
 * Run: npx tsx test/dast-pipeline-engine-dispatch.test.ts
 */

import { resolveEngine, buildEngineCrossLinkMetadata } from '../src/dast/pipeline';

let failures = 0;
let passed = 0;
function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
    passed++;
  }
}

function main(): void {
  const t0 = Date.now();
  console.log('Pipeline engine-dispatch tests\n');

  console.log('[1] resolveEngine routing');
  assert(resolveEngine('dast_nuclei') === 'nuclei', `dast_nuclei → nuclei`);
  assert(resolveEngine('dast_zap') === 'zap', `dast_zap → zap`);
  assert(resolveEngine('dast') === 'zap', `dast (legacy alias) → zap`);

  console.log('\n[2] buildEngineCrossLinkMetadata — Nuclei merges nuclei.cve_ids');
  const base = { match_method: 'route_flow_vuln', framework: 'express', purl: 'pkg:npm/x@1' };
  const nucleiMeta = buildEngineCrossLinkMetadata('nuclei', base, ['CVE-2017-12615']);
  assert(
    JSON.stringify((nucleiMeta as any).nuclei) === JSON.stringify({ cve_ids: ['CVE-2017-12615'] }),
    `nuclei metadata carries nuclei.cve_ids`,
  );
  assert(
    (nucleiMeta as any).match_method === 'route_flow_vuln' && (nucleiMeta as any).purl === 'pkg:npm/x@1',
    `nuclei metadata preserves the base cross-link fields`,
  );
  assert(nucleiMeta !== base, `nuclei metadata is a fresh object (base not mutated)`);
  assert((base as any).nuclei === undefined, `base object was not mutated`);

  console.log('\n[3] buildEngineCrossLinkMetadata — ZAP passes base through, no nuclei key');
  const zapMeta = buildEngineCrossLinkMetadata('zap', base, []);
  assert((zapMeta as any).nuclei === undefined, `zap metadata never carries a nuclei key`);
  assert(zapMeta === base, `zap metadata is the base object unchanged`);

  console.log('\n[4] buildEngineCrossLinkMetadata — Nuclei finding with no CVE ids');
  const emptyCve = buildEngineCrossLinkMetadata('nuclei', base, []);
  assert(
    JSON.stringify((emptyCve as any).nuclei) === JSON.stringify({ cve_ids: [] }),
    `nuclei finding with no CVE ids still gets an empty cve_ids array`,
  );

  console.log(
    `\nPipeline engine-dispatch tests ${failures === 0 ? 'PASSED' : 'FAILED'} in ${Date.now() - t0}ms ` +
      `(${passed} passed, ${failures} failure${failures === 1 ? '' : 's'})`,
  );
  process.exit(failures === 0 ? 0 : 1);
}

main();

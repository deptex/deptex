/**
 * Wave 10 subset benchmark — Jackson + Log4j + Python SSRF (12 CVEs).
 *
 * Targets the 5 Jackson + 4 Log4j-family + 3 Python SSRF CVEs the Wave 9
 * 88-CVE rerun (`docs/88-cve-benchmark-2026-05-10-wave8.md`) flagged as
 * `fixture_round_trip_failed`. Re-runs them after the prompt-only changes
 * shipped in this PR: new gadget-shape few-shot examples (Jackson +
 * urllib3 SSRF), the Log4Shell gadget-shape primer in the prompt, and the
 * iterate-runner fix that pipes few-shots through the production library
 * (the old `loadFewShotExamples` path silently returned [] because
 * `depscanner/reachability-rules/` doesn't exist any more).
 *
 *   npx tsx test/iterate/scripts/subset-fewshot-wave10.ts
 *
 * Output: bench-iterate/wave10-fewshot-subset/<timestamp>/{report.json, summary.txt}
 *
 * Sibling: `subset-maven-jackson-log4j-wave10.ts` covers the same Maven
 * surface but exercises a different Wave 10 lever (framework-spec
 * relaxation in `framework-models/*.yaml`). The two scripts can run
 * sequentially against the same baseline; their per-CVE rows are
 * directly comparable.
 */

import * as fs from 'fs';
import * as path from 'path';
import { pathToFileURL } from 'url';
import * as dotenv from 'dotenv';
import type { VariantModule } from '../runner';
import { runVariant, formatSummary } from '../runner';
import { CANDIDATES } from '../candidates';

const TARGET_CVES = [
  // Jackson polymorphic-deser gadget (5)
  'CVE-2017-7525',
  'CVE-2018-7489',
  'CVE-2019-12384',
  'CVE-2019-14439',
  'CVE-2020-9548',
  // Log4j JNDI-substitution gadget (4)
  'CVE-2021-44228',
  'CVE-2021-44832',
  'CVE-2017-5645',
  'CVE-2021-45046',
  // Python SSRF on requests / urllib3 (3)
  'CVE-2018-18074',
  'CVE-2023-32681',
  'CVE-2023-43804',
];

function loadEnv(): void {
  const worktreeEnv = path.resolve(__dirname, '..', '..', '..', '..', '.env');
  if (fs.existsSync(worktreeEnv)) dotenv.config({ path: worktreeEnv });
  for (const cand of ['C:\\Coding\\Deptex\\backend\\.env', '/c/Coding/Deptex/backend/.env']) {
    if (fs.existsSync(cand)) dotenv.config({ path: cand });
  }
}

async function main(): Promise<void> {
  loadEnv();
  const apiKey = process.env.DEEPINFRA_API_KEY;
  if (!apiKey) throw new Error('DEEPINFRA_API_KEY missing');

  const variantFile = path.join(__dirname, '..', 'variants', 'v_base.ts');
  const variant = (await import(pathToFileURL(variantFile).href)) as VariantModule;

  const subset = CANDIDATES.filter((c) => TARGET_CVES.includes(c.cveId));
  if (subset.length !== TARGET_CVES.length) {
    const missing = TARGET_CVES.filter((id) => !subset.some((c) => c.cveId === id));
    throw new Error(`missing CVEs in corpus: ${missing.join(',')}`);
  }

  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const outputDir = path.resolve(__dirname, '..', '..', '..', 'bench-iterate', 'wave10-fewshot-subset', ts);
  fs.mkdirSync(outputDir, { recursive: true });

  console.log(`[subset] running ${subset.length} CVEs (5 Jackson + 4 Log4j + 3 Python SSRF) on Qwen3-235B / DeepInfra`);
  console.log(`[subset] output dir: ${outputDir}`);

  const report = await runVariant({
    variant,
    provider: 'openai',
    model: 'Qwen/Qwen3-235B-A22B-Instruct-2507',
    apiKey,
    baseUrl: 'https://api.deepinfra.com/v1/openai',
    candidates: subset,
    concurrency: 4,
    outputDir,
    perCveTimeoutMs: 360_000,
  });

  fs.writeFileSync(path.join(outputDir, 'report.json'), JSON.stringify(report, null, 2));
  fs.writeFileSync(path.join(outputDir, 'summary.txt'), formatSummary(report));

  console.log('\n' + formatSummary(report));
  console.log(`\n[subset] DeepInfra spend: $${report.totalCostUsd.toFixed(4)}`);

  // Per-class breakdown.
  const classes: Record<string, string[]> = {
    jackson: ['CVE-2017-7525', 'CVE-2018-7489', 'CVE-2019-12384', 'CVE-2019-14439', 'CVE-2020-9548'],
    log4j: ['CVE-2021-44228', 'CVE-2021-44832', 'CVE-2017-5645', 'CVE-2021-45046'],
    'python-ssrf': ['CVE-2018-18074', 'CVE-2023-32681', 'CVE-2023-43804'],
  };
  console.log('\n[subset] per-class recall:');
  for (const [klass, ids] of Object.entries(classes)) {
    const rows = ids.map((id) => report.perCve.find((p) => p.cveId === id));
    const validated = rows.filter((r) => r?.status === 'validated').length;
    console.log(`  ${klass.padEnd(12)} ${validated}/${ids.length}`);
  }

  console.log('\n[subset] per-CVE detail:');
  for (const id of TARGET_CVES) {
    const r = report.perCve.find((p) => p.cveId === id);
    if (!r) { console.log(`  ${id} (no result)`); continue; }
    const symbol = r.status === 'validated' ? 'PASS' : 'FAIL';
    console.log(`  [${symbol}] ${id} ${r.status} $${r.costUsd.toFixed(4)} ${r.errors[0] ?? ''}`);
  }

  const validated = report.perCve.filter((p) => p.status === 'validated').length;
  console.log(`\n[subset] ${validated}/${subset.length} validated`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

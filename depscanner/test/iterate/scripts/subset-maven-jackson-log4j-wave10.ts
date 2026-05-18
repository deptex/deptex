/**
 * Wave 10 subset benchmark — Jackson + Log4j (10 maven CVEs).
 *
 * Targets the 5 Jackson + 5 Log4j-family CVEs the Wave 9 88-CVE rerun
 * flagged as `fixture_round_trip_failed`. Re-runs them against the Wave 10
 * relaxed framework specs (jackson.yaml: dropped enableDefaultTyping marker
 * sinks; log4j.yaml: argument_indices: [] on every Logger sink) to verify
 * the relaxation lifts recall on this subset.
 *
 *   npx tsx test/iterate/scripts/subset-maven-jackson-log4j-wave10.ts
 *
 * Output: bench-iterate/wave10-jackson-log4j-subset/<timestamp>/{report.json, summary.txt}
 */

import * as fs from 'fs';
import * as path from 'path';
import { pathToFileURL } from 'url';
import * as dotenv from 'dotenv';
import type { VariantModule } from '../runner';
import { runVariant, formatSummary } from '../runner';
import { CANDIDATES } from '../candidates';

const TARGET_CVES = [
  // Jackson 5
  'CVE-2017-7525',
  'CVE-2018-7489',
  'CVE-2019-12384',
  'CVE-2019-14439',
  'CVE-2020-9548',
  // Log4j family 5
  'CVE-2021-44228',
  'CVE-2021-45046',
  'CVE-2021-44832',
  'CVE-2017-5645',
  'CVE-2023-26464',
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
  const outputDir = path.resolve(__dirname, '..', '..', '..', 'bench-iterate', 'wave10-jackson-log4j-subset', ts);
  fs.mkdirSync(outputDir, { recursive: true });

  console.log(`[subset] running ${subset.length} CVEs (5 Jackson + 5 Log4j) on Qwen3-235B / DeepInfra`);
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

  console.log('\n[subset] per-CVE recall:');
  for (const id of TARGET_CVES) {
    const r = report.perCve.find((p) => p.cveId === id);
    if (!r) { console.log(`  ${id} (no result)`); continue; }
    const symbol = r.status === 'validated' ? 'PASS' : 'FAIL';
    console.log(`  [${symbol}] ${id} ${r.status} ${r.errors[0] ?? ''}`);
  }

  const validated = report.perCve.filter((p) => p.status === 'validated').length;
  console.log(`\n[subset] ${validated}/${subset.length} validated`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

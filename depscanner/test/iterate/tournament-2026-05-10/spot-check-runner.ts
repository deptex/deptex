/**
 * Spot-check runner — runs the tournament winner against the 10-CVE
 * baseline corpus (CVEs v_base already passes) to confirm the winning
 * prompt doesn't regress.
 *
 *   npm run tournament:spot-check -- --variant=<name>
 *
 * Pass criterion: ≥ 8/10 validate. Below 8/10 = regression, roll back to
 * next-best non-regressing variant.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as dotenv from 'dotenv';
import { pathToFileURL } from 'url';
import { runVariant, type VariantModule } from '../runner';
import { getSpotCheckCandidates } from './spot-check-corpus';

function loadEnv(): void {
  const worktreeEnv = path.resolve(__dirname, '..', '..', '..', '..', '.env');
  if (fs.existsSync(worktreeEnv)) dotenv.config({ path: worktreeEnv });
  const mainEnvWindows = 'C:\\Coding\\Deptex\\backend\\.env';
  const mainEnvPosix = '/c/Coding/Deptex/backend/.env';
  for (const cand of [mainEnvWindows, mainEnvPosix]) {
    if (fs.existsSync(cand)) dotenv.config({ path: cand });
  }
}

async function loadVariant(name: string): Promise<VariantModule> {
  const file = path.join(__dirname, '..', 'variants', `${name}.ts`);
  if (!fs.existsSync(file)) throw new Error(`variant file not found: ${file}`);
  const mod = await import(pathToFileURL(file).href);
  return mod as VariantModule;
}

function parseFlags(argv: string[]): { variant: string } {
  for (const a of argv) if (a.startsWith('--variant=')) return { variant: a.slice('--variant='.length) };
  throw new Error('missing --variant=<name>');
}

async function main(): Promise<void> {
  loadEnv();
  const flags = parseFlags(process.argv.slice(2));
  const apiKey = process.env.DEEPINFRA_API_KEY;
  if (!apiKey) throw new Error('DEEPINFRA_API_KEY not set');

  const variant = await loadVariant(flags.variant);
  const candidates = getSpotCheckCandidates();
  process.stderr.write(`Spot-check: ${variant.NAME} vs ${candidates.length} v_base-passing CVEs.\n`);

  const outDir = path.join(__dirname, 'spot-check-out', variant.NAME);
  const report = await runVariant({
    variant,
    provider: 'openai',
    model: 'Qwen/Qwen3-235B-A22B-Instruct-2507',
    baseUrl: 'https://api.deepinfra.com/v1/openai',
    apiKey,
    candidates,
    concurrency: 3,
    outputDir: outDir,
    perCveTimeoutMs: 240_000,
  });

  const passed = report.validated;
  const pct = ((passed / candidates.length) * 100).toFixed(1);
  process.stdout.write(`\nSpot-check result: ${passed}/${candidates.length} = ${pct}% (cost $${report.totalCostUsd.toFixed(4)})\n`);
  process.stdout.write(`Status breakdown: ${JSON.stringify(report.byStatus)}\n`);
  if (passed < 8) {
    process.stdout.write(`REGRESSION: ${passed}/10 < 8/10 threshold. Roll back.\n`);
    process.exit(2);
  }
  process.stdout.write(`PASS: ${passed}/10 ≥ 8/10 threshold. Variant is safe to adopt.\n`);
}

main().catch((err) => {
  process.stderr.write(`fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});

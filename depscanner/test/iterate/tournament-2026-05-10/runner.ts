/**
 * Tournament runner for the 2026-05-10 source/sink-mismatch lift attempt.
 *
 * Runs 5 prompt variants (v_t_a..v_t_e) against the 29-CVE mismatch
 * subsample on DeepInfra Qwen3-235B, with concurrency 3. Outputs a
 * per-variant report and a markdown leaderboard.
 *
 *   npm run tournament:rule-gen
 *
 * Cost budget: ~$0.50 (29 × 5 = 145 rule-gen calls @ ~$0.003 each).
 *
 * Env: DEEPINFRA_API_KEY in backend/.env (worktree or main repo). All
 * variants share the same model + base URL for a fair comparison.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as dotenv from 'dotenv';
import { pathToFileURL } from 'url';
import { runVariant, type VariantModule, type VariantRunReport } from '../runner';
import { getMismatchCandidates, getFastMismatchCandidates } from './mismatch-corpus';

const VARIANT_NAMES = ['v_base', 'v_t_a', 'v_t_b', 'v_t_c', 'v_t_d', 'v_t_e'];

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
  if (!mod.NAME || !mod.VERSION || typeof mod.buildGenerationPrompt !== 'function') {
    throw new Error(`variant ${name} missing required exports`);
  }
  return mod as VariantModule;
}

interface VariantSummary {
  name: string;
  version: string;
  validated: number;
  candidates: number;
  costUsd: number;
  funnel: VariantRunReport['funnel'];
  byStatus: Record<string, number>;
}

function formatLeaderboard(rows: VariantSummary[]): string {
  const sorted = [...rows].sort((a, b) => b.validated - a.validated || a.costUsd - b.costUsd);
  const lines: string[] = [];
  lines.push(`# Source/Sink-Mismatch Tournament — 2026-05-10`);
  lines.push(``);
  lines.push(`Corpus: 29 CVEs that v_base failed with source_sink_mismatch (schema_pass=true, fixture_pre_match=false).`);
  lines.push(`Model: openai/Qwen/Qwen3-235B-A22B-Instruct-2507 via DeepInfra. Concurrency 3.`);
  lines.push(``);
  lines.push(`## Leaderboard`);
  lines.push(``);
  lines.push(`| Rank | Variant | Version | Validated / 29 | Schema pass | Fixture pre-match | Cost |`);
  lines.push(`|------|---------|---------|----------------|-------------|--------------------|------|`);
  sorted.forEach((r, i) => {
    lines.push(
      `| ${i + 1} | ${r.name} | ${r.version} | ${r.validated} / ${r.candidates} | ${r.funnel.schemaPass} | ${r.funnel.fixturePre} | $${r.costUsd.toFixed(4)} |`,
    );
  });
  lines.push(``);
  lines.push(`## Status breakdown`);
  lines.push(``);
  for (const r of sorted) {
    const breakdown = Object.entries(r.byStatus)
      .sort((a, b) => b[1] - a[1])
      .map(([k, v]) => `${k}=${v}`)
      .join(', ');
    lines.push(`- **${r.name}**: ${breakdown}`);
  }
  lines.push(``);
  return lines.join('\n');
}

async function main(): Promise<void> {
  loadEnv();
  const apiKey = process.env.DEEPINFRA_API_KEY;
  if (!apiKey) throw new Error('DEEPINFRA_API_KEY not set (check backend/.env)');

  const fastMode = process.argv.includes('--fast');
  const candidates = fastMode ? getFastMismatchCandidates() : getMismatchCandidates();
  if (fastMode) process.stderr.write(`(fast mode: 15-CVE subset)\n`);
  process.stderr.write(`Tournament: ${VARIANT_NAMES.length} variants × ${candidates.length} CVEs = ${VARIANT_NAMES.length * candidates.length} rule-gen calls.\n`);

  const outRoot = __dirname;
  const variantsRoot = path.join(outRoot, 'variants-out');
  if (!fs.existsSync(variantsRoot)) fs.mkdirSync(variantsRoot, { recursive: true });

  const summaries: VariantSummary[] = [];
  for (const name of VARIANT_NAMES) {
    const variant = await loadVariant(name);
    const variantOutDir = path.join(variantsRoot, variant.NAME);
    process.stderr.write(`\n=== ${variant.NAME} (${variant.VERSION}) ===\n`);
    const report = await runVariant({
      variant,
      provider: 'openai',
      model: 'Qwen/Qwen3-235B-A22B-Instruct-2507',
      baseUrl: 'https://api.deepinfra.com/v1/openai',
      apiKey,
      candidates,
      concurrency: 5,
      outputDir: variantOutDir,
      perCveTimeoutMs: 240_000,
    });
    summaries.push({
      name: variant.NAME,
      version: variant.VERSION,
      validated: report.validated,
      candidates: report.candidates,
      costUsd: report.totalCostUsd,
      funnel: report.funnel,
      byStatus: report.byStatus,
    });
    process.stderr.write(`[${variant.NAME}] validated=${report.validated}/${report.candidates} cost=$${report.totalCostUsd.toFixed(4)}\n`);
  }

  const totalCost = summaries.reduce((s, r) => s + r.costUsd, 0);
  const leaderboardMd = formatLeaderboard(summaries) + `\n## Total tournament spend\n\n$${totalCost.toFixed(4)} across ${summaries.length} variants × ${candidates.length} CVEs.\n`;
  fs.writeFileSync(path.join(outRoot, 'leaderboard.md'), leaderboardMd, 'utf8');
  fs.writeFileSync(path.join(outRoot, 'summaries.json'), JSON.stringify(summaries, null, 2), 'utf8');

  process.stdout.write(leaderboardMd);
  process.stderr.write(`\nTotal tournament spend: $${totalCost.toFixed(4)}\n`);
}

main().catch((err) => {
  process.stderr.write(`fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});

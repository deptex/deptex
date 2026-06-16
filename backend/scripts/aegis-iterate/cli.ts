/**
 * Aegis local-iterate harness — drives `createAegisAgent` end-to-end against a
 * scripted JSON scenario, prints a structured trace, and writes a JSONL
 * transcript. Mirrors the depscanner `npm run iterate` pattern.
 *
 *   npm run aegis:iterate -- --scenario=dogfood-round2 --case=01-single-fix
 *   npm run aegis:iterate -- --scenario=dogfood-round2          # all cases
 *   npm run aegis:iterate -- --scenario=dogfood-round2 --max-cost=0.50
 *   npm run aegis:iterate -- --scenario=dogfood-round2 --keep-thread
 *
 * Loads .env from backend/.env. Uses the org's default model (DeepSeek V4 Flash
 * for the Deptex org). Runs against the real Supabase project — every scenario
 * gets a fresh isolated thread by default and cleans up after itself unless
 * --keep-thread is passed.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as dotenv from 'dotenv';
import { runScenarioCase, loadScenario, type ScenarioCase } from './runner';
import { cleanupThread } from './cleanup';

interface CliFlags {
  scenario: string;
  caseFilter?: string;
  maxCostUsd: number;
  keepThread: boolean;
  outputRoot: string;
  dryRun: boolean;
}

function parseFlags(argv: string[]): CliFlags {
  const flags: Partial<CliFlags> = {
    maxCostUsd: 0.5,
    keepThread: false,
    dryRun: false,
  };
  for (const arg of argv) {
    if (arg.startsWith('--scenario=')) flags.scenario = arg.slice('--scenario='.length);
    else if (arg.startsWith('--case=')) flags.caseFilter = arg.slice('--case='.length);
    else if (arg.startsWith('--max-cost=')) flags.maxCostUsd = parseFloat(arg.slice('--max-cost='.length));
    else if (arg === '--keep-thread') flags.keepThread = true;
    else if (arg === '--dry-run') flags.dryRun = true;
    else if (arg.startsWith('--output-root=')) flags.outputRoot = arg.slice('--output-root='.length);
  }
  if (!flags.scenario) throw new Error('missing --scenario=<name>');
  if (!flags.outputRoot) flags.outputRoot = path.join(process.cwd(), 'bench-aegis');
  if (Number.isNaN(flags.maxCostUsd) || flags.maxCostUsd! <= 0) flags.maxCostUsd = 0.5;
  return flags as CliFlags;
}

async function main(): Promise<void> {
  const repoBackend = path.resolve(__dirname, '../../');
  dotenv.config({ path: path.join(repoBackend, '.env') });

  const flags = parseFlags(process.argv.slice(2));

  const scenarioPath = path.resolve(
    repoBackend,
    'scripts',
    'aegis-scenarios',
    `${flags.scenario}.json`,
  );
  if (!fs.existsSync(scenarioPath)) {
    throw new Error(`scenario file not found: ${scenarioPath}`);
  }

  const scenario = loadScenario(scenarioPath);
  const cases: ScenarioCase[] = flags.caseFilter
    ? scenario.cases.filter((c) => c.id.includes(flags.caseFilter!))
    : scenario.cases;

  if (cases.length === 0) {
    throw new Error(`no cases match filter: ${flags.caseFilter}`);
  }

  const runId = new Date().toISOString().replace(/[:.]/g, '-');
  const runDir = path.join(flags.outputRoot, scenario.scenario, runId);
  fs.mkdirSync(runDir, { recursive: true });

  console.log(`\n=== aegis-iterate ===`);
  console.log(`scenario:  ${scenario.scenario}`);
  console.log(`org:       ${scenario.orgId}`);
  console.log(`user:      ${scenario.userId}`);
  console.log(`cases:     ${cases.map((c) => c.id).join(', ')}`);
  console.log(`max-cost:  $${flags.maxCostUsd.toFixed(2)} per case`);
  console.log(`output:    ${runDir}`);
  if (flags.dryRun) console.log(`mode:      dry-run (no LLM call, no DB writes)`);
  console.log('');

  if (flags.dryRun) {
    process.exit(0);
  }

  const summary: Array<{
    caseId: string;
    threadId: string;
    turns: number;
    costUsd: number;
    expectations: { passed: number; failed: number };
    error?: string;
  }> = [];

  for (const sc of cases) {
    const result = await runScenarioCase({
      scenario,
      case: sc,
      runDir,
      maxCostUsd: flags.maxCostUsd,
    });
    summary.push({
      caseId: sc.id,
      threadId: result.threadId,
      turns: result.turns,
      costUsd: result.costUsd,
      expectations: result.expectations,
      error: result.error,
    });
    if (!flags.keepThread) {
      await cleanupThread(result.threadId);
    } else {
      console.log(`  (kept thread ${result.threadId} for inspection)`);
    }
  }

  const totalCost = summary.reduce((s, r) => s + r.costUsd, 0);
  const totalPassed = summary.reduce((s, r) => s + r.expectations.passed, 0);
  const totalFailed = summary.reduce((s, r) => s + r.expectations.failed, 0);

  const summaryText =
    `aegis-iterate run ${runId}\n` +
    `scenario: ${scenario.scenario}\n` +
    `cases: ${cases.length}\n` +
    `total cost: $${totalCost.toFixed(4)}\n` +
    `expectations: ${totalPassed} passed, ${totalFailed} failed\n\n` +
    summary
      .map(
        (r) =>
          `  ${r.caseId.padEnd(28)} ${(r.expectations.failed === 0 && !r.error) ? 'PASS' : 'FAIL'} ` +
          `${r.turns}t  $${r.costUsd.toFixed(4)}` +
          (r.error ? `  ERROR: ${r.error}` : ''),
      )
      .join('\n') +
    '\n';

  fs.writeFileSync(path.join(runDir, 'summary.txt'), summaryText);
  console.log('\n' + summaryText);

  if (totalFailed > 0 || summary.some((r) => r.error)) process.exit(1);
}

main().catch((err) => {
  console.error('aegis-iterate failed:', err);
  process.exit(1);
});

/**
 * No-cost assertion harness for the LANGUAGE_GATE env -> planner-enabled-langs
 * mapping. Validates that the same env values we'd ship to Fly produce the
 * expected language list — without spending an LLM token or touching the DB.
 *
 *   npm run aegis:gate-test
 *
 * Each case sets `process.env.LANGUAGE_GATE`, calls the planner's
 * `getEnabledPlannerLanguages()`, and asserts the result. Exits non-zero on
 * any mismatch so CI can wire this in later if we want.
 */

import * as path from 'path';
import * as dotenv from 'dotenv';

// Load .env first so reading LANGUAGE_GATE from the worktree doesn't crash if
// it's already set there — we override it case-by-case below regardless.
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

import { getEnabledPlannerLanguages } from '../../src/lib/aegis-v3/fix-planner';
import { getEnabledLanguages as getEnabledWorkerLanguages } from '../../../fix-worker/src/plan-types';

interface Case {
  name: string;
  envValue: string | undefined;
  expected: string[];
}

const cases: Case[] = [
  {
    name: 'unset → ship gate',
    envValue: undefined,
    expected: ['js', 'ts', 'python', 'go', 'other'],
  },
  {
    name: 'empty → ship gate',
    envValue: '',
    expected: ['js', 'ts', 'python', 'go', 'other'],
  },
  {
    name: '"all" → all 9 langs (8 + other)',
    envValue: 'all',
    expected: ['js', 'ts', 'python', 'go', 'java', 'ruby', 'php', 'rust', 'csharp', 'other'],
  },
  {
    name: '"ALL" (case-insensitive) → all 9 langs',
    envValue: 'ALL',
    expected: ['js', 'ts', 'python', 'go', 'java', 'ruby', 'php', 'rust', 'csharp', 'other'],
  },
  {
    name: 'CSV "js,ruby" → js, ruby, other (other appended)',
    envValue: 'js,ruby',
    expected: ['js', 'ruby', 'other'],
  },
  {
    name: 'CSV with explicit other "js, ts, other" (whitespace tolerated) → no duplicate other',
    envValue: 'js, ts, other',
    expected: ['js', 'ts', 'other'],
  },
  {
    name: 'CSV with typos "js,foo,ruby" → typos dropped, valid kept',
    envValue: 'js,foo,ruby',
    expected: ['js', 'ruby', 'other'],
  },
  {
    name: 'all-typos "foo,bar" → falls back to ship gate',
    envValue: 'foo,bar',
    expected: ['js', 'ts', 'python', 'go', 'other'],
  },
  {
    name: 'java only → java + other (so config files still patchable)',
    envValue: 'java',
    expected: ['java', 'other'],
  },
];

let passed = 0;
let failed = 0;

console.log('\n=== LANGUAGE_GATE assertion test ===\n');

for (const tc of cases) {
  if (tc.envValue === undefined) {
    delete process.env.LANGUAGE_GATE;
  } else {
    process.env.LANGUAGE_GATE = tc.envValue;
  }
  const plannerGot = [...getEnabledPlannerLanguages()];
  const workerGot = [...getEnabledWorkerLanguages()];
  const plannerOk =
    plannerGot.length === tc.expected.length &&
    plannerGot.every((g, i) => g === tc.expected[i]);
  const workerOk =
    workerGot.length === tc.expected.length &&
    workerGot.every((g, i) => g === tc.expected[i]);
  const inSync =
    plannerGot.length === workerGot.length &&
    plannerGot.every((g, i) => g === workerGot[i]);
  if (plannerOk && workerOk && inSync) {
    console.log(`  ✅ ${tc.name}`);
    passed += 1;
  } else {
    console.log(`  ❌ ${tc.name}`);
    console.log(`     expected: [${tc.expected.join(', ')}]`);
    console.log(`     planner:  [${plannerGot.join(', ')}]${plannerOk ? '' : ' MISMATCH'}`);
    console.log(`     worker:   [${workerGot.join(', ')}]${workerOk ? '' : ' MISMATCH'}`);
    if (!inSync) console.log(`     ⚠ planner and worker disagree — gate has drifted`);
    failed += 1;
  }
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);

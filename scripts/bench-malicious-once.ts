/**
 * One-shot smoke benchmark for the malicious-package scanner.
 *
 * Run BEFORE merging M1 to record a detection-rate baseline in the PR
 * description. Not maintained, not in CI — the maintained replacement
 * lands in the v1.1 benchmark-harness work item.
 *
 * Usage:
 *   FIXTURE_DIR=./bench-fixtures \
 *     npx tsx scripts/bench-malicious-once.ts
 *
 * Expected fixture layout:
 *   bench-fixtures/
 *     manifest.json          (sha256-pinned list of (name, version, ecosystem, expected: 'malicious'|'clean'))
 *     packages/<eco>/<name>-<version>/   (already-unpacked package source)
 *
 * Output: a Markdown summary printed to stdout for paste into PR
 * description (detection rate, false positive rate, per-ecosystem
 * breakdown). Does not write to any DB.
 */
import * as fs from 'fs';
import * as path from 'path';
import {
  runGuardDog,
  isGuardDogAvailable,
  GUARDDOG_VERSION,
} from '../backend/extraction-worker/src/malicious/guarddog';
import {
  canonicalizeEcosystem,
  type CanonicalEcosystem,
} from '../backend/extraction-worker/src/malicious/ecosystem';

interface FixtureEntry {
  name: string;
  version: string;
  ecosystem: string;
  expected: 'malicious' | 'clean';
  sha256: string;
}

interface Manifest {
  fixtures: FixtureEntry[];
}

function loadManifest(dir: string): Manifest {
  const p = path.join(dir, 'manifest.json');
  if (!fs.existsSync(p)) {
    throw new Error(`fixture manifest missing: ${p}`);
  }
  return JSON.parse(fs.readFileSync(p, 'utf8')) as Manifest;
}

function pkgDir(root: string, e: FixtureEntry): string {
  return path.join(root, 'packages', e.ecosystem, `${e.name}-${e.version}`);
}

function main(): void {
  const root = process.env.FIXTURE_DIR || './bench-fixtures';
  if (!fs.existsSync(root)) {
    console.error(`Fixture dir not found: ${root}`);
    console.error('Set FIXTURE_DIR to a directory containing manifest.json + packages/<eco>/<name>-<ver>/');
    process.exit(1);
  }
  if (!isGuardDogAvailable()) {
    console.error('GuardDog binary not found at /opt/guarddog-venv/bin/guarddog — build the extraction-worker image and run inside the container.');
    process.exit(2);
  }

  const manifest = loadManifest(root);
  const byEco = new Map<string, { tp: number; fn: number; fp: number; tn: number; total: number }>();

  let tp = 0; let fp = 0; let tn = 0; let fn = 0;

  for (const fixture of manifest.fixtures) {
    const eco: CanonicalEcosystem | null = canonicalizeEcosystem(fixture.ecosystem);
    if (!eco) continue;

    const dir = pkgDir(root, fixture);
    if (!fs.existsSync(dir)) {
      console.warn(`skipping (missing dir): ${fixture.ecosystem}/${fixture.name}@${fixture.version}`);
      continue;
    }

    const result = runGuardDog(dir, eco, fixture.name);
    const flagged = result.rules.length > 0;
    const expected = fixture.expected === 'malicious';

    if (flagged && expected) tp++;
    else if (flagged && !expected) fp++;
    else if (!flagged && !expected) tn++;
    else fn++;

    const stats = byEco.get(eco) ?? { tp: 0, fn: 0, fp: 0, tn: 0, total: 0 };
    if (flagged && expected) stats.tp++;
    else if (flagged && !expected) stats.fp++;
    else if (!flagged && !expected) stats.tn++;
    else stats.fn++;
    stats.total++;
    byEco.set(eco, stats);
  }

  const total = tp + fp + tn + fn;
  const detectionRate = (tp + fn) > 0 ? (tp / (tp + fn)) * 100 : 0;
  const fpRate = (fp + tn) > 0 ? (fp / (fp + tn)) * 100 : 0;

  // Markdown report — paste into PR description
  console.log(`### Malicious-package smoke benchmark`);
  console.log('');
  console.log(`Scanner: ${GUARDDOG_VERSION}`);
  console.log(`Fixtures: ${total}/${manifest.fixtures.length}`);
  console.log('');
  console.log(`| Metric | Value |`);
  console.log(`|---|---|`);
  console.log(`| Detection rate (TP/(TP+FN)) | **${detectionRate.toFixed(1)}%** (${tp}/${tp + fn}) |`);
  console.log(`| False positive rate (FP/(FP+TN)) | ${fpRate.toFixed(1)}% (${fp}/${fp + tn}) |`);
  console.log(`| True negatives | ${tn} |`);
  console.log(`| False negatives | ${fn} |`);
  console.log('');
  console.log(`#### By ecosystem`);
  console.log(`| Ecosystem | Total | TP | FP | TN | FN |`);
  console.log(`|---|---|---|---|---|---|`);
  for (const [eco, s] of byEco) {
    console.log(`| ${eco} | ${s.total} | ${s.tp} | ${s.fp} | ${s.tn} | ${s.fn} |`);
  }
}

main();

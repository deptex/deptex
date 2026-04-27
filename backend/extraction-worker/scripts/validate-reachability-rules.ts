/**
 * Validator: load every rule pack from reachability-rules/ and verify:
 *   - every CVE-* folder loaded cleanly (no malformed YAML, missing metadata)
 *   - every loaded rule has both vulnerable.<ext> and safe.<ext> fixture files
 *   - every rule id is unique across the whole library
 *
 * Exits non-zero on any failure so CI catches broken rule packs before they
 * ship. Run locally with:
 *   npx tsx scripts/validate-reachability-rules.ts
 */

import * as fs from 'fs';
import * as path from 'path';
import { loadAllRulesWithSkipped } from '../src/reachability-rules';

const ECOSYSTEM_FIXTURE_EXTS: Record<string, string> = {
  npm: 'js',
  pypi: 'py',
  maven: 'java',
  golang: 'go',
  gem: 'rb',
  composer: 'php',
};

(async () => {
  const dir = path.resolve(__dirname, '..', 'reachability-rules');
  const { loaded, skipped } = await loadAllRulesWithSkipped(dir);

  console.log(`Discovered in ${dir}:`);
  console.log(`  loaded:  ${loaded.length}`);
  console.log(`  skipped: ${skipped.length}`);
  console.log('');

  const failures: string[] = [];

  if (skipped.length > 0) {
    console.error('Skipped rule packs (these must be fixed before shipping):');
    for (const s of skipped) {
      console.error(`  - ${s.folder}: ${s.reason}`);
      failures.push(`skipped: ${s.folder} (${s.reason})`);
    }
    console.error('');
  }

  const seenIds = new Map<string, string>();
  for (const r of loaded) {
    const m = r.metadata;
    console.log([r.ruleId, m.cve, m.package, m.ecosystem, m.confidence ?? '-'].join(' | '));

    // Uniqueness check
    const prior = seenIds.get(r.ruleId);
    if (prior) {
      failures.push(`duplicate rule id ${r.ruleId}: ${prior} and ${r.rulePath}`);
    }
    seenIds.set(r.ruleId, r.rulePath);

    // Fixture check — vulnerable.<ext> and safe.<ext> must exist in
    // __fixtures__/ so the live-semgrep Jest block and the per-rule
    // CI test can prove the rule matches its own intent.
    const ecoDir = path.dirname(r.rulePath);
    const fixturesDir = path.join(ecoDir, '__fixtures__');
    const ext = ECOSYSTEM_FIXTURE_EXTS[m.ecosystem] ?? '';
    if (!ext) {
      failures.push(`${path.basename(ecoDir)}: unknown ecosystem "${m.ecosystem}" — no fixture extension mapping`);
      continue;
    }
    const vulnerable = path.join(fixturesDir, `vulnerable.${ext}`);
    const safe = path.join(fixturesDir, `safe.${ext}`);
    if (!fs.existsSync(vulnerable)) {
      failures.push(`${path.basename(ecoDir)}: missing __fixtures__/vulnerable.${ext}`);
    }
    if (!fs.existsSync(safe)) {
      failures.push(`${path.basename(ecoDir)}: missing __fixtures__/safe.${ext}`);
    }
  }

  // Suffix-collision check — guards reachability-rules.ts:normaliseOneFinding
  // which falls back to a `.`-anchored endsWith match when semgrep emits a
  // prefixed check_id (the production `--config <dir>` path produces
  // `tmp.tmp.<random>.<ruleId>`-style ids). If two rule ids share a dotted
  // tail, that fallback returns whichever entry is iterated first — silently
  // mis-attributing findings to the wrong CVE.
  const ruleIds = Array.from(seenIds.keys()).sort();
  for (let i = 0; i < ruleIds.length; i++) {
    for (let j = i + 1; j < ruleIds.length; j++) {
      const a = ruleIds[i];
      const b = ruleIds[j];
      if (a.endsWith('.' + b) || b.endsWith('.' + a)) {
        failures.push(
          `suffix collision: '${a}' and '${b}' share a dotted tail; semgrep --config <dir> findings can mis-attribute. Rename one rule's id.`,
        );
      }
    }
  }

  console.log('');
  if (failures.length === 0) {
    console.log(`OK: ${loaded.length} rule(s) loaded with fixtures, unique ids.`);
    process.exit(0);
  } else {
    console.error(`FAIL: ${failures.length} validator issue(s):`);
    for (const f of failures) console.error(`  - ${f}`);
    process.exit(1);
  }
})().catch((e) => {
  console.error('validator crashed:', e);
  process.exit(1);
});

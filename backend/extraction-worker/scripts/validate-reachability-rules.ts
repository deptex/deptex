/**
 * Ad-hoc validator: load every rule pack from reachability-rules/, report
 * how many were rejected, and dump a one-line summary per accepted rule.
 * Used during M5 to sanity-check the 20-pack batch — run with tsx:
 *   npx tsx scripts/validate-reachability-rules.ts
 */

import * as path from 'path';
import { loadAllRules } from '../src/reachability-rules';

(async () => {
  const dir = path.resolve(__dirname, '..', 'reachability-rules');
  const rules = await loadAllRules(dir);
  console.log(`loaded ${rules.length} rules from ${dir}`);
  for (const r of rules) {
    const m = r.metadata;
    console.log([r.ruleId, m.cve, m.package, m.ecosystem, m.confidence ?? '-'].join(' | '));
  }
})().catch((e) => {
  console.error('validate failed:', e);
  process.exit(1);
});

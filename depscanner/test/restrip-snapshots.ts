/**
 * One-shot helper: re-apply `DEFAULT_IGNORE_FIELDS` to every committed
 * snapshot under `fixtures/<name>/snapshots/`. The ignore list grew
 * (volatile EPSS / NVD / CISA KEV fields, tool-version stamps, rule-gen
 * pricing) after the original snapshots were bootstrapped, so the
 * committed files still contain those keys. Running this once strips
 * them in place; the diff is reviewable in a single commit.
 *
 *   npx tsx test/restrip-snapshots.ts            # dry-run
 *   npx tsx test/restrip-snapshots.ts --apply    # rewrite files in place
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

/* eslint-disable @typescript-eslint/no-explicit-any */

// Mirror of DEFAULT_IGNORE_FIELDS in snapshot.ts. Kept in sync by code review
// — if you edit one, edit the other, and this helper exists precisely so the
// re-strip is auditable when they drift.
const IGNORE = new Set([
  'id',
  'project_id',
  'organization_id',
  'dependency_id',
  'dependency_version_id',
  'project_dependency_id',
  'extraction_run_id',
  'last_seen_extraction_run_id',
  'active_extraction_run_id',
  'previous_extraction_run_id',
  'created_at',
  'updated_at',
  'removed_at',
  'detected_at',
  'completed_at',
  'started_at',
  'heartbeat_at',
  'policy_evaluated_at',
  'ast_parsed_at',
  'last_vuln_check_at',
  'last_webhook_at',
  'duration_ms',
  'sla_due_at',
  'first_seen_at',
  'last_seen_at',
  'epss_score',
  'cvss_score',
  'cisa_kev',
  'published_at',
  'generation_cost_usd',
  'generation_model_version',
  'generated_at',
  'rule_id',
  'semgrep_version',
  'trufflehog_version',
  'cdxgen_version',
  'flow_extracted_at',
  'confidence_calibrated_at',
]);

function strip(value: any): any {
  if (Array.isArray(value)) return value.map(strip);
  if (value && typeof value === 'object') {
    const out: Record<string, any> = {};
    for (const [k, v] of Object.entries(value)) {
      if (IGNORE.has(k)) continue;
      out[k] = strip(v);
    }
    return out;
  }
  return value;
}

function loadFixtureIgnore(fixtureDir: string): Set<string> {
  const p = path.join(fixtureDir, 'snapshot-ignore.json');
  if (!fs.existsSync(p)) return new Set();
  try {
    const raw = JSON.parse(fs.readFileSync(p, 'utf8')) as { ignore_fields?: string[] };
    return new Set(raw.ignore_fields ?? []);
  } catch {
    return new Set();
  }
}

function main() {
  const apply = process.argv.includes('--apply');
  const root = path.resolve(__dirname, '../fixtures');
  const fixtures = fs.readdirSync(root, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name);

  let changed = 0;
  let unchanged = 0;
  for (const name of fixtures) {
    const snapDir = path.join(root, name, 'snapshots');
    if (!fs.existsSync(snapDir)) continue;
    const extraIgnore = loadFixtureIgnore(path.join(root, name));
    const localIgnore = new Set([...IGNORE, ...extraIgnore]);
    const stripLocal = (v: any): any => {
      if (Array.isArray(v)) return v.map(stripLocal);
      if (v && typeof v === 'object') {
        const out: Record<string, any> = {};
        for (const [k, val] of Object.entries(v)) {
          if (localIgnore.has(k)) continue;
          out[k] = stripLocal(val);
        }
        return out;
      }
      return v;
    };

    for (const file of fs.readdirSync(snapDir)) {
      if (!file.endsWith('.json')) continue;
      const full = path.join(snapDir, file);
      const before = fs.readFileSync(full, 'utf8');
      const parsed = JSON.parse(before);
      const stripped = stripLocal(parsed);
      const after = JSON.stringify(stripped, null, 2) + '\n';
      if (after !== before) {
        changed++;
        console.log(`${apply ? 'rewrite' : 'would rewrite'}: ${name}/${file}`);
        if (apply) fs.writeFileSync(full, after, 'utf8');
      } else {
        unchanged++;
      }
    }
  }
  console.log(`\n${apply ? 'rewrote' : 'would rewrite'} ${changed} file(s); ${unchanged} already clean`);
}

main();

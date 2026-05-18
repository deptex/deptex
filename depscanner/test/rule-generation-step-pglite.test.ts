/**
 * PGLite integration test for the Phase 25 schema + the writes
 * `rule-generation-step.ts` performs against it.
 *
 * The unit test in src/__tests__/rule-generation-step.test.ts uses a
 * hand-rolled FakeStorage chain mock — fast, but it does NOT honor
 * UNIQUE / CHECK / FK CASCADE constraints from
 * phase25_reachability_rule_generation.sql or
 * phase25b_reachability_validation_breakdown.sql. This test boots PGLite
 * (which loads backend/database/schema.sql) and exercises the writes the
 * step actually performs:
 *
 *   - INSERT into organization_reachability_settings (new in phase25)
 *   - INSERT into organization_generated_rules (new in phase25)
 *   - UNIQUE(organization_id, cve_id, package_purl) enforcement
 *   - CHECK constraint on validation_status (enum)
 *   - CHECK constraint on ai_provider / on_budget_exhaustion
 *   - UPDATE on extraction_jobs with the new phase25/25b columns
 *     (reachability_rules_*, reachability_generation_cost_usd,
 *      reachability_validation_breakdown jsonb)
 *   - FK CASCADE: deleting an org wipes both new-table rows
 *
 * If a future migration renames a column or changes a constraint, this
 * test trips. The FakeStorage unit test would not.
 *
 * Run: npx tsx test/rule-generation-step-pglite.test.ts
 */

import * as fs from 'fs';
import * as path from 'path';
import { createPGLiteStorage } from '../src/storage';

// Bootstrap: a real org + project + extraction_jobs row so the phase25 FKs can
// resolve. We skip the full schema.sql dump (which carries dump-helper
// functions PGLite can't parse) and instead apply the phase25 / phase25b
// migrations directly on top of a minimal scaffold. This proves the migration
// files themselves apply cleanly — the criticalreview P0 was specifically about
// migration drift not being caught by unit-mocked tests.
// Test seeds explicit ids so we don't need pgcrypto.gen_random_uuid().
const SCAFFOLD_SQL = `
  CREATE TABLE IF NOT EXISTS organizations (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
  );

  CREATE TABLE IF NOT EXISTS projects (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
  );

  CREATE TABLE IF NOT EXISTS extraction_jobs (
    id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    status text NOT NULL,
    triggered_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
  );

  -- Stand in for auth.users so the updated_by FK in phase25 resolves locally.
  CREATE SCHEMA IF NOT EXISTS auth;
  CREATE TABLE IF NOT EXISTS auth.users (id uuid PRIMARY KEY);
`;

const PHASE25_SQL_PATH = path.resolve(__dirname, '../../backend/database/phase25_reachability_rule_generation.sql');
const PHASE25B_SQL_PATH = path.resolve(__dirname, '../../backend/database/phase25b_reachability_validation_breakdown.sql');
const PHASE25C_SQL_PATH = path.resolve(__dirname, '../../backend/database/phase25c_reachability_settings_updated_by_index.sql');

let failures = 0;

function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
  }
}

async function expectError(p: Promise<{ error: unknown }>, msg: string): Promise<void> {
  const { error } = await p;
  assert(error !== null && error !== undefined, msg);
}

async function main() {
  const t0 = Date.now();
  console.log('Booting PGLiteStorage (skipSchemaLoad=true; applying phase25 directly)...');
  const storage = await createPGLiteStorage({ skipSchemaLoad: true });
  await storage.db.exec(SCAFFOLD_SQL);

  // Apply each migration in order — strip the auth.users() existence check
  // (Supabase ships it; our local scaffold provides the table directly) and
  // any RLS policy that depends on auth.uid() (no auth in PGLite). This
  // mirrors the same pattern phase19/phase20 PGLite tests use.
  const sanitize = (sql: string) =>
    sql
      // Remove RLS enable + CREATE POLICY blocks — they reference auth.uid()
      // which PGLite doesn't have.
      .replace(/ALTER TABLE [^\s]+ ENABLE ROW LEVEL SECURITY\s*;?/gi, '')
      .replace(/DROP POLICY IF EXISTS[\s\S]*?;\s*/gi, '')
      .replace(/CREATE POLICY[\s\S]*?\);\s*/gi, '');

  for (const p of [PHASE25_SQL_PATH, PHASE25B_SQL_PATH, PHASE25C_SQL_PATH]) {
    const sql = fs.readFileSync(p, 'utf8');
    await storage.db.exec(sanitize(sql));
    console.log(`  applied ${path.basename(p)}`);
  }
  console.log(`  booted + migrated in ${Date.now() - t0}ms\n`);

  const ORG_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
  const OTHER_ORG_ID = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
  const PROJECT_ID = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
  const JOB_ID = 'dddddddd-dddd-dddd-dddd-dddddddddddd';

  // --- Seed: orgs ---
  await storage.from('organizations').insert({
    id: ORG_ID,
    name: 'rulegen-pglite-test-org',
    created_at: new Date().toISOString(),
  });
  await storage.from('organizations').insert({
    id: OTHER_ORG_ID,
    name: 'rulegen-pglite-test-org-2',
    created_at: new Date().toISOString(),
  });

  // --- Seed: project ---
  await storage.from('projects').insert({
    id: PROJECT_ID,
    organization_id: ORG_ID,
    name: 'rulegen-pglite-test-project',
    created_at: new Date().toISOString(),
  });

  // --- Seed: extraction_jobs row so we can test the telemetry UPDATE ---
  await storage.from('extraction_jobs').insert({
    id: JOB_ID,
    project_id: PROJECT_ID,
    organization_id: ORG_ID,
    status: 'completed',
    triggered_by: 'manual',
    created_at: new Date().toISOString(),
  });

  // ============================================================
  // 1. organization_reachability_settings — phase25 new table
  // ============================================================
  console.log('\n[settings] insert one row per org');
  {
    const { error } = await storage.from('organization_reachability_settings').insert({
      organization_id: ORG_ID,
      auto_generate_enabled: true,
      trigger_severities: ['critical', 'high'],
      trigger_kev: true,
      trigger_asset_tier_max_rank: 2,
      trigger_newly_discovered: true,
      trigger_reevaluate_existing: false,
      ai_provider: 'anthropic',
      ai_model: 'claude-sonnet-4-6',
      monthly_budget_usd: 25.0,
      on_budget_exhaustion: 'skip',
      max_wait_seconds: 300,
    });
    assert(error === null, `insert settings (error=${(error as any)?.message ?? 'null'})`);
  }

  console.log('[settings] PRIMARY KEY rejects a second row for the same org');
  await expectError(
    storage.from('organization_reachability_settings').insert({
      organization_id: ORG_ID,
      ai_provider: 'openai',
      ai_model: 'gpt-4o',
      monthly_budget_usd: 5,
      on_budget_exhaustion: 'skip',
    }) as Promise<{ error: unknown }>,
    'second insert for same org_id is rejected by PK',
  );

  console.log('[settings] CHECK rejects unknown ai_provider');
  await expectError(
    storage.from('organization_reachability_settings').insert({
      organization_id: OTHER_ORG_ID,
      ai_provider: 'fake-provider',
      ai_model: 'whatever',
      monthly_budget_usd: 10,
      on_budget_exhaustion: 'skip',
    }) as Promise<{ error: unknown }>,
    'unknown ai_provider rejected by CHECK constraint',
  );

  console.log('[settings] CHECK rejects unknown on_budget_exhaustion');
  await expectError(
    storage.from('organization_reachability_settings').insert({
      organization_id: OTHER_ORG_ID,
      ai_provider: 'anthropic',
      ai_model: 'claude-sonnet-4-6',
      monthly_budget_usd: 10,
      on_budget_exhaustion: 'crash-and-burn',
    }) as Promise<{ error: unknown }>,
    'unknown on_budget_exhaustion rejected by CHECK constraint',
  );

  // ============================================================
  // 2. organization_generated_rules — phase25 new table
  // ============================================================
  console.log('\n[rules] insert a validated rule with every phase25 column populated');
  {
    const { error } = await storage.from('organization_generated_rules').insert({
      organization_id: ORG_ID,
      cve_id: 'CVE-2024-1234',
      package_purl: 'pkg:npm/lodash@4.17.20',
      ecosystem: 'npm',
      affected_version_range: '<4.17.21',
      rule_yaml: 'rules:\n  - id: deptex.lodash.test\n    languages: [javascript]\n    severity: ERROR\n    message: test\n    pattern: foo($X)\n',
      vulnerable_fixture: 'foo(req.body.x)',
      safe_fixture: 'bar()',
      reachability_level: 'confirmed',
      entry_point_class: 'PUBLIC_UNAUTH',
      generated_with_provider: 'anthropic',
      generated_with_model: 'claude-sonnet-4-6',
      generation_cost_usd: 0.0234,
      validation_status: 'validated',
      validation_log: { fixture_pre_matches: 1, fixture_post_matches: 0 },
      enabled: true,
      generated_at: new Date().toISOString(),
      previous_versions: [],
    });
    assert(error === null, `insert validated rule (error=${(error as any)?.message ?? 'null'})`);
  }

  console.log('[rules] UNIQUE(organization_id, cve_id, package_purl) rejects duplicates within an org');
  await expectError(
    storage.from('organization_generated_rules').insert({
      organization_id: ORG_ID,
      cve_id: 'CVE-2024-1234',
      package_purl: 'pkg:npm/lodash@4.17.20',
      ecosystem: 'npm',
      rule_yaml: 'different rule',
      vulnerable_fixture: 'x',
      safe_fixture: 'y',
      generated_with_provider: 'anthropic',
      generated_with_model: 'claude-haiku-4-5-20251001',
      generation_cost_usd: 0.01,
      validation_status: 'validated',
      enabled: true,
      generated_at: new Date().toISOString(),
    }) as Promise<{ error: unknown }>,
    'duplicate (org_id, cve_id, package_purl) rejected',
  );

  console.log('[rules] same (cve_id, package_purl) WORKS for a different org (per-tenant scope)');
  {
    const { error } = await storage.from('organization_generated_rules').insert({
      organization_id: OTHER_ORG_ID,
      cve_id: 'CVE-2024-1234',
      package_purl: 'pkg:npm/lodash@4.17.20',
      ecosystem: 'npm',
      rule_yaml: 'rules:\n  - id: deptex.x\n    languages: [javascript]\n    severity: INFO\n    message: m\n    pattern: x\n',
      vulnerable_fixture: 'a',
      safe_fixture: 'b',
      reachability_level: 'function',
      generated_with_provider: 'anthropic',
      generated_with_model: 'claude-haiku-4-5-20251001',
      generation_cost_usd: 0.01,
      validation_status: 'validated',
      enabled: true,
      generated_at: new Date().toISOString(),
    });
    assert(
      error === null,
      `same CVE/purl in a DIFFERENT org succeeds — UNIQUE is correctly per-tenant (error=${(error as any)?.message ?? 'null'})`,
    );
  }

  console.log('[rules] CHECK rejects unknown validation_status');
  await expectError(
    storage.from('organization_generated_rules').insert({
      organization_id: ORG_ID,
      cve_id: 'CVE-2024-9999',
      package_purl: 'pkg:npm/x@1',
      ecosystem: 'npm',
      rule_yaml: 'rules: []',
      vulnerable_fixture: 'a',
      safe_fixture: 'b',
      reachability_level: 'function',
      generated_with_provider: 'anthropic',
      generated_with_model: 'm',
      generation_cost_usd: 0,
      validation_status: 'wat',
      enabled: false,
      generated_at: new Date().toISOString(),
    }) as Promise<{ error: unknown }>,
    'unknown validation_status rejected by CHECK constraint',
  );

  // ============================================================
  // 3. extraction_jobs — phase25/25b new columns the worker writes
  // ============================================================
  console.log('\n[jobs] update extraction_jobs with the new phase25 + phase25b columns');
  {
    const { error } = await storage
      .from('extraction_jobs')
      .update({
        reachability_rules_total_detectable: 3,
        reachability_rules_matched: 2,
        reachability_rules_generated_this_scan: 1,
        reachability_generation_cost_usd: 0.0337,
        reachability_validation_breakdown: {
          candidates: 3,
          schema_pass: 3,
          pattern_compile_pass: 3,
          fixture_pre_pass: 2,
          fixture_safe_pass: 2,
          patch_pre_pass: 1,
          patch_post_pass: 2,
        },
      })
      .eq('id', JOB_ID);
    assert(error === null, `update phase25/25b columns on extraction_jobs (error=${(error as any)?.message ?? 'null'})`);

    // Read back and verify values landed.
    const { data, error: readErr } = await storage
      .from('extraction_jobs')
      .select(
        'reachability_rules_total_detectable, reachability_rules_matched, reachability_rules_generated_this_scan, reachability_generation_cost_usd, reachability_validation_breakdown',
      )
      .eq('id', JOB_ID)
      .single();
    assert(readErr === null, `read extraction_jobs back (error=${(readErr as any)?.message ?? 'null'})`);
    const row = data as any;
    assert(row.reachability_rules_total_detectable === 3, `total_detectable=3 (got ${row.reachability_rules_total_detectable})`);
    assert(row.reachability_rules_matched === 2, `matched=2 (got ${row.reachability_rules_matched})`);
    assert(row.reachability_rules_generated_this_scan === 1, `generated_this_scan=1 (got ${row.reachability_rules_generated_this_scan})`);
    // Numeric — PGLite returns it as string sometimes; accept either.
    const cost = typeof row.reachability_generation_cost_usd === 'string'
      ? parseFloat(row.reachability_generation_cost_usd)
      : row.reachability_generation_cost_usd;
    assert(Math.abs(cost - 0.0337) < 0.0001, `generation_cost_usd≈0.0337 (got ${cost})`);
    assert(
      row.reachability_validation_breakdown?.candidates === 3,
      `validation_breakdown.candidates=3 (got ${JSON.stringify(row.reachability_validation_breakdown)})`,
    );
  }

  // ============================================================
  // 4. FK CASCADE: deleting OTHER_ORG_ID wipes its rule row
  // ============================================================
  console.log('\n[cascade] deleting an organization removes its generated rules');
  {
    const { error: delErr } = await storage.from('organizations').delete().eq('id', OTHER_ORG_ID);
    assert(delErr === null, `delete OTHER_ORG (error=${(delErr as any)?.message ?? 'null'})`);
    const { data: leftover } = await storage
      .from('organization_generated_rules')
      .select('id')
      .eq('organization_id', OTHER_ORG_ID);
    assert(
      Array.isArray(leftover) && leftover.length === 0,
      `org delete cascaded to organization_generated_rules (leftover rows=${Array.isArray(leftover) ? leftover.length : 'not array'})`,
    );
  }

  console.log(`\nDone in ${Date.now() - t0}ms. ${failures === 0 ? 'ALL GREEN' : `${failures} FAILURES`}.`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('test crashed:', e);
  process.exit(1);
});

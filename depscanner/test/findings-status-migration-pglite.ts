/**
 * Backfill harness for phase55 (findings-status foundation).
 *
 * The finalize-extraction PGLite tests boot a DDL-only schema.sql, so they can't
 * test a migration's BACKFILL. This boots the CURRENT (pre-phase55) schema.sql,
 * seeds one row per golden-master case across all seven finding stores, execs
 * the raw phase55.sql, and asserts the stored (finding_key, auto_ignored,
 * auto_ignore_reason, status) per row — including the legacy->status mapping,
 * the malicious allowlist exclusion, the IaC generic-severity divergence fix,
 * and idempotency (the migration runs twice).
 *
 * Run: npx tsx test/findings-status-migration-pglite.ts
 */

import { PGlite } from '@electric-sql/pglite';
import { vector } from '@electric-sql/pglite/vector';
import { uuid_ossp } from '@electric-sql/pglite/contrib/uuid_ossp';
import * as fs from 'fs';
import * as path from 'path';

const SCHEMA_FILE = path.resolve(__dirname, '../../backend/database/schema.sql');
const PHASE55_FILE = path.resolve(__dirname, '../../backend/database/phase55_findings_status_foundation.sql');

let failures = 0;
let passed = 0;
function assert(cond: unknown, msg: string): void {
  if (!cond) { console.error(`    FAIL: ${msg}`); failures++; } else { console.log(`    ok: ${msg}`); passed++; }
}

const ORG = '11111111-1111-1111-1111-111111111111';
const PROJ = '22222222-2222-2222-2222-222222222222';
const DEP = '33333333-3333-3333-3333-333333333333';
const TARGET = '44444444-4444-4444-4444-444444444444';
const RUN = 'run_phase55_001';

async function bootDb(): Promise<PGlite> {
  const db = new PGlite({ extensions: { vector, uuid_ossp } });
  await db.waitReady;
  await db.exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`);
  await db.exec(`CREATE EXTENSION IF NOT EXISTS vector;`);
  await db.exec(`
    CREATE SCHEMA IF NOT EXISTS auth;
    CREATE TABLE IF NOT EXISTS auth.users (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), email text, created_at timestamptz DEFAULT now());
    CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT NULL::uuid $$;
    CREATE OR REPLACE FUNCTION auth.role() RETURNS text LANGUAGE sql STABLE AS $$ SELECT 'service_role'::text $$;
    CREATE OR REPLACE FUNCTION auth.email() RETURNS text LANGUAGE sql STABLE AS $$ SELECT NULL::text $$;
    CREATE TABLE IF NOT EXISTS public.aegis_memory (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid, category text, key text, content text, embedding vector(1536), expires_at timestamptz);
  `);
  await db.exec(`SET check_function_bodies = off;`);
  await db.exec(fs.readFileSync(SCHEMA_FILE, 'utf8'));
  return db;
}

async function seed(db: PGlite): Promise<void> {
  await db.exec(`
    INSERT INTO organizations (id, name, created_at) VALUES ('${ORG}', 'org', NOW()) ON CONFLICT (id) DO NOTHING;
    INSERT INTO projects (id, organization_id, name, active_extraction_run_id, created_at)
      VALUES ('${PROJ}', '${ORG}', 'proj', '${RUN}', NOW()) ON CONFLICT (id) DO NOTHING;
    INSERT INTO dependencies (id, name, ecosystem, status, created_at)
      VALUES ('${DEP}', 'lodash', 'npm', 'pending', NOW()) ON CONFLICT (id) DO NOTHING;
    INSERT INTO project_dependencies (id, project_id, name, version, is_direct, source, last_seen_extraction_run_id, created_at)
      VALUES ('${DEP}', '${PROJ}', 'lodash', '4.17.20', true, 'dependencies', '${RUN}', NOW());
  `);

  // --- SCA: reachability spread + runtime override + legacy suppressed ---
  await db.exec(`
    INSERT INTO project_dependency_vulnerabilities (project_id, project_dependency_id, osv_id, severity, extraction_run_id, status, reachability_level, is_reachable, runtime_confirmed_at, suppressed, depscore)
    VALUES
      ('${PROJ}','${DEP}','CVE-UNREACH','high','${RUN}','open','unreachable',true,NULL,false,90),
      ('${PROJ}','${DEP}','CVE-CONFIRMED','high','${RUN}','open','confirmed',true,NULL,false,90),
      ('${PROJ}','${DEP}','CVE-MODULE','high','${RUN}','open','module',true,NULL,false,50),
      ('${PROJ}','${DEP}','CVE-RUNTIME','high','${RUN}','open','unreachable',true,NOW(),false,90),
      ('${PROJ}','${DEP}','CVE-SUPPRESSED','high','${RUN}','open','confirmed',true,NULL,true,90);
  `);

  // --- secret + semgrep (never auto-ignored) ---
  await db.exec(`
    INSERT INTO project_secret_findings (project_id, extraction_run_id, detector_type, file_path, redacted_value, status, depscore)
      VALUES ('${PROJ}','${RUN}','aws','src/a.ts','AKIA****','open',80);
    INSERT INTO project_semgrep_findings (project_id, extraction_run_id, rule_id, file_path, start_line, status, depscore, semgrep_fingerprint)
      VALUES ('${PROJ}','${RUN}','rules.xss','src/b.ts',12,'open',75,'fp_semgrep_1');
  `);

  // --- DAST: passive vs active vs legacy 'closed' ---
  await db.exec(`
    INSERT INTO project_dast_targets (id, project_id, organization_id, target_url, active_dast_run_id)
      VALUES ('${TARGET}','${PROJ}','${ORG}','https://app.test','${RUN}');
    INSERT INTO project_dast_findings (project_id, organization_id, dast_run_id, target_id, endpoint_url, http_method, vulnerability_type, severity, status, payload_redacted, rule_id, handler_file_path, created_at)
    VALUES
      ('${PROJ}','${ORG}','${RUN}','${TARGET}','https://app.test/h','GET','Missing Header','low','open',NULL,'10020','src/h.ts', NOW()),
      ('${PROJ}','${ORG}','${RUN}','${TARGET}','https://app.test/q','GET','SQL Injection','high','open',''' OR 1=1--','40018','src/q.ts', NOW()),
      ('${PROJ}','${ORG}','${RUN}','${TARGET}','https://app.test/c','GET','Old Finding','medium','suppressed',NULL,'99999','src/c.ts', NOW());
  `);

  // --- IaC: critical / hardening / unmapped-HIGH (divergence) / legacy risk-accept ---
  await db.exec(`
    INSERT INTO project_iac_findings (project_id, organization_id, extraction_run_id, scanner, rule_id, framework, file_path, start_line, severity, status, suppressed, risk_accepted, depscore)
    VALUES
      ('${PROJ}','${ORG}','${RUN}','checkov','CKV_K8S_16','kubernetes','k8s/a.yml',10,'HIGH','open',false,false,82),
      ('${PROJ}','${ORG}','${RUN}','checkov','CKV_K8S_13','kubernetes','k8s/b.yml',20,'MEDIUM','open',false,false,24),
      ('${PROJ}','${ORG}','${RUN}','checkov','CKV_AWS_23','terraform','tf/c.tf',5,'HIGH','open',false,false,66),
      ('${PROJ}','${ORG}','${RUN}','checkov','CKV_K8S_16','kubernetes','k8s/d.yml',30,'HIGH','open',false,true,82);
  `);

  // --- container: KEV vs non-KEV ---
  await db.exec(`
    INSERT INTO project_container_findings (project_id, organization_id, extraction_run_id, image_reference, image_digest, image_source, os_package_name, os_package_version, osv_id, is_kev, depscore, status, container_fingerprint)
    VALUES
      ('${PROJ}','${ORG}','${RUN}','debian:11','sha256:aaa','dockerfile_base','openssl','1.1','CVE-KEV',true,95,'open','cfp_kev'),
      ('${PROJ}','${ORG}','${RUN}','debian:11','sha256:aaa','dockerfile_base','zlib','1.2','CVE-NONKEV',false,60,'open','cfp_nonkev');
  `);

  // --- malicious: normal / allowlist-suppressed (stays open) / non-allowlist suppressed (->ignored) ---
  await db.exec(`
    INSERT INTO project_malicious_findings (project_id, organization_id, extraction_run_id, project_dependency_id, dependency_id, rule_id, scanner, severity, suppressed, suppressed_reason, risk_accepted)
    VALUES
      ('${PROJ}','${ORG}','${RUN}','${DEP}','${DEP}','mal.rule.1','guarddog','critical',false,NULL,false),
      ('${PROJ}','${ORG}','${RUN}','${DEP}','${DEP}','mal.rule.2','guarddog','critical',true,'allowlist:approved by owner',false),
      ('${PROJ}','${ORG}','${RUN}','${DEP}','${DEP}','mal.rule.3','guarddog','critical',true,'false positive',false);
  `);
}

async function one(db: PGlite, sql: string, params: unknown[] = []): Promise<Record<string, unknown>> {
  const r = await db.query<Record<string, unknown>>(sql, params);
  return r.rows[0];
}

async function assertState(db: PGlite, phase: string): Promise<void> {
  console.log(`\n  [${phase}] SCA`);
  const unreach = await one(db, `SELECT auto_ignored, auto_ignore_reason, finding_key FROM project_dependency_vulnerabilities WHERE osv_id='CVE-UNREACH'`);
  assert(unreach.auto_ignored === true && unreach.auto_ignore_reason === 'not_reachable', 'unreachable -> auto_ignored not_reachable');
  assert(typeof unreach.finding_key === 'string' && (unreach.finding_key as string).length === 64, 'unreachable -> finding_key is a sha256 hex');
  const conf = await one(db, `SELECT auto_ignored FROM project_dependency_vulnerabilities WHERE osv_id='CVE-CONFIRMED'`);
  assert(conf.auto_ignored === false, 'confirmed -> not auto_ignored');
  const mod = await one(db, `SELECT auto_ignore_reason FROM project_dependency_vulnerabilities WHERE osv_id='CVE-MODULE'`);
  assert(mod.auto_ignore_reason === 'unconfirmed_reachable', 'module -> unconfirmed_reachable');
  const rt = await one(db, `SELECT auto_ignored, auto_ignore_reason FROM project_dependency_vulnerabilities WHERE osv_id='CVE-RUNTIME'`);
  assert(rt.auto_ignored === true && rt.auto_ignore_reason === 'not_reachable', 'runtime+unreachable -> stored auto_ignored (read-time override handles effective)');
  const sup = await one(db, `SELECT status FROM project_dependency_vulnerabilities WHERE osv_id='CVE-SUPPRESSED'`);
  assert(sup.status === 'ignored', 'legacy suppressed -> status ignored');

  console.log(`  [${phase}] secret + semgrep`);
  const sec = await one(db, `SELECT auto_ignored, finding_key FROM project_secret_findings LIMIT 1`);
  assert(sec.auto_ignored === false && typeof sec.finding_key === 'string', 'secret -> finding_key set, never auto_ignored');
  const sg = await one(db, `SELECT auto_ignored, finding_key FROM project_semgrep_findings LIMIT 1`);
  assert(sg.auto_ignored === false && typeof sg.finding_key === 'string', 'semgrep -> finding_key set, never auto_ignored');

  console.log(`  [${phase}] DAST`);
  const passive = await one(db, `SELECT auto_ignored, auto_ignore_reason FROM project_dast_findings WHERE vulnerability_type='Missing Header'`);
  assert(passive.auto_ignored === true && passive.auto_ignore_reason === 'passive_hygiene', 'passive dast -> passive_hygiene');
  const active = await one(db, `SELECT auto_ignored FROM project_dast_findings WHERE vulnerability_type='SQL Injection'`);
  assert(active.auto_ignored === false, 'active dast (payload) -> not auto_ignored');
  const suppressed = await one(db, `SELECT status FROM project_dast_findings WHERE vulnerability_type='Old Finding'`);
  assert(suppressed.status === 'suppressed', 'dast native suppressed status preserved (counts as hidden via status<>open)');

  console.log(`  [${phase}] IaC`);
  const crit = await one(db, `SELECT auto_ignored FROM project_iac_findings WHERE rule_id='CKV_K8S_16' AND risk_accepted=false`);
  assert(crit.auto_ignored === false, 'iac critical rule -> not auto_ignored');
  const hard = await one(db, `SELECT auto_ignore_reason FROM project_iac_findings WHERE rule_id='CKV_K8S_13'`);
  assert(hard.auto_ignore_reason === 'iac_hardening', 'iac hardening rule -> iac_hardening');
  const unmapped = await one(db, `SELECT auto_ignored FROM project_iac_findings WHERE rule_id='CKV_AWS_23'`);
  assert(unmapped.auto_ignored === false, 'iac unmapped HIGH -> open (phase54 divergence FIXED)');
  const iacRa = await one(db, `SELECT status FROM project_iac_findings WHERE risk_accepted=true`);
  assert(iacRa.status === 'ignored', 'legacy iac risk-accepted -> status ignored');

  console.log(`  [${phase}] container`);
  const kev = await one(db, `SELECT auto_ignored FROM project_container_findings WHERE osv_id='CVE-KEV'`);
  assert(kev.auto_ignored === false, 'container KEV -> open');
  const nonkev = await one(db, `SELECT auto_ignore_reason FROM project_container_findings WHERE osv_id='CVE-NONKEV'`);
  assert(nonkev.auto_ignore_reason === 'base_image', 'container non-KEV -> base_image');

  console.log(`  [${phase}] malicious`);
  const malNormal = await one(db, `SELECT status FROM project_malicious_findings WHERE rule_id='mal.rule.1'`);
  assert(malNormal.status === 'open', 'malicious normal -> open');
  const malAllow = await one(db, `SELECT status FROM project_malicious_findings WHERE rule_id='mal.rule.2'`);
  assert(malAllow.status === 'open', 'malicious allowlist-suppressed -> stays open (excluded from legacy->status)');
  const malFp = await one(db, `SELECT status FROM project_malicious_findings WHERE rule_id='mal.rule.3'`);
  assert(malFp.status === 'ignored', 'malicious non-allowlist suppressed -> status ignored');
}

async function main() {
  const t0 = Date.now();
  console.log('Booting PGLite + schema.sql...');
  const db = await bootDb();
  console.log('Seeding finding rows...');
  await seed(db);

  const phase55 = fs.readFileSync(PHASE55_FILE, 'utf8');
  console.log('\nApplying phase55 (first run)...');
  await db.exec(phase55);
  await assertState(db, 'after 1st apply');

  console.log('\nApplying phase55 AGAIN (idempotency)...');
  await db.exec(phase55);
  await assertState(db, 'after 2nd apply');

  // The divergence fix must also surface in the COUNT path: the open IaC set
  // now includes the unmapped HIGH rule (CKV_K8S_16 + CKV_AWS_23), not just the
  // narrow phase54 IN-list.
  console.log('\n  [count] security_summary_counts');
  const openIac = await one(db, `SELECT count(*)::int AS n FROM project_iac_findings WHERE project_id='${PROJ}' AND extraction_run_id='${RUN}' AND status NOT IN ('ignored','resolved') AND auto_ignored=false`);
  assert(openIac.n === 2, 'open IaC set = 2 (critical + unmapped HIGH), divergence fix visible to the count path');
  const rpc = await one(db, `SELECT * FROM security_summary_counts(ARRAY['${PROJ}']::uuid[], ARRAY['${RUN}']::text[])`);
  assert(rpc !== undefined && Number(rpc.band_critical) >= 0, 'security_summary_counts runs without error');

  await db.close();
  console.log(`\n${'='.repeat(48)}`);
  console.log(`phase55 backfill harness: ${passed} passed, ${failures} failed (${Date.now() - t0}ms)`);
  if (failures > 0) process.exit(1);
  console.log('PASSED');
}

main().catch((e) => { console.error('Unhandled error:', e); process.exit(1); });

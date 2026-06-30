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
const PHASE55C_FILE = path.resolve(__dirname, '../../backend/database/phase55c_finding_status_triggers.sql');

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

  // Triggers (phase55c): a fresh scan's inserts must auto-stamp finding_key +
  // auto_ignored without re-running the backfill, and an auto-ignored finding
  // must auto-reopen when its reachability later improves.
  const phase55c = fs.readFileSync(PHASE55C_FILE, 'utf8');
  console.log('\nApplying phase55c (triggers)...');
  await db.exec(phase55c);

  console.log('\n  [triggers] fresh insert + auto-reopen');
  await db.exec(`INSERT INTO project_dependency_vulnerabilities (project_id, project_dependency_id, osv_id, severity, extraction_run_id, status, reachability_level, is_reachable)
    VALUES ('${PROJ}','${DEP}','CVE-TRIGGER','high','${RUN}','open','unreachable',true);`);
  const trig = await one(db, `SELECT finding_key, auto_ignored, auto_ignore_reason FROM project_dependency_vulnerabilities WHERE osv_id='CVE-TRIGGER'`);
  assert(typeof trig.finding_key === 'string' && (trig.finding_key as string).length === 64, 'trigger stamps finding_key on a fresh insert (no backfill)');
  assert(trig.auto_ignored === true && trig.auto_ignore_reason === 'not_reachable', 'trigger stamps auto_ignored on a fresh insert');
  await db.exec(`UPDATE project_dependency_vulnerabilities SET reachability_level='confirmed' WHERE osv_id='CVE-TRIGGER';`);
  const reopened = await one(db, `SELECT auto_ignored, finding_key FROM project_dependency_vulnerabilities WHERE osv_id='CVE-TRIGGER'`);
  assert(reopened.auto_ignored === false, 'trigger auto-reopens when reachability becomes confirmed');
  assert(reopened.finding_key === trig.finding_key, 'finding_key is stable across updates (computed on INSERT only)');
  await db.exec(`INSERT INTO project_container_findings (project_id, organization_id, extraction_run_id, image_reference, image_digest, image_source, os_package_name, os_package_version, osv_id, is_kev, depscore, status, container_fingerprint)
    VALUES ('${PROJ}','${ORG}','${RUN}','debian:11','sha256:bbb','dockerfile_base','curl','7.1','CVE-TRIG2',false,55,'open','cfp_trig');`);
  const ctrig = await one(db, `SELECT auto_ignore_reason, finding_key FROM project_container_findings WHERE osv_id='CVE-TRIG2'`);
  assert(ctrig.auto_ignore_reason === 'base_image', 'trigger stamps container non-KEV as base_image on a fresh insert');
  assert(typeof ctrig.finding_key === 'string', 'trigger stamps container finding_key on a fresh insert');

  // The divergence fix must also surface in the COUNT path: the open IaC set
  // now includes the unmapped HIGH rule (CKV_K8S_16 + CKV_AWS_23), not just the
  // narrow phase54 IN-list.
  console.log('\n  [count] security_summary_counts');
  const openIac = await one(db, `SELECT count(*)::int AS n FROM project_iac_findings WHERE project_id='${PROJ}' AND extraction_run_id='${RUN}' AND status NOT IN ('ignored','resolved') AND auto_ignored=false`);
  assert(openIac.n === 2, 'open IaC set = 2 (critical + unmapped HIGH), divergence fix visible to the count path');
  const rpc = await one(db, `SELECT * FROM security_summary_counts(ARRAY['${PROJ}']::uuid[], ARRAY['${RUN}']::text[])`);
  assert(rpc !== undefined && Number(rpc.band_critical) >= 0, 'security_summary_counts runs without error');

  // phase56: malicious carry-forward + is_malicious recompute + reap. Malicious
  // findings are inserted by insert_malicious_findings_with_recompute (not
  // finalize), so the carry-forward lives there, keyed on the trigger-stamped
  // finding_key.
  console.log('\n  [malicious] carry-forward + is_malicious recompute + reap');
  const RUN2 = 'run_phase56_002';

  // Baseline: an open malicious finding marks the dependency malicious.
  await db.exec(`SELECT recompute_dependency_is_malicious(ARRAY['${DEP}']::uuid[]);`);
  const baseMal = await one(db, `SELECT is_malicious FROM dependencies WHERE id='${DEP}'`);
  assert(baseMal.is_malicious === true, 'an open malicious finding marks dependencies.is_malicious');

  // A manual status ignore + recompute clears the flag (the desync fix).
  await db.exec(`UPDATE project_malicious_findings SET status='ignored', ignore_reason='false_positive', ignored_at=NOW() WHERE rule_id='mal.rule.1' AND extraction_run_id='${RUN}';`);
  await db.exec(`SELECT recompute_dependency_is_malicious(ARRAY['${DEP}']::uuid[]);`);
  const ignoredMal = await one(db, `SELECT is_malicious FROM dependencies WHERE id='${DEP}'`);
  assert(ignoredMal.is_malicious === false, 'ignoring the only active malicious finding clears dependencies.is_malicious');

  // Rescan: the same finding reappears in a new run via the insert RPC — the
  // manual ignore must carry forward (matched on finding_key) and the dep stays
  // un-flagged.
  await db.query(`SELECT insert_malicious_findings_with_recompute($1::jsonb)`, [JSON.stringify([
    { project_id: PROJ, organization_id: ORG, extraction_run_id: RUN2, project_dependency_id: DEP, dependency_id: DEP, rule_id: 'mal.rule.1', scanner: 'guarddog', severity: 'critical', message: 'x', depscore: 90 },
  ])]);
  const carried = await one(db, `SELECT status, ignore_reason FROM project_malicious_findings WHERE rule_id='mal.rule.1' AND extraction_run_id='${RUN2}'`);
  assert(carried?.status === 'ignored', 'manual ignore carries forward onto the new run (finding_key match)');
  assert(carried?.ignore_reason === 'false_positive', 'ignore_reason carries forward onto the new run');
  const stillNotMal = await one(db, `SELECT is_malicious FROM dependencies WHERE id='${DEP}'`);
  assert(stillNotMal.is_malicious === false, 'is_malicious stays false after a rescan of a carried-ignore finding');

  // A genuinely new malicious finding does not inherit the ignore and re-flags.
  await db.query(`SELECT insert_malicious_findings_with_recompute($1::jsonb)`, [JSON.stringify([
    { project_id: PROJ, organization_id: ORG, extraction_run_id: RUN2, project_dependency_id: DEP, dependency_id: DEP, rule_id: 'mal.rule.NEW', scanner: 'guarddog', severity: 'critical', message: 'y', depscore: 90 },
  ])]);
  const fresh = await one(db, `SELECT status FROM project_malicious_findings WHERE rule_id='mal.rule.NEW' AND extraction_run_id='${RUN2}'`);
  assert(fresh?.status === 'open', 'a brand-new malicious finding starts open (no spurious carry)');
  const reMal = await one(db, `SELECT is_malicious FROM dependencies WHERE id='${DEP}'`);
  assert(reMal.is_malicious === true, 'a new active malicious finding re-flags dependencies.is_malicious');

  // Reap: advance the run window so the first run's malicious rows fall out.
  await db.exec(`UPDATE projects SET active_extraction_run_id='${RUN2}', previous_extraction_run_id=NULL WHERE id='${PROJ}';`);
  const reap = await one(db, `SELECT reap_old_extractions('${PROJ}'::uuid) AS r`);
  const reapJson = reap.r as Record<string, unknown>;
  assert(Number(reapJson.malicious_deleted) >= 1, 'reap_old_extractions deletes malicious rows outside the active+previous window');
  const oldRunGone = await one(db, `SELECT count(*)::int AS n FROM project_malicious_findings WHERE extraction_run_id='${RUN}'`);
  assert(oldRunGone.n === 0, 'first-run malicious rows are reaped (2-run invariant now holds for malicious)');

  // phase57: finding_tracker_links constraints + cascade.
  console.log('\n  [tracker] finding_tracker_links constraints + cascade');
  await db.exec(`INSERT INTO finding_tracker_links (organization_id, project_id, finding_type, finding_key, provider, external_id, external_key, external_url)
    VALUES ('${ORG}','${PROJ}','vulnerability','fk_abc','jira','10001','SEC-1','https://x/browse/SEC-1');`);
  const tl1 = await one(db, `SELECT count(*)::int AS n FROM finding_tracker_links WHERE finding_key='fk_abc'`);
  assert(tl1.n === 1, 'tracker link inserts');

  // phase62 relaxed the uniqueness from one-per-provider to
  // (project_id, finding_type, finding_key, provider, external_id): a finding
  // can now carry MULTIPLE tickets from the same provider as long as each has a
  // distinct external_id. A true duplicate (same provider + external_id) is
  // still rejected by finding_tracker_links_unique.
  await db.exec(`INSERT INTO finding_tracker_links (organization_id, project_id, finding_type, finding_key, provider, external_id) VALUES ('${ORG}','${PROJ}','vulnerability','fk_abc','jira','10002');`);
  const tlMulti = await one(db, `SELECT count(*)::int AS n FROM finding_tracker_links WHERE finding_key='fk_abc' AND provider='jira'`);
  assert(tlMulti.n === 2, 'a second jira ticket (distinct external_id) links to the same finding');

  let dupLink = false;
  try {
    await db.exec(`INSERT INTO finding_tracker_links (organization_id, project_id, finding_type, finding_key, provider, external_id) VALUES ('${ORG}','${PROJ}','vulnerability','fk_abc','jira','10001');`);
  } catch { dupLink = true; }
  assert(dupLink, 'a true duplicate (same provider + external_id) is rejected');

  await db.exec(`INSERT INTO finding_tracker_links (organization_id, project_id, finding_type, finding_key, provider, external_id, external_key) VALUES ('${ORG}','${PROJ}','vulnerability','fk_abc','github','42','#42');`);
  const tl2 = await one(db, `SELECT count(*)::int AS n FROM finding_tracker_links WHERE finding_key='fk_abc'`);
  assert(tl2.n === 3, 'a different provider links to the same finding (jira x2 + github)');

  // Data-flow findings file by flow_signature_hash, stored as finding_type=taint_flow.
  await db.exec(`INSERT INTO finding_tracker_links (organization_id, project_id, finding_type, finding_key, provider, external_id, external_key) VALUES ('${ORG}','${PROJ}','taint_flow','flowhash_1','linear','L-9','ENG-9');`);
  const tf = await one(db, `SELECT count(*)::int AS n FROM finding_tracker_links WHERE finding_type='taint_flow'`);
  assert(tf.n === 1, 'taint_flow link (filed by flow_signature_hash) is accepted');

  // phase58: a GitHub issue-close webhook flips external_state to 'done', scoped
  // to the project connected to the event's repo (issue numbers collide across
  // repos, so the join on project_repositories.repo_full_name is load-bearing).
  console.log('\n  [tracker] external_state github webhook sync (repo-scoped)');
  const PROJ3 = '66666666-6666-6666-6666-666666666666';
  await db.exec(`INSERT INTO projects (id, organization_id, name, created_at) VALUES ('${PROJ3}','${ORG}','proj3', NOW());`);
  await db.exec(`INSERT INTO project_repositories (project_id, repo_full_name, repo_id, installation_id, default_branch, provider) VALUES
    ('${PROJ}','deptex/app','111','999','main','github'),
    ('${PROJ3}','other/repo','222','999','main','github');`);
  await db.exec(`INSERT INTO finding_tracker_links (organization_id, project_id, finding_type, finding_key, provider, external_id, external_key, external_state) VALUES
    ('${ORG}','${PROJ}','vulnerability','fk_gh','github','7','#7','open'),
    ('${ORG}','${PROJ3}','vulnerability','fk_gh3','github','7','#7','open');`);
  await db.exec(`
    UPDATE finding_tracker_links l
    SET external_state='done', external_state_synced_at=now()
    FROM project_repositories pr
    WHERE l.provider='github' AND l.external_id='7'
      AND pr.project_id=l.project_id AND pr.provider='github' AND pr.repo_full_name='deptex/app';
  `);
  const ghDone = await one(db, `SELECT external_state FROM finding_tracker_links WHERE finding_key='fk_gh'`);
  assert(ghDone.external_state === 'done', 'github issue close flips the matching project link to done');
  const ghOther = await one(db, `SELECT external_state FROM finding_tracker_links WHERE finding_key='fk_gh3'`);
  assert(ghOther.external_state === 'open', 'same issue number in a different repo is NOT flipped (repo-scoped)');

  let badProvider = false;
  try {
    await db.exec(`INSERT INTO finding_tracker_links (organization_id, project_id, finding_type, finding_key, provider, external_id) VALUES ('${ORG}','${PROJ}','vulnerability','fk_xyz','asana','1');`);
  } catch { badProvider = true; }
  assert(badProvider, 'unknown provider rejected by CHECK');

  let badType = false;
  try {
    await db.exec(`INSERT INTO finding_tracker_links (organization_id, project_id, finding_type, finding_key, provider, external_id) VALUES ('${ORG}','${PROJ}','bogus','fk_xyz','jira','1');`);
  } catch { badType = true; }
  assert(badType, 'unknown finding_type rejected by CHECK');

  // Cascade: a fresh project with no other dependents proves ON DELETE CASCADE.
  const PROJ2 = '55555555-5555-5555-5555-555555555555';
  await db.exec(`INSERT INTO projects (id, organization_id, name, created_at) VALUES ('${PROJ2}','${ORG}','proj2', NOW());`);
  await db.exec(`INSERT INTO finding_tracker_links (organization_id, project_id, finding_type, finding_key, provider, external_id) VALUES ('${ORG}','${PROJ2}','secret','fk_p2','linear','L-1');`);
  await db.exec(`DELETE FROM projects WHERE id='${PROJ2}';`);
  const cascade = await one(db, `SELECT count(*)::int AS n FROM finding_tracker_links WHERE project_id='${PROJ2}'`);
  assert(cascade.n === 0, 'tracker links cascade-delete with their project');

  await db.close();
  console.log(`\n${'='.repeat(48)}`);
  console.log(`findings-status + tracker harness: ${passed} passed, ${failures} failed (${Date.now() - t0}ms)`);
  if (failures > 0) process.exit(1);
  console.log('PASSED');
}

main().catch((e) => { console.error('Unhandled error:', e); process.exit(1); });

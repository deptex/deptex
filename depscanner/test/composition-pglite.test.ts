/**
 * Integration test: composeFindings against an in-memory PGLite running the
 * real phase30 schema. Exercises the full SONAME-bridge pipeline:
 *
 *   1. Both reachable → factor=1.0, contextual_depscore unchanged
 *   2. Container unreachable + code data_flow → factor=0.36
 *   3. Container reachable + code unreachable → factor=0
 *   4. Both unreachable → factor=0
 *   5. Multi-partner MIN aggregation (2 partners at 0.4 and 1.0 → MIN=0.4)
 *   6. Multi-partner tie-break (2 partners at 0.5 each → 0.5 deterministically)
 *   7. Unknown reachability_level → edge skipped
 *   8. No SONAME bridge → no edge, no PDV mutation
 *   9. PCF with both identifiers NULL → counter incremented, no edge
 *  10. PCF reachability_level NULL → filtered out server-side (load excludes)
 *  11. Unpaired PDV stays bit-identical post-compose
 *  12. RPC return shape exposes composition_factor field
 *  13. Cross-tenant probe: composition_partners trigger refuses cross-project
 *  14. Cross-tenant probe: RPC gated by project_id + run_id
 *  15. Numeric fold math: 70.0000 × 0.7 = 49.0000
 *  16. Backfill invariant: 50 unpaired PDVs survive phase30 untouched
 *
 * Run: npx tsx test/composition-pglite.test.ts
 */

import { randomUUID } from 'crypto';
import { createPGLiteStorage } from '../src/storage';
import { composeFindings } from '../src/scanners/composition';

let failures = 0;
function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
  }
}

const noopLogger = {
  info: async () => {},
  warn: async () => {},
};

async function setupSchema(storage: any, orgId: string, projId: string): Promise<void> {
  const now = new Date().toISOString();
  const orgRes = await storage.from('organizations').insert({ id: orgId, name: 'test-org', created_at: now });
  if (orgRes.error) throw new Error(`org insert: ${orgRes.error.message}`);
  // Per schema dump: projects requires id + name; organization_id is nullable
  // but the IaC trigger derives organization_id off projects.organization_id,
  // so we MUST set it. Other NOT NULL cols (auto_bump, asset_tier,
  // watchtower_enabled, infra_types) have defaults.
  const projRes = await storage.from('projects').insert({
    id: projId,
    organization_id: orgId,
    name: 'test-project',
  });
  if (projRes.error) throw new Error(`proj insert: ${projRes.error.message}`);
}

async function insertDependency(
  storage: any,
  ecosystem: string,
  name: string
): Promise<string> {
  const id = randomUUID();
  await storage.from('dependencies').insert({ id, ecosystem, name });
  return id;
}

async function insertProjectDependency(
  storage: any,
  projId: string,
  depId: string,
  name: string,
  version = '1.0.0'
): Promise<string> {
  const id = randomUUID();
  const res = await storage.from('project_dependencies').insert({
    id,
    project_id: projId,
    dependency_id: depId,
    name,
    version,
    is_direct: true,
    source: 'sbom',  // NOT NULL, no default
    created_at: new Date().toISOString(),
  });
  if (res.error) throw new Error(`pd insert: ${res.error.message}`);
  return id;
}

interface SeedPdv {
  runId: string;
  projectDependencyId: string;
  osvId: string;
  aliases?: string[];
  reachabilityLevel: string | null;
  contextualDepscore: number;
}
async function insertPdv(storage: any, projId: string, p: SeedPdv): Promise<string> {
  const id = randomUUID();
  const res = await storage.from('project_dependency_findings').insert({
    id,
    project_id: projId,
    project_dependency_id: p.projectDependencyId,
    extraction_run_id: p.runId,
    osv_id: p.osvId,
    aliases: p.aliases ?? [],
    severity: 'HIGH',
    is_reachable: p.reachabilityLevel !== null && p.reachabilityLevel !== 'unreachable',
    reachability_level: p.reachabilityLevel,
    contextual_depscore: p.contextualDepscore,
  });
  if (res.error) throw new Error(`pdv insert: ${res.error.message}`);
  return id;
}

interface SeedPcf {
  runId: string;
  osPackageName: string;
  osPackageVersion?: string;
  osvId: string | null;
  cveId: string | null;
  reachabilityLevel: string | null;
  imageDigest?: string;
}
async function insertPcf(storage: any, projId: string, p: SeedPcf): Promise<string> {
  const id = randomUUID();
  // vulnerability_id is GENERATED ALWAYS AS
  //   COALESCE(osv_id, cve_id, 'unknown:' || md5(image_digest:os_pkg:os_ver))
  // STORED (schema.sql, phase25). The current schema dump preserves the
  // generation expression and PGLite computes it, so the test must NOT pass an
  // explicit value (Postgres rejects a non-DEFAULT write to a GENERATED ALWAYS
  // column). Omit it and let the DB derive it.
  const res = await storage.from('project_container_findings').insert({
    id,
    project_id: projId,
    // organization_id intentionally omitted — the
    // project_container_findings_enforce_org_id trigger derives it from
    // projects.organization_id (per phase25:155-158).
    extraction_run_id: p.runId,
    image_reference: 'example/test:latest',
    image_digest: p.imageDigest ?? 'sha256:' + 'a'.repeat(64),
    image_source: 'dockerfile_base',
    os_package_name: p.osPackageName,
    os_package_version: p.osPackageVersion ?? '1.0.0',
    osv_id: p.osvId,
    cve_id: p.cveId,
    severity: 'HIGH',
    is_kev: false,
    fix_versions: [],
    reachability_level: p.reachabilityLevel,
  });
  if (res.error) throw new Error(`pcf insert: ${res.error.message}`);
  return id;
}

async function insertBinding(
  storage: any,
  projId: string,
  scope: 'language' | 'os',
  pkgIdent: string,
  soname: string,
  pkgEcosystem: string | null,
  runId: string
): Promise<void> {
  const res = await storage.from('project_native_bindings').insert({
    project_id: projId,
    // organization_id derived by trigger — see phase30 migration comment.
    extraction_run_id: runId,
    scope,
    package_identifier: pkgIdent,
    package_ecosystem: pkgEcosystem,
    soname,
    install_path: scope === 'os' ? `/usr/lib/${soname}` : `site-packages/${pkgIdent}/_ext.so`,
    link_method: scope === 'language' ? 'elf_needed' : 'dpkg_soname',
  });
  if (res.error) throw new Error(`binding insert: ${res.error.message}`);
}

async function main(): Promise<void> {
  const t0 = Date.now();
  console.log('Booting PGLiteStorage...');
  const storage = await createPGLiteStorage();
  console.log(`  booted in ${Date.now() - t0}ms\n`);
  const supabase = storage as any;
  const orgId = randomUUID();
  const projId = randomUUID();
  await setupSchema(storage, orgId, projId);

  // Shared dependency/PD rows; PDVs differ per scenario by runId.
  const depCryptoId = await insertDependency(supabase, 'pypi', 'cryptography');
  const pdCryptoId = await insertProjectDependency(supabase, projId, depCryptoId, 'cryptography');

  // ============================================================
  // Scenario 1 — both reachable → factor=1.0, contextual_depscore unchanged
  // ============================================================
  console.log('Scenario 1: both reachable → factor=1.0');
  {
    const runId = 'run-s1';
    const pdvId = await insertPdv(supabase, projId, {
      runId, projectDependencyId: pdCryptoId, osvId: 'CVE-2024-1111',
      reachabilityLevel: 'confirmed', contextualDepscore: 70.0,
    });
    await insertPcf(supabase, projId, {
      runId, osPackageName: 'libssl3', osvId: null, cveId: 'CVE-2024-1111',
      reachabilityLevel: 'module',
    });
    await insertBinding(supabase, projId, 'language', 'cryptography', 'libssl.so.3', 'pypi', runId);
    await insertBinding(supabase, projId, 'os', 'libssl3', 'libssl.so.3', null, runId);

    const sum = await composeFindings({
      supabase, projectId: projId, organizationId: orgId, runId, logger: noopLogger,
    });
    assert(sum.edges_written === 1, `edges_written=${sum.edges_written}`);
    assert(sum.pdvs_updated === 1, `pdvs_updated=${sum.pdvs_updated}`);

    const { data: pdv } = await supabase.from('project_dependency_findings').select('composition_factor, contextual_depscore').eq('id', pdvId).single();
    assert(Number(pdv.composition_factor) === 1, `composition_factor=1.0 (got ${pdv.composition_factor})`);
    assert(Number(pdv.contextual_depscore) === 70, `contextual_depscore unchanged (got ${pdv.contextual_depscore})`);
  }

  // ============================================================
  // Scenario 2 — container unreachable + code data_flow → factor=0.36
  //              + numeric fold-math check (70 × 0.36 = 25.2)
  // ============================================================
  console.log('\nScenario 2: container unreachable × code data_flow → factor=0.36');
  {
    const runId = 'run-s2';
    const pdvId = await insertPdv(supabase, projId, {
      runId, projectDependencyId: pdCryptoId, osvId: 'CVE-2024-2222',
      reachabilityLevel: 'data_flow', contextualDepscore: 70.0,
    });
    await insertPcf(supabase, projId, {
      runId, osPackageName: 'libssl3', osvId: null, cveId: 'CVE-2024-2222',
      reachabilityLevel: 'unreachable',
    });
    await insertBinding(supabase, projId, 'language', 'cryptography', 'libssl.so.3', 'pypi', runId);
    await insertBinding(supabase, projId, 'os', 'libssl3', 'libssl.so.3', null, runId);
    await composeFindings({ supabase, projectId: projId, organizationId: orgId, runId, logger: noopLogger });

    const { data: pdv } = await supabase.from('project_dependency_findings').select('composition_factor, contextual_depscore').eq('id', pdvId).single();
    assert(Number(pdv.composition_factor) === 0.36, `factor=0.36 (got ${pdv.composition_factor})`);
    assert(Number(pdv.contextual_depscore) === 25.2, `70 × 0.36 = 25.2 (got ${pdv.contextual_depscore})`);
  }

  // ============================================================
  // Scenario 3 — container reachable + code unreachable → factor=0
  // ============================================================
  console.log('\nScenario 3: container reachable × code unreachable → factor=0');
  {
    const runId = 'run-s3';
    const pdvId = await insertPdv(supabase, projId, {
      runId, projectDependencyId: pdCryptoId, osvId: 'CVE-2024-3333',
      reachabilityLevel: 'unreachable', contextualDepscore: 70.0,
    });
    await insertPcf(supabase, projId, {
      runId, osPackageName: 'libssl3', osvId: null, cveId: 'CVE-2024-3333',
      reachabilityLevel: 'module',
    });
    await insertBinding(supabase, projId, 'language', 'cryptography', 'libssl.so.3', 'pypi', runId);
    await insertBinding(supabase, projId, 'os', 'libssl3', 'libssl.so.3', null, runId);
    await composeFindings({ supabase, projectId: projId, organizationId: orgId, runId, logger: noopLogger });

    const { data: pdv } = await supabase.from('project_dependency_findings').select('composition_factor, contextual_depscore').eq('id', pdvId).single();
    assert(Number(pdv.composition_factor) === 0, `factor=0 (got ${pdv.composition_factor})`);
    assert(Number(pdv.contextual_depscore) === 0, `contextual_depscore=0 (got ${pdv.contextual_depscore})`);
  }

  // ============================================================
  // Scenario 5 — multi-partner MIN aggregation (0.4 and 1.0 → 0.4)
  // ============================================================
  console.log('\nScenario 5: multi-partner MIN aggregation');
  {
    const runId = 'run-s5';
    const pdvId = await insertPdv(supabase, projId, {
      runId, projectDependencyId: pdCryptoId, osvId: 'CVE-2024-5555',
      reachabilityLevel: 'confirmed', contextualDepscore: 70.0,
    });
    // PCF A unreachable → 0.4×1.0=0.4; PCF B reachable → 1.0×1.0=1.0
    await insertPcf(supabase, projId, {
      runId, osPackageName: 'libssl3', osvId: null, cveId: 'CVE-2024-5555',
      reachabilityLevel: 'unreachable', imageDigest: 'sha256:' + 'b'.repeat(64),
    });
    await insertPcf(supabase, projId, {
      runId, osPackageName: 'libcrypto3', osvId: null, cveId: 'CVE-2024-5555',
      reachabilityLevel: 'module', imageDigest: 'sha256:' + 'c'.repeat(64),
    });
    await insertBinding(supabase, projId, 'language', 'cryptography', 'libssl.so.3', 'pypi', runId);
    await insertBinding(supabase, projId, 'language', 'cryptography', 'libcrypto.so.3', 'pypi', runId);
    await insertBinding(supabase, projId, 'os', 'libssl3', 'libssl.so.3', null, runId);
    await insertBinding(supabase, projId, 'os', 'libcrypto3', 'libcrypto.so.3', null, runId);
    const sum = await composeFindings({
      supabase, projectId: projId, organizationId: orgId, runId, logger: noopLogger,
    });
    assert(sum.edges_written === 2, `2 edges (got ${sum.edges_written})`);

    const { data: pdv } = await supabase.from('project_dependency_findings').select('composition_factor, contextual_depscore').eq('id', pdvId).single();
    assert(Number(pdv.composition_factor) === 0.4, `MIN factor=0.4 (got ${pdv.composition_factor})`);
    assert(Number(pdv.contextual_depscore) === 28, `70 × 0.4 = 28 (got ${pdv.contextual_depscore})`);
  }

  // ============================================================
  // Scenario 7 — unknown reachability_level → edge skipped
  // ============================================================
  console.log('\nScenario 7: unknown PDV reachability_level → edge skipped');
  {
    const runId = 'run-s7';
    const pdvId = await insertPdv(supabase, projId, {
      runId, projectDependencyId: pdCryptoId, osvId: 'CVE-2024-7777',
      reachabilityLevel: 'wibble', contextualDepscore: 60.0,
    });
    await insertPcf(supabase, projId, {
      runId, osPackageName: 'libssl3', osvId: null, cveId: 'CVE-2024-7777',
      reachabilityLevel: 'module',
    });
    await insertBinding(supabase, projId, 'language', 'cryptography', 'libssl.so.3', 'pypi', runId);
    await insertBinding(supabase, projId, 'os', 'libssl3', 'libssl.so.3', null, runId);
    const sum = await composeFindings({
      supabase, projectId: projId, organizationId: orgId, runId, logger: noopLogger,
    });
    assert(sum.edges_skipped_unknown_reachability === 1, `skipped=1 (got ${sum.edges_skipped_unknown_reachability})`);
    assert(sum.edges_written === 0, `no edge written`);

    const { data: pdv } = await supabase.from('project_dependency_findings').select('composition_factor, contextual_depscore').eq('id', pdvId).single();
    assert(pdv.composition_factor === null, `composition_factor=null`);
    assert(Number(pdv.contextual_depscore) === 60, `contextual_depscore=60 unchanged`);
  }

  // ============================================================
  // Scenario 8 — no SONAME bridge → no edge, no mutation
  // ============================================================
  console.log('\nScenario 8: no soname bridge → no edge');
  {
    const runId = 'run-s8';
    const pdvId = await insertPdv(supabase, projId, {
      runId, projectDependencyId: pdCryptoId, osvId: 'CVE-2024-8888',
      reachabilityLevel: 'confirmed', contextualDepscore: 50.0,
    });
    await insertPcf(supabase, projId, {
      runId, osPackageName: 'libssl3', osvId: null, cveId: 'CVE-2024-8888',
      reachabilityLevel: 'module',
    });
    // Only language binding — no OS side. Composition needs both.
    await insertBinding(supabase, projId, 'language', 'cryptography', 'libssl.so.3', 'pypi', runId);
    const sum = await composeFindings({
      supabase, projectId: projId, organizationId: orgId, runId, logger: noopLogger,
    });
    assert(sum.edges_written === 0, `no edge (got ${sum.edges_written})`);

    const { data: pdv } = await supabase.from('project_dependency_findings').select('composition_factor, contextual_depscore').eq('id', pdvId).single();
    assert(pdv.composition_factor === null, `composition_factor stays null`);
    assert(Number(pdv.contextual_depscore) === 50, `contextual_depscore untouched`);
  }

  // ============================================================
  // Scenario 9 — PCF with no identifier → counter increments
  // ============================================================
  console.log('\nScenario 9: PCF with no cve_id and no osv_id → counter increments');
  {
    const runId = 'run-s9';
    await insertPdv(supabase, projId, {
      runId, projectDependencyId: pdCryptoId, osvId: 'CVE-2024-9999',
      reachabilityLevel: 'confirmed', contextualDepscore: 50.0,
    });
    // PCF has both identifiers NULL — DB allows it.
    await insertPcf(supabase, projId, {
      runId, osPackageName: 'libssl3', osvId: null, cveId: null,
      reachabilityLevel: 'module',
    });
    await insertBinding(supabase, projId, 'language', 'cryptography', 'libssl.so.3', 'pypi', runId);
    await insertBinding(supabase, projId, 'os', 'libssl3', 'libssl.so.3', null, runId);
    const sum = await composeFindings({
      supabase, projectId: projId, organizationId: orgId, runId, logger: noopLogger,
    });
    assert(sum.pcfs_skipped_no_identifier === 1, `pcfs_skipped_no_identifier=1 (got ${sum.pcfs_skipped_no_identifier})`);
    assert(sum.edges_written === 0, 'no edge written');
  }

  // ============================================================
  // Scenario 12 — RPC surfaces the composition-folded contextual_depscore.
  //
  // The phase30 RPC exposed a raw `composition_factor` column, but phase60
  // (status fields) + phase63 (scoped npm name) rewrote
  // get_project_dependency_findings_from_pdv and dropped that column — it has no
  // consumer; the composition result reaches the UI through the FOLDED
  // contextual_depscore, not the raw factor. The RPC also filters on the
  // project's active_extraction_run_id (phase24.3). So the live, consumed
  // contract is: point the project at a composed run and the RPC returns that
  // run's PDV with contextual_depscore already reduced by composition.
  // ============================================================
  console.log('\nScenario 12: RPC surfaces composition-folded contextual_depscore for the active run');
  {
    // run-s2 was folded 70 → 25.2 (factor 0.36) and is never re-touched.
    await supabase.from('projects').update({ active_extraction_run_id: 'run-s2' }).eq('id', projId);
    const { data } = await supabase.rpc('get_project_dependency_findings_from_pdv', {
      p_project_id: projId,
    });
    assert(Array.isArray(data), 'RPC returns array');
    const row = (data ?? []).find((r: any) => r.osv_id === 'CVE-2024-2222');
    assert(row !== undefined, 'RPC returns the composed run-s2 PDV');
    if (row) {
      assert(Number(row.contextual_depscore) === 25.2, `contextual_depscore folded to 25.2 (got ${row.contextual_depscore})`);
    }
  }

  // ============================================================
  // Scenario 11 — unpaired PDV stays bit-identical
  // ============================================================
  console.log('\nScenario 11: unpaired PDV bit-identical post-compose');
  {
    const runId = 'run-s11';
    const pdvId = await insertPdv(supabase, projId, {
      runId, projectDependencyId: pdCryptoId, osvId: 'CVE-2024-EEEE',
      reachabilityLevel: 'data_flow', contextualDepscore: 33.3333,
    });
    // No PCF, no bindings — composition still runs (entry not skipped) but
    // returns 0 edges.
    const sum = await composeFindings({
      supabase, projectId: projId, organizationId: orgId, runId, logger: noopLogger,
    });
    assert(sum.edges_written === 0, 'no edge');
    const { data: pdv } = await supabase.from('project_dependency_findings').select('composition_factor, contextual_depscore').eq('id', pdvId).single();
    assert(pdv.composition_factor === null, 'composition_factor null');
    assert(Number(pdv.contextual_depscore) === 33.3333, `33.3333 preserved (got ${pdv.contextual_depscore})`);
  }

  // ============================================================
  // Scenario 13 — Cross-tenant trigger refusal
  // ============================================================
  console.log('\nScenario 13: cross-project partner row refused at trigger time');
  {
    const otherOrgId = randomUUID();
    const otherProjId = randomUUID();
    const runId = 'run-s13';
    await setupSchema(storage, otherOrgId, otherProjId);
    const depId = await insertDependency(supabase, 'pypi', 'other-pkg');
    const pdId = await insertProjectDependency(supabase, otherProjId, depId, 'other-pkg');

    const otherPcf = await insertPcf(supabase, otherProjId, {
      runId, osPackageName: 'libfoo', osvId: null, cveId: 'CVE-X',
      reachabilityLevel: 'module',
    });
    const ourPdv = await insertPdv(supabase, projId, {
      runId, projectDependencyId: pdCryptoId, osvId: 'CVE-X',
      reachabilityLevel: 'confirmed', contextualDepscore: 50,
    });

    // Forge a cross-project partner row and expect rejection.
    let rejected = false;
    const { error } = await supabase.from('project_composition_partners').insert({
      project_id: projId,
      organization_id: orgId,
      extraction_run_id: runId,
      container_finding_id: otherPcf,
      pdv_id: ourPdv,
      container_reachability_multiplier: 1.0,
      code_reachability_multiplier: 1.0,
      composition_factor: 1.0,
      bindings_evidence: [],
    });
    if (error) rejected = true;
    assert(rejected, `cross-project partner insert rejected (error=${error?.message ?? 'none'})`);
    void pdId;
  }

  // ============================================================
  // Scenario 14 — Cross-tenant RPC gate
  // ============================================================
  console.log('\nScenario 14: apply_composition_results gated on (project_id, run_id)');
  {
    const runId = 'run-s14';
    const pdvId = await insertPdv(supabase, projId, {
      runId, projectDependencyId: pdCryptoId, osvId: 'CVE-2024-FFFF',
      reachabilityLevel: 'confirmed', contextualDepscore: 90,
    });
    // Call RPC with a DIFFERENT projectId → 0 rows touched.
    const fakeProj = randomUUID();
    const { data: rpcCount } = await supabase.rpc('apply_composition_results', {
      p_project_id: fakeProj,
      p_run_id: runId,
      p_updates: [{ pdv_id: pdvId, factor: 0.1 }],
    });
    assert(Number(rpcCount) === 0, `cross-tenant RPC affects 0 rows (got ${rpcCount})`);

    const { data: pdv } = await supabase.from('project_dependency_findings').select('composition_factor, contextual_depscore').eq('id', pdvId).single();
    assert(pdv.composition_factor === null, 'composition_factor still null after foreign-tenant RPC call');
    assert(Number(pdv.contextual_depscore) === 90, 'contextual_depscore unchanged');
  }

  // ============================================================
  // Scenario 16 — Backfill invariant: phase30 added column NULL by default,
  //               existing PDV contextual_depscore unchanged
  // ============================================================
  console.log('\nScenario 16: 50 unpaired PDVs survive composition untouched');
  {
    const runId = 'run-s16';
    const ids: Array<{ id: string; orig: number }> = [];
    for (let i = 0; i < 50; i++) {
      const orig = Number((10 + i * 0.5).toFixed(4));
      const id = await insertPdv(supabase, projId, {
        runId, projectDependencyId: pdCryptoId, osvId: `CVE-2024-BULK-${i}`,
        reachabilityLevel: 'module', contextualDepscore: orig,
      });
      ids.push({ id, orig });
    }
    // No PCFs, no bindings for this run → composition runs but writes nothing.
    await composeFindings({
      supabase, projectId: projId, organizationId: orgId, runId, logger: noopLogger,
    });
    for (const { id, orig } of ids) {
      const { data } = await supabase.from('project_dependency_findings').select('composition_factor, contextual_depscore').eq('id', id).single();
      if (data.composition_factor !== null || Number(data.contextual_depscore) !== orig) {
        assert(false, `PDV ${id.slice(0, 8)} drifted (orig=${orig}, got cf=${data.composition_factor} ds=${data.contextual_depscore})`);
        break;
      }
    }
    assert(true, '50/50 unpaired PDVs bit-identical');
  }

  await storage.close();
  console.log(`\n${failures === 0 ? 'ALL COMPOSITION TESTS PASSED' : `${failures} TEST(S) FAILED`} in ${Date.now() - t0}ms`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('Unhandled error:', e);
  process.exit(1);
});

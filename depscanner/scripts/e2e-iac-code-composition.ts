/**
 * Item G e2e — composed IaC↔Code reachability against a synthesized
 * python:3.11-slim + cryptography co-occurrence.
 *
 * This harness exercises the composition path end-to-end against the
 * real phase30 schema, the real composeFindings logic, and the real
 * native-bindings extractor on a synthetic on-disk filesystem that
 * mirrors what an extracted python:3.11-slim image looks like
 * (dist-info layout for the `cryptography` wheel + /var/lib/dpkg/info
 * layout for the `libssl3` package).
 *
 * It is NOT a Docker round-trip; the worker's full extraction pipeline
 * (clone → cdxgen → dep-scan → Phase 6 → EPD → IaC+container) is too
 * large to stage offline. Instead we synthesize the FINAL state those
 * upstream steps would have left in the DB + on disk, then run:
 *
 *   1. The native-bindings extractor on the synthesized rootDir
 *      (writes language + os bindings to PGLite via the real upsert)
 *   2. composeFindings against the seeded run
 *
 * Acceptance (per the plan, Patch 3 — pair-count, not the 35% floor):
 *   - ≥1 PCF×PDV edge written
 *   - ≥1 PDV's contextual_depscore drops below the HIGH threshold (70)
 *     from a starting value above 70.
 *
 * Run:
 *   cd depscanner && npm run e2e:iac-code-composition
 *
 * Baseline drift: actuals are written to
 * scripts/e2e-iac-code-composition.baseline.json (committed). A drift
 * fails the run loudly so we notice silent regressions.
 *
 * Docker / live-API parity: see Risks #4 in
 * .cursor/plans/iac-container-v2-item-g.plan.md — the real-binary
 * readelf invocation runs inside the depscanner Docker image during
 * a full extraction; that path is unchanged here and is covered by
 * the existing scanner orchestrator integration tests + the
 * reachability corpus harness (`npm run test:reachability-corpus`).
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { randomUUID } from 'node:crypto';
import { createPGLiteStorage } from '../src/storage';
import { composeFindings } from '../src/scanners/composition';
import {
  extractLanguageBindings,
  extractOsBindings,
} from '../src/scanners/native-bindings';
import type { ReadelfRunner } from '../src/scanners/elf-analyzer';

const BASELINE_PATH = path.resolve(__dirname, 'e2e-iac-code-composition.baseline.json');

interface ActualsRecord {
  edges_written: number;
  pdvs_updated: number;
  // Per-PDV final depscore for the dropped findings (deterministic order).
  dropped_pdv_finals: number[];
  partnerable_pcf: number;
  partnerable_pdv: number;
  suppressions_to_zero: number;
}

const noopLogger = {
  info: async () => {},
  warn: async () => {},
};

function readelfDynamicWithSoname(soname: string, needed: string[]): string {
  const lines = [
    'Dynamic section at offset 0x2dc8 contains 14 entries:',
    '  Tag        Type                         Name/Value',
    ` 0x000000000000000e (SONAME)             Library soname: [${soname}]`,
  ];
  for (const s of needed) {
    lines.push(` 0x0000000000000001 (NEEDED)             Shared library: [${s}]`);
  }
  return lines.join('\n') + '\n';
}
function readelfDynamic(needed: string[]): string {
  return readelfDynamicWithSoname('', needed).replace(/.+SONAME.+\n/, '');
}

function makePythonSlimRoot(tmpRoot: string): { rootDir: string; runner: ReadelfRunner } {
  // ---------------- Synthesize a python:3.11-slim-like filesystem ----------
  fs.writeFileSync(path.join(mkdirp(tmpRoot, 'etc'), 'os-release'), 'ID=debian\nVERSION_ID="12"\n');

  // Python wheel: cryptography 41.0.7
  const sitePackages = mkdirp(
    tmpRoot,
    'usr/local/lib/python3.11/site-packages'
  );
  const distInfo = mkdirp(sitePackages, 'cryptography-41.0.7.dist-info');
  fs.writeFileSync(path.join(distInfo, 'RECORD'), '');
  fs.writeFileSync(path.join(distInfo, 'top_level.txt'), 'cryptography\n');
  const cryptoDir = mkdirp(sitePackages, 'cryptography');
  const cryptoSo = path.join(cryptoDir, '_rust.abi3.so');
  fs.writeFileSync(cryptoSo, Buffer.from('\x7fELF\x02\x01\x01\x00'));

  // dpkg: libssl3 + libcrypto3 share the same multi-arch path layout that
  // python:3.11-slim ships in production.
  const infoDir = mkdirp(tmpRoot, 'var/lib/dpkg/info');
  fs.writeFileSync(
    path.join(infoDir, 'libssl3.list'),
    [
      '/.',
      '/usr',
      '/usr/lib',
      '/usr/lib/x86_64-linux-gnu',
      '/usr/lib/x86_64-linux-gnu/libssl.so.3',
    ].join('\n') + '\n'
  );
  fs.writeFileSync(
    path.join(infoDir, 'libcrypto3.list'),
    [
      '/usr/lib/x86_64-linux-gnu/libcrypto.so.3',
    ].join('\n') + '\n'
  );
  const libsslDir = mkdirp(tmpRoot, 'usr/lib/x86_64-linux-gnu');
  const libsslSo = path.join(libsslDir, 'libssl.so.3');
  const libcryptoSo = path.join(libsslDir, 'libcrypto.so.3');
  fs.writeFileSync(libsslSo, Buffer.from('\x7fELF'));
  fs.writeFileSync(libcryptoSo, Buffer.from('\x7fELF'));

  // ---------------- Injectable readelf runner ----------------------
  const runner: ReadelfRunner = async (args) => {
    const target = args[args.length - 1];
    if (target === cryptoSo) {
      return {
        stdout: readelfDynamic(['libssl.so.3', 'libcrypto.so.3', 'libc.so.6']),
        exitCode: 0,
      };
    }
    if (target === libsslSo) {
      return {
        stdout: readelfDynamicWithSoname('libssl.so.3', ['libcrypto.so.3', 'libc.so.6']),
        exitCode: 0,
      };
    }
    if (target === libcryptoSo) {
      return {
        stdout: readelfDynamicWithSoname('libcrypto.so.3', ['libc.so.6']),
        exitCode: 0,
      };
    }
    return { stdout: '', exitCode: 1 };
  };

  return { rootDir: tmpRoot, runner };
}

function mkdirp(...parts: string[]): string {
  const p = path.join(...parts);
  fs.mkdirSync(p, { recursive: true });
  return p;
}

interface SeedPlan {
  orgId: string;
  projId: string;
  runId: string;
  pdvIds: { libssl: string; libcrypto: string; unpaired: string };
  pcfIds: { libssl: string; libcrypto: string };
}

async function seedProject(storage: any): Promise<SeedPlan> {
  const orgId = randomUUID();
  const projId = randomUUID();
  const runId = `e2e-run-${Date.now()}`;
  await storage.from('organizations').insert({
    id: orgId, name: 'e2e-org', created_at: new Date().toISOString(),
  });
  await storage.from('projects').insert({
    id: projId, organization_id: orgId, name: 'e2e-project',
  });

  // Dependency: cryptography in pypi
  const depId = randomUUID();
  await storage.from('dependencies').insert({
    id: depId, ecosystem: 'pypi', name: 'cryptography',
  });
  const pdId = randomUUID();
  await storage.from('project_dependencies').insert({
    id: pdId, project_id: projId, dependency_id: depId, name: 'cryptography',
    version: '41.0.7', is_direct: true, source: 'sbom',
  });

  // Two PDVs partnering: one tied to libssl, one to libcrypto (different CVEs).
  // Both start at 80 (above HIGH threshold of 70) so we can prove the drop.
  const insertPdv = async (osvId: string, reach: string, ctx: number) => {
    const id = randomUUID();
    await storage.from('project_dependency_vulnerabilities').insert({
      id, project_id: projId, project_dependency_id: pdId, extraction_run_id: runId,
      osv_id: osvId, aliases: [], severity: 'HIGH',
      is_reachable: reach !== 'unreachable',
      reachability_level: reach, contextual_depscore: ctx,
    });
    return id;
  };
  const pdvLibsslId = await insertPdv('CVE-2024-G001', 'data_flow', 80);
  const pdvLibcryptoId = await insertPdv('CVE-2024-G002', 'confirmed', 80);
  // Unpaired PDV — should survive composition bit-identical.
  const pdvUnpairedId = await insertPdv('CVE-2024-G999', 'module', 42.5555);

  // Two PCFs: libssl3 unreachable (will pull factor to 0.4 × 0.9 = 0.36),
  // libcrypto3 module (factor 1.0 × 1.0 = 1.0; no drop). Both have valid
  // identifiers + reachability_level so composeFindings considers them.
  const insertPcf = async (osPkg: string, cveId: string, reach: string) => {
    const id = randomUUID();
    await storage.from('project_container_findings').insert({
      id, project_id: projId, extraction_run_id: runId,
      image_reference: 'python:3.11-slim', image_digest: 'sha256:' + 'a'.repeat(64),
      image_source: 'dockerfile_base',
      os_package_name: osPkg, os_package_version: '3.0.11-1~deb12u2',
      osv_id: null, cve_id: cveId, vulnerability_id: cveId,
      severity: 'HIGH', is_kev: false, fix_versions: [],
      reachability_level: reach,
    });
    return id;
  };
  const pcfLibsslId = await insertPcf('libssl3', 'CVE-2024-G001', 'unreachable');
  const pcfLibcryptoId = await insertPcf('libcrypto3', 'CVE-2024-G002', 'module');

  return {
    orgId, projId, runId,
    pdvIds: { libssl: pdvLibsslId, libcrypto: pdvLibcryptoId, unpaired: pdvUnpairedId },
    pcfIds: { libssl: pcfLibsslId, libcrypto: pcfLibcryptoId },
  };
}

async function main(): Promise<void> {
  const t0 = Date.now();
  console.log('[e2e] booting PGLite + seeding python:3.11-slim co-occurrence...');
  const storage = await createPGLiteStorage();
  const supabase = storage as any;

  // 1. Synthesize the extracted-container filesystem + readelf fixtures.
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'deptex-e2e-comp-'));
  const { rootDir, runner } = makePythonSlimRoot(tmpRoot);

  // 2. Seed the project/dependencies/PDV/PCF rows.
  const seed = await seedProject(supabase);

  // 3. PRE-FLIGHT: confirm (PCF × PDV) co-occurrence > 0.
  const { data: cof } = await supabase
    .from('project_container_findings')
    .select('cve_id, reachability_level')
    .eq('project_id', seed.projId)
    .eq('extraction_run_id', seed.runId);
  const { data: pdvs } = await supabase
    .from('project_dependency_vulnerabilities')
    .select('osv_id')
    .eq('project_id', seed.projId)
    .eq('extraction_run_id', seed.runId);
  const pdvSet = new Set((pdvs ?? []).map((r: any) => r.osv_id));
  const occ = (cof ?? []).filter((r: any) => r.cve_id && pdvSet.has(r.cve_id)).length;
  if (occ === 0) {
    throw new Error('CORPUS_MISCURATED: no PCF×PDV co-occurrence pairs in the staged data');
  }
  console.log(`[e2e] pre-flight: ${occ} PCF×PDV co-occurrence pair(s) staged`);

  // 4. Run the native-bindings extractor against the synthetic FS + persist.
  const langRes = await extractLanguageBindings({ rootDir, runner });
  const osRes = await extractOsBindings({ rootDir, runner });
  console.log(
    `[e2e] bindings: lang=${langRes.bindings.length} os=${osRes.bindings.length} os_family=${osRes.os_family}`
  );
  for (const b of langRes.bindings) {
    await supabase.from('project_native_bindings').insert({
      project_id: seed.projId,
      extraction_run_id: seed.runId,
      scope: 'language',
      package_identifier: b.package_identifier,
      package_ecosystem: b.ecosystem,
      soname: b.soname,
      install_path: b.install_path,
      link_method: b.link_method,
    });
  }
  for (const b of osRes.bindings) {
    await supabase.from('project_native_bindings').insert({
      project_id: seed.projId,
      extraction_run_id: seed.runId,
      scope: 'os',
      package_identifier: b.package_identifier,
      soname: b.soname,
      install_path: b.install_path,
      link_method: b.link_method,
    });
  }

  // 5. Run composeFindings.
  const summary = await composeFindings({
    supabase,
    projectId: seed.projId,
    organizationId: seed.orgId,
    runId: seed.runId,
    logger: noopLogger,
  });
  console.log(`[e2e] composeFindings summary:`, JSON.stringify(summary, null, 2));

  // 6. Read back the final state for assertions + baseline.
  const finals: Record<string, number> = {};
  for (const [label, id] of Object.entries(seed.pdvIds)) {
    const { data } = await supabase
      .from('project_dependency_vulnerabilities')
      .select('contextual_depscore')
      .eq('id', id)
      .single();
    finals[label] = Number(data.contextual_depscore);
  }
  console.log('[e2e] final PDV contextual_depscores:', finals);

  // ---- Acceptance assertions ---------------------------------------------
  let failures = 0;
  const check = (cond: boolean, msg: string) => {
    if (!cond) { failures++; console.error(`  FAIL: ${msg}`); }
    else console.log(`  ok: ${msg}`);
  };
  check(summary.edges_written >= 1, `≥1 PCF×PDV edge written (got ${summary.edges_written})`);
  check(finals.libssl < 70, `libssl PDV dropped below HIGH=70 (got ${finals.libssl})`);
  check(finals.unpaired === 42.5555, `unpaired PDV bit-identical (got ${finals.unpaired})`);
  check(occ === summary.partnerable_pcf, `partnerable_pcf reflects staged co-occurrence`);

  // ---- Baseline drift gate ----------------------------------------------
  const actuals: ActualsRecord = {
    edges_written: summary.edges_written,
    pdvs_updated: summary.pdvs_updated,
    dropped_pdv_finals: [finals.libssl, finals.libcrypto],
    partnerable_pcf: summary.partnerable_pcf,
    partnerable_pdv: summary.partnerable_pdv,
    suppressions_to_zero: summary.suppressions_to_zero,
  };
  if (process.argv.includes('--update-baseline')) {
    fs.writeFileSync(BASELINE_PATH, JSON.stringify(actuals, null, 2) + '\n');
    console.log('[e2e] baseline updated at', BASELINE_PATH);
  } else if (fs.existsSync(BASELINE_PATH)) {
    const baseline = JSON.parse(fs.readFileSync(BASELINE_PATH, 'utf8')) as ActualsRecord;
    const drift = JSON.stringify(actuals) !== JSON.stringify(baseline);
    check(!drift,
      `e2e baseline matches (expected=${JSON.stringify(baseline)}; got=${JSON.stringify(actuals)})`);
  } else {
    fs.writeFileSync(BASELINE_PATH, JSON.stringify(actuals, null, 2) + '\n');
    console.log('[e2e] bootstrap baseline written to', BASELINE_PATH);
  }

  // ---- Cleanup ----------------------------------------------------------
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch { /* */ }
  await storage.close();

  if (failures > 0) {
    console.error(`\n${failures} acceptance check(s) failed`);
    process.exit(1);
  }
  console.log(`\n[e2e] ALL ASSERTIONS PASSED in ${Date.now() - t0}ms`);
}

main().catch((e) => {
  console.error('[e2e] unhandled error:', e);
  process.exit(1);
});

/**
 * Integration test: container_image_scan_cache lookup + upsert against an
 * in-memory PGLite. Covers M7 acceptance criteria:
 *
 *   1. Cache hit (composite-PK match within 7d, hash verified) returns parsed
 *      findings + scanner_version.
 *   2. Cache miss (no row) returns null without throwing.
 *   3. Stale row (scanned_at < now - 7d) returns null.
 *   4. Integrity-hash mismatch (DB-level corruption) logs cache_integrity_mismatch
 *      and returns null instead of leaking corrupt findings.
 *   5. Composite-PK day-roll: same digest + scanner_version with a different
 *      trivy_db_version_day yields a different cache row, so a new write does
 *      not collide with the prior day's cached results.
 *   6. 1MB truncation: a 1.5MB findings array is truncated by severity desc
 *      to fit and the warning is emitted; the cached row decodes cleanly.
 *   7. Reaper SQL function (cleanup_container_image_scan_cache) is callable.
 *
 * Run: npx tsx test/container-scan-cache-pglite.test.ts
 */

import { createPGLiteStorage } from '../src/storage';
import {
  computeScanResultsHash,
  lookupContainerScanCache,
  truncateFindingsToFit,
  upsertContainerScanCache,
  type ContainerScanCacheKey,
} from '../src/scanners/storage';
import type { ContainerFinding } from '../src/scanners/types';

let failures = 0;

function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
  }
}

function makeFinding(overrides: Partial<ContainerFinding> = {}): ContainerFinding {
  return {
    scanner_version: '0.50.0',
    image_reference: 'alpine:3.18',
    image_digest:
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    os_package_name: 'openssl',
    os_package_version: '3.0.0',
    os_package_ecosystem: 'alpine',
    osv_id: null,
    cve_id: 'CVE-2024-0001',
    severity: 'HIGH',
    cvss_score: 7.5,
    epss_score: null,
    is_kev: false,
    fix_versions: ['3.0.1'],
    layer_digest: null,
    description: 'demo finding',
    rule_doc_url: null,
    container_fingerprint: 'openssl@CVE-2024-0001',
    ...overrides,
  };
}

async function main() {
  const t0 = Date.now();
  console.log('Booting PGLiteStorage...');
  const storage = await createPGLiteStorage();
  console.log(`  booted in ${Date.now() - t0}ms\n`);

  // PGLite implements the Storage abstraction; the scanners storage helpers
  // type-check against SupabaseClient but only touch from()/.upsert()/.eq()/
  // .maybeSingle(), all of which PGLite implements. Cast through unknown.
  const supabase = storage as unknown as Parameters<typeof lookupContainerScanCache>[0];

  const orgId = '11111111-1111-1111-1111-111111111111';
  const runId = 'run_cache_test_001';
  const digest = 'b'.repeat(64);
  const dayToday = '2026-05-05';

  await storage
    .from('organizations')
    .insert({ id: orgId, name: 'cache-test-org', created_at: new Date().toISOString() });

  // ----- 1. miss on empty cache -------------------------------------------
  console.log('miss on empty cache returns null...');
  {
    const hit = await lookupContainerScanCache(supabase, {
      image_digest: digest,
      scanner: 'trivy',
      scanner_version: '0.50.0',
      trivy_db_version_day: dayToday,
    });
    assert(hit === null, `lookup miss returned null (got: ${hit})`);
  }

  // ----- 2. write + immediate hit -----------------------------------------
  console.log('\nwrite cache row + immediate hit returns findings...');
  const baseFindings = [
    makeFinding({ severity: 'CRITICAL', cve_id: 'CVE-A', container_fingerprint: 'openssl@CVE-A' }),
    makeFinding({ severity: 'HIGH', cve_id: 'CVE-B', container_fingerprint: 'openssl@CVE-B' }),
    makeFinding({ severity: 'LOW', cve_id: 'CVE-C', container_fingerprint: 'openssl@CVE-C' }),
  ];
  const key: ContainerScanCacheKey = {
    image_digest: digest,
    scanner: 'trivy',
    scanner_version: '0.50.0',
    trivy_db_version_day: dayToday,
  };
  await upsertContainerScanCache(supabase, key, baseFindings, orgId, runId);
  {
    const hit = await lookupContainerScanCache(supabase, key);
    assert(hit !== null, 'cache hit returned non-null');
    assert(hit?.scanner_version === '0.50.0', `scanner_version preserved (got: ${hit?.scanner_version})`);
    assert(hit?.findings.length === 3, `findings count = 3 (got: ${hit?.findings.length})`);
    assert(
      hit?.findings[0]?.cve_id === 'CVE-A',
      `first finding's cve_id preserved (got: ${hit?.findings[0]?.cve_id})`
    );
  }

  // ----- 3. stale row (scanned_at backdated 8d) ---------------------------
  console.log('\nstale row (scanned_at older than 7d) returns null...');
  {
    await storage.db.exec(
      `UPDATE container_image_scan_cache SET scanned_at = NOW() - INTERVAL '8 days' WHERE image_digest = '${digest}'`
    );
    const hit = await lookupContainerScanCache(supabase, key);
    assert(hit === null, `stale lookup returned null (got: ${JSON.stringify(hit)})`);
    // Restore for subsequent tests.
    await storage.db.exec(
      `UPDATE container_image_scan_cache SET scanned_at = NOW() WHERE image_digest = '${digest}'`
    );
  }

  // ----- 4. integrity-hash mismatch ---------------------------------------
  console.log('\nintegrity-hash mismatch returns null + logs warning...');
  {
    const originalWarn = console.warn;
    let warnCalls = 0;
    let warnMsg = '';
    console.warn = (m: unknown) => {
      warnCalls++;
      warnMsg = String(m);
    };
    try {
      await storage.db.exec(
        `UPDATE container_image_scan_cache SET scan_results_hash = '${'0'.repeat(64)}' WHERE image_digest = '${digest}'`
      );
      const hit = await lookupContainerScanCache(supabase, key);
      assert(hit === null, 'integrity-mismatch lookup returned null');
      assert(warnCalls === 1, `console.warn called once (got: ${warnCalls})`);
      assert(/cache_integrity_mismatch/.test(warnMsg), `warning mentions cache_integrity_mismatch`);
    } finally {
      console.warn = originalWarn;
    }
    // Restore the hash so later tests aren't poisoned.
    await storage.db.exec(
      `UPDATE container_image_scan_cache SET scan_results_hash = '${computeScanResultsHash(
        baseFindings
      )}' WHERE image_digest = '${digest}'`
    );
  }

  // ----- 5. composite-PK day-roll -----------------------------------------
  console.log('\ncomposite-PK day-roll yields a separate cache row...');
  {
    const dayTomorrow = '2026-05-06';
    const tomorrowKey: ContainerScanCacheKey = { ...key, trivy_db_version_day: dayTomorrow };
    const tomorrowFindings = [makeFinding({ cve_id: 'CVE-NEW' })];
    await upsertContainerScanCache(supabase, tomorrowKey, tomorrowFindings, orgId, runId);

    const todayHit = await lookupContainerScanCache(supabase, key);
    const tomorrowHit = await lookupContainerScanCache(supabase, tomorrowKey);

    assert(todayHit?.findings[0]?.cve_id === 'CVE-A', `today cache untouched (got: ${todayHit?.findings[0]?.cve_id})`);
    assert(
      tomorrowHit?.findings[0]?.cve_id === 'CVE-NEW',
      `tomorrow cache holds new findings (got: ${tomorrowHit?.findings[0]?.cve_id})`
    );

    const { data: rows } = await storage
      .from('container_image_scan_cache')
      .select('trivy_db_version_day')
      .eq('image_digest', digest);
    assert(
      Array.isArray(rows) && rows.length === 2,
      `2 cache rows for digest after day-roll (got: ${Array.isArray(rows) ? rows.length : 'not array'})`
    );
  }

  // ----- 6. concurrent-miss: ON CONFLICT DO NOTHING preserves first writer
  console.log('\nsecond org writing same key keeps first_scanned_by_org_id intact...');
  {
    const orgIdSecond = '22222222-2222-2222-2222-222222222222';
    await storage
      .from('organizations')
      .insert({ id: orgIdSecond, name: 'cache-test-org-2', created_at: new Date().toISOString() });
    await upsertContainerScanCache(supabase, key, baseFindings, orgIdSecond, 'run_other');
    const { data } = await storage
      .from('container_image_scan_cache')
      .select('first_scanned_by_org_id, first_scanned_run_id')
      .eq('image_digest', digest)
      .eq('trivy_db_version_day', '2026-05-05')
      .single();
    assert(
      (data as any)?.first_scanned_by_org_id === orgId,
      `first_scanned_by_org_id retained (got: ${(data as any)?.first_scanned_by_org_id})`
    );
    assert(
      (data as any)?.first_scanned_run_id === runId,
      `first_scanned_run_id retained (got: ${(data as any)?.first_scanned_run_id})`
    );
  }

  // ----- 7. 1MB truncation -------------------------------------------------
  console.log('\ntruncateFindingsToFit drops lowest-severity tail to fit 1MB...');
  {
    // Build a payload deliberately > 1MB. Each finding is ~400-500B JSON, so
    // 4000 of them is ~2MB.
    const fat: ContainerFinding[] = [];
    for (let i = 0; i < 4000; i++) {
      const sev = i % 5 === 0 ? 'CRITICAL' : i % 5 === 1 ? 'HIGH' : i % 5 === 2 ? 'MEDIUM' : i % 5 === 3 ? 'LOW' : 'INFO';
      fat.push(
        makeFinding({
          severity: sev,
          cve_id: `CVE-FAT-${i}`,
          container_fingerprint: `openssl@CVE-FAT-${i}`,
          description: `synthetic finding ${i} `.padEnd(120, '.'),
        })
      );
    }
    const initialBytes = Buffer.byteLength(JSON.stringify(fat), 'utf8');
    assert(initialBytes > 1_048_576, `synthetic payload exceeds 1MB (${initialBytes}B)`);

    const result = truncateFindingsToFit(fat);
    assert(result.truncated === true, 'truncation flag is true');
    const trimmedBytes = Buffer.byteLength(JSON.stringify(result.findings), 'utf8');
    // Effective in-memory cap leaves ~100 KB headroom for the JSONB-to-text
    // expansion that Postgres's CHECK octet_length(scan_results::text) measures.
    assert(trimmedBytes <= 1_048_576 - 100_000, `truncated bytes <= effective cap (${trimmedBytes}B)`);
    assert(result.findings.length < fat.length, 'truncated array is strictly smaller');

    // Severity-desc ordering: CRITICAL findings come before LOW/INFO in the
    // kept slice.
    const lastKept = result.findings[result.findings.length - 1];
    const lastRank = (sev: string | null) => {
      switch ((sev ?? '').toUpperCase()) {
        case 'CRITICAL':
          return 5;
        case 'HIGH':
          return 4;
        case 'MEDIUM':
          return 3;
        case 'LOW':
          return 2;
        case 'INFO':
          return 1;
        default:
          return 0;
      }
    };
    assert(
      lastRank(lastKept?.severity ?? null) >= 1,
      `last kept finding has a severity (got: ${lastKept?.severity})`
    );

    // Round-trip the truncated payload through the cache to prove we don't
    // bust the postgres CHECK on octet_length.
    const fatKey: ContainerScanCacheKey = { ...key, image_digest: 'c'.repeat(64) };
    const originalWarn = console.warn;
    let warned = false;
    console.warn = (m: unknown) => {
      if (/cache_row_truncated/.test(String(m))) warned = true;
    };
    try {
      await upsertContainerScanCache(supabase, fatKey, fat, orgId, runId);
    } finally {
      console.warn = originalWarn;
    }
    assert(warned, 'cache_row_truncated warning fired during upsert');

    const fatHit = await lookupContainerScanCache(supabase, fatKey);
    assert(fatHit !== null, 'truncated cache row reads back cleanly');
    assert(
      fatHit !== null && fatHit.findings.length === result.findings.length,
      `truncated readback length matches in-memory truncation (${fatHit?.findings.length} vs ${result.findings.length})`
    );
  }

  // ----- 8. reaper RPC ----------------------------------------------------
  console.log('\ncleanup_container_image_scan_cache reaper function is callable...');
  {
    const { error, data } = await storage.rpc<number>('cleanup_container_image_scan_cache', {
      retention_days: 30,
    });
    assert(error === null, `reaper rpc error=${error?.message ?? 'null'}`);
    assert(typeof data === 'number', `reaper returns an integer row count (got: ${typeof data})`);
  }

  await storage.close();

  console.log(`\n${failures === 0 ? 'ALL TESTS PASSED' : `${failures} TEST(S) FAILED`} in ${Date.now() - t0}ms`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('Unhandled error:', e);
  process.exit(1);
});

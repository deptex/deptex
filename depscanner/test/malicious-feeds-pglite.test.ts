/**
 * Integration test: `lookupFeed` matching precision against an in-memory
 * PGLite seeded with `known_malicious_packages` rows.
 *
 * Covers N4 (semver-RANGE matching) and N6 (Maven bare-artifactId fallback):
 *
 *   N4 — exact-version rows still match exactly; an npm row with a populated
 *        `vulnerable_range` flags an installed version that SATISFIES the
 *        range and only that; an out-of-range version does NOT match; a row
 *        with neither an exact version nor a range still SKIPS (the flag-all
 *        FP fix is preserved); a malformed range SKIPS (never match-all); a
 *        range on a NON-npm row is ignored (range matching is npm-scoped).
 *
 *   N6 — a bare Maven `artifactId` resolves to a `groupId:artifactId` advisory
 *        when the artifactId is globally unique in the feed; an ambiguous
 *        artifactId (two groupIds) does NOT match (cross-group FP guard); the
 *        colon-joined exact path keeps working; version still gates the hit.
 *
 * Run: npx tsx test/malicious-feeds-pglite.test.ts
 */

import { createPGLiteStorage } from '../src/storage';
import { lookupFeed } from '../src/malicious/feeds';

let failures = 0;

function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
  }
}

interface SeedRow {
  package_name: string;
  ecosystem: string;
  source: string;
  source_id: string;
  version: string | null;
  vulnerable_range: string | null;
  severity: string;
  description: string;
}

function row(overrides: Partial<SeedRow> & Pick<SeedRow, 'package_name' | 'ecosystem' | 'source_id'>): SeedRow {
  return {
    source: 'ghsa',
    version: null,
    vulnerable_range: null,
    severity: 'critical',
    description: 'seeded malicious advisory',
    ...overrides,
  };
}

async function main() {
  const t0 = Date.now();
  console.log('Booting PGLiteStorage...');
  const storage = await createPGLiteStorage();
  console.log(`  booted in ${Date.now() - t0}ms\n`);

  const seed: SeedRow[] = [
    // N4 exact-version (npm)
    row({ package_name: 'exactpkg', ecosystem: 'npm', source_id: 'GHSA-exact', version: '1.2.3' }),
    // N4 single-bound range (npm)
    row({ package_name: 'rangepkg', ecosystem: 'npm', source_id: 'GHSA-range', vulnerable_range: '<2.0.0' }),
    // N4 compound AND range (npm)
    row({ package_name: 'compoundpkg', ecosystem: 'npm', source_id: 'GHSA-compound', vulnerable_range: '>=1.0.0 <2.0.0' }),
    // N4 flag-all: neither version nor range (npm) — must still skip
    row({ package_name: 'flagallpkg', ecosystem: 'npm', source_id: 'GHSA-flagall' }),
    // N4 malformed range (npm) — must skip, never match-all
    row({ package_name: 'badrangepkg', ecosystem: 'npm', source_id: 'GHSA-badrange', vulnerable_range: 'not a version range' }),
    // N4 range on a NON-npm row — must be ignored (range matching is npm-scoped)
    row({ package_name: 'pyrangepkg', ecosystem: 'pypi', source_id: 'GHSA-pyrange', vulnerable_range: '<2.0.0' }),

    // N6 unique bare artifactId (one groupId)
    row({ package_name: 'com.evil:widget', ecosystem: 'maven', source_id: 'GHSA-widget', version: '1.0.0' }),
    // N6 ambiguous bare artifactId (two groupIds)
    row({ package_name: 'com.foo:core', ecosystem: 'maven', source_id: 'GHSA-core-foo', version: '1.0.0' }),
    row({ package_name: 'org.bar:core', ecosystem: 'maven', source_id: 'GHSA-core-bar', version: '1.0.0' }),
  ];

  await storage.from('known_malicious_packages').insert(seed);

  // ----- N4: exact-version matching is unchanged --------------------------
  console.log('N4 exact-version still matches...');
  {
    const hit = await lookupFeed(storage, 'exactpkg', 'npm', '1.2.3');
    assert(hit.length === 1, `exact version 1.2.3 matches (got ${hit.length})`);
    const miss = await lookupFeed(storage, 'exactpkg', 'npm', '1.2.4');
    assert(miss.length === 0, `non-matching version 1.2.4 does not match (got ${miss.length})`);
  }

  // ----- N4: in-range matches, out-of-range does not ----------------------
  console.log('\nN4 in-range version matches, out-of-range does not...');
  {
    const inRange = await lookupFeed(storage, 'rangepkg', 'npm', '1.5.0');
    assert(inRange.length === 1, `1.5.0 satisfies <2.0.0 (got ${inRange.length})`);
    const boundary = await lookupFeed(storage, 'rangepkg', 'npm', '2.0.0');
    assert(boundary.length === 0, `2.0.0 does NOT satisfy <2.0.0 (got ${boundary.length})`);
    const above = await lookupFeed(storage, 'rangepkg', 'npm', '2.5.0');
    assert(above.length === 0, `2.5.0 does NOT satisfy <2.0.0 (got ${above.length})`);
  }

  // ----- N4: compound AND range ------------------------------------------
  console.log('\nN4 compound >=1.0.0 <2.0.0 range...');
  {
    const inRange = await lookupFeed(storage, 'compoundpkg', 'npm', '1.5.0');
    assert(inRange.length === 1, `1.5.0 satisfies >=1.0.0 <2.0.0 (got ${inRange.length})`);
    const below = await lookupFeed(storage, 'compoundpkg', 'npm', '0.9.0');
    assert(below.length === 0, `0.9.0 below the range does not match (got ${below.length})`);
    const above = await lookupFeed(storage, 'compoundpkg', 'npm', '2.0.0');
    assert(above.length === 0, `2.0.0 above the range does not match (got ${above.length})`);
  }

  // ----- N4: flag-all FP fix preserved (no version, no range) -------------
  console.log('\nN4 null-version + null-range still SKIPS (flag-all FP fix intact)...');
  {
    const miss = await lookupFeed(storage, 'flagallpkg', 'npm', '1.0.0');
    assert(miss.length === 0, `name-only row never flags an installed version (got ${miss.length})`);
  }

  // ----- N4: malformed range skips ---------------------------------------
  console.log('\nN4 malformed range SKIPS (never match-all)...');
  {
    const miss = await lookupFeed(storage, 'badrangepkg', 'npm', '1.0.0');
    assert(miss.length === 0, `unparseable range never matches (got ${miss.length})`);
  }

  // ----- N4: range matching is npm-scoped --------------------------------
  console.log('\nN4 a range on a non-npm row is ignored...');
  {
    const miss = await lookupFeed(storage, 'pyrangepkg', 'pypi', '1.0.0');
    assert(miss.length === 0, `pypi range row is not range-evaluated → skips (got ${miss.length})`);
  }

  // ----- N6: bare Maven artifactId, globally unique -----------------------
  console.log('\nN6 unique bare Maven artifactId resolves to groupId:artifactId...');
  {
    const hit = await lookupFeed(storage, 'widget', 'maven', '1.0.0');
    assert(hit.length === 1, `bare 'widget' matches com.evil:widget (got ${hit.length})`);
    assert(hit[0]?.source_id === 'GHSA-widget', `resolved to the right advisory (got ${hit[0]?.source_id})`);

    const colon = await lookupFeed(storage, 'com.evil:widget', 'maven', '1.0.0');
    assert(colon.length === 1, `colon-joined coordinate still matches exactly (got ${colon.length})`);

    const wrongVersion = await lookupFeed(storage, 'widget', 'maven', '2.0.0');
    assert(wrongVersion.length === 0, `version still gates the resolved bare match (got ${wrongVersion.length})`);
  }

  // ----- N6: ambiguous bare artifactId → no match (cross-group guard) ------
  console.log('\nN6 ambiguous bare artifactId does NOT match (cross-group FP guard)...');
  {
    const miss = await lookupFeed(storage, 'core', 'maven', '1.0.0');
    assert(miss.length === 0, `bare 'core' spanning two groupIds is declined (got ${miss.length})`);
  }

  // ----- N6: bare artifactId with no advisory -----------------------------
  console.log('\nN6 bare artifactId with no advisory returns no hits...');
  {
    const miss = await lookupFeed(storage, 'nonexistent', 'maven', '1.0.0');
    assert(miss.length === 0, `unknown artifactId returns nothing (got ${miss.length})`);
  }

  await storage.close();

  console.log(`\n${failures === 0 ? 'ALL TESTS PASSED' : `${failures} TEST(S) FAILED`} in ${Date.now() - t0}ms`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('Unhandled error:', e);
  process.exit(1);
});

/**
 * Real end-to-end smoke for the container reachability classifier.
 *
 * container-reachability.test.ts proves the classifier LOGIC with injected
 * fake crane / tar / readelf runners — it never executes the real binaries.
 * This harness is the opposite: it runs the REAL `defaultReachabilityRunners`
 * against REAL public images. It pulls each image with crane, extracts the
 * filesystem with tar, parses the real dpkg/apk database, and analyzes the
 * entrypoint's ELF DT_NEEDED graph with readelf — the exact path that runs in
 * production. It is the only check that catches a crane/readelf output-shape
 * mismatch or a missing binary (e.g. binutils not installed).
 *
 * It needs crane, tar and readelf on PATH plus network access, so it must run
 * INSIDE the depscanner Docker image — the dev tree (Windows, no readelf)
 * cannot run it. One command:
 *
 *   npm run e2e:container-reachability
 *
 * which builds the image and runs `node dist/scanners/container-reachability-e2e.js`
 * inside it. Exits non-zero on any failure so it can gate a release.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  decorateContainerFindingsWithReachability,
  defaultReachabilityRunners,
} from './container-reachability';
import type { ContainerFinding } from './types';

/**
 * What the case is meant to prove:
 *  - `classified`         the real crane/tar/readelf path runs to a per-finding
 *                         verdict (no fallback) — the entrypoint is a
 *                         resolvable ELF binary.
 *  - `fail_closed_module` the entrypoint is genuinely unanalyzable (a common
 *                         `exec "$@"` wrapper); the classifier MUST fail closed
 *                         — every finding `module`, none dropped `unreachable`.
 */
type Expectation = 'classified' | 'fail_closed_module';

interface SmokeCase {
  image: string;
  ecosystem: string;
  /** Real OS packages expected in the image — at least one must resolve in the
   *  image's own dpkg/apk database for a `classified` case to count. */
  packages: string[];
  expect: Expectation;
  note: string;
}

// Three real images: two with a resolvable ELF entrypoint (one dpkg/glibc, one
// apk/musl — exercising both DB backends and both libc families), and one with
// the ubiquitous `exec "$@"` wrapper entrypoint to prove the fail-closed path.
const CASES: SmokeCase[] = [
  {
    image: 'debian:bookworm-slim',
    ecosystem: 'debian',
    packages: ['libc6', 'libtinfo6', 'gzip'],
    expect: 'classified',
    note: 'dpkg / glibc — /bin/bash is a resolvable dynamic ELF entrypoint',
  },
  {
    image: 'python:3.12-alpine',
    ecosystem: 'alpine',
    packages: ['musl', 'libssl3', 'busybox'],
    expect: 'classified',
    note: 'apk / musl — python3.12 is a resolvable dynamic ELF entrypoint',
  },
  {
    image: 'node:20-bookworm-slim',
    ecosystem: 'debian',
    packages: ['libssl3', 'libc6'],
    expect: 'fail_closed_module',
    note: 'docker-entrypoint.sh is an `exec "$@"` wrapper — must fail closed to module',
  },
];

// Generous per-image budget: a first-time `crane export` pulls the whole image
// over the network, which can take well past the 30s production default.
const E2E_BUDGET_MS = 240_000;

function makeFinding(c: SmokeCase, pkg: string, n: number): ContainerFinding {
  return {
    scanner_version: 'e2e',
    image_reference: c.image,
    image_digest: 'e2e-no-digest',
    os_package_name: pkg,
    os_package_version: '0',
    os_package_ecosystem: c.ecosystem,
    osv_id: null,
    cve_id: `E2E-${n}`,
    severity: 'HIGH',
    cvss_score: null,
    epss_score: null,
    is_kev: false,
    fix_versions: [],
    layer_digest: null,
    description: null,
    rule_doc_url: null,
    container_fingerprint: `${pkg}@E2E-${n}`,
  };
}

async function runCase(c: SmokeCase): Promise<boolean> {
  console.log(`\n=== ${c.image} (${c.ecosystem}) — expect ${c.expect} ===`);
  console.log(`  ${c.note}`);
  const scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'reach-e2e-'));
  const findings = c.packages.map((pkg, i) => makeFinding(c, pkg, i + 1));

  try {
    const summary = await decorateContainerFindingsWithReachability(findings, {
      imageRef: c.image,
      scratchDir,
      runners: defaultReachabilityRunners,
      budgetMs: E2E_BUDGET_MS,
    });

    for (const f of findings) {
      console.log(
        `  ${f.os_package_name.padEnd(14)} -> ${String(f.reachability_level)}` +
          (f.reachability_details?.reason ? ` (${f.reachability_details.reason})` : '')
      );
    }
    console.log(
      `  summary: classified=${summary.classified} module=${summary.module} ` +
        `unreachable=${summary.unreachable} fallback=${summary.fallbackReason ?? 'none'}`
    );

    if (c.expect === 'classified') {
      // The real crane/tar/readelf path must run to per-finding verdicts.
      if (summary.fallbackReason !== null) {
        console.error(`  FAIL — fell back ('${summary.fallbackReason}'); the real path did not run`);
        return false;
      }
      if (summary.classified < 1) {
        console.error('  FAIL — nothing classified; the dpkg/apk parse or lookup is broken');
        return false;
      }
    } else {
      // Unanalyzable entrypoint: must fail CLOSED — never infer `unreachable`.
      if (summary.fallbackReason === null) {
        console.error('  FAIL — expected a fail-closed fallback, classifier reported none');
        return false;
      }
      if (summary.unreachable > 0 || summary.module !== findings.length) {
        console.error(
          `  FAIL — not fail-closed: ${summary.unreachable} finding(s) marked unreachable`
        );
        return false;
      }
    }
    console.log('  PASS');
    return true;
  } catch (err) {
    console.error(`  FAIL — threw: ${(err as Error).message}`);
    return false;
  } finally {
    fs.rmSync(scratchDir, { recursive: true, force: true });
  }
}

async function main(): Promise<void> {
  console.log('Container reachability — real end-to-end smoke');
  let failed = 0;
  for (const c of CASES) {
    const ok = await runCase(c);
    if (!ok) failed += 1;
  }
  console.log(`\n${CASES.length - failed}/${CASES.length} cases passed`);
  if (failed > 0) {
    console.error('Container reachability e2e FAILED');
    process.exit(1);
  }
  console.log('Container reachability e2e passed');
}

main().catch((err) => {
  console.error('e2e harness crashed:', err);
  process.exit(1);
});

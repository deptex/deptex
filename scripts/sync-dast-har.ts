#!/usr/bin/env tsx
/**
 * Phase 36 (v1.1) — sync the DAST HAR shared modules from backend →
 * depscanner. The depscanner package is a separate npm workspace; backend's
 * tsconfig cannot be imported from it.
 *
 * Maintained copies:
 *   - backend/src/lib/dast-har-constants.ts → depscanner/src/dast/har-constants.ts
 *   - backend/src/lib/dast-har-parse.ts     → depscanner/src/dast/har-parse.ts
 *
 * url-guard.ts is already synced for PR #51 via sync-dast-openapi.ts and
 * is reused for per-entry SSRF revalidation at scan time. ReplayedRequest /
 * HarTotpStep / ReplayCredentialPayload are HAND-mirrored into
 * depscanner/src/dast/auth-config.ts (the existing precedent for
 * RecordedCredentialPayload) — the shape-coverage test in
 * dast-replay-auth-config.test.ts round-trips every optional field to
 * keep that hand mirror honest.
 *
 * Each destination file is prepended with a sync header so a casual reader
 * sees the source-of-truth pointer at the top. The body is otherwise
 * byte-identical to the source so a `git diff --exit-code` step in CI
 * fails the PR if the worker copy drifts.
 *
 * Usage:
 *   npx tsx scripts/sync-dast-har.ts
 *
 * CI wire-up: extend the existing schema-check workflow (or add a sibling
 * dast-sync-check.yml) that re-runs this and the openapi sync, then runs
 * `git diff --exit-code` against the worker tree.
 */

import * as fs from 'fs';
import * as path from 'path';

const ROOT = path.resolve(__dirname, '..');

interface SyncTarget {
  src: string;
  dest: string;
  header: string;
}

const TARGETS: SyncTarget[] = [
  {
    src: path.join(ROOT, 'backend', 'src', 'lib', 'dast-har-constants.ts'),
    dest: path.join(ROOT, 'depscanner', 'src', 'dast', 'har-constants.ts'),
    header: [
      '// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
      '// DO NOT EDIT — synced from backend/src/lib/dast-har-constants.ts via',
      '//   scripts/sync-dast-har.ts',
      '// Edit the backend source and re-run the sync script. CI fails if this file',
      '// drifts.',
      '// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
      '',
      '',
    ].join('\n'),
  },
  {
    src: path.join(ROOT, 'backend', 'src', 'lib', 'dast-har-parse.ts'),
    dest: path.join(ROOT, 'depscanner', 'src', 'dast', 'har-parse.ts'),
    header: [
      '// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
      '// DO NOT EDIT — synced from backend/src/lib/dast-har-parse.ts via',
      '//   scripts/sync-dast-har.ts',
      '//',
      "// The depscanner can't `import` from `backend/src/lib/` (separate package",
      '// boundary in CI + Fly). This duplicate is enforced byte-identical via a CI',
      '// step that re-runs the sync script and fails on `git diff --exit-code`.',
      '// To change parser caps / detectors / scrubbers, edit the backend source and',
      '// re-run the sync script.',
      '//',
      '// Import path differences:',
      "//   backend:    import { ... } from '../types/dast';",
      "//   depscanner: import { ... } from './auth-config'; // hand mirror",
      '// The sync rewrites the import line below.',
      '// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
      '',
      '',
    ].join('\n'),
  },
];

/**
 * Rewrite backend-relative import paths to their depscanner equivalents.
 * The two shared modules import:
 *   - `./dast-har-constants` (sibling — same name on worker side: `./har-constants`)
 *   - `../types/dast` (parser-only; worker doesn't have a types/ dir at
 *     that depth, so we point ReplayedRequest / HarTotpStep at the hand
 *     mirror in `./auth-config`)
 */
function rewriteImports(src: string, body: string): string {
  let out = body;
  if (src.endsWith('dast-har-parse.ts')) {
    out = out.replace(
      /from '\.\/dast-har-constants'/g,
      "from './har-constants'",
    );
    out = out.replace(
      /from '\.\.\/types\/dast'/g,
      "from './auth-config'",
    );
  }
  return out;
}

function main(): void {
  for (const t of TARGETS) {
    if (!fs.existsSync(t.src)) {
      console.error(`Source missing: ${t.src}`);
      process.exit(1);
    }
    const body = fs.readFileSync(t.src, 'utf8');
    const rewritten = rewriteImports(t.src, body);
    fs.mkdirSync(path.dirname(t.dest), { recursive: true });
    fs.writeFileSync(t.dest, t.header + rewritten, 'utf8');
    console.log(`Wrote ${t.dest} (${t.header.length + rewritten.length} bytes)`);
  }
}

main();

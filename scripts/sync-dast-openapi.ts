#!/usr/bin/env tsx
/**
 * Phase 35 (v1.1) — sync the DAST OpenAPI shared modules from backend →
 * depscanner. The depscanner package is a separate npm workspace; backend's
 * tsconfig cannot be imported from it.
 *
 * Maintained copies:
 *   - backend/src/lib/url-guard.ts                  → depscanner/src/dast/url-guard.ts
 *   - backend/src/lib/dast-openapi-constants.ts     → depscanner/src/dast/openapi-constants.ts
 *
 * Each destination file is prepended with a sync header so a casual reader
 * sees the source-of-truth pointer at the top. The body is otherwise
 * byte-identical to the source so a `git diff --exit-code` step in CI
 * fails the PR if the worker copy drifts.
 *
 * Usage:
 *   npx tsx scripts/sync-dast-openapi.ts
 *
 * CI wire-up: .github/workflows/dast-openapi-sync-check.yml (or wherever
 * the existing schema-check job lives) re-runs this and `git diff
 * --exit-code` on the worker copies.
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
    src: path.join(ROOT, 'backend', 'src', 'lib', 'url-guard.ts'),
    dest: path.join(ROOT, 'depscanner', 'src', 'dast', 'url-guard.ts'),
    header: [
      '// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
      '// DO NOT EDIT — synced from backend/src/lib/url-guard.ts via',
      '//   scripts/sync-dast-openapi.ts',
      '//',
      "// The depscanner can't `import` from `backend/src/lib/` (separate package",
      '// boundary in CI + Fly). This duplicate is enforced byte-identical via a CI',
      '// step that re-runs the sync script and fails on `git diff --exit-code`.',
      '// To change the SSRF guard, edit `backend/src/lib/url-guard.ts` and re-run',
      '// the sync script.',
      '// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
      '',
      '',
    ].join('\n'),
  },
  {
    src: path.join(ROOT, 'backend', 'src', 'lib', 'dast-openapi-constants.ts'),
    dest: path.join(ROOT, 'depscanner', 'src', 'dast', 'openapi-constants.ts'),
    header: [
      '// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
      '// DO NOT EDIT — synced from backend/src/lib/dast-openapi-constants.ts via',
      '//   scripts/sync-dast-openapi.ts',
      '// Edit the backend source and re-run the sync script. CI fails if this file',
      '// drifts.',
      '// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
      '',
      '',
    ].join('\n'),
  },
];

function main(): void {
  for (const t of TARGETS) {
    if (!fs.existsSync(t.src)) {
      console.error(`Source missing: ${t.src}`);
      process.exit(1);
    }
    const body = fs.readFileSync(t.src, 'utf8');
    fs.mkdirSync(path.dirname(t.dest), { recursive: true });
    fs.writeFileSync(t.dest, t.header + body, 'utf8');
    console.log(`Wrote ${t.dest} (${t.header.length + body.length} bytes)`);
  }
}

main();

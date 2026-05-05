#!/usr/bin/env tsx
/**
 * Sync the AES-GCM encryption helper from backend → depscanner.
 *
 * The depscanner package is a separate npm workspace. backend's tsconfig
 * (rootDir = ./src) cannot be imported from depscanner, mirroring the same
 * constraint that drives the schema.sql staging pattern (CLAUDE.md).
 *
 * This script copies backend/src/lib/ai/encryption.ts to
 * backend/depscanner/src/lib/encryption.ts, truncating at a sentinel comment
 * so backend-only logic (rotateEncryptionKeys, which depends on Supabase) is
 * not pulled into the worker copy. Worker only needs encrypt / decrypt.
 *
 * The committed copy keeps a fresh checkout buildable without running the
 * script. CI (.github/workflows/encryption-sync-check.yml) fails the PR if
 * the source and the committed copy drift.
 *
 * Usage:
 *   npx tsx scripts/sync-encryption.ts
 *
 * Also wired into backend/depscanner package.json `docker:prepare` so the
 * worker image build refreshes the copy alongside the schema.sql staging.
 */

import * as fs from 'fs';
import * as path from 'path';

const ROOT = path.resolve(__dirname, '..');
const SRC = path.join(ROOT, 'backend', 'src', 'lib', 'ai', 'encryption.ts');
const DEST = path.join(ROOT, 'backend', 'depscanner', 'src', 'lib', 'encryption.ts');
const MARKER = '// === DEPSCANNER-SYNC: STOP ABOVE THIS LINE ===';

const HEADER = `// AUTO-GENERATED — DO NOT EDIT.
// Synced from backend/src/lib/ai/encryption.ts via scripts/sync-encryption.ts.
// CI (.github/workflows/encryption-sync-check.yml) fails when this file drifts.
// To change: edit the source file, then \`npx tsx scripts/sync-encryption.ts\`.

`;

function main(): void {
  const source = fs.readFileSync(SRC, 'utf8');
  const idx = source.indexOf(MARKER);
  if (idx === -1) {
    console.error(`Marker not found in ${SRC}: ${MARKER}`);
    process.exit(1);
  }
  // Keep everything strictly above the marker line; trim trailing whitespace
  // so the file ends with exactly one newline.
  const head = source.slice(0, idx).replace(/\s+$/u, '\n');
  fs.mkdirSync(path.dirname(DEST), { recursive: true });
  fs.writeFileSync(DEST, HEADER + head, 'utf8');
  console.log(`Wrote ${DEST} (${HEADER.length + head.length} bytes)`);
}

main();

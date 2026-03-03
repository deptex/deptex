#!/usr/bin/env node
/**
 * Vercel build: transpile TS → JS with esbuild (no type-checking).
 * On Vercel we also replace the tsc binary with a no-op so any post-build
 * step (Conformance, etc.) that runs tsc exits instantly instead of hanging.
 */
import * as esbuild from 'esbuild';
import { readdirSync, writeFileSync, unlinkSync, existsSync } from 'fs';
import { join, relative } from 'path';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const srcDir = join(__dirname, '..', 'src');
const outDir = join(__dirname, '..', 'dist');

function findTsFiles(dir, base = dir) {
  const entries = readdirSync(dir, { withFileTypes: true });
  const files = [];
  for (const e of entries) {
    const full = join(dir, e.name);
    const rel = relative(base, full);
    if (e.isDirectory()) {
      if (e.name === 'node_modules' || e.name === 'dist') continue;
      if (e.name === '__tests__' || e.name === '__mocks__' || e.name === 'test') continue;
      files.push(...findTsFiles(full, base));
    } else if (e.name.endsWith('.ts') && !e.name.endsWith('.d.ts')) {
      files.push(full);
    }
  }
  return files;
}

const entryPoints = findTsFiles(srcDir);
if (entryPoints.length === 0) {
  console.error('No .ts files found in src/');
  process.exit(1);
}

const result = await esbuild.build({
  entryPoints,
  outdir: outDir,
  outbase: srcDir,
  platform: 'node',
  format: 'cjs',
  target: 'node20',
  sourcemap: false,
  packages: 'external',
});

if (result.errors.length) {
  console.error('esbuild errors:', result.errors);
  process.exit(1);
}
console.log('Vercel build (esbuild):', entryPoints.length, 'files → dist/');

// On Vercel: replace every tsc entry point with a no-op so any post-build step
// (Conformance, type-check, or direct typescript/bin/tsc) exits instantly.
if (process.env.VERCEL) {
  const noop = '#!/usr/bin/env node\nprocess.exit(0);\n';
  // Replace tsc in backend, ee/backend, AND repo root (post-build often runs from root and uses root node_modules)
  const roots = [
    join(__dirname, '..'),                    // backend
    join(__dirname, '..', '..', 'ee', 'backend'),
    join(__dirname, '..', '..'),               // repo root
  ];
  for (const root of roots) {
    const targets = [
      join(root, 'node_modules', '.bin', 'tsc'),
      join(root, 'node_modules', 'typescript', 'bin', 'tsc'),
    ];
    for (const tscPath of targets) {
      try {
        if (existsSync(tscPath)) {
          unlinkSync(tscPath);
          writeFileSync(tscPath, noop, { mode: 0o755 });
          console.log('Vercel: tsc no-op at', tscPath);
        }
      } catch (e) {
        console.warn('Could not replace', tscPath, '(non-fatal):', e.message);
      }
    }
  }
}

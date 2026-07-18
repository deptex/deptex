/**
 * Second-app validation (entry-point auth classification, T13c-ish): run the
 * REAL express detector over the actual Deptex backend source and print the
 * route classification distribution + a sample. Validates the classifier on a
 * large real app (not the dogfood fixture) to catch overfit.
 *
 * Run: npx tsx scripts/entry-point-auth-backend-probe.ts
 */
import * as path from 'path';
import { extractUsage } from '../src/tree-sitter-extractor';

async function main(): Promise<void> {
  const workspaceRoot = path.resolve(__dirname, '../../backend/src');
  const extraction = await extractUsage({
    workspaceRoot, ecosystem: 'npm', maxFiles: 5000,
    deps: [{ name: 'express', namespace: null }],
  });
  const eps = extraction.files.flatMap((f) => (f.entryPoints ?? []).filter((e) => e.framework === 'express'));

  const dist: Record<string, number> = {};
  for (const ep of eps) dist[ep.classification] = (dist[ep.classification] ?? 0) + 1;
  const authed = eps.filter((e) => e.classification === 'AUTH_INTERNAL');
  const worker = eps.filter((e) => e.classification === 'OFFLINE_WORKER');
  const withSpan = eps.filter((e) => e.handlerSpan != null);

  console.log(`Deptex backend — ${eps.length} express routes across ${extraction.files.length} files`);
  console.log(`classification distribution: ${JSON.stringify(dist)}`);
  console.log(`routes with captured handler span: ${withSpan.length}`);
  console.log(`\nsample AUTH_INTERNAL routes (should be the authenticateUser-guarded ones):`);
  for (const ep of authed.slice(0, 12)) {
    console.log(`  ${ep.routePattern}  mw=${JSON.stringify(ep.middlewareChain)}`);
  }
  console.log(`\nsample OFFLINE_WORKER routes (should be internal/QStash/webhook-verifier):`);
  for (const ep of worker.slice(0, 8)) {
    console.log(`  ${ep.routePattern}  mw=${JSON.stringify(ep.middlewareChain)}`);
  }
  // Spot-check: /health-style routes must NOT be AUTH_INTERNAL (belt / public).
  const health = eps.filter((e) => /health|ping|status/.test(e.routePattern ?? ''));
  console.log(`\nhealth/ping/status routes (${health.length}) — must stay public:`);
  for (const ep of health.slice(0, 6)) console.log(`  ${ep.routePattern} -> ${ep.classification}`);
}

main().catch((e) => { console.error(e); process.exit(1); });

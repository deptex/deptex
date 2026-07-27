/**
 * Class-aware corpus tripwire (detector-level) for the entry-point auth arc.
 *
 * The full paired corpus run (scripts/oss-corpus.ts) needs the depscanner Docker
 * image + the 38GB reachability VDB. But the auth CLASSIFICATION the arc adds is
 * a pure detector-level operation (tree-sitter + framework-rules, no VDB), so we
 * can exercise the exact decision the tripwire guards — "does the classifier
 * demote only routes it genuinely should, and NEVER wrongly demote a public
 * route" — by running the real detectors over real cloned apps and auditing the
 * demotions.
 *
 * For a target workspace it prints:
 *   - the classification distribution across every framework detected,
 *   - a full DEMOTION AUDIT: every AUTH_INTERNAL / OFFLINE_WORKER route with the
 *     evidence that demoted it (route pattern, auth mechanism, middleware chain,
 *     span presence, demotion-eligibility) — the rows a human adjudicates for
 *     wrongful demotion (the cardinal sin: under-scoring real public surface),
 *   - a PUBLIC sample (missed-auth eyeball — the benign over-scoring direction),
 *   - the belt check: login/logout/signup/password/health/webhook routes must
 *     NOT be demoted even under centralized auth.
 *
 * Run (from depscanner/):
 *   npx tsx scripts/entry-point-auth-corpus-probe.ts \
 *     --workspace=/path/to/clone --ecosystem=pypi [--max-files=6000] \
 *     [--framework=flask] [--json=out.json]
 */
import * as path from 'path';
import * as fs from 'fs';
import { extractUsage } from '../src/tree-sitter-extractor';
import type { KnownDep, SupportedEcosystem } from '../src/tree-sitter-extractor/languages/types';
import { runPostProcess, buildEntryPointAuthMap } from '../src/framework-rules/build-auth-map';
import type { EntryPoint, EntryPointClassification } from '../src/framework-rules/types';

// Generous per-ecosystem dep list. Detectors gate on triggerImports (file
// imports), not on this — it only satisfies any internal depName checks and
// import→dep resolution. Over-inclusive is harmless.
const ECO_DEPS: Record<string, string[]> = {
  npm: ['express', 'fastify', 'koa', '@koa/router', 'koa-router', '@nestjs/common', '@nestjs/core', 'next'],
  pypi: ['flask', 'fastapi', 'starlette', 'django', 'djangorestframework', 'aiohttp', 'tornado'],
  golang: [
    'github.com/gin-gonic/gin', 'github.com/go-chi/chi', 'github.com/go-chi/chi/v5',
    'github.com/labstack/echo', 'github.com/labstack/echo/v4', 'github.com/gofiber/fiber',
    'github.com/gofiber/fiber/v2', 'github.com/gorilla/mux', 'net/http',
  ],
  gem: ['rails', 'actionpack', 'sinatra', 'grape'],
  composer: ['symfony/framework-bundle', 'symfony/routing', 'laravel/framework', 'slim/slim'],
  maven: ['org.springframework', 'jakarta.ws.rs', 'io.quarkus', 'io.micronaut'],
  nuget: ['Microsoft.AspNetCore'],
  cargo: ['axum', 'actix-web', 'rocket', 'warp'],
};

// Route-name families that must survive centralized auth (the public-route-name
// belt). Mirrors PUBLIC_OVERRIDE_PATTERNS intent — used only for the belt report.
const BELT_RE = /(^|[\/_.-])(login|logout|signin|signup|register|password|reset|forgot|health|healthz|livez|readyz|ping|status|metrics|webhook|callback|oauth|\.well-known)([\/_.-]|$)/i;

interface Flags { [k: string]: string | boolean }
function parseFlags(argv: string[]): Flags {
  const out: Flags = {};
  for (const a of argv) {
    if (!a.startsWith('--')) continue;
    const eq = a.indexOf('=');
    if (eq < 0) out[a.slice(2)] = true;
    else out[a.slice(2, eq)] = a.slice(eq + 1);
  }
  return out;
}

interface AuditRow {
  source: 'route' | 'crossfile';
  framework: string;
  file: string;
  line: number;
  routePattern: string | null;
  classification: EntryPointClassification;
  authMechanism: string | null;
  middlewareChain: string[] | null;
  demotionEligible: boolean;
  hasSpan: boolean;
}

async function main(): Promise<void> {
  const flags = parseFlags(process.argv.slice(2));
  const workspaceRoot = flags.workspace ? path.resolve(String(flags.workspace)) : null;
  const ecosystem = (flags.ecosystem ? String(flags.ecosystem) : 'npm') as SupportedEcosystem;
  const maxFiles = flags['max-files'] ? Number(flags['max-files']) : 8000;
  const onlyFramework = flags.framework ? String(flags.framework) : null;
  if (!workspaceRoot) { console.error('--workspace=<dir> required'); process.exit(2); }
  if (!fs.existsSync(workspaceRoot)) { console.error(`workspace not found: ${workspaceRoot}`); process.exit(2); }

  const deps: KnownDep[] = (ECO_DEPS[ecosystem] ?? []).map((name) => ({ name, namespace: null }));

  const t0 = Date.now();
  const extraction = await extractUsage({ workspaceRoot, ecosystem, deps, maxFiles });
  const postRecords = await runPostProcess(extraction.files, workspaceRoot);
  // Build the map purely to exercise the exact join key path the pipeline uses.
  buildEntryPointAuthMap(extraction.files, postRecords, workspaceRoot);
  const elapsed = ((Date.now() - t0) / 1000).toFixed(1);

  const rel = (p: string): string => path.relative(workspaceRoot, p).replace(/\\/g, '/') || p;

  // Collect route-level entry points + cross-file records into one audit list.
  const rows: AuditRow[] = [];
  for (const f of extraction.files) {
    for (const ep of (f.entryPoints ?? []) as EntryPoint[]) {
      if (onlyFramework && ep.framework !== onlyFramework) continue;
      rows.push({
        source: 'route', framework: ep.framework, file: rel(ep.filePath), line: ep.lineNumber,
        routePattern: ep.routePattern, classification: ep.classification,
        authMechanism: ep.authMechanism, middlewareChain: ep.middlewareChain,
        demotionEligible: ep.demotionEligible ?? (ep.handlerSpan != null), hasSpan: ep.handlerSpan != null,
      });
    }
  }
  for (const rec of postRecords) {
    rows.push({
      source: 'crossfile', framework: 'crossfile', file: rec.filePath.replace(/\\/g, '/'), line: rec.handlerSpan?.startLine ?? 0,
      routePattern: rec.routePattern, classification: rec.classification,
      authMechanism: rec.authMechanism, middlewareChain: rec.middlewareChain,
      demotionEligible: rec.demotionEligible, hasSpan: rec.handlerSpan != null,
    });
  }

  // ---- distribution ----
  const dist: Record<string, number> = {};
  const byFramework: Record<string, Record<string, number>> = {};
  for (const r of rows) {
    dist[r.classification] = (dist[r.classification] ?? 0) + 1;
    (byFramework[r.framework] ??= {})[r.classification] = ((byFramework[r.framework] ??= {})[r.classification] ?? 0) + 1;
  }
  const demotions = rows.filter((r) => r.classification === 'AUTH_INTERNAL' || r.classification === 'OFFLINE_WORKER');
  // A demotion that ACTUALLY moves a score = eligible + has span (route-local)
  // or a cross-file record (always eligible by construction).
  const effectiveDemotions = demotions.filter((r) => r.demotionEligible && (r.hasSpan || r.source === 'crossfile'));

  console.log(`\n=== entry-point auth corpus probe: ${path.basename(workspaceRoot)} (${ecosystem}) ===`);
  console.log(`files scanned: ${extraction.files.length}  entry points: ${rows.length}  (${elapsed}s)`);
  if (extraction.failedGrammars.length) console.log(`failed grammars: ${extraction.failedGrammars.join(', ')}`);
  console.log(`classification distribution: ${JSON.stringify(dist)}`);
  console.log(`demotions (AUTH_INTERNAL+OFFLINE_WORKER): ${demotions.length}  effective (eligible+span/crossfile): ${effectiveDemotions.length}`);
  console.log(`\nper-framework:`);
  for (const fw of Object.keys(byFramework).sort()) console.log(`  ${fw}: ${JSON.stringify(byFramework[fw])}`);

  // ---- belt check: named-public routes must not demote ----
  const beltViolations = demotions.filter((r) => BELT_RE.test(r.routePattern ?? '') || BELT_RE.test(r.file));
  console.log(`\n=== BELT CHECK (login/health/webhook/oauth must stay public) ===`);
  if (beltViolations.length === 0) {
    console.log('  ✅ no named-public route was demoted');
  } else {
    console.log(`  ⚠️  ${beltViolations.length} named-public route(s) demoted — INSPECT for wrongful demotion:`);
    for (const r of beltViolations.slice(0, 30)) {
      console.log(`   [${r.classification}] ${r.file}:${r.line} route=${r.routePattern} mw=${JSON.stringify(r.middlewareChain)} authBy=${r.authMechanism} eligible=${r.demotionEligible} span=${r.hasSpan}`);
    }
  }

  // ---- full demotion audit ----
  console.log(`\n=== DEMOTION AUDIT (${effectiveDemotions.length} effective; adjudicate each for TRUE auth) ===`);
  for (const r of effectiveDemotions.slice(0, 80)) {
    console.log(`  [${r.classification}] (${r.framework}) ${r.file}:${r.line}`);
    console.log(`     route=${r.routePattern}  authBy=${r.authMechanism}  mw=${JSON.stringify(r.middlewareChain)}`);
  }
  if (effectiveDemotions.length > 80) console.log(`  … +${effectiveDemotions.length - 80} more`);

  // ---- public sample (missed-auth eyeball) ----
  const publicRows = rows.filter((r) => r.classification === 'PUBLIC_UNAUTH' || r.classification === 'UNKNOWN');
  const publicWithMw = publicRows.filter((r) => (r.middlewareChain?.length ?? 0) > 0);
  console.log(`\n=== PUBLIC SAMPLE with middleware (eyeball for missed auth — benign over-score direction) ===`);
  for (const r of publicWithMw.slice(0, 20)) {
    console.log(`  [${r.classification}] ${r.file}:${r.line} route=${r.routePattern} mw=${JSON.stringify(r.middlewareChain)}`);
  }
  if (publicWithMw.length === 0) console.log('  (no public routes carry a middleware chain)');

  if (flags.json) {
    const outPath = path.resolve(String(flags.json));
    fs.writeFileSync(outPath, JSON.stringify({
      workspace: path.basename(workspaceRoot), ecosystem, files: extraction.files.length,
      entryPoints: rows.length, distribution: dist, byFramework,
      demotions: demotions.length, effectiveDemotions: effectiveDemotions.length,
      beltViolations, effectiveDemotionRows: effectiveDemotions,
    }, null, 2));
    console.log(`\nwrote ${outPath}`);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });

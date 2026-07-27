/**
 * Cardinal-sin CI gate for the entry-point auth arc (detector-level, no VDB).
 *
 * Runs the REAL framework detectors over every committed `test-repos/*` fixture
 * (one per shipped ecosystem) and asserts the ONE invariant the whole arc rests
 * on: an unambiguous public auth-entry route — login / logout / signup / register
 * / password-reset / oauth-callback / webhook — is NEVER demoted below public.
 * You cannot require prior authentication to authenticate, so a demotion there is
 * a wrongful demotion (the cardinal sin: it under-scores real public surface).
 *
 * This is golden-free on purpose: it asserts the SAFETY property, not specific
 * per-route classifications, so it can't rot as detectors improve. It complements
 * the per-detector unit suites (synthetic snippets) by exercising fuller fixture
 * apps, and the e2e (real engine over the express fixture) by covering all
 * ecosystems at the detector layer with no VDB / clone / Docker cost.
 *
 * Run: npx tsx test/entry-point-auth-corpus-gate.test.ts
 */
import * as path from 'path';
import { extractUsage } from '../src/tree-sitter-extractor';
import type { KnownDep, SupportedEcosystem } from '../src/tree-sitter-extractor/languages/types';
import { runPostProcess, buildEntryPointAuthMap } from '../src/framework-rules/build-auth-map';
import type { EntryPoint } from '../src/framework-rules/types';

// Fixture → ecosystem. Detectors gate on triggerImports (file imports), so the
// dep list only needs to be non-empty enough to satisfy import resolution; the
// classification runs regardless. `react` has no backend routes → skipped.
const FIXTURES: Array<{ dir: string; ecosystem: SupportedEcosystem }> = [
  { dir: 'express', ecosystem: 'npm' },
  { dir: 'nextjs', ecosystem: 'npm' },
  { dir: 'flask', ecosystem: 'pypi' },
  { dir: 'fastapi', ecosystem: 'pypi' },
  { dir: 'django', ecosystem: 'pypi' },
  { dir: 'gin-gonic', ecosystem: 'golang' },
  { dir: 'rails', ecosystem: 'gem' },
  { dir: 'laravel', ecosystem: 'composer' },
  { dir: 'spring-boot', ecosystem: 'maven' },
  { dir: 'aspnet', ecosystem: 'nuget' },
  { dir: 'axum', ecosystem: 'cargo' },
];

const ECO_DEPS: Record<string, string[]> = {
  npm: ['express', 'fastify', 'koa', '@nestjs/common', 'next'],
  pypi: ['flask', 'fastapi', 'starlette', 'django', 'djangorestframework'],
  golang: ['github.com/gin-gonic/gin', 'github.com/go-chi/chi', 'github.com/labstack/echo', 'net/http'],
  gem: ['rails', 'actionpack', 'sinatra'],
  composer: ['laravel/framework', 'symfony/routing', 'slim/slim'],
  maven: ['org.springframework', 'jakarta.ws.rs'],
  nuget: ['Microsoft.AspNetCore'],
  cargo: ['axum', 'actix-web'],
};

// Unambiguous PUBLIC auth-entry / hook routes: requiring prior auth here is a
// contradiction, so a demotion is always a wrongful demote. (Deliberately NOT
// including /health, /metrics, /status, /ping — those can legitimately sit behind
// auth in some apps, so they'd make the gate brittle.)
const AUTH_ENTRY_RE = /(^|[\/_.-])(login|logout|signin|signout|signup|register|password|forgot|reset|oauth|callback|webhook|\.well-known)([\/_.-]|$)/i;

let failures = 0;
let passes = 0;
function assert(cond: unknown, msg: string): void {
  if (!cond) { console.error(`  FAIL: ${msg}`); failures++; }
  else { console.log(`  ok: ${msg}`); passes++; }
}

async function classifyFixture(dir: string, ecosystem: SupportedEcosystem): Promise<{
  routes: Array<{ routePattern: string | null; classification: string; file: string }>;
  demotions: number;
}> {
  const workspaceRoot = path.resolve(__dirname, '..', 'test-repos', dir);
  const deps: KnownDep[] = (ECO_DEPS[ecosystem] ?? []).map((name) => ({ name, namespace: null }));
  const extraction = await extractUsage({ workspaceRoot, ecosystem, deps, maxFiles: 4000 });
  const post = await runPostProcess(extraction.files, workspaceRoot);
  buildEntryPointAuthMap(extraction.files, post, workspaceRoot); // exercise the exact join-key path

  const routes: Array<{ routePattern: string | null; classification: string; file: string }> = [];
  for (const f of extraction.files) {
    for (const ep of (f.entryPoints ?? []) as EntryPoint[]) {
      routes.push({ routePattern: ep.routePattern, classification: ep.classification, file: f.filePath });
    }
  }
  for (const rec of post) {
    routes.push({ routePattern: rec.routePattern, classification: rec.classification, file: rec.filePath });
  }
  const demotions = routes.filter((r) => r.classification === 'AUTH_INTERNAL' || r.classification === 'OFFLINE_WORKER').length;
  return { routes, demotions };
}

async function run(): Promise<void> {
  console.log('\nCARDINAL-SIN CORPUS GATE — no auth-entry route may be demoted\n');
  let totalRoutes = 0;
  let totalDemotions = 0;

  for (const { dir, ecosystem } of FIXTURES) {
    let result;
    try {
      result = await classifyFixture(dir, ecosystem);
    } catch (err) {
      assert(false, `${dir}: detector run threw — ${(err as Error).message}`);
      continue;
    }
    totalRoutes += result.routes.length;
    totalDemotions += result.demotions;

    // The gate: any demoted route whose pattern is an unambiguous public
    // auth-entry point is a wrongful demotion.
    const violations = result.routes.filter(
      (r) => (r.classification === 'AUTH_INTERNAL' || r.classification === 'OFFLINE_WORKER')
        && r.routePattern != null && AUTH_ENTRY_RE.test(r.routePattern),
    );
    if (violations.length > 0) {
      for (const v of violations) {
        console.error(`    WRONGFUL DEMOTE: ${dir} ${v.routePattern} → ${v.classification} (${v.file})`);
      }
    }
    assert(violations.length === 0, `${dir}: no auth-entry route demoted (${result.routes.length} routes, ${result.demotions} demoted)`);
  }

  // Non-degenerate sanity: the pipeline actually classified routes across the
  // corpus (guards against a silent extractor break making the gate vacuous).
  assert(totalRoutes > 0, `corpus produced routes (${totalRoutes} total across fixtures)`);
  console.log(`\n${passes} passed, ${failures} failed — ${totalRoutes} routes, ${totalDemotions} demoted across the corpus`);
  if (failures > 0) process.exit(1);
}

run().catch((e) => { console.error(e); process.exit(1); });

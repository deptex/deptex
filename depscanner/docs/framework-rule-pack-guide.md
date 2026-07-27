# Framework Rule-Pack Guide

How to add a new framework detector to the tree-sitter reachability extractor.

A "framework detector" is a flat rule-pack that walks a parsed AST and emits `EntryPoint` rows (HTTP routes, serverless handlers, message consumers, etc.) into `project_entry_points`. Entry points feed EPD contextual scoring, which flows into `depscore`.

The 34 current detectors (8 languages, MVP v1) live under `src/framework-rules/detectors/`. Each is a single file exporting a `FrameworkDetector`. No class hierarchies, no registrations beyond a list entry.

---

## The detector shape

```ts
// src/framework-rules/detectors/myframework.ts
import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';

export const myFrameworkDetector: FrameworkDetector = {
  name: 'myframework',          // stored in project_entry_points.framework
  displayName: 'My Framework',  // shown in the UI
  language: 'javascript',       // SupportedLanguageId — must match a language module
  triggerImports: ['my-framework'], // file skipped if none of these are imported
  detect(ctx: DetectorContext): EntryPoint[] {
    // walk ctx.tree and return matching entry points
  },
};
```

The registry (`src/framework-rules/registry.ts`) is a flat array — import the detector and append it.

---

## Lifecycle

Per source file, the pipeline does:

1. Language module parses the file and extracts `imports` + `usages` (see `language-query-guide.md`).
2. For each detector registered for that language:
   - If `triggerImports` is non-empty and none of them appear in `file.imports` (exact match or `source.startsWith(\`${t}/\`)`), skip.
   - If empty, run unconditionally (Next.js App Router, AWS Lambda — gated by filename/export, not imports).
3. `detector.detect({ source, tree, file })` runs inside a try/catch. Detector throws are swallowed — a bug in one detector must not take down the whole extractor.
4. Returned entry points are attached to `ExtractedFile.entryPoints`.
5. `storeEntryPoints()` batches them into `project_entry_points` under the pending `extraction_run_id`. Atomic commit is handled by the Phase 19 active-run pointer — no soft-delete or carry-forward logic belongs in the detector.

---

## Writing the `detect` function

Most detectors follow one of three patterns.

### Pattern A — framework instance + method calls (Express, Koa, Fastify, Gin, Echo, Rails, Sinatra, ...)

Bind an instance from the import (`const app = express()` / `r := gin.Default()`), then collect `instance.VERB(pattern, handler)` calls.

```ts
import { walkTree, HTTP_METHOD_NAMES, findInstancesOfImport, detectAuthMechanism, classifyFromAuth, lineOf, stringLiteralValue } from '../util/javascript';

detect(ctx) {
  const { tree, file, source } = ctx;
  const imp = file.imports.find((i) => i.source === 'my-framework');
  if (!imp?.localName) return [];

  const instances = findInstancesOfImport(tree.rootNode, source, imp.localName);
  if (instances.size === 0) return [];

  const authMechanism = detectAuthMechanism(file.imports);
  const classification = classifyFromAuth(authMechanism);
  const out: EntryPoint[] = [];

  walkTree(tree, (node) => {
    if (node.type !== 'call_expression') return;
    // ... shape-match `instance.METHOD(pattern, handler)` ...
    out.push({
      filePath: file.filePath,
      lineNumber: lineOf(node),           // 1-based, matches DB
      framework: 'myframework',
      handlerName,
      httpMethod,
      routePattern,
      entryPointType: 'http_route',
      classification,
      authenticated: !!authMechanism,
      authMechanism,
      middlewareChain: null,
      metadata: null,
    });
  });
  return out;
}
```

See `detectors/express.ts` for a canonical JS instance-based detector. `detectors/gin.ts` for Go.

### Pattern B — decorators / attributes (NestJS, Spring, FastAPI, Symfony, Laravel, ASP.NET Core)

Walk class/method nodes, read decorators/annotations/attributes preceding them. AST shape varies per language — see `language-query-guide.md` for the quirks.

Reference implementations:
- JS decorators: `detectors/nestjs.ts`
- Java annotations: `detectors/spring.ts`, `detectors/jaxrs.ts`
- Python decorators: `detectors/flask.ts`, `detectors/fastapi.ts`
- PHP attributes (PHP 8): `detectors/symfony.ts`
- C# attributes: `detectors/aspnet-core.ts`
- Rust attributes: `detectors/actix.ts`, `detectors/rocket.ts`

### Pattern C — convention-based (filename / export names)

No imports to trigger on — run unconditionally and gate by filename or export shape.

Examples:
- `detectors/nextjs.ts` — checks filename matches `app/**/route.(ts|js)` and inspects exported functions named `GET`/`POST`/...
- `detectors/aws-lambda.ts` — matches `exports.handler = ...` / `export const handler = ...`.

Set `triggerImports: []` for these.

---

## Helpers (share, don't reinvent)

Per-language util modules under `src/framework-rules/util/` cover the 80% of tree-walking work:

| Language | Util module | Key helpers |
|----------|-------------|-------------|
| JS/TS | `util/javascript.ts` | `walkTree`, `findInstancesOfImport`, `HTTP_METHOD_NAMES`, `handlerDescriptor`, `stringLiteralValue`, `detectAuthMechanism`, `classifyFromAuth`, `lineOf` |
| Python | `util/python.ts` | `findClassInstances`, `pythonStringLiteral`, `HTTP_METHOD_NAMES`, decorator helpers |
| Java | `util/java.ts` | annotation walkers, `javaStringLiteral`, `@RequestMapping` shape helpers |
| Go | `util/go.ts` | `findInstancesFromFactory`, `findRouteCalls`, `GO_HTTP_METHODS_UPPER`/`_PASCAL`, `goStringLiteral` |
| Ruby | `util/ruby.ts` | DSL block walkers, `rubyStringLiteral` |
| PHP | `util/php.ts` | `phpStringLiteral`, attribute walkers, `PHP_HTTP_METHODS` |

Common rules everywhere:
- `lineOf(node)` → 1-based line number (matches how Postgres stores it)
- `classifyFromAuth(auth)` → `auth ? 'AUTH_INTERNAL' : 'PUBLIC_UNAUTH'`
- Each `detectAuthMechanism()` returns a mechanism string if any known auth middleware package is imported, else `null`. Keeps classification consistent across languages.

If you find yourself writing the same AST walk twice, promote it to the util module rather than copy-pasting across detectors.

---

## Authentication classification (route-level, evidence-based)

Classification flows into EPD scoring:
- `PUBLIC_UNAUTH` (entry-weight 1.0) — an HTTP route with no auth evidence (the default)
- `AUTH_INTERNAL` (entry-weight 0.5) — a route with positive route-level auth evidence
- `OFFLINE_WORKER` (entry-weight 0.2) — a signed/verified machine endpoint or a background job / cron
- `UNKNOWN` (entry-weight 1.0) — no signal; the safe worst-case default

Classification is **route-level and evidence-based** — the old file-level import
sniff (`classifyFromAuth(detectAuthMechanism(file.imports))`, which flipped every
route in a file to AUTH_INTERNAL on a single auth import) is **retired**. Each
route is classified from its own evidence via `classifyRoute(evidence)` in
`util/auth-evidence.ts`. The `authMechanism` field is kept only as a DAST/UI
hint; it no longer decides the class.

**Gathering evidence.** Reduce a route's middleware / guards / decorators to
tokens and hand them to `classifyRoute`:
- `authTokens` — identifiers matched against the shared auth-name patterns
  (`authenticate`, `requireAuth`, `*AuthGuard`, `login_required`, …); subject to
  the optional-veto tokens (`optional`, `anonymous`, `guest`) so
  `passport.authenticate('anonymous')` / `jwt_required(optional=True)` are NOT
  evidence.
- `vettedAuthTokens` — for exact-semantics families (Java/PHP/C# annotations:
  `@Secured`, `[Authorize]`, `#[IsGranted]`, non-public `@PreAuthorize` SpEL);
  bypass name matching, still subject to overrides/belt/conditional.
- `publicOverrides` — explicit-public markers (`@PermitAll`, `[AllowAnonymous]`,
  `permitAll()`, `AllowAny`, `skip_before_action`, `->withoutMiddleware('auth')`).
  These always win.
- `internalTokens` — machine/verifier evidence (`*.verify`, `constructEvent`,
  `internal|signature|hmac|webhook.?verif|qstash|svix` middleware) → OFFLINE_WORKER.
- `centralizedOnly` — set true when the ONLY auth evidence is a centralized idiom
  (app-level `app.use(auth)`, a Spring `SecurityFilterChain`, a Laravel/Slim
  group). The **public-route-name belt** then blocks the demotion on
  `login|logout|signup|password|health|webhook|…`-segment routes (a route-local
  guard still demotes them).
- `conditional` — set true for carve-out coverage (Rails `before_action` with any
  non-`only:` kwarg, DRF `IsAuthenticatedOrReadOnly`, `.unless(`) → does NOT cover.

**Handler spans (`handlerSpan` + `demotionEligible`, Sem 6).** Capture the span
of the terminal handler so a taint flow demotes only when its source line falls
inside an authed handler. Inline handlers span themselves and are always
eligible. A named handler resolves to its single same-file declaration; it is
**ineligible** (classifies but never demotes) when it is exported or referenced
elsewhere in the file (JS/TS), is a capitalized/exported symbol (Go/Rust), or is
wrapped / a member expression / cross-file (→ null span). Declaration-bound
families (annotations, decorators, Rails/Django actions) are always eligible —
the evidence travels with the declaration.

**Cross-file (Rails/Django).** The auth evidence lives in the controller/view
file, next to the taint sources, so those detectors bank per-action facts on
`ExtractedFile.authFacts` during `detect` and re-home them via `postProcess`
into ctx-only records keyed on that file (never persisted). See
`analyzeRailsController` / `analyzeDjangoViews`.

Do NOT heuristically classify as `AUTH_INTERNAL` because a path contains
`/admin/`. Trust the evidence, not the path string. When in doubt, leave it
PUBLIC — a wrongful demote under-scores real public attack surface, the one
thing this system must never do.

---

## Adding a detector — step by step

1. **Scaffold the file.** Copy the closest existing detector for your language and rename.

2. **Set `triggerImports` correctly.** Exact package-source string as it appears in imports:
   - JS: `'express'`, `'@koa/router'`, `'@nestjs/common'`
   - Python: `'flask'`, `'fastapi'` (matches module source after `from X import Y` is normalized)
   - Java: fully-qualified package prefix — e.g. `'org.springframework.web.bind.annotation'`
   - Go: full import path — `'github.com/gin-gonic/gin'`

   The trigger is a prefix match (`imp.source === t || imp.source.startsWith(t + '/')`), so `@nestjs/common` triggers on both `@nestjs/common` and `@nestjs/common/websockets`.

3. **Walk the AST.** Use `walkTree` from the util module — do not roll your own recursion unless you need early-exit.

4. **Emit entry points.** Every field on `EntryPoint` is required (some may be `null`). Don't invent custom fields; use `metadata: Record<string, unknown>` for extras.

5. **Register it.** Add to the `ALL_DETECTORS` array in `src/framework-rules/registry.ts`.

6. **Write a detector test.** See next section.

---

## Testing a detector

There are **no direct unit tests for the detectors yet** — the
`src/framework-rules/__tests__/<language>.test.ts` path referenced by earlier
drafts of this guide was never created. Today the detectors are covered
**end-to-end**:

- **Snapshot fixture suite** — `npm run test:fixtures` runs the full pipeline,
  including the `usage-extraction` step that invokes each language module's
  framework detectors, over `fixtures/test-*`. A detector regression shifts the
  emitted JSON and fails the snapshot diff (the `depscanner-fixtures` CI job).
- **Per-language taint suites** — `npm run test:taint-engine-<lang>` (run by
  `npm run test:taint-engine-all`) exercise the real language extractor +
  framework entry-point detection over the taint fixtures.

To add a **direct** detector test, the `extractInline` helper in
`src/framework-rules/test-helpers.ts` runs the real language module + detector
over inline source without staging a workspace:

```ts
import { javascriptModule } from '../src/tree-sitter-extractor/languages/javascript';
import { dep, entryPointsFor, extractInline } from '../src/framework-rules/test-helpers';

const file = await extractInline(
  javascriptModule,
  `const mf = require('my-framework');
   const app = mf();
   app.get('/hello', handler);`,
  '/tmp/app.js',
  [dep('my-framework')],
);
const eps = entryPointsFor(file, 'myframework');
// assert: eps.length === 1, eps[0].httpMethod === 'GET', eps[0].routePattern === '/hello'
```

Write such suites as **standalone tsx** scripts under `test/` — the pattern the
existing `test/taint-engine-*.test.ts` suites use — and run them with
`npx tsx test/<your-suite>.test.ts`. Do **not** use jest: the extractor
dynamically imports `web-tree-sitter` WASM grammars, which don't survive jest's
vm-isolate sandbox without `--experimental-vm-modules` (this is why the whole
taint-engine regression matrix is tsx-driven, not jest — see the preflight job
in `.github/workflows/test.yml`).

One test per framework is the baseline. Add a second test when you've handled a non-obvious shape (decorator nesting, CJS IIFE, macro form) — that's where regressions sneak in.

---

## End-to-end fixture validation

Detector unit tests prove the AST pattern works. Fixture snapshots (`fixtures/test-*/`) prove the full pipeline wires correctly — SBOM → extractor → storage → CLI output.

The only fixture that currently exercises framework detection end-to-end is `test-go` (2 Gin entry points). If you add a detector for an ecosystem that isn't yet represented in the fixtures and you change pipeline glue code, add a small fixture so the snapshot catches regressions. For pure detector additions, the unit tests are enough.

Regenerate snapshots after any detector-affecting change:

```bash
cd depscanner
npm run test:fixtures -- --include-slow --update    # regenerate
npm run test:fixtures -- --include-slow             # verify idempotent
```

---

## Common pitfalls

- **Node wrapper identity.** web-tree-sitter returns a fresh Node wrapper object on each lookup, so `node1 === node2` is not reliable even for the same underlying AST node. Compare `startIndex`/`endIndex` instead.
- **Grammar drift.** Grammars change shapes across versions — the PHP grammar started emitting `named_argument` wrappers in older versions and shifted to `argument > name + value` pairs for PHP 8 attributes. When writing a detector, handle both old and new shapes defensively (see `detectors/symfony.ts`).
- **Ecosystem names are canonical.** `SupportedEcosystem` values (`golang`, `gem`, `pypi`, ...) match what the pipeline passes down from cdxgen/SBOM, not tree-sitter's internal language IDs (`go`, `ruby`, `python`, ...). If your detector works in a unit test but doesn't fire in production, check the pipeline's `supportedEcosystems.includes(ecosystem)` gate first.
- **Triggers must match exactly.** For Java, the trigger must be a package prefix you'll see in `ImportBinding.source` — usually the fully-qualified class path minus the class name. Check the extractor's output in a unit test before assuming a trigger is correct.
- **Don't mutate shared state in `detect`.** Detectors must be pure-over-`ctx`. Module-level state won't survive the Fly.io worker's stateless mode.

---

## Where entry points go downstream

1. `storeEntryPoints()` upserts rows into `project_entry_points` keyed by `(project_id, extraction_run_id, file_path, line_number, framework, handler_name)`.
2. EPD scoring reads `classification` + per-vuln reachability to compute `epd_factor`.
3. Final `contextual_depscore = base_depscore * reachability_weight * epd_factor * tier_multiplier`.
4. Frontend surfaces them on the project overview + vuln detail sidebar.

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

## Authentication classification

Classification flows into EPD scoring:
- `PUBLIC_UNAUTH` (epd_factor 1.0) — default for an unauthenticated HTTP route
- `AUTH_INTERNAL` (epd_factor 0.5) — flipped when an auth middleware is imported in the same file
- `OFFLINE_WORKER` (epd_factor 0.2) — background jobs, message consumers, cron
- `UNKNOWN` (epd_factor 1.0) — no signal; safe default is worst-case

File-level auth detection (import-based) is deliberately coarse. It's a starting point; route-level classification via AST middleware chain inspection is possible but not wired for every framework yet. Rust/C# detectors currently default to `PUBLIC_UNAUTH` unconditionally — pattern matching their middleware chains is TODO.

Do NOT heuristically classify as `AUTH_INTERNAL` just because a route has `/admin/` in the path. Trust the middleware chain, not the path string.

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

Tests live in `src/framework-rules/__tests__/<language>.test.ts`. They use the `extractInline` helper to run the real language module + detector over inline source, without staging a workspace.

```ts
// src/framework-rules/__tests__/javascript.test.ts
import { javascriptModule } from '../../tree-sitter-extractor/languages/javascript';
import { dep, entryPointsFor, extractInline } from '../test-helpers';

describe('myframework', () => {
  it('detects a basic route', async () => {
    const file = await extractInline(
      javascriptModule,
      `
        const mf = require('my-framework');
        const app = mf();
        app.get('/hello', handler);
      `,
      '/tmp/app.js',
      [dep('my-framework')],
    );
    const eps = entryPointsFor(file, 'myframework');
    expect(eps).toHaveLength(1);
    expect(eps[0].httpMethod).toBe('GET');
    expect(eps[0].routePattern).toBe('/hello');
  });
});
```

Run them:

```bash
cd depscanner
NODE_OPTIONS=--experimental-vm-modules npx jest src/framework-rules/__tests__/javascript.test.ts
```

The `NODE_OPTIONS=--experimental-vm-modules` flag is required — the extractor dynamically imports `web-tree-sitter` WASM grammars.

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

See `.cursor/plans/reachability_phase2_tree_sitter.plan.md` and the overall strategy in `.cursor/plans/reachability-analysis.plan.md` for the full pipeline context.

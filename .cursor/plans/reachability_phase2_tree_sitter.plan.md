# Reachability Phase 2 — Tree-Sitter Universal Usage Extractor + Framework Rule-Pack

**Status:** planning complete, ready to implement
**Worktree:** `worktree-reachability-phase2` (branched off `worktree-reachability-phase1` HEAD `05147fe`)
**Created:** 2026-04-20
**Parent plan:** `.cursor/plans/reachability-analysis.plan.md` (overall reachability strategy)
**Timeline estimate:** 4–6 weeks (one milestone ≈ one week)

---

## Overview

Build a universal, deterministic call-site extractor on top of tree-sitter that gives every supported language function-level reachability (Level 3 in the maturity ladder) in a single TypeScript program, plus a framework-aware rule-pack layer that tags HTTP/worker/event/CLI entry points so Phase 4 EPD can correctly classify exposure.

Today the extraction pipeline has three overlapping extractors:
- **parser-worker (`oxc-parser`)** — npm-only, import names only, populates `project_dependency_functions` + `files_importing_count`
- **atom (`atom usages` + `atom reachables`)** — populates `project_usage_slices` and `project_reachable_flows`. Works well for Java CPG flows, weak/empty for JS/TS/Go/Rust/C#
- **reachability.ts `updateReachabilityLevels()`** — fuses signals into `data_flow | function | module`

This plan replaces parser-worker's role entirely, reduces atom to a Java-only bonus signal, and fills in call-site data for Python / Go / Ruby / PHP / Rust / C# which currently have nothing. It adds a new `project_entry_points` table populated by a rule-pack layer that reads extractor output and tags entry points per framework.

After Phase 2 lands, Phase 3 (Semgrep rules) can scope per-file rule loading by imported package, Phase 4 (EPD) has real entry-point classifications to score against, and Phase 7 (AI cross-file stitching) has a resolved call graph to stitch across.

---

## Competitive Research & Design Rationale

Research summary (full sources in conversation history, dated 2026-04-20):

| Product | Approach | Scope | Public |
|---|---|---|---|
| **Endor Labs** | Deterministic static call graphs + curated function→CVE DB + LLM for explain/remediate only | Java, Python, Rust, JS, Go, .NET/C#, Kotlin, Scala | Partial (docs) |
| **Coana / Socket** (acq. Apr 2025) | Static control-flow / call-graph, **not LLM**. Over-approximating (conservative) | JS, Python, C#, Go, Java, Kotlin, Scala | Paper-backed (Aarhus Univ) |
| **Semgrep Supply Chain** | Semgrep rules, **direct-deps only**, no transitive function-level | 12 langs | Partially open (OSS engine is single-file) |
| **Snyk DeepCode AI** | Symbolic + generative hybrid, proprietary | 19 langs | Closed |
| **Mend** | Per-library dot-file graphs | Java-only reachability | Docs |
| **OWASP dep-scan + atom** (what we use today) | AppThreat CPG → slices | Java/JS/TS/Python strong, others weak | MIT |

**Pattern we're adopting (industry consensus):** Build a deterministic static extractor. Every credible competitor uses static analysis as the primary reachability signal. LLMs are used for explanation, cross-file stitching, and spec inference — not as the primary extractor.

**Where we differentiate:**
1. **Open-source.** Every comparable product above except dep-scan is closed or partially closed.
2. **Transitive function-level reachability.** Semgrep SC is direct-only; Mend is Java-only. Our tree-sitter passes run over every source file, irrespective of whether it imports a direct or transitive dep.
3. **Explicit `unreachable` classification.** Most tools silently omit unreachable deps; we want to show users "0 code paths touch this dep" as a first-class outcome.
4. **Contributor-extensible framework rule-packs.** A user can add "my company's in-house RPC framework" as a YAML file and get EPD classification for it. No competitor exposes this.

**Design rationale for tree-sitter over alternatives:**

| Alternative | Why rejected |
|---|---|
| Raw oxc-parser for JS/TS + tree-sitter for others (my original pick) | User correctly pushed back — hybrid adds cognitive load. Pure tree-sitter is one system. Perf delta is noise vs. dep-scan/Semgrep/atom runtime. |
| `ast-grep` CLI | Great for pattern rules, but we need programmatic control to resolve aliases across calls (`import _ from 'lodash'; _.template(x)`). ast-grep is pattern-match-only. |
| SCIP indexers (`scip-typescript`, `scip-python`, `scip-java`) | Requires buildable project (`tsc`, `mvn compile`). Breaks our "scan any clone, no install" contract. |
| `tree-sitter-stack-graphs` | Archived by GitHub Sept 2025; only JS/TS/Python/Java shipped. |
| CodeQL | License forbids redistribution for scanning private customer code in a commercial product. Dead-end for open-core. |
| Joern (full CPG) | Apache-2.0 but Scala/JVM, 16-64GB memory. Deferred to Phase 8 for Go/Kotlin/Swift. |

**Tree-sitter binding choice:** `web-tree-sitter` (WASM) over native `tree-sitter` node bindings. Reasons:
- Zero-compile distribution (no `node-gyp`, no per-platform rebuilds)
- Ships the same `.wasm` files that tree-sitter publishes upstream — always up-to-date
- Perf delta (~2-3x slower than native) is irrelevant next to dep-scan/Semgrep runtime
- Our Docker-only CLI already runs in a controlled Node environment, but WASM is still simpler operationally

---

## Codebase Analysis

### Files we'll modify

| File | Lines | Current behavior | Phase 2 change |
|---|---|---|---|
| `backend/extraction-worker/src/pipeline.ts` | ~2100 | Calls parser-worker oxc at L765-796, atom at L1215-1268 | Replace parser-worker call with new extractor for all MVP 8 langs; restrict atom to Java; rename step `ast_parsing` → `usage_extraction`; add new `framework_detection` sub-step after |
| `backend/extraction-worker/src/reachability.ts` | ~700 | `parseReachableFlows()`, `parseUsageSlices()`, `parseLlmPrompts()`, `updateReachabilityLevels()`, `computeImportCountsFromUsageSlices()` | Add `function` priority path that reads from new extractor output when atom is absent; keep atom path for Java |
| `backend/extraction-worker/src/logger.ts` | L36 | Step enum | Add `usage_extraction`, `framework_detection` |
| `backend/extraction-worker/src/cli/format.ts` | L63 | Step label map | Add labels for new steps |
| `backend/extraction-worker/Dockerfile` | | Installs atom, dep-scan, semgrep, trufflehog | Add `web-tree-sitter` + grammar `.wasm` files via `npm install` (no new system deps) |
| `backend/extraction-worker/package.json` | | | Add `web-tree-sitter`, `js-yaml`, `zod` |
| `backend/extraction-worker/src/storage.ts` (Storage interface) | | Defines `from(table).upsert(...)` surface used by pipeline | Add extractor-output write helpers if useful (or reuse existing `upsert`) |
| `backend/extraction-worker/__tests__/snapshot-fixtures.test.ts` | | Phase 1 snapshot pattern | Extend with new extractor output per-fixture |
| `backend/parser-worker/*` | All | Standalone worker, currently called inline from pipeline for npm | Retired (delete, or keep stub for back-compat if external callers exist — TBD during impl) |

### Files we'll create

| File | Purpose |
|---|---|
| `backend/extraction-worker/src/tree-sitter-extractor/index.ts` | Public entry — `extractUsage(workspaceRoot, ecosystem) → ExtractorResult` |
| `backend/extraction-worker/src/tree-sitter-extractor/parser.ts` | `web-tree-sitter` bootstrap + cached `Parser` instances per language |
| `backend/extraction-worker/src/tree-sitter-extractor/languages/javascript.ts` | JS/TS queries + alias tracker |
| `backend/extraction-worker/src/tree-sitter-extractor/languages/python.ts` | |
| `backend/extraction-worker/src/tree-sitter-extractor/languages/java.ts` | |
| `backend/extraction-worker/src/tree-sitter-extractor/languages/go.ts` | |
| `backend/extraction-worker/src/tree-sitter-extractor/languages/ruby.ts` | |
| `backend/extraction-worker/src/tree-sitter-extractor/languages/php.ts` | |
| `backend/extraction-worker/src/tree-sitter-extractor/languages/rust.ts` | |
| `backend/extraction-worker/src/tree-sitter-extractor/languages/csharp.ts` | |
| `backend/extraction-worker/src/tree-sitter-extractor/languages/types.ts` | `LanguageModule` interface + shared types |
| `backend/extraction-worker/src/tree-sitter-extractor/import-mapping/index.ts` | Public `resolveImportToDep(importName, ecosystem, deps) → depName \| null` |
| `backend/extraction-worker/src/tree-sitter-extractor/import-mapping/pypi.ts` | PyPI distribution ↔ module name table (pillow↔PIL, scikit-learn↔sklearn, PyYAML↔yaml, beautifulsoup4↔bs4, opencv-python↔cv2, msgpack-python↔msgpack, etc — curated list, contributor-extensible) |
| `backend/extraction-worker/src/tree-sitter-extractor/import-mapping/maven.ts` | Java package prefix ↔ Maven artifact lookup (from Maven Central index snapshots) |
| `backend/extraction-worker/src/tree-sitter-extractor/import-mapping/rubygems.ts` | gem name ↔ require path (rest-client↔rest_client, activesupport↔active_support, etc) |
| `backend/extraction-worker/src/tree-sitter-extractor/import-mapping/npm.ts` | Mostly 1:1 but handles scoped packages (`@types/node`) + subpath exports (`lodash/template`) |
| `backend/extraction-worker/src/tree-sitter-extractor/import-mapping/go.ts` | Go module path is the import path — 1:1 but handles stdlib exclusion |
| `backend/extraction-worker/src/tree-sitter-extractor/import-mapping/composer.ts` | PHP Packagist vendor/package namespace mapping |
| `backend/extraction-worker/src/tree-sitter-extractor/import-mapping/cargo.ts` | Rust crate name ↔ `use` path |
| `backend/extraction-worker/src/tree-sitter-extractor/import-mapping/nuget.ts` | .NET namespace ↔ NuGet package — relies on assembly metadata when available |
| `backend/extraction-worker/src/framework-rules/index.ts` | Rule-pack loader + runner |
| `backend/extraction-worker/src/framework-rules/schema.ts` | Zod schema for rule-pack YAML |
| `backend/extraction-worker/src/framework-rules/packs/javascript/express.yaml` | One YAML per framework |
| `backend/extraction-worker/src/framework-rules/packs/javascript/fastify.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/javascript/koa.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/javascript/nextjs.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/javascript/nestjs.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/javascript/aws-lambda.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/python/flask.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/python/django.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/python/fastapi.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/python/starlette.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/python/tornado.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/python/aiohttp.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/java/spring.yaml` | Spring MVC + Boot + WebFlux |
| `backend/extraction-worker/src/framework-rules/packs/java/quarkus.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/java/micronaut.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/java/jaxrs.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/go/nethttp.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/go/gin.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/go/echo.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/go/fiber.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/go/chi.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/go/gorilla-mux.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/ruby/rails.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/ruby/sinatra.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/ruby/grape.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/php/laravel.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/php/symfony.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/php/slim.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/rust/actix.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/rust/axum.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/rust/rocket.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/rust/warp.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/csharp/aspnet-core.yaml` | |
| `backend/extraction-worker/src/framework-rules/packs/csharp/minimal-apis.yaml` | |
| `backend/extraction-worker/__tests__/tree-sitter-extractor.test.ts` | Per-language extractor snapshot tests |
| `backend/extraction-worker/__tests__/framework-rules.test.ts` | Per-framework detection tests against fixture snippets |
| `backend/database/phase20_entry_points.sql` | Adds `project_entry_points` table + indexes |
| `backend/extraction-worker/fixtures/test-ruby/` | Rails-Gemfile + minimal Sinatra app for snapshot regen |
| `backend/extraction-worker/fixtures/test-php/` | Laravel composer.json + route file |
| `backend/extraction-worker/fixtures/test-rust/` | Cargo.toml + Actix handler |
| `backend/extraction-worker/fixtures/test-csharp/` | csproj + minimal ASP.NET Core controller |

### Existing schema (relevant tables)

**`project_dependencies`** (schema.sql:729-748) — has `files_importing_count` already, we'll keep writing to it.

**`project_dependency_functions`** (`add_import_analysis_to_project_dependencies.sql:9-15`) — has `project_dependency_id`, `function_name`, `extraction_run_id`. We'll write a row per (dep, function) pair from the new extractor.

**`project_usage_slices`** (`phase6b_reachability_tables.sql:32-46`) — has per-call-site columns: `file_path`, `line_number`, `containing_method`, `target_name`, `target_type`, `resolved_method`, `usage_label`, `ecosystem`. UNIQUE on `(project_id, file_path, line_number, target_name)`. We'll write a row per call site.

**`project_reachable_flows`** (`phase6b_reachability_tables.sql:5-29`) — only atom populates this today; tree-sitter doesn't produce flow chains (that's Phase 7's AI stitching job). No change.

**`project_dependency_vulnerabilities.reachability_level`** — TEXT, no CHECK constraint. Currently `data_flow | function | module`. We'll start emitting `unreachable` for transitive deps with zero imports.

### Existing pipeline ordering (pipeline.ts)

```
Step 1: deps_sync              (~L560-745)
Step 2: populate callback       (L660-670)
Step 3: ast_parsing            (L762-796, npm-only oxc-parser)   ← REPLACE
Step 4: vuln_scan (dep-scan)   (L900-1213)
Step 5: atom reachables/usages (L1215-1268)                      ← RESTRICT TO JAVA
Step 6: parseReachableFlows + parseUsageSlices (reachability.ts)
Step 7: updateReachabilityLevels (reachability.ts)
Step 8: semgrep                (later)
Step 9: trufflehog             (later)
Step 10: EPD                   (currently stubbed, pending Phase 4)
Step 11: finalize (soft-switch commit via commit_extraction RPC)
```

**Phase 2 pipeline ordering:**

```
Step 1: deps_sync
Step 2: populate callback
Step 3: usage_extraction (NEW) ← tree-sitter for MVP 8 langs
Step 4: vuln_scan (dep-scan)
Step 5: atom (JAVA ONLY)       ← restricted; runs only if jobEcosystem === 'maven'
Step 6: parseReachableFlows + parseUsageSlices (reachability.ts) ← atom output + new extractor output
Step 7: framework_detection (NEW) ← rule-pack layer over Step 3 output, writes project_entry_points
Step 8: updateReachabilityLevels
Step 9: semgrep / trufflehog / EPD / finalize  (unchanged for this phase)
```

### Existing reachability signal priority (reachability.ts:384-533)

1. `data_flow` if matching flow in `project_reachable_flows` (Java via atom)
2. `function` if dep name fuzzy-matches a `project_usage_slices` row (atom output)
3. `module` as fallback (dep imported but no usage match)

**Phase 2 priority:**

1. `data_flow` if Java flow exists (unchanged)
2. `function` if usage slice resolves to this dep (from either atom-Java OR tree-sitter)
3. `module` if any import references this dep but no call site (fallback)
4. `unreachable` if dep is transitive AND zero imports across all files (NEW)

Direct deps never downgrade below `module`.

---

## Data Model

### New table: `project_entry_points`

Populated by the framework rule-pack layer (Step 7). Consumed by Phase 4 EPD for entry-point classification; renderable in the UI for "where does the attacker get in?" visualizations.

**Migration file:** `backend/database/phase20_entry_points.sql`

```sql
-- Phase 20 — Entry-point detection from framework rule-packs.
-- Populated by tree-sitter extractor + framework rule-pack layer (Phase 2).
-- Consumed by EPD contextual scoring (Phase 4) and UI entry-point visualizations.

CREATE TABLE IF NOT EXISTS project_entry_points (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  extraction_run_id TEXT NOT NULL,
  file_path TEXT NOT NULL,
  line_number INTEGER NOT NULL,
  framework TEXT NOT NULL,
    -- 'express' | 'fastify' | 'koa' | 'nextjs' | 'nestjs' | 'aws-lambda'
    -- | 'flask' | 'django' | 'fastapi' | 'starlette' | 'tornado' | 'aiohttp'
    -- | 'spring' | 'quarkus' | 'micronaut' | 'jaxrs'
    -- | 'nethttp' | 'gin' | 'echo' | 'fiber' | 'chi' | 'gorilla-mux'
    -- | 'rails' | 'sinatra' | 'grape'
    -- | 'laravel' | 'symfony' | 'slim'
    -- | 'actix' | 'axum' | 'rocket' | 'warp'
    -- | 'aspnet-core' | 'minimal-apis'
  handler_name TEXT,
  http_method TEXT,
    -- 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS' | NULL
  route_pattern TEXT,
  entry_point_type TEXT NOT NULL,
    -- 'http_route' | 'graphql_resolver' | 'websocket' | 'message_handler'
    -- | 'cli_command' | 'cron_job' | 'background_job' | 'event_listener'
    -- | 'rpc_method' | 'serverless_handler'
  classification TEXT NOT NULL DEFAULT 'UNKNOWN',
    -- 'PUBLIC_UNAUTH' | 'AUTH_INTERNAL' | 'OFFLINE_WORKER' | 'UNKNOWN'
  authenticated BOOLEAN,
  auth_mechanism TEXT,
    -- Free-form signal from rule: 'bearer_jwt' | 'session_cookie' | 'api_key' | 'mtls' | NULL
  middleware_chain TEXT[],
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (project_id, extraction_run_id, file_path, line_number, framework, handler_name)
);

CREATE INDEX IF NOT EXISTS idx_pep_project ON project_entry_points(project_id);
CREATE INDEX IF NOT EXISTS idx_pep_run ON project_entry_points(extraction_run_id);
CREATE INDEX IF NOT EXISTS idx_pep_framework ON project_entry_points(framework);
CREATE INDEX IF NOT EXISTS idx_pep_classification ON project_entry_points(classification);
CREATE INDEX IF NOT EXISTS idx_pep_project_run ON project_entry_points(project_id, extraction_run_id);

-- RLS: users can view entry points for projects they have access to.
ALTER TABLE project_entry_points ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view entry points for accessible projects"
  ON project_entry_points FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM projects p
      WHERE p.id = project_entry_points.project_id
        AND (
          p.organization_id IN (SELECT om.organization_id FROM organization_members om WHERE om.user_id = auth.uid())
          OR p.team_id IN (SELECT tm.team_id FROM team_members tm WHERE tm.user_id = auth.uid())
        )
    )
  );

-- Service role full access (workers).
CREATE POLICY "Service role has full access to entry points"
  ON project_entry_points FOR ALL
  USING (auth.role() = 'service_role')
  WITH CHECK (auth.role() = 'service_role');
```

### Schema.sql refresh

After the migration lands, run `cd backend/extraction-worker && npm run schema:dump` to refresh `backend/database/schema.sql` (PGLite source-of-truth). The CI `schema-check.yml` workflow will reject the PR otherwise.

### commit_extraction RPC

Existing RPC (Phase 19) already writes to `project_usage_slices`, `project_reachable_flows`, `project_dependency_functions`. Need to add `project_entry_points` to its atomic commit set. Modify the RPC to insert into the new table under the same `extraction_run_id` and flip it atomically on `commit_extraction`. See `backend/database/commit_extraction_rpc.sql` (or wherever the RPC lives — confirm exact file during M1).

---

## Implementation Tasks

Ordered milestones. Each milestone = 1–2 commits, tests pass, pipeline still green on `fixtures/test-npm`.

### Phase 2a — Core extractor

#### **M1: Scaffold + schema + import-mapping skeleton** (S–M, ~3 days)

**Files created:**
- `backend/database/phase20_entry_points.sql` — migration
- `backend/extraction-worker/src/tree-sitter-extractor/index.ts` — public entry with stub that returns empty
- `backend/extraction-worker/src/tree-sitter-extractor/parser.ts` — `web-tree-sitter` init + language WASM loader
- `backend/extraction-worker/src/tree-sitter-extractor/languages/types.ts` — `LanguageModule` interface
- `backend/extraction-worker/src/tree-sitter-extractor/import-mapping/index.ts` — public `resolveImportToDep()` dispatching per ecosystem
- `backend/extraction-worker/src/tree-sitter-extractor/import-mapping/{npm,pypi,maven,go,rubygems,composer,cargo,nuget}.ts` — stub files with TODOs, npm + go actually implemented (trivial)

**Files modified:**
- `backend/extraction-worker/package.json` — add `web-tree-sitter`, `js-yaml`, `zod`
- `backend/extraction-worker/Dockerfile` — grammar `.wasm` files come via `npm install`, no new system deps

**Acceptance:**
- Migration applies cleanly in Supabase + PGLite
- `schema:dump` regenerates `schema.sql` with new table
- `import { extractUsage } from './tree-sitter-extractor'` works in TS build
- Snapshot tests still pass

#### **M2: JS/TS + Python queries + pipeline wire-in** (M–L, ~1 week)

**Files created:**
- `backend/extraction-worker/src/tree-sitter-extractor/languages/javascript.ts` — handles JS, TS, JSX, TSX
  - Queries: ES6 `import`, default import, namespace import, named import with alias, dynamic `import()`, CJS `require()`, `require()` destructure
  - Call-site extraction: member call `obj.method(...)`, call on imported identifier, method chains, tagged template
  - Alias tracker: `import _ from 'lodash'` → `_` binds to `lodash`
- `backend/extraction-worker/src/tree-sitter-extractor/languages/python.ts`
  - Queries: `import X`, `import X as Y`, `from X import Y`, `from X import Y as Z`, `from X import *`, `__import__`, `importlib.import_module`
  - Call-site extraction: `X.fn(...)`, `Y.method(...)` where Y is aliased
  - Handles Python's weird module/distribution name split via `import-mapping/pypi.ts`
- `backend/extraction-worker/src/tree-sitter-extractor/import-mapping/pypi.ts` — curated table (~200 entries, covers all stdlib + top-500 PyPI)

**Files modified:**
- `backend/extraction-worker/src/pipeline.ts`
  - Rename step `ast_parsing` → `usage_extraction`
  - Replace npm-only `analyzeRepository(workspaceRoot)` call with `extractUsage(workspaceRoot, jobEcosystem)` for all ecosystems in MVP 8
  - Keep fallback for unsupported ecosystems (warn, skip)
  - Write extractor output via `Storage.upsert` to `project_usage_slices`, `project_dependency_functions`, and update `project_dependencies.files_importing_count`
- `backend/extraction-worker/src/logger.ts` — add `usage_extraction`, `framework_detection` step enum members
- `backend/extraction-worker/src/cli/format.ts` — add CLI labels
- `backend/extraction-worker/src/reachability.ts`
  - Update `updateReachabilityLevels()` to read usage slices regardless of source (atom or tree-sitter)
  - Add `unreachable` classification for transitive deps with zero imports
- `backend/extraction-worker/__tests__/snapshot-fixtures.test.ts` — regen snapshots for test-npm + test-python

**Acceptance:**
- `./bin/deptex-scan run fixtures/test-npm` produces non-empty `project_usage_slices` + `project_dependency_functions` entries for lodash.template, minimist, jwt.sign/verify, axios.get, readline-sync.question
- `./bin/deptex-scan run fixtures/test-python` produces entries for yaml.load, Template.render, requests.get, Image.open
- `project_dependencies.files_importing_count > 0` for every directly-imported dep
- Snapshot tests pass
- Pipeline still green end-to-end for both fixtures

#### **M3: Java + Go queries** (M, ~1 week)

**Files created:**
- `backend/extraction-worker/src/tree-sitter-extractor/languages/java.ts`
  - Queries: `import a.b.C`, `import static a.b.C.m`, wildcards `import a.b.*`
  - Call sites: `obj.method(...)`, static `Cls.method(...)`, method references `Cls::method`
  - Handles the big open problem: `org.apache.logging.log4j.Logger` → Maven artifact `log4j-core`
- `backend/extraction-worker/src/tree-sitter-extractor/languages/go.ts`
  - Queries: `import "path"`, `import alias "path"`, grouped imports
  - Call sites: `pkg.Fn(...)`, method calls on typed receivers
  - Go imports are module paths; use `go.mod` resolution for main module identity
- `backend/extraction-worker/src/tree-sitter-extractor/import-mapping/maven.ts`
  - Uses a bundled snapshot of Maven Central package→artifact index (~5-10 MB gzip)
  - Fallback: if package unresolved, match longest-common-prefix against known deps list
- `backend/extraction-worker/src/tree-sitter-extractor/import-mapping/go.ts`
  - 1:1 module path ↔ dep name. Stdlib exclusion list.

**Files modified:**
- Snapshot tests for test-java + test-go

**Acceptance:**
- `fixtures/test-java` produces call sites for `Logger.info`, `ObjectMapper.readValue`, `StringSubstitutor.replace`
- `fixtures/test-go` produces call sites for `language.Parse`, `html.Parse`, `ssh.InsecureIgnoreHostKey`
- Maven prefix resolver correctly maps `org.apache.logging.log4j.*` → `log4j-core`

#### **M4: Ruby, PHP, Rust, C# queries + retire parser-worker + atom-Java-only** (M–L, ~1 week)

**Files created:**
- `backend/extraction-worker/src/tree-sitter-extractor/languages/{ruby,php,rust,csharp}.ts`
- `backend/extraction-worker/src/tree-sitter-extractor/import-mapping/{rubygems,composer,cargo,nuget}.ts`
- `backend/extraction-worker/fixtures/test-{ruby,php,rust,csharp}/` — minimal fixtures

**Files modified:**
- `backend/extraction-worker/src/pipeline.ts`
  - Atom invocation (L1215-1268) gated on `jobEcosystem === 'maven'`
  - Delete the npm-only oxc-parser inline call (already replaced in M2)
- `backend/parser-worker/*` — delete directory (confirm no external callers first)

**Acceptance:**
- All 8 languages produce usage slices against their respective fixtures
- Atom no longer runs for JS/TS/Py/Go/Ruby/PHP/Rust/C# (confirm via logs)
- Java extraction still produces both tree-sitter call sites AND atom reachable flows
- `parser-worker` directory gone, no build errors
- Docker image size does not increase materially (WASM grammars are small)
- Full snapshot regen, snapshot tests pass

### Phase 2b — Framework rule-pack system

#### **M5: Rule-pack loader + schema + first framework** (M, ~1 week)

**Files created:**
- `backend/extraction-worker/src/framework-rules/schema.ts` — zod schema for rule-pack YAML
- `backend/extraction-worker/src/framework-rules/index.ts` — loader + runner
  - `loadRulePacks(langs: string[]) → RulePack[]`
  - `detectEntryPoints(usageSlices, astByFile, rulePacks) → EntryPoint[]`
- `backend/extraction-worker/src/framework-rules/packs/javascript/express.yaml` — first framework as reference implementation

**YAML shape (draft):**

```yaml
name: express
language: javascript
display_name: "Express.js"

# Imports that signal this framework is in use (any match = pack activates).
trigger_imports:
  - express
  - express-rate-limit  # optional supporting libs
  - "@types/express"

# Patterns that identify route handlers and classify them.
entry_points:
  - type: http_route
    pattern:
      # tree-sitter-expressible query pattern
      call:
        object: { binding: express_instance }
        method: { in: [get, post, put, patch, delete, head, options, all, use] }
      arguments:
        - kind: string_literal
          capture: route_pattern
        - kind: [function, arrow_function, identifier]
          capture: handler
    http_method_from_method: true
    classification_rules:
      - if:
          middleware_imported_any: [passport, express-jwt, express-session, jsonwebtoken]
          middleware_in_chain: true
        then:
          classification: AUTH_INTERNAL
          auth_mechanism: bearer_jwt
      - default:
          classification: PUBLIC_UNAUTH

# Per-framework metadata the rule can stash in metadata JSONB.
metadata_extractors:
  middleware_chain:
    from: argument_list_before_handler
    as: array_of_identifiers
```

Schema validation via zod. Unknown fields rejected. Contributor docs: "Add a YAML file under `framework-rules/packs/<lang>/<name>.yaml` and it's picked up automatically."

**Files modified:**
- `backend/extraction-worker/src/pipeline.ts` — add `framework_detection` substep after `parseUsageSlices()` but before `updateReachabilityLevels()`; call `detectEntryPoints()` and write to `project_entry_points`
- `commit_extraction` RPC — include `project_entry_points` in the atomic commit set

**Acceptance:**
- Loader rejects malformed YAML with clear error
- `fixtures/test-npm` detects any Express route (add a minimal Express route to the fixture if not already present)
- `project_entry_points` table populated correctly with `framework='express'`, `http_method='GET'`, etc.
- `commit_extraction` RPC correctly flips the pointer with entry-point data included

#### **M6: JS/TS + Python framework packs** (M, ~1 week)

**Files created:**
- `backend/extraction-worker/src/framework-rules/packs/javascript/{fastify,koa,nextjs,nestjs,aws-lambda}.yaml`
- `backend/extraction-worker/src/framework-rules/packs/python/{flask,django,fastapi,starlette,tornado,aiohttp}.yaml`

**Acceptance:**
- Each framework pack detects its canonical entry-point pattern against a hand-rolled test snippet
- Framework packs coexist (express + fastify in same project both detected)
- `__tests__/framework-rules.test.ts` has one snippet + expected `project_entry_points` row per framework

#### **M7: Java + Go framework packs** (M, ~1 week)

**Files created:**
- `backend/extraction-worker/src/framework-rules/packs/java/{spring,quarkus,micronaut,jaxrs}.yaml`
  - Spring: `@RestController`, `@Controller`, `@GetMapping`, `@PostMapping`, `@RequestMapping`
  - JAX-RS: `@Path`, `@GET`, `@POST`
  - Quarkus/Micronaut: similar annotation-driven
- `backend/extraction-worker/src/framework-rules/packs/go/{nethttp,gin,echo,fiber,chi,gorilla-mux}.yaml`
  - net/http: `http.HandleFunc`, `mux.Handle`
  - Gin: `r.GET/POST/etc`
  - Echo: `e.GET(...)`
  - Fiber: `app.Get(...)`
  - Chi / Gorilla Mux: route register patterns

**Acceptance:**
- Each framework pack detects entry points in its snippet
- Annotation-driven detection (Java) correctly extracts route pattern from annotation arg
- `fixtures/test-java` detects Log4j CVE entry-point context (Spring `@RestController` → log4j call → flagged as `PUBLIC_UNAUTH`)

#### **M8: Ruby, PHP, Rust, C# framework packs** (M, ~1 week)

**Files created:**
- `backend/extraction-worker/src/framework-rules/packs/ruby/{rails,sinatra,grape}.yaml`
  - Rails: `routes.rb` `get/post/resources`, controller `def action`
  - Sinatra: `get '/path' do ... end`
- `backend/extraction-worker/src/framework-rules/packs/php/{laravel,symfony,slim}.yaml`
  - Laravel: `Route::get`, `Route::resource`, controller methods
  - Symfony: `#[Route]` attribute
  - Slim: `$app->get(...)`
- `backend/extraction-worker/src/framework-rules/packs/rust/{actix,axum,rocket,warp}.yaml`
  - Actix: `#[get("/path")]`, `HttpServer::new(|| App::new().service(...))`
  - Axum: `Router::new().route("/path", get(handler))`
  - Rocket: `#[get("/path")]`
- `backend/extraction-worker/src/framework-rules/packs/csharp/{aspnet-core,minimal-apis}.yaml`
  - ASP.NET Core: `[ApiController]`, `[HttpGet("path")]`, `[Route]`
  - Minimal APIs: `app.MapGet("/path", handler)`

**Acceptance:**
- Every MVP 8 language has at least 2 framework packs
- Framework detection test suite covers all ~27 packs

#### **M9: Tests, docs, final validation** (S–M, ~3 days)

**Files created:**
- `backend/extraction-worker/docs/framework-rule-pack-guide.md` — "How to add a new framework" for contributors
- `backend/extraction-worker/docs/language-query-guide.md` — "How to add a new language" (Elixir / Kotlin / Swift path for Phase 2.5)

**Files modified:**
- `backend/extraction-worker/README.md` — section on extractor + rule packs
- `backend/extraction-worker/__tests__/snapshot-fixtures.test.ts` — all 8 fixtures regenerated with extractor + entry-point output

**Acceptance:**
- Full Phase 2 snapshot regen on all 8 fixtures, tests green
- End-to-end run of `./bin/deptex-scan run fixtures/test-npm --verbose` produces:
  - usage slices: >50 entries across direct + transitive
  - entry points: ≥1 per Express/Fastify/whatever is in fixture
  - reachability levels: `function` for direct deps with usage, `module` for imported-but-not-called, `unreachable` for transitive with zero imports
- Documentation readable enough that an outside contributor could add a new framework pack without asking
- PR ready to merge (pending phase1 merge first per dependency ordering)

---

## Testing & Validation Strategy

### Per-milestone tests

- **Unit:** each `languages/<lang>.ts` has a test that feeds in a known snippet and asserts the emitted usage slices exactly match a snapshot
- **Integration:** pipeline tests run the full extractor + reachability pass on each fixture; diff against committed snapshots
- **Framework packs:** each pack has ≥1 positive test snippet (detects correctly) and ≥1 negative (does NOT match on unrelated code)

### Per-phase end-to-end

After M4 (core extractor done):
```
for F in test-npm test-python test-java test-go test-ruby test-php test-rust test-csharp; do
  ./bin/deptex-scan run fixtures/$F --verbose
  # Assert: exit 0, non-empty project_usage_slices count matching fixture's expected imports
done
```

After M8 (framework packs done):
```
# Same loop, plus: assert project_entry_points has expected framework rows
```

### Performance targets

| Stage | Target | How measured |
|---|---|---|
| Tree-sitter parse, medium repo (~5k files) | < 15s | Time `extractUsage()` end-to-end |
| Framework detection over full extractor output | < 3s | Time `detectEntryPoints()` |
| Total pipeline time overhead from Phase 2 | < 30s | Compare total pipeline time pre/post on test-npm |

### Regression checks

- Existing atom-Java data flows still populate `project_reachable_flows` with the same row count after Phase 2
- `project_dependencies.files_importing_count` matches or exceeds pre-Phase-2 values for every npm fixture (we shouldn't regress the oxc-parser coverage)
- Reachability-level distribution on test-npm approximates pre-Phase-2 results +/- (new `unreachable` classifications for transitive deps that were `module` before)

---

## Risks & Open Questions

### Technical risks

1. **`web-tree-sitter` + WASM grammar size in Docker image.** Each grammar `.wasm` is ~1–5 MB. For 8 languages + potential future additions, that's 20–50 MB. Acceptable but should be measured. **Mitigation:** lazy-load grammars (only load the ecosystem's grammar for a given extraction).

2. **Maven package → artifact resolution.** `org.apache.logging.log4j.*` maps to `log4j-core`, but `org.apache.commons.lang3.*` maps to `commons-lang3`. Bundling a full Maven Central index is ~100 MB. **Mitigation:** ship a curated subset (top-10k artifacts by download count from the Maven Central dataset), plus a runtime fallback that queries a local snapshot when available.

3. **Python distribution name ↔ module name.** No authoritative static mapping exists. **Mitigation:** curate ~200 entries covering stdlib + top PyPI + all our fixture deps; document extension path.

4. **Tree-sitter grammar correctness edge cases.** TypeScript decorators, JSX, Svelte single-file components — grammars may drop on edge syntax. **Mitigation:** graceful per-file failure (log `warn`, skip file, pipeline continues), same as atom's failure mode today.

5. **Framework rule-pack YAML expressiveness.** Some frameworks have conditional routing (`if ENV['FOO']; get '/x'; end`). **Mitigation:** ship simple pattern-match semantics in M5; add capability expansion (dynamic pattern-match, `pattern-not`) in follow-up if needed. Don't over-engineer the DSL upfront.

6. **Contributor barrier for new frameworks.** YAML + tree-sitter query language is still intimidating. **Mitigation:** `docs/framework-rule-pack-guide.md` with copy-pasteable starter templates; 3 worked examples per language.

7. **`project_entry_points` index blowup on large repos.** A monorepo with 10k Rails controller actions could hit memory limits. **Mitigation:** batched upserts (chunk size 500), UNIQUE key prevents dupes across re-extractions.

8. **Atom still running for Java.** We're not dropping atom — it's our only data_flow signal for Java until Phase 7. Means Docker image keeps ~100 MB of Java/JRE + atom binaries. **Mitigation:** acceptable, reviewed in pre-OSS image-size pass (see `future_oss_launch_prep.md`).

### Design decisions (locked, flagging for the record)

- **Native tree-sitter node bindings vs WASM:** WASM (zero-compile, simpler). Revisit if perf is a problem.
- **YAML vs TS for rule packs:** YAML (contributor ergonomics, Semgrep-consistent).
- **Snapshot test format:** keep Phase 1's ignore-fields JSON-diff pattern.
- **commit_extraction atomicity:** new table included in the RPC's atomic set.
- **Step name:** `ast_parsing` → `usage_extraction` (more accurate label).

### Open questions (resolve during implementation)

- **Parser-worker deletion:** confirm there are no external callers (Redis queue consumers, cron jobs) before deleting the directory. Verify during M4.
- **Maven artifact index snapshot:** static JSON / SQLite / embedded Trie? Benchmark during M3.
- **Should `project_entry_points.handler_name` FK to `project_usage_slices.id`?** Makes join cheaper but couples the tables. Alternative: match by `(file_path, line_number)`. Defer to M5, decide based on query patterns.
- **Backward-compatibility for the existing `reachability_level = 'module'` rows:** when we add `'unreachable'`, do we rewrite existing rows in-place on next extraction, or leave historical rows alone? Atomic commit makes this a non-issue — every extraction writes a fresh generation.

---

## Dependencies

- **Phase 1 (atomic commit + local CLI)** — MERGED in concept; PR open awaiting Thursday 2026-04-23 demo. Phase 2 branch is built on top of Phase 1 HEAD, so if Phase 1 gets merge-conflict rework, Phase 2 absorbs it downstream.
- **atom binary** — still shipped in Dockerfile; restricted to Java only after M4.
- **dep-scan** — unchanged; still the primary vuln detector. Phase 2 runs after it so we know which deps exist.
- **Existing `Storage` interface** — extractor writes go through it; no changes to the interface.
- **`commit_extraction` RPC** — modified to include `project_entry_points` in atomic commit.
- **`backend/parser-worker/`** — retired at M4.
- **Phase 3 (Semgrep reachability rules)** — consumer of Phase 2 output. Blocked on Phase 2.
- **Phase 4 (re-enable EPD)** — consumer of `project_entry_points`. Blocked on Phase 2b.
- **Phase 7 (AI cross-file taint stitching)** — consumer of resolved call graph from Phase 2. Blocked on Phase 2a.

---

## Success Criteria

Phase 2 is done when all of the following are true:

1. **All 8 MVP languages produce usage slices end-to-end.** `./bin/deptex-scan run fixtures/test-{npm,python,java,go,ruby,php,rust,csharp}` each produce ≥10 rows in `project_usage_slices` for a non-trivial fixture.
2. **All 27+ framework rule-packs detect their canonical entry-point pattern.** Each pack has a green test.
3. **Reachability level distribution shifts as expected.** On test-npm, every direct dep is `function` or `module`; every transitive dep is `module` or `unreachable`; every `data_flow` signal still comes only from atom-Java.
4. **Atom runs only for Java.** Other ecosystems skip it (logged explicitly as "atom skipped: ecosystem=X, Java-only").
5. **parser-worker is retired.** Directory deleted (or clearly marked deprecated if external callers exist).
6. **Snapshot tests green.** All 8 fixtures have committed snapshots that match.
7. **Docker image rebuilds cleanly.** Size increase < 75 MB (grammar WASMs only).
8. **Local CLI works.** `./bin/deptex-scan run <any fixture>` exits 0 with meaningful output.
9. **Performance budgets met.** Extractor < 15s on medium repo; framework detection < 3s; total pipeline overhead < 30s.
10. **Documentation complete.** `framework-rule-pack-guide.md` + `language-query-guide.md` exist and are accurate enough that a contributor could add a new framework / language.
11. **PR ready to merge.** `git status` clean; opened against phase1 branch (or main if phase1 is merged by then); CI green; review-ready.

---

## Notes for future phases

- **Phase 2.5 (deferred language expansion):** Kotlin, Swift, Scala, Elixir, Dart — tree-sitter grammars exist but are less mature. Add when specific user demand or fixtures materialize.
- **Phase 3 (Semgrep rules):** Now scoped by imported-package set from Phase 2 — only load rules for packages we actually import.
- **Phase 4 (EPD re-enable):** Reads `project_entry_points.classification` directly; previously had to guess from filename patterns.
- **Phase 7 (AI cross-file):** Uses Phase 2's resolved call graph as the input to AI stitching — extractor provides the mechanical layer, AI stitches ambiguous multi-hop.
- **Pre-computed package cache (Phase 12):** Tree-sitter analysis of popular packages (lodash, requests, etc.) can be cached globally. Phase 2 structure supports this — extractor output is per-file and easily serializable.

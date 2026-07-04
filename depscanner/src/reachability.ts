/**
 * Phase 6B: Reachability engine -- parse atom/dep-scan deep analysis output,
 * store reachable flows & usage slices, update reachability levels on vulnerabilities.
 */

import * as fs from 'fs';
import * as path from 'path';
import { Readable } from 'stream';
import type { Storage } from './storage';
import { parsePurl, resolvePurlToDependencyId } from './purl';
import {
  type SpringFeatureSignals,
  gatherSpringFeatureSignals,
  evaluateFeaturePreconditionDemotion,
  evaluateAlwaysOnRuntimePromotion,
  evaluateFrameworkMediatedUsage,
} from './reachability-feature-preconditions';
import {
  type SymfonyFeatureSignals,
  gatherSymfonyFeatureSignals,
  evaluateSymfonyFeaturePreconditionDemotion,
  evaluateComposerDevOnlyDemotion,
  evaluateSymfonyAlwaysOnRuntimePromotion,
} from './reachability-symfony-preconditions';
import {
  type RailsFeatureSignals,
  gatherRailsFeatureSignals,
  evaluateRailsFeaturePreconditionDemotion,
  evaluateRailsDevOnlyDemotion,
  evaluateRailsAlwaysOnRuntimePromotion,
} from './reachability-rails-preconditions';
import {
  type GoImportSignals,
  gatherGoImportSignals,
  evaluateGoSubpackageDemotion,
  evaluateGoAlwaysOnRuntimePromotion,
} from './reachability-go-preconditions';
import {
  type DjangoFeatureSignals,
  gatherDjangoFeatureSignals,
  evaluateDjangoFeaturePreconditionDemotion,
  evaluateDjangoDevOnlyDemotion,
  evaluateDjangoAlwaysOnRuntimePromotion,
} from './reachability-django-preconditions';
import {
  type LaravelFeatureSignals,
  gatherLaravelFeatureSignals,
  evaluateLaravelFeaturePreconditionDemotion,
  evaluateLaravelAlwaysOnRuntimePromotion,
} from './reachability-laravel-preconditions';
import {
  type FlaskFeatureSignals,
  gatherFlaskFeatureSignals,
  evaluateFlaskFeaturePreconditionDemotion,
  evaluateFlaskDevOnlyDemotion,
  evaluateFlaskAlwaysOnRuntimePromotion,
} from './reachability-flask-preconditions';
import { unionImportedModules, type TransitiveImportIndex } from './transitive-imports';

interface LogLike {
  info(step: string, msg: string): Promise<void>;
  warn(step: string, msg: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// Streaming JSON parser for large reachables files (>50MB)
// ---------------------------------------------------------------------------

async function streamParseJsonArray(filePath: string): Promise<any[]> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const streamJson = require('stream-json');
  const streamArray = require('stream-json/streamers/StreamArray').streamArray;

  return new Promise((resolve, reject) => {
    const items: any[] = [];
    const stream = fs.createReadStream(filePath)
      .pipe(streamJson.parser())
      .pipe(streamArray());

    stream.on('data', ({ value }: { value: any }) => {
      items.push(value);
    });
    stream.on('end', () => resolve(items));
    stream.on('error', reject);
  });
}

// ---------------------------------------------------------------------------
// Parse reachable flows from *-reachables.slices.json
// ---------------------------------------------------------------------------

export async function parseReachableFlows(
  reportsDir: string,
  projectId: string,
  runId: string,
  supabase: Storage,
  logger: LogLike,
): Promise<void> {
  const reachableFiles = fs.readdirSync(reportsDir)
    .filter(f => f.endsWith('-reachables.slices.json'));

  if (reachableFiles.length === 0) {
    await logger.info('reachability', 'No reachable slices found — skipping deep reachability');
    return;
  }

  let totalFlows = 0;
  let skippedFlows = 0;
  let unmatchedPurls = 0;

  for (const rf of reachableFiles) {
    const filePath = path.join(reportsDir, rf);
    const fileSize = fs.statSync(filePath).size;

    let slices: any[];
    if (fileSize > 50 * 1024 * 1024) {
      try {
        slices = await streamParseJsonArray(filePath);
      } catch (err: any) {
        await logger.warn('reachability', `Failed to stream-parse ${rf}: ${err.message}. Skipping.`);
        continue;
      }
    } else {
      try {
        slices = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      } catch (err: any) {
        await logger.warn('reachability', `Failed to parse ${rf}: ${err.message}. Skipping.`);
        continue;
      }
    }

    if (!Array.isArray(slices)) {
      await logger.warn('reachability', `${rf} is not an array. Skipping.`);
      continue;
    }

    const batch: any[] = [];

    for (const slice of slices) {
      if (!slice.flows?.length || !slice.purls?.length) {
        skippedFlows++;
        continue;
      }
      if (slice.flows.length < 2) {
        await logger.warn('reachability', `Skipping flow with ${slice.flows.length} node(s) — need >= 2`);
        skippedFlows++;
        continue;
      }

      const firstNode = slice.flows[0];
      const lastNode = slice.flows[slice.flows.length - 1];

      for (const purl of slice.purls) {
        if (!purl || typeof purl !== 'string') continue;
        const parsed = parsePurl(purl);
        let dependencyId: string | null = null;
        if (parsed) {
          dependencyId = await resolvePurlToDependencyId(supabase, parsed);
          if (!dependencyId) {
            unmatchedPurls++;
          }
        }

        batch.push({
          project_id: projectId,
          extraction_run_id: runId,
          purl,
          dependency_id: dependencyId,
          flow_nodes: slice.flows,
          entry_point_file: firstNode.parentFileName ?? null,
          entry_point_method: firstNode.parentMethodName ?? null,
          entry_point_line: firstNode.lineNumber ?? null,
          entry_point_tag: firstNode.tags || null,
          sink_file: lastNode.parentFileName ?? null,
          sink_method: lastNode.fullName || lastNode.name || null,
          sink_line: lastNode.lineNumber ?? null,
          sink_is_external: lastNode.isExternal ?? true,
          flow_length: slice.flows.length,
          llm_prompt: null,
        });
        totalFlows++;
      }
    }

    for (let i = 0; i < batch.length; i += 100) {
      const chunk = batch.slice(i, i + 100);
      // Must match phase23.4's source-aware UNIQUE exactly. Atom rows carry
      // NULL osv_id / NULL rule_id; under NULLS NOT DISTINCT they dedup on
      // coords alone, which preserves the original atom-vs-atom semantics.
      await supabase.from('project_reachable_flows').upsert(chunk, {
        onConflict: 'project_id,extraction_run_id,purl,entry_point_file,entry_point_line,sink_method,osv_id,rule_id',
      });
    }
  }

  await logger.info('reachability', `Parsed ${totalFlows} reachable flows (${skippedFlows} skipped, ${unmatchedPurls} unmatched PURLs)`);
}

// ---------------------------------------------------------------------------
// Parse usage slices from *-usages.slices.json
// ---------------------------------------------------------------------------

export async function parseUsageSlices(
  reportsDir: string,
  projectId: string,
  runId: string,
  ecosystem: string,
  supabase: Storage,
  logger: LogLike,
): Promise<void> {
  const usageFiles = fs.readdirSync(reportsDir)
    .filter(f => f.endsWith('-usages.slices.json'));

  if (usageFiles.length === 0) {
    await logger.info('reachability', 'No usage slices found — skipping usage analysis');
    return;
  }

  let totalUsages = 0;

  for (const uf of usageFiles) {
    const filePath = path.join(reportsDir, uf);
    let content: any;
    try {
      content = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (err: any) {
      await logger.warn('reachability', `Failed to parse ${uf}: ${err.message}. Skipping.`);
      continue;
    }

    const batch: any[] = [];

    const objectSlices = content?.objectSlices;
    if (Array.isArray(objectSlices)) {
      for (const objSlice of objectSlices) {
        const fileName = objSlice.fileName ?? null;
        const containingMethod = objSlice.fullName ?? null;

        if (!Array.isArray(objSlice.usages)) continue;

        for (const usage of objSlice.usages) {
          const targetObj = usage.targetObj;
          if (!targetObj) continue;

          const targetName = targetObj.name ?? 'unknown';
          const lineNumber = targetObj.lineNumber ?? objSlice.lineNumber ?? 0;
          const targetType = targetObj.typeFullName ?? null;
          const usageLabel = targetObj.label ?? null;

          let resolvedMethod: string | null = null;
          if (Array.isArray(usage.invokedCalls) && usage.invokedCalls.length > 0) {
            resolvedMethod = usage.invokedCalls[0].resolvedMethod ?? null;
          }

          if (fileName && lineNumber > 0) {
            batch.push({
              project_id: projectId,
              extraction_run_id: runId,
              file_path: fileName,
              line_number: lineNumber,
              containing_method: containingMethod,
              target_name: targetName,
              target_type: targetType,
              resolved_method: resolvedMethod,
              usage_label: usageLabel,
              ecosystem,
            });
            totalUsages++;
          }
        }
      }
    }

    const userDefinedTypes = content?.userDefinedTypes;
    if (Array.isArray(userDefinedTypes)) {
      for (const udt of userDefinedTypes) {
        if (!Array.isArray(udt.procedures)) continue;
        for (const proc of udt.procedures) {
          if (!proc.callName || !proc.lineNumber) continue;
          batch.push({
            project_id: projectId,
            extraction_run_id: runId,
            file_path: udt.fileName ?? 'unknown',
            line_number: proc.lineNumber,
            containing_method: null,
            target_name: proc.callName,
            target_type: udt.name ?? null,
            resolved_method: `${udt.name ?? ''}.${proc.callName}`,
            usage_label: 'userDefinedType',
            ecosystem,
          });
          totalUsages++;
        }
      }
    }

    for (let i = 0; i < batch.length; i += 100) {
      const chunk = batch.slice(i, i + 100);
      await supabase.from('project_usage_slices').upsert(chunk, {
        onConflict: 'project_id,file_path,line_number,target_name,extraction_run_id',
      });
    }
  }

  // parsed usage slices (no user-facing log)
}

// ---------------------------------------------------------------------------
// Parse LLM prompts and attach to reachable flows
// ---------------------------------------------------------------------------

export async function parseLlmPrompts(
  reportsDir: string,
  projectId: string,
  runId: string,
  supabase: Storage,
  logger: LogLike,
): Promise<void> {
  const promptFiles = fs.readdirSync(reportsDir)
    .filter(f => f.endsWith('.explain.json') || f.endsWith('-llm-prompts.json') || f.endsWith('.prompts.json'));

  if (promptFiles.length === 0) {
    // LLMPrompts may be embedded in other output files — check for explanation fields
    const explainFiles = fs.readdirSync(reportsDir)
      .filter(f => f.endsWith('.json') && !f.endsWith('.slices.json') && !f.endsWith('.vdr.json'));

    for (const ef of explainFiles) {
      try {
        const content = JSON.parse(fs.readFileSync(path.join(reportsDir, ef), 'utf8'));
        if (!content?.explanations && !content?.prompts && !Array.isArray(content)) continue;

        const prompts: Array<{ purl?: string; entry_file?: string; entry_line?: number; prompt?: string }> =
          content.explanations ?? content.prompts ?? (Array.isArray(content) ? content : []);

        await matchPromptsToFlows(prompts, projectId, runId, supabase);
      } catch { /* skip non-parseable files */ }
    }
    return;
  }

  let totalPrompts = 0;

  for (const pf of promptFiles) {
    try {
      const content = JSON.parse(fs.readFileSync(path.join(reportsDir, pf), 'utf8'));
      const prompts: any[] = Array.isArray(content) ? content : (content.prompts ?? content.explanations ?? []);

      totalPrompts += await matchPromptsToFlows(prompts, projectId, runId, supabase);
    } catch (err: any) {
      await logger.warn('reachability', `Failed to parse LLM prompts from ${pf}: ${err.message}`);
    }
  }

  if (totalPrompts > 0) {
    await logger.info('reachability', `Matched ${totalPrompts} LLM prompts to reachable flows`);
  }
}

async function matchPromptsToFlows(
  prompts: any[],
  projectId: string,
  runId: string,
  supabase: Storage,
): Promise<number> {
  let matched = 0;

  for (const p of prompts) {
    if (!p) continue;
    const promptText = p.prompt ?? p.text ?? p.explanation ?? (typeof p === 'string' ? p : null);
    if (!promptText) continue;

    const purl = p.purl ?? p.package_url ?? null;
    const entryFile = p.entry_file ?? p.entryPoint?.file ?? null;
    const entryLine = p.entry_line ?? p.entryPoint?.line ?? null;

    let query = supabase
      .from('project_reachable_flows')
      .update({ llm_prompt: promptText })
      .eq('project_id', projectId)
      .eq('extraction_run_id', runId);

    if (purl) query = query.eq('purl', purl);
    if (entryFile) query = query.eq('entry_point_file', entryFile);
    if (entryLine) query = query.eq('entry_point_line', entryLine);

    const { data: updated } = await query.select('id').limit(1);
    if (updated && updated.length > 0) matched++;
  }

  return matched;
}

// ---------------------------------------------------------------------------
// Update reachability levels on project_dependency_vulnerabilities
// ---------------------------------------------------------------------------

/**
 * Read a snippet of source code around a given line number.
 * Returns ~5 lines before and ~5 lines after for context.
 */
function readCodeSnippet(workspaceRoot: string, filePath: string, lineNumber: number, contextLines: number = 5): string | null {
  if (!workspaceRoot || !filePath || !lineNumber) return null;
  // Try multiple path resolutions (atom may return paths relative to src/ or workspace root)
  const candidates = [
    path.join(workspaceRoot, filePath),
    path.join(workspaceRoot, 'src', filePath),
  ];
  let fullPath: string | null = null;
  for (const c of candidates) {
    if (fs.existsSync(c) && fs.statSync(c).isFile()) {
      fullPath = c;
      break;
    }
  }
  if (!fullPath) return null;

  try {
    const content = fs.readFileSync(fullPath, 'utf8');
    const lines = content.split(/\r?\n/);
    const startLine = Math.max(0, lineNumber - contextLines - 1);
    const endLine = Math.min(lines.length, lineNumber + contextLines);
    const snippet = lines.slice(startLine, endLine)
      .map((line, i) => {
        const num = startLine + i + 1;
        const marker = num === lineNumber ? '→' : ' ';
        return `${marker} ${num.toString().padStart(4)} │ ${line}`;
      })
      .join('\n');
    return snippet;
  } catch {
    return null;
  }
}

export interface UpdateReachabilityOptions {
  /**
   * Phase 6.5 — set of CVE ids whose FrameworkSpec actually loaded for this
   * extraction (the keys of `cveSpecResult.specs[].sinks[].osv_id`). When a
   * `taint_engine` flow's `osv_id` is NOT in this set, we treat it as data
   * drift (CHECK disabled, dual-read window, manual SQL) and demote the
   * promotion to `data_flow` instead of `confirmed`. Mismatches log a
   * `osv_id_drift_rejected` security event.
   *
   * Optional: when undefined we skip the drift check entirely so legacy
   * callers (CLI tests, snapshot harness) keep working — the M5 confirmed
   * tier still promotes, just without the defense-in-depth guard.
   */
  validOsvIds?: Set<string>;
  /** Organization id for audit-log writes when an `osv_id_drift_rejected` event fires. */
  organizationId?: string;
  /**
   * Whether the tree-sitter usage-extraction step produced output for this
   * run (ctx.astParsedSuccessfully). When false the absence of usage slices
   * is NOT evidence of unreachability — extraction crashed/timed-out — so the
   * classifier must never collapse a PDV to `unreachable`; it floors at
   * `module` instead. Defaults to true so legacy callers keep prior behavior.
   */
  astParsedSuccessfully?: boolean;
  /**
   * Whether the direct/transitive split on `project_dependencies` is
   * trustworthy (ctx.graphTrusted). False when cdxgen returned an unwired
   * dependency graph AND graph recovery couldn't rebuild the direct set — in
   * that case `is_direct` is meaningless, so the `unreachable` verdict (which
   * keys on `!is_direct`) would hide real vulns. When false the classifier
   * floors at `module`. Defaults to true so legacy callers keep prior behavior.
   */
  graphTrusted?: boolean;
  /**
   * osv_id → the vulnerable call patterns of every CVE-targeted FrameworkSpec
   * sink that loaded this run (from the taint-engine step). When a PDV's
   * osv_id has an entry, the classifier verifies whether the CVE's *specific*
   * vulnerable symbol is on a call path — rather than the weaker "package name
   * appears somewhere" heuristic. Absent / empty for legacy callers and for
   * CVEs with no generated spec, which keep the package-name `function` tier.
   */
  cveSinkPatterns?: Map<string, string[]>;
  /**
   * v3 (precision arc) — lowercase set of dep package names the taint-engine
   * callgraph confirmed are reached by at least one CallEdge from workspace
   * code. The heuristicUnreachable branch AND-clauses with
   * `!usedTransitives.has(depName.toLowerCase())` so a transitive dep
   * exercised through a framework's request handler (the jackson-core case)
   * is demoted to `module` instead of being mis-classified `unreachable`.
   *
   * Semantics:
   *   - undefined / empty Set: callgraph didn't extract for this ecosystem
   *     yet (Ruby/PHP/C#/Java/Python/Go/Rust pre-T3.2) or the engine was
   *     rollout-gated off. Classifier falls back to v2 heuristic behavior
   *     for every transitive — `!callgraphReachedThisDep` is vacuously true.
   *   - Populated Set: the dep names listed get `callgraph_reached=true` —
   *     they short-circuit the unreachable verdict on transitives. Deps
   *     NOT in the set with the standard heuristic preconditions
   *     (transitive, zero files importing) collapse to `unreachable` as
   *     v2 did.
   */
  usedTransitives?: Set<string>;
  /**
   * v3 follow-up — the project's ecosystem (`composer` / `pypi` / `npm` /
   * `gem` / etc.). When set to an explicit-import ecosystem, the
   * `heuristicUnreachable` gate relaxes its `!isDirect` requirement and
   * also demotes DIRECT deps that have `files_importing_count === 0` AND
   * `!callgraphReached` — composer/pypi/npm source code MUST `use`/`import`
   * a package to call into it, so files=0 is strong negative evidence
   * regardless of whether the package is listed in composer.json /
   * pyproject.toml / package.json.
   *
   * Excluded: `gem` (Rails autoload + Bundler.require make files=0
   * unreliable — a Gemfile-declared gem may be used solely through
   * Bundler-managed autoloading and never explicitly required). Also
   * excluded: any ecosystem where the tree-sitter usage extractor
   * doesn't reliably resolve imports (`maven`, `golang`, `cargo`,
   * `nuget` — these keep the v2 transitive-only behavior).
   *
   * Undefined defaults to the legacy `!isDirect`-only gate.
   */
  ecosystem?: string;
  /**
   * True when the project is a pure client-side SPA (React/Vue/… bundled to a
   * browser artifact). A bundler ships the project's ENTIRE production
   * dependency graph, so a prod/unknown-scope dep's vulnerable module is loaded
   * even when no first-party file imports it directly (e.g. dompurify pulled in
   * by monaco-editor, react-router under react-router-dom). For such projects we
   * reserve `unreachable` for dev/build-only deps (not bundled) and floor every
   * prod/unknown dep at `module`. Undefined / false → unchanged server-project
   * behavior.
   */
  isClientSpaProject?: boolean;
  /**
   * Feature-precondition gate (reachability noise reduction). Pre-gathered
   * project-feature signals used to DEMOTE a `module` /
   * `callgraph_reached_transitive` finding to `unreachable` when the framework
   * feature its CVE requires is PROVABLY ABSENT (see
   * `reachability-feature-preconditions.ts`).
   *
   * When omitted, the classifier gathers signals itself from `workspaceRoot`
   * for the `maven` ecosystem (and skips the gate entirely otherwise). Tests
   * inject signals directly to exercise the gate without a filesystem. An
   * unrecognized / empty signals object refuses every demotion (fail-safe).
   */
  springFeatureSignals?: SpringFeatureSignals;
  /**
   * Always-on framework-runtime PROMOTION gate (reachability silence-FN
   * recovery). The number of HTTP-route entry points framework detection found
   * this run. `> 0` marks the project a DEPLOYED WEB APP, which is the required
   * precondition for promoting a `module` finding whose CVE lives in always-on
   * framework-runtime code (servlet-container request parser, MVC resource
   * handler) to a visible tier — see `reachability-feature-preconditions.ts`
   * (`ALWAYS_ON_RUNTIME` + `evaluateAlwaysOnRuntimePromotion`). `0` / undefined
   * disables every promotion (a library repo must not get promotions).
   * Threaded from usage_extraction's already-detected entry points (never
   * re-detected); tests inject it directly.
   */
  httpEntryPointCount?: number;
  /**
   * PHP / Symfony feature-precondition + always-on-runtime signals — the
   * composer-ecosystem mirror of `springFeatureSignals` (see
   * `reachability-symfony-preconditions.ts`). Used to DEMOTE a `module` composer
   * finding to `unreachable` when its Symfony feature is provably absent (Twig
   * sandbox, untrusted-YAML parse, x509 firewall, `unanimous` strategy) or the
   * package is DEV-ONLY (composer.lock `packages-dev`), and to PROMOTE always-on
   * request-path CVEs (http-foundation Request parsing, the security firewall
   * login path) to a visible tier on a deployed web app.
   *
   * When omitted, the classifier gathers signals itself from `workspaceRoot` for
   * the `composer` ecosystem (and skips the gate otherwise). Tests inject signals
   * directly. An unrecognized / non-Symfony signals object refuses every move.
   */
  symfonyFeatureSignals?: SymfonyFeatureSignals;
  /**
   * Ruby/Rails framework-mediated reachability signals — the RubyGems mirror of
   * `symfonyFeatureSignals`. Used to DEMOTE `module`→`unreachable` when a CVE's
   * required gem feature is provably absent (Rack::Static/Directory, Nokogiri
   * XSLT/Schema, Oj streaming APIs, rails-ujs, a Windows-only bug) or the gem is
   * DEV-ONLY (Gemfile `:development`/`:test`/`:assets` group), and to PROMOTE
   * always-on request-path CVEs (Puma, Rack request parsing, ActionDispatch, Oj
   * codec, the Rails HTML sanitizer stack) to a visible tier on a deployed app.
   *
   * When omitted, the classifier gathers signals itself from `workspaceRoot` for
   * the `gem` ecosystem (and skips the gate otherwise). Tests inject signals
   * directly. An unrecognized / non-Rails signals object refuses every move.
   */
  railsFeatureSignals?: RailsFeatureSignals;
  /**
   * Go framework-mediated reachability signals — the Go-module mirror of the
   * dynamic-framework models, but keyed on the PRECISE subpackage import graph.
   * Used to DEMOTE `module`→`unreachable` when a CVE's affected subpackage is
   * provably not imported (x/crypto/ssh on a non-SSH server; x/net/html on a
   * server that parses no HTML) and to PROMOTE always-on request-path CVEs
   * (x/net/http2 on a deployed HTTP/2 server) to a visible tier.
   *
   * When omitted, the classifier gathers signals itself from `workspaceRoot` for
   * the `golang` ecosystem (and skips the gate otherwise). Tests inject signals
   * directly. An unrecognized / non-Go signals object refuses every move.
   */
  goImportSignals?: GoImportSignals;
  /**
   * Arc 2 (dependency-source import graphs): the transitive import index the
   * dep-import-graph pipeline step computed for this run — `go list -deps`
   * compile set (golang) or per-dist wheel import/token extraction (pypi).
   * Merged into the matching ecosystem's signals object (NEW object, injected
   * fields win, transitive data only in new fields) so the demotion pass and
   * the promotion wouldDemote backstop see identical answers. Absent =
   * today's behavior everywhere. Tests inject either this or pre-merged
   * signals fields directly.
   */
  transitiveImports?: TransitiveImportIndex;
  /**
   * Python/Django framework-mediated reachability signals — the pypi mirror of
   * the dynamic-framework models plus a Go-style SUBMODULE import gate. Used to
   * DEMOTE `module`→`unreachable` when a CVE's required feature is provably
   * absent (a pillow/cryptography submodule the first-party import set never
   * touches, django.contrib.humanize never referenced, a Windows-only bug, the
   * h11 parser shadowed by httptools, setuptools' build-time PackageIndex) or
   * the package is DEV-ONLY (poetry dev groups / Pipfile dev-packages /
   * requirements-dev.txt), and to PROMOTE always-on request-path CVEs
   * (django uri_to_iri / response logging / validator ReDoS, pillow WebP decode
   * on an image-upload surface) to a visible tier on a deployed app.
   *
   * When omitted, the classifier gathers signals itself from `workspaceRoot`
   * for the `pypi` ecosystem (and skips the gate otherwise). Tests inject
   * signals directly. An unrecognized / non-Django signals object refuses
   * every move.
   */
  djangoFeatureSignals?: DjangoFeatureSignals;
  /**
   * Flask/FastAPI framework-mediated reachability signals — the SECOND pypi model
   * beside Django (a Flask/FastAPI app carries no django dep, so Django's
   * `recognized` is false there, and vice-versa). Injected by unit tests.
   */
  flaskFeatureSignals?: FlaskFeatureSignals;
  /**
   * Laravel framework-mediated reachability signals — a SECOND composer-ecosystem
   * model beside `symfonyFeatureSignals` (a Laravel app carries no
   * symfony/framework-bundle, so the Symfony model does not recognize it). Used to
   * DEMOTE `module`→`unreachable` when a laravel/framework CVE's required feature
   * is provably absent (no signed-URL API anywhere) and to PROMOTE always-on
   * request-path CVEs to a visible tier when the feature is present (signed URLs
   * in use → signed-URL path-confusion; file-upload validation in use →
   * file-validation bypass). Every row is feature-gated because the same
   * laravel/framework CVE is reachable on one app and not another (monica uses
   * signed URLs, koel does not).
   *
   * When omitted, the classifier gathers signals itself from `workspaceRoot` for
   * the `composer` ecosystem (and skips the gate otherwise). Tests inject signals
   * directly. An unrecognized / non-Laravel signals object refuses every move.
   */
  laravelFeatureSignals?: LaravelFeatureSignals;
}

/**
 * Extract substring-match tokens from a CVE-targeted FrameworkSink pattern.
 * The pattern grammar (see taint-engine/spec.ts) is `Foo.bar`, `Foo.bar.*`,
 * or `Foo.bar(*)`. Returns the lowercased full dotted callee plus its last
 * segment — both matched against `project_usage_slices` strings. Segments
 * shorter than 3 chars are dropped as too generic to match reliably.
 */
export function extractSymbolTokens(pattern: string): string[] {
  let p = pattern.trim().toLowerCase();
  p = p.replace(/\(\s*\*?\s*\)\s*$/, ''); // strip trailing (*) / ()
  p = p.replace(/\.\*$/, '');             // strip trailing .*
  p = p.replace(/\*+$/, '').trim();
  if (!p) return [];
  const tokens = new Set<string>();
  if (p.length >= 3) tokens.add(p);
  const segs = p.split(/[.#:/]/).filter(Boolean);
  const last = segs[segs.length - 1];
  if (last && last.length >= 3) tokens.add(last);
  return [...tokens];
}

/**
 * Framework-embedded runtime components — servlet containers, embedded
 * app-servers, reactive runtimes and template engines that a framework's
 * starter / auto-configuration wires into the application. The app's own
 * first-party code never `import`s them (Spring Boot embeds Tomcat; the app
 * never imports `org.apache.catalina`), so the import-absence heuristic below
 * would wrongly collapse them to `unreachable` — yet the servlet container is
 * on every request path and the template engine renders every view. Never
 * emit `unreachable` for a dep whose name matches one of these; floor it at
 * `module` (we know it runs; we just can't pin the vulnerable function).
 *
 * Surfaced by the M4 reachability corpus: spring-petclinic's tomcat-embed-core
 * and thymeleaf-spring6 were false-negative `unreachable` verdicts.
 */
const FRAMEWORK_EMBEDDED_RUNTIME = [
  'tomcat-embed', 'jetty', 'undertow', 'netty', 'spring-boot-starter-tomcat',
  'thymeleaf', 'freemarker', 'mustache', 'pebble', 'groovy-templates',
];

/** True when `depName` is a framework-embedded runtime component (see above). */
export function isFrameworkEmbeddedRuntime(depName: string | undefined): boolean {
  if (!depName) return false;
  const n = depName.toLowerCase();
  return FRAMEWORK_EMBEDDED_RUNTIME.some((p) => n.includes(p));
}

/**
 * JS/TS framework runtime packages a project uses *without an explicit import*.
 * Modern frameworks wire their runtime in by convention, not by a call-site the
 * usage extractor can see: a Next.js `app/` page or a pure-JSX component is
 * compiled to `react`/`next` by the bundler, so `files_importing_count` is 0 for
 * `next` / `react` / `react-dom` even though they are on every render path (the
 * automatic JSX runtime means React 17+ JSX needs no `import React`). Treat
 * these like the embedded-runtime components above: never collapse them to
 * `unreachable` on import-absence — floor at `module`. Skipping this would bury
 * a genuinely-exploitable framework CVE (e.g. Next.js CVE-2025-29927) at
 * depscore weight 0 the moment the app happens not to `import` the framework.
 *
 * EXACT match (not substring) so it can't false-exempt `next-auth`, `nextra`,
 * `react-router`, etc. — those are ordinary libraries the app does import.
 */
const FRAMEWORK_RUNTIME_PACKAGES = new Set([
  'next', 'react', 'react-dom', 'react-native',
  'vue', 'nuxt',
  '@angular/core', '@angular/common', '@angular/platform-browser',
  'svelte', '@sveltejs/kit',
  'solid-js', 'preact', 'gatsby', 'astro', '@remix-run/react',
]);

/** True when `depName` is a convention-wired framework runtime (see above). */
export function isFrameworkRuntimePackage(depName: string | undefined): boolean {
  if (!depName) return false;
  return FRAMEWORK_RUNTIME_PACKAGES.has(depName.toLowerCase());
}

/**
 * Scope strings that mark a dependency as dev/test/build — by definition NOT
 * on the production call path. Centralized (R4) so every dev-scope check shares
 * one definition. The worker currently only ever writes `'dev'`
 * (deps-sync.ts derives environment ∈ {'prod','dev',null}), so on real data
 * this set is behaviourally identical to the old literal `=== 'dev'`; the extra
 * members back the long-standing "dev/test/build" docstring contract and make
 * the predicate robust to other ecosystems' scope vocabulary.
 */
export const DEV_SCOPES: ReadonlySet<string> = new Set([
  'dev', 'development', 'test', 'build',
]);

/**
 * True when `project_dependencies.environment` marks a dependency as
 * dev/test/build scope. A dev-scoped dependency's vulnerable code is, by
 * definition, not on the production call path — the classifier floors it at
 * `unreachable`. `environment` is derived from the manifest (`deps-sync.ts`)
 * and from transitive dev-only propagation; it is the single dev-scope signal.
 * Matching is case/whitespace-insensitive via the centralized `DEV_SCOPES` set.
 */
export function isDevScoped(environment: string | null | undefined): boolean {
  if (!environment) return false;
  return DEV_SCOPES.has(environment.trim().toLowerCase());
}

/**
 * v3 precision arc — does the taint-engine callgraph's `usedDependencies`
 * set credit this dependency as reached?
 *
 * Per-ecosystem matching:
 *   - **npm** populates the set with package names (`lodash`, `@scope/x`).
 *     A direct `.has(depName.toLowerCase())` covers it.
 *   - **java** (maven) populates the set with FQN packages (e.g.
 *     `com.fasterxml.jackson.databind`, `org.springframework.web`) plus
 *     ancestors. The PDV's name is the maven artifactId (e.g.
 *     `jackson-core`) and namespace is the groupId (e.g.
 *     `com.fasterxml.jackson.core`). The matcher does:
 *       (a) bidirectional dot-segmented prefix match between `namespace`
 *           and any used-FQN — credits jackson-core for a workspace that
 *           imports `com.fasterxml.jackson.databind` via common ancestor
 *           `com.fasterxml.jackson`.
 *       (b) artifactId hyphen→dot substring against any used-FQN —
 *           fallback for artifacts whose groupId doesn't share a prefix
 *           with the package (e.g. older shaded jars).
 *
 * Returns false on empty depName or empty usedTransitives. Never throws.
 */
export function depMatchesUsedTransitives(
  depName: string | null | undefined,
  depNamespace: string | null | undefined,
  usedTransitives: Set<string>,
): boolean {
  if (usedTransitives.size === 0) return false;
  const lowerName = (depName ?? '').toLowerCase();
  // npm exact-name match (lowercase).
  if (lowerName && usedTransitives.has(lowerName)) return true;

  // maven groupId bidirectional dot-segmented prefix match.
  // `com.fasterxml.jackson.core` ↔ `com.fasterxml.jackson.databind` via
  // ancestor `com.fasterxml.jackson`. The Java callgraph emits both the
  // FQN package AND every non-trivial ancestor, so the ancestor lookup
  // succeeds with a single `.has` on `com.fasterxml.jackson`.
  const lowerNs = (depNamespace ?? '').toLowerCase();
  if (lowerNs) {
    if (usedTransitives.has(lowerNs)) return true;
    // groupId is a strict prefix of some used-FQN (e.g. groupId
    // `org.springframework` ⊂ used `org.springframework.web`).
    for (const used of usedTransitives) {
      if (used.startsWith(lowerNs + '.') || lowerNs.startsWith(used + '.')) {
        return true;
      }
    }
  }

  // maven artifactId hyphen→dot substring — catches e.g.
  // `jackson-databind` mapping to FQN containing `jackson.databind`.
  // Skip when the dot-converted token is shorter than 5 chars or has
  // no dots (would degenerate to "anything containing `lodash`" already
  // covered by the npm exact-match path).
  if (lowerName.includes('-')) {
    const dotted = lowerName.replace(/-/g, '.');
    if (dotted.length >= 5 && dotted.includes('.')) {
      for (const used of usedTransitives) {
        if (used.includes(dotted)) return true;
      }
    }
  }

  return false;
}

/**
 * True when `needle` occurs in `haystack` on package-segment boundaries — i.e.
 * neither the character before nor the character after the match is an
 * identifier char (`[a-z0-9]`). Both strings are expected lowercase. Used by
 * the usage-heuristic name match (R5) to stop a short/generic dep name from
 * fuzzy-matching the middle of an unrelated identifier.
 */
export function tokenBoundaryIncludes(haystack: string, needle: string): boolean {
  if (!needle || !haystack) return false;
  const isTok = (c: string) => c !== '' && c >= '0' && /[a-z0-9]/.test(c);
  let from = 0;
  for (;;) {
    const idx = haystack.indexOf(needle, from);
    if (idx === -1) return false;
    const before = idx === 0 ? '' : haystack[idx - 1];
    const afterIdx = idx + needle.length;
    const after = afterIdx >= haystack.length ? '' : haystack[afterIdx];
    if (!isTok(before) && !isTok(after)) return true;
    from = idx + 1;
  }
}

/**
 * Bare, extremely-common method names that — on their own — are NOT evidence a
 * CVE's vulnerable function is reached. These identifiers hang off countless
 * unrelated classes across every ecosystem (`logger.error`, `cache.get`,
 * `router.handle`, `console.log`, `queue.send` …), so a usage whose only tie to
 * a dependency is a same-named bare call is noise, not a call-path proof.
 *
 * The usage heuristic below (`isDepUsed`) matches a CVE's dependency by
 * substring, so a CVE whose vulnerable surface is one of these words gets
 * lifted to `function` the instant ANY like-named call exists anywhere in the
 * project — the symfony/demo CVE-2020-5274 false positive (matched the
 * unrelated Console `SymfonyStyle->error()` call) is the canonical case. When
 * the ONLY matched call is a bare word from this set, we require a stronger,
 * qualifying signal before promoting (see `COMMON_BARE_METHODS` usage in the
 * classifier). Distinctive names — deserialization verbs (`readValue`, `load`,
 * `unserialize`, `deserialize`), template/render helpers with a real name
 * (`template`, `safeLoad`), etc. — are deliberately NOT listed here, so a CVE
 * whose sink IS a distinctive method still promotes on its own. Keep entries
 * lowercase and in bare (last-segment) form.
 */
export const COMMON_BARE_METHODS: ReadonlySet<string> = new Set([
  'error', 'warn', 'warning', 'info', 'log', 'debug',
  'get', 'set', 'run', 'handle', 'send', 'render',
  'write', 'read', 'add', 'remove', 'execute', 'call',
]);

/**
 * Last bare segment of a resolved-method / callee string, lowercased. Splits on
 * any non-identifier separator so `org.apache.logging.log4j.Logger.error`,
 * `SymfonyStyle::error`, `mapper->readValue`, and a bare `error` all reduce to
 * their trailing method name (`error`, `error`, `readvalue`, `error`). Used by
 * the bare-common-method guard to decide whether a matched usage is a
 * distinctive call-path signal or an ambiguous same-named collision.
 */
export function bareMethodName(resolvedMethod: string | null | undefined): string {
  if (!resolvedMethod) return '';
  const segs = resolvedMethod.toLowerCase().split(/[^a-z0-9_$]+/).filter(Boolean);
  return segs.length ? segs[segs.length - 1] : '';
}

/**
 * Ecosystems where source code MUST explicitly `use`/`import` a package to
 * exercise it, so `files_importing_count === 0` is strong negative evidence
 * even on a directly-declared dep. Hoisted to module scope (R1) so the
 * transitive-of-reachable seed computation and the per-PDV heuristic share one
 * definition. Excluded: `gem` (Rails autoload + Bundler.require) and
 * `maven`/`golang`/`cargo`/`nuget` (partial tree-sitter import resolution).
 */
const EXPLICIT_IMPORT_ECOSYSTEMS = new Set(['composer', 'pypi', 'npm']);

export async function updateReachabilityLevels(
  projectId: string,
  runId: string,
  supabase: Storage,
  logger: LogLike,
  workspaceRoot?: string,
  options: UpdateReachabilityOptions = {},
): Promise<void> {
  const { data: pdvs, error: pdvErr } = await supabase
    .from('project_dependency_vulnerabilities')
    .select('id, project_dependency_id, osv_id, aliases, summary')
    .eq('project_id', projectId)
    .eq('extraction_run_id', runId);

  if (pdvErr) {
    throw new Error(`updateReachabilityLevels: failed to fetch PDVs: ${pdvErr.message}`);
  }
  if (!pdvs || pdvs.length === 0) return;

  const { data: pds, error: pdErr } = await supabase
    .from('project_dependencies')
    .select('id, dependency_id, is_direct, files_importing_count, environment, dependency_version_id, name, namespace')
    .eq('project_id', projectId)
    .eq('last_seen_extraction_run_id', runId);
  if (pdErr) {
    throw new Error(`updateReachabilityLevels: failed to fetch project_dependencies: ${pdErr.message}`);
  }

  const depIdMap = new Map(pds?.map((pd: any) => [pd.id, pd.dependency_id]) ?? []);
  const pdMetaMap = new Map<
    string,
    {
      isDirect: boolean;
      filesImporting: number;
      scope: string | null;
      versionId: string | null;
      name: string | null;
      namespace: string | null;
    }
  >(
    pds?.map((pd: any) => [
      pd.id,
      {
        isDirect: !!pd.is_direct,
        filesImporting: Number(pd.files_importing_count ?? 0),
        scope: (pd.environment ?? null) as string | null,
        versionId: (pd.dependency_version_id ?? null) as string | null,
        name: (pd.name ?? null) as string | null,
        namespace: (pd.namespace ?? null) as string | null,
      },
    ]) ?? []
  );

  // Try the full phase23 column list first. On pre-migration schemas the
  // select returns `42703 undefined_column` — fall back to the pre-phase23
  // column list (which still produces atom-based module/function/data_flow
  // classification) rather than silently collapsing every PDV to `module`
  // with no log. Any other error is a real failure and must surface.
  let flows: Array<{
    dependency_id: string | null;
    reachability_source?: string | null;
    osv_id?: string | null;
    rule_id?: string | null;
    flow_signature_hash?: string | null;
    entry_point_file: string | null;
    entry_point_line: number | null;
    entry_point_tag: string | null;
    sink_method: string | null;
  }> = [];
  {
    const { data, error } = await supabase
      .from('project_reachable_flows')
      .select('dependency_id, reachability_source, osv_id, rule_id, flow_signature_hash, entry_point_file, entry_point_line, entry_point_tag, sink_method')
      .eq('project_id', projectId)
      .eq('extraction_run_id', runId);

    if (error) {
      const code = (error as { code?: string }).code ?? '';
      const msg = error.message ?? '';
      const isMissingColumn = code === '42703' || /reachability_source|osv_id|rule_id/.test(msg);
      if (!isMissingColumn) {
        throw new Error(`updateReachabilityLevels: failed to fetch flows: ${msg}`);
      }
      // Phase23 not applied to this DB — retry with the pre-phase23 shape so
      // atom-only classification still works. Confirmed promotions are
      // impossible until the migration lands; log it once so operators see
      // the degradation instead of silent 'no confirmed levels ever'.
      await logger.warn(
        'reachability',
        'project_reachable_flows missing phase23 columns; taint classification disabled until migration lands',
      );
      const { data: baseData, error: baseErr } = await supabase
        .from('project_reachable_flows')
        .select('dependency_id, entry_point_file, entry_point_line, entry_point_tag, sink_method')
        .eq('project_id', projectId)
        .eq('extraction_run_id', runId);
      if (baseErr) {
        throw new Error(`updateReachabilityLevels: pre-phase23 fallback select failed: ${baseErr.message}`);
      }
      flows = (baseData ?? []) as typeof flows;
    } else {
      flows = (data ?? []) as typeof flows;
    }
  }

  // Phase 6.5 — fetch suppressions for this project so we can demote any
  // confirmed-tier promotion whose flow_signature_hash matches a user
  // suppression. Hash-keyed (Option B / OD-4): a re-extraction recomputes
  // the same canonical hash and re-matches the suppression row.
  const suppressedHashes = new Set<string>();
  {
    const { data: suppressions, error: suppErr } = await supabase
      .from('project_reachable_flow_suppressions')
      .select('flow_signature_hash')
      .eq('project_id', projectId);
    if (suppErr) {
      // Pre-phase27a schema or table-missing. Continue without the
      // suppression filter — confirmed-tier promotion still works; users
      // simply can't suppress yet.
      const code = (suppErr as { code?: string }).code ?? '';
      const isMissing = code === '42P01' || /project_reachable_flow_suppressions/.test(suppErr.message ?? '');
      if (!isMissing) {
        await logger.warn('reachability', `flow suppression fetch failed: ${suppErr.message}`);
      }
    } else {
      for (const row of (suppressions ?? []) as Array<{ flow_signature_hash: string | null }>) {
        if (row.flow_signature_hash) suppressedHashes.add(row.flow_signature_hash);
      }
    }
  }

  // Flows are polymorphic over their source. `flowsByDep` preserves the
  // original "any flow for this dep" semantics used by the data_flow branch
  // — atom, semgrep-derived, and taint_engine rows all count there since
  // any one of them proves the dep is actually wired into the project's
  // call graph.
  //
  // `taintByDepOsv` is the narrower index used by the confirmed branch:
  // a match requires not just the right dep but the specific CVE the taint
  // rule was authored for. Phase 6.5 / M5 task 27 extends this to also
  // pick up `taint_engine` flows whose `osv_id` was stamped by a
  // CVE-targeted FrameworkSpec sink (the new generator path), so the
  // OR-clause matches both Phase 3 Semgrep packs (`semgrep_taint`) and
  // the new cross-file engine path (`taint_engine`). Suppressed flows are
  // excluded so a user-suppressed promotion stays out of `confirmed`.
  type StoredFlow = (typeof flows)[number];
  const flowsByDep = new Map<string, StoredFlow[]>();
  const taintByDepOsv = new Map<string, StoredFlow[]>();
  let driftRejectedCount = 0;
  for (const flow of flows) {
    if (!flow.dependency_id) continue;
    const existing = flowsByDep.get(flow.dependency_id) ?? [];
    existing.push(flow);
    flowsByDep.set(flow.dependency_id, existing);

    const isSemgrepTaint = flow.reachability_source === 'semgrep_taint';
    const isCveTargetedEngine =
      flow.reachability_source === 'taint_engine' && !!flow.osv_id;
    if (!flow.osv_id) continue;
    if (!isSemgrepTaint && !isCveTargetedEngine) continue;

    // Phase 6.5 / M5 task 27 — server-side osv_id drift guard. The osv_id
    // on a `taint_engine` row was substituted server-side at engine-emission
    // time from the loaded CVE spec. Mismatch at classifier time means the
    // CHECK constraint was disabled, the dual-read window leaked, or someone
    // ran manual SQL — i.e. data drift, not model hallucination. Demote the
    // flow to data_flow tier and log a security event so the alert is
    // attributable. We only run the check when the caller passed the spec
    // set (M5 pipeline path); legacy callers without specs skip the guard
    // and inherit the prior behaviour.
    if (isCveTargetedEngine && options.validOsvIds && !options.validOsvIds.has(flow.osv_id)) {
      driftRejectedCount++;
      try {
        await supabase.from('security_audit_logs').insert({
          organization_id: options.organizationId ?? null,
          action: 'osv_id_drift_rejected',
          target_type: 'project_reachable_flow',
          target_id: null,
          severity: 'warn',
          metadata: {
            project_id: projectId,
            extraction_run_id: runId,
            flow_osv_id: flow.osv_id,
            flow_dependency_id: flow.dependency_id,
            flow_signature_hash: flow.flow_signature_hash ?? null,
            reason: 'taint_engine flow osv_id not in loaded cve_spec set',
          },
        });
      } catch (logErr) {
        // Audit-log failure must not block the classifier; log a warn and
        // continue with the demotion semantics.
        const msg = logErr instanceof Error ? logErr.message : String(logErr);
        await logger.warn('reachability', `osv_id_drift_rejected audit-log write failed: ${msg}`);
      }
      continue;
    }

    // Suppression: a user-suppressed flow stays out of the confirmed-tier
    // bucket. It still appears in `flowsByDep` for the data_flow branch
    // (the dep is still wired into the call graph), so the PDV doesn't
    // collapse all the way back to `module`/`unreachable` just because a
    // user suppressed one specific flow.
    if (flow.flow_signature_hash && suppressedHashes.has(flow.flow_signature_hash)) {
      continue;
    }

    const key = `${flow.dependency_id}|${flow.osv_id}`;
    const taintBucket = taintByDepOsv.get(key) ?? [];
    taintBucket.push(flow);
    taintByDepOsv.set(key, taintBucket);
  }
  if (driftRejectedCount > 0) {
    await logger.warn(
      'reachability',
      `${driftRejectedCount} taint_engine flow(s) demoted: osv_id not in loaded cve_spec set (osv_id_drift_rejected)`,
    );
  }

  const { data: usages, error: usagesErr } = await supabase
    .from('project_usage_slices')
    .select('target_type, resolved_method, file_path, line_number')
    .eq('project_id', projectId)
    .eq('extraction_run_id', runId);
  if (usagesErr) {
    throw new Error(`updateReachabilityLevels: failed to fetch usages: ${usagesErr.message}`);
  }

  // Fail-open guard for the `unreachable` verdict. `unreachable` (depscore
  // weight 0.0) is only safe to emit when usage analysis actually ran and
  // produced output for this run. If the tree-sitter usage-extraction step
  // crashed/timed-out (astParsedSuccessfully=false), or it produced zero
  // slices at all, the absence of a match is not evidence of unreachability —
  // floor every otherwise-unreachable PDV at `module` instead.
  const astParsedSuccessfully = options.astParsedSuccessfully ?? true;
  const usageAnalysisProducedOutput = astParsedSuccessfully && (usages?.length ?? 0) > 0;
  if (!usageAnalysisProducedOutput) {
    await logger.warn(
      'reachability',
      'Usage analysis produced no output (extraction crashed/timed-out or zero slices) — ' +
        'flooring unreachable verdicts at module to avoid hiding real vulnerabilities',
    );
  }

  // Import-resolution output (files_importing_count) is produced by the same AST
  // parse but, UNLIKE call-slices, is reliable even when the app makes zero
  // direct dep *calls*. A framework-driven app — a Next.js `app/` page that only
  // renders JSX, a component that wires deps in by convention — legitimately
  // produces zero usage slices while still importing (or framework-importing)
  // its deps. So the import-ABSENCE `unreachable` verdict gates on whether the
  // parse ran (astParsedSuccessfully), not on whether call-slices exist; the
  // call-slice branches above keep gating on usageAnalysisProducedOutput. This
  // is what lets a genuinely-unused direct dep (e.g. a `dompurify` listed in
  // package.json but imported by no file) be classified `unreachable` (weight 0)
  // instead of dishonestly floored at `module` (is_reachable=true) just because
  // the app happens to call none of its deps directly. Framework runtimes are
  // exempted below (isFrameworkRuntimePackage) so the framework's own package
  // never gets buried by this path.
  const importAnalysisRan = astParsedSuccessfully;

  // Second fail-open guard: `unreachable` keys on `!is_direct`, so it is only
  // safe when the direct/transitive split is trustworthy. cdxgen sometimes
  // returns an unwired dependency graph; when graph recovery also couldn't
  // rebuild the direct set, every dep looks transitive and a real direct vuln
  // could be hidden. Floor at `module` in that case.
  const graphTrusted = options.graphTrusted ?? true;
  if (!graphTrusted) {
    await logger.warn(
      'reachability',
      'Dependency graph untrusted (cdxgen graph unwired, recovery unavailable) — ' +
        'flooring unreachable verdicts at module',
    );
  }

  // -------------------------------------------------------------------------
  // R1 — transitive-of-reachable floor.
  //
  // The import-absence heuristic below collapses a transitive dep with
  // `files_importing_count === 0` to `unreachable` (depscore 0) UNLESS the
  // workspace-rooted taint callgraph traced a CallEdge into it. But a prod
  // transitive that executes only *via its parent* (form-data←axios,
  // qs←express) never shows up in either signal, so it is silenced even though
  // it runs. Consult the global `dependency_version_edges` graph: a transitive
  // whose parent version is itself >= `module` reachable inherits a `module`
  // floor (verdict `transitive_of_reachable`).
  //
  // GATING (conservative — never guess):
  //   - Only versions present in THIS project participate (intra-project edge
  //     slice), so we never reason about deps that aren't installed here.
  //   - Seeds are PDs with self-standing reachability evidence (imported /
  //     framework-runtime / callgraph-reached / direct-in-a-non-explicit-
  //     -import ecosystem), non-dev. A genuine orphan (no reachable parent) is
  //     never reached by the closure and stays `unreachable`.
  //   - dev-scope deps are excluded from seeds AND the floor is applied inside
  //     the `!devScoped` heuristic branch, so a dev dep is never promoted.
  //   - When the edge table is absent/empty for this project (edges are
  //     backfilled asynchronously and may not exist on a brand-new dependency
  //     set's first scan), the closure is empty → behaviour is unchanged.
  //   - Requires `graphTrusted` (same precondition as the verdict it overrides).
  const transitiveOfReachableVersionIds = new Set<string>();
  {
    const allowDirectDemotionForSeeds =
      !!options.ecosystem && EXPLICIT_IMPORT_ECOSYSTEMS.has(options.ecosystem);
    const callgraphRanForSeeds =
      options.usedTransitives !== undefined && options.usedTransitives.size > 0;
    const seedVersionIds = new Set<string>();
    const projectVersionIds = new Set<string>();
    for (const meta of pdMetaMap.values()) {
      if (!meta.versionId) continue;
      projectVersionIds.add(meta.versionId);
      if (isDevScoped(meta.scope)) continue;
      const cgReached =
        callgraphRanForSeeds &&
        depMatchesUsedTransitives(meta.name, meta.namespace, options.usedTransitives!);
      const hasEvidence =
        meta.filesImporting > 0 ||
        isFrameworkEmbeddedRuntime(meta.name ?? undefined) ||
        isFrameworkRuntimePackage(meta.name ?? undefined) ||
        cgReached ||
        (meta.isDirect && !allowDirectDemotionForSeeds);
      if (hasEvidence) seedVersionIds.add(meta.versionId);
    }

    if (graphTrusted && projectVersionIds.size > 0 && seedVersionIds.size > 0) {
      const parentToChildren = new Map<string, string[]>();
      let edgesLoaded = false;
      try {
        const versionList = [...projectVersionIds];
        const CHUNK = 200;
        for (let i = 0; i < versionList.length; i += CHUNK) {
          const slice = versionList.slice(i, i + CHUNK);
          const { data, error } = await supabase
            .from('dependency_version_edges')
            .select('parent_version_id, child_version_id')
            .in('child_version_id', slice);
          if (error) {
            const code = (error as { code?: string }).code ?? '';
            const isMissing = code === '42P01' || /dependency_version_edges/.test(error.message ?? '');
            if (isMissing) { edgesLoaded = false; break; }
            throw error;
          }
          for (const e of (data ?? []) as Array<{ parent_version_id: string | null; child_version_id: string | null }>) {
            const p = e.parent_version_id;
            const c = e.child_version_id;
            // Intra-project edges only: both endpoints must be installed here.
            if (!p || !c || !projectVersionIds.has(p) || !projectVersionIds.has(c)) continue;
            edgesLoaded = true;
            const kids = parentToChildren.get(p);
            if (kids) kids.push(c);
            else parentToChildren.set(p, [c]);
          }
        }
      } catch (edgeErr) {
        // Edge graph unavailable — keep current behaviour (do NOT guess).
        const msg = edgeErr instanceof Error ? edgeErr.message : String(edgeErr);
        await logger.warn(
          'reachability',
          `dependency_version_edges fetch failed; skipping transitive-of-reachable floor: ${msg}`,
        );
        edgesLoaded = false;
      }

      if (edgesLoaded) {
        // BFS down the edges from the reachable seeds. Anything reached purely
        // by propagation (not itself a seed) is a transitive of a reachable
        // parent and earns the `module` floor.
        const reached = new Set<string>(seedVersionIds);
        const queue: string[] = [...seedVersionIds];
        while (queue.length > 0) {
          const v = queue.shift()!;
          for (const child of parentToChildren.get(v) ?? []) {
            if (!reached.has(child)) {
              reached.add(child);
              queue.push(child);
            }
          }
        }
        for (const v of reached) {
          if (!seedVersionIds.has(v)) transitiveOfReachableVersionIds.add(v);
        }
      }
    }
  }

  // Collect all type/method strings from usage slices for fuzzy matching
  const allUsageStrings: string[] = [];
  for (const u of usages ?? []) {
    if (u.target_type) allUsageStrings.push(u.target_type.toLowerCase());
    if (u.resolved_method) allUsageStrings.push(u.resolved_method.toLowerCase());
  }

  // Check if a dependency name appears in any usage slice (fuzzy)
  // e.g. "jackson-databind" matches "com.fasterxml.jackson.databind.ObjectMapper"
  // e.g. "log4j-core" matches "org.apache.logging.log4j.Logger"
  //
  // R5: matching is TOKEN-BOUNDARY, not raw substring. A bare `s.includes(x)`
  // over-promotes — a short or generic dep name (`ms`, `cli`, `react`) bleeds
  // into unrelated identifiers (`params`, `client`, `react-router`) and lifts
  // the dep to `function` on noise. We require the needle to sit on package
  // segment boundaries (`.` `/` `#` `:` `-` `_` `@` or string ends), so
  // `log4j-core`→`log4j` still matches `…logging.log4j.Logger` while
  // `ms`-in-`params` no longer does.
  function isDepUsed(depName: string): boolean {
    if (!depName || allUsageStrings.length === 0) return false;
    const lower = depName.toLowerCase();
    // Direct (whole-name) match.
    if (allUsageStrings.some(s => tokenBoundaryIncludes(s, lower))) return true;
    // Convert hyphens to dots for Java package matching: "jackson-databind" → "jackson.databind"
    const dotted = lower.replace(/-/g, '.');
    if (dotted !== lower && allUsageStrings.some(s => tokenBoundaryIncludes(s, dotted))) return true;
    // Also try just the first segment for compound names: "log4j-core" → "log4j".
    // Length-gated (>= 4) so a 2–3 char first segment ("py", "go", "is") can't
    // fuzzy-match half the codebase.
    const parts = lower.split('-');
    if (parts.length > 1 && parts[0].length >= 4 && allUsageStrings.some(s => tokenBoundaryIncludes(s, parts[0]))) return true;
    return false;
  }

  const depNameCache = new Map<string, string>();
  // v3 precision arc — namespace (groupId for maven) cached alongside name.
  // Used by the callgraph-reach matcher to bridge maven artifactIds (e.g.
  // `jackson-core`) and Java FQN packages (e.g. `com.fasterxml.jackson.*`).
  const depNamespaceCache = new Map<string, string | null>();

  // Feature-precondition gate signals (reachability noise reduction). Gathered
  // ONCE per run. Only the Java/Spring (maven) ecosystem is modelled today; for
  // every other ecosystem the signals stay unrecognized and the gate is a
  // no-op. Tests inject `options.springFeatureSignals` to exercise the gate
  // without a filesystem. Failure to read the workspace yields an unrecognized
  // signals object, which refuses every demotion (fail-safe).
  const featureSignals: SpringFeatureSignals | null =
    options.springFeatureSignals ??
    (options.ecosystem === 'maven' ? gatherSpringFeatureSignals(workspaceRoot) : null);
  // PHP/Symfony feature-precondition + always-on-runtime signals — the composer
  // mirror of `featureSignals`. Gathered ONCE per run; only the composer
  // ecosystem is modelled today (a non-Symfony composer app yields unrecognized
  // signals → the gate is a no-op). Tests inject `options.symfonyFeatureSignals`.
  const symfonySignals: SymfonyFeatureSignals | null =
    options.symfonyFeatureSignals ??
    (options.ecosystem === 'composer' ? gatherSymfonyFeatureSignals(workspaceRoot) : null);
  // Ruby/Rails framework-mediated signals — the gem mirror of `symfonySignals`.
  // Gathered ONCE per run; only the `gem` ecosystem is modelled (a non-Rails gem
  // app yields unrecognized signals → the gate is a no-op). Tests inject
  // `options.railsFeatureSignals`.
  const railsSignals: RailsFeatureSignals | null =
    options.railsFeatureSignals ??
    (options.ecosystem === 'gem' ? gatherRailsFeatureSignals(workspaceRoot) : null);
  // Go framework-mediated signals — the Go-module mirror, keyed on the PRECISE
  // subpackage import graph (see reachability-go-preconditions.ts). Gathered ONCE
  // per run; only the `golang` ecosystem is modelled. `isDeployedHttpServer` is
  // the Go stand-in for the http-route-entry-point signal (a caddy-shaped server
  // routes via its own module system, so the framework detectors emit 0 routes).
  const goSignalsBase: GoImportSignals | null =
    options.goImportSignals ??
    (options.ecosystem === 'golang' ? gatherGoImportSignals(workspaceRoot) : null);
  // Arc 2 merge (pinned rule): construct a NEW object — never mutate an
  // injected signals object; injected transitive fields win; transitive data
  // lives ONLY in the new fields; the index applies only to its own ecosystem.
  // Both the demotion pass and the promotion wouldDemote backstop read this
  // one merged object, so the two passes stay consistent automatically.
  const goTransitiveIdx: TransitiveImportIndex | null =
    options.transitiveImports?.ecosystem === 'golang' ? options.transitiveImports : null;
  const goSignals: GoImportSignals | null = goSignalsBase
    ? goTransitiveIdx &&
      goSignalsBase.transitiveImportedPackages === undefined &&
      goTransitiveIdx.status !== 'unavailable'
      ? {
          ...goSignalsBase,
          transitiveImportedPackages: unionImportedModules(goTransitiveIdx),
          transitiveComplete: goTransitiveIdx.status === 'complete',
        }
      : goSignalsBase
    : null;
  const goServerReachable = goSignals?.isDeployedHttpServer ?? false;
  // Python/Django framework-mediated signals — the pypi mirror. Gathered ONCE
  // per run; only the `pypi` ecosystem is modelled (a non-Django Python app
  // yields unrecognized signals → the gate is a no-op). Tests inject
  // `options.djangoFeatureSignals`. `isDeployedWebApp` is the pypi stand-in for
  // the http-route-entry-point signal (a GraphQL-only Django app may emit 0
  // detected HTTP routes even though it serves requests).
  const pypiTransitiveIdx: TransitiveImportIndex | null =
    options.transitiveImports?.ecosystem === 'pypi' ? options.transitiveImports : null;
  const djangoSignalsBase: DjangoFeatureSignals | null =
    options.djangoFeatureSignals ??
    (options.ecosystem === 'pypi' ? gatherDjangoFeatureSignals(workspaceRoot) : null);
  // Same pinned Arc 2 merge rule as goSignals above.
  const djangoSignals: DjangoFeatureSignals | null = djangoSignalsBase
    ? pypiTransitiveIdx && djangoSignalsBase.transitiveImports === undefined
      ? { ...djangoSignalsBase, transitiveImports: pypiTransitiveIdx }
      : djangoSignalsBase
    : null;
  const djangoDeployed = djangoSignals?.isDeployedWebApp ?? false;
  // Flask/FastAPI framework-mediated signals — a SECOND pypi model beside
  // `djangoSignals`. A Flask/FastAPI app carries no django dep (so the Django
  // model's `recognized` is false there) and vice-versa, so the two never both
  // fire. Gathered ONCE per run for the pypi ecosystem; a non-Flask/FastAPI pypi
  // app yields unrecognized signals → no-op. Tests inject `options.flaskFeatureSignals`.
  const flaskSignalsBase: FlaskFeatureSignals | null =
    options.flaskFeatureSignals ??
    (options.ecosystem === 'pypi' ? gatherFlaskFeatureSignals(workspaceRoot) : null);
  // Same pinned Arc 2 merge rule (no Flask row consults it in v1 — type parity).
  const flaskSignals: FlaskFeatureSignals | null = flaskSignalsBase
    ? pypiTransitiveIdx && flaskSignalsBase.transitiveImports === undefined
      ? { ...flaskSignalsBase, transitiveImports: pypiTransitiveIdx }
      : flaskSignalsBase
    : null;
  const flaskDeployed = flaskSignals?.isDeployedWebApp ?? false;
  // Laravel framework-mediated signals — a SECOND composer-ecosystem model beside
  // `symfonySignals` (a Laravel app carries no symfony/framework-bundle, so the
  // Symfony model's `recognized` is false there). Gathered ONCE per run for the
  // composer ecosystem; a non-Laravel composer app yields unrecognized signals →
  // the gate is a no-op. Tests inject `options.laravelFeatureSignals`.
  const laravelSignals: LaravelFeatureSignals | null =
    options.laravelFeatureSignals ??
    (options.ecosystem === 'composer' ? gatherLaravelFeatureSignals(workspaceRoot) : null);
  // Always-on framework-runtime PROMOTION gate. `> 0` HTTP-route entry points ⇒
  // this is a deployed web app, so a CVE in an always-on framework component is
  // genuinely on the request path. Gathered once per run from the already-
  // detected entry-point count threaded via options (never re-detected here).
  const hasHttpRouteEntryPoint = (options.httpEntryPointCount ?? 0) > 0;
  let updatedCount = 0;
  let detailsSetCount = 0;
  const levelCounts: Record<string, number> = {
    confirmed: 0,
    data_flow: 0,
    function: 0,
    module: 0,
    unreachable: 0,
  };
  // R3 — accumulate the per-PDV verdicts and flush them with a single batched
  // upsert (onConflict id) instead of one UPDATE round-trip per PDV. On a
  // 30k-row project the N+1 UPDATE loop dominated this step. `id` is the PK;
  // every row already exists, so each upsert resolves to ON CONFLICT DO UPDATE
  // touching only the three reachability columns — exact prior semantics.
  const pdvUpdates: Array<{
    id: string;
    project_id: string;
    project_dependency_id: string;
    osv_id: string;
    reachability_level: string;
    reachability_details: any;
    is_reachable: boolean;
  }> = [];

  // M1 silence-event log (workstream M). One durable row per (run, pdv)
  // recording the verdict + the classifier inputs that produced it. PURE
  // OBSERVABILITY — nothing reads it on the prod silence path; M2 diffs two
  // runs to catch silence false-negatives. Accumulated beside `pdvUpdates`
  // and flushed in a second fail-soft batched upsert after the PDV write.
  const silenceEvents: Array<{
    project_id: string;
    extraction_run_id: string;
    pdv_id: string;
    project_dependency_id: string;
    dependency_id: string;
    osv_id: string;
    reachability_level: string;
    is_reachable: boolean;
    verdict: string | null;
    graph_trusted: boolean;
    ast_parsed: boolean;
    ecosystem: string | null;
    files_importing_count: number | null;
    is_direct: boolean | null;
    dev_scoped: boolean | null;
    callgraph_reached: boolean | null;
    classifier_inputs: any;
  }> = [];

  for (const pdv of pdvs) {
    const dependencyId = depIdMap.get(pdv.project_dependency_id);
    if (!dependencyId) continue;

    // M1: hoist the per-PDV meta + callgraph-reached signal to loop top so they
    // are available at the silence_events push site regardless of which
    // classification branch runs below. Pure observability — these do NOT change
    // the level/details/is_reachable decision (the branches recompute what they
    // need). The else-branch's former `const meta` now reuses this binding.
    const meta = pdMetaMap.get(pdv.project_dependency_id);
    const cgReached =
      options.usedTransitives !== undefined &&
      options.usedTransitives.size > 0 &&
      depMatchesUsedTransitives(meta?.name ?? null, meta?.namespace ?? null, options.usedTransitives);

    // A PDV's primary osv_id may be a GHSA advisory while the taint engine
    // and CVE-targeted specs key on the CVE id. Match on the primary id plus
    // every alias so a GHSA-primary PDV still resolves its CVE-keyed flow.
    const candidateOsvIds: string[] = [];
    if (pdv.osv_id) candidateOsvIds.push(pdv.osv_id);
    if (Array.isArray(pdv.aliases)) {
      for (const a of pdv.aliases) {
        if (typeof a === 'string' && a && !candidateOsvIds.includes(a)) candidateOsvIds.push(a);
      }
    }

    const matchingFlows = flowsByDep.get(dependencyId) ?? [];
    const taintMatches: StoredFlow[] = [];
    {
      const seen = new Set<StoredFlow>();
      for (const osv of candidateOsvIds) {
        for (const f of taintByDepOsv.get(`${dependencyId}|${osv}`) ?? []) {
          if (!seen.has(f)) { seen.add(f); taintMatches.push(f); }
        }
      }
    }

    // Precision / noise reduction: a PDV earns `data_flow` only from flows that
    // are about IT — an un-attributed flow (osv_id null: atom or a
    // framework-generic engine flow, i.e. "the dep is reachable, CVE unknown")
    // or one of its own CVE ids — NOT from a sibling CVE's flow on the same
    // dependency. Without this, one confirmed CVE (e.g. lodash `_.template` →
    // CVE-2021-23337) inflates every OTHER lodash CVE to `data_flow`, even
    // though their vulnerable function (`_.trim`, `_.toNumber`, …) is never
    // reached — pure noise. Own-CVE flows that land here rather than in
    // `taintMatches` are suppressed / drift-demoted, still legitimate data-flow
    // evidence for this CVE, so they stay eligible.
    const ownOsvIds = new Set(candidateOsvIds);
    const dataFlowFlows = matchingFlows.filter((f) => !f.osv_id || ownOsvIds.has(f.osv_id));

    let level: string = 'module';
    let details: any = null;

    if (taintMatches.length > 0) {
      // A taint signal specific to this CVE on this specific dep —
      // either a hand-authored Phase 3 Semgrep rule (`semgrep_taint`,
      // legacy until M5 retires it) or a CVE-targeted FrameworkSpec
      // sink in the cross-file engine (`taint_engine`, Phase 6.5).
      // Trumps the heuristic ladder below regardless of usage slices.
      level = 'confirmed';
      const sources = [
        ...new Set(taintMatches.map((f) => f.reachability_source).filter((x): x is string => !!x)),
      ];
      details = {
        // rule_ids carry the Phase 3 rule id when present; taint_engine
        // rows leave it null. Keep the field for backwards compat with
        // any frontend reader that already iterates it.
        rule_ids: [...new Set(taintMatches.map((f) => f.rule_id).filter((x): x is string => !!x))],
        sources,
        flow_count: taintMatches.length,
        entry_points: taintMatches.map((f) => `${f.entry_point_file}:${f.entry_point_line}`),
        sink_methods: [...new Set(taintMatches.map((f) => f.sink_method).filter((x): x is string => !!x))],
      };
    } else if (dataFlowFlows.length > 0) {
      level = 'data_flow';
      details = {
        flow_count: dataFlowFlows.length,
        entry_points: dataFlowFlows.map((f) => `${f.entry_point_file}:${f.entry_point_line}`),
        sink_methods: [...new Set(dataFlowFlows.map((f) => f.sink_method).filter((x): x is string => !!x))],
        tags: [...new Set(dataFlowFlows.map((f) => f.entry_point_tag).filter((x): x is string => !!x))],
      };
    } else {
      // Dependency scope out-ranks the usage heuristic: a dev/test/build-scope
      // dependency's vulnerable code is by definition not on the production
      // call path. A genuine taint/data_flow signal (handled above) still wins;
      // this branch only runs when no flow was found.
      const scopeMeta = pdMetaMap.get(pdv.project_dependency_id);
      const devScoped = !!scopeMeta && isDevScoped(scopeMeta.scope);
      if (devScoped) {
        level = 'unreachable';
        details = {
          reason: 'dependency is dev/test/build scope — not on the production call path',
          scope: 'dev',
          verdict: 'dev_scope_unreachable',
        };
      }

      // Resolve the dep's name + namespace from `project_dependencies`, which
      // carries BOTH columns. The `dependencies` table has only `name` (no
      // `namespace`), so the previous `dependencies.select('name, namespace')`
      // failed with a 42703 (undefined_column) on every call — the error was
      // swallowed and depName silently became '', which broke every name-based
      // heuristic below (function-tier name match, embedded-runtime + framework
      // -runtime exemptions, callgraph artifactId bridging). Keying the cache on
      // project_dependency_id is correct: every PDV maps to exactly one PD row.
      let depName = depNameCache.get(pdv.project_dependency_id);
      let depNamespace = depNamespaceCache.get(pdv.project_dependency_id);
      if (depName === undefined || depNamespace === undefined) {
        const { data: pdRow } = await supabase
          .from('project_dependencies')
          .select('name, namespace')
          .eq('id', pdv.project_dependency_id)
          .single();
        depName = pdRow?.name ?? '';
        depNamespace = ((pdRow?.namespace || null) as string | null);
        depNameCache.set(pdv.project_dependency_id, depName as string);
        depNamespaceCache.set(pdv.project_dependency_id, depNamespace);
      }

      // Composer packages are `vendor/name` (cdxgen splits them into
      // namespace=`vendor` + name=`name`). Reconstruct the full name so the
      // Symfony DEV-ONLY demotion can match it against composer.lock's
      // `packages-dev` (which carries full `symfony/process`-style names).
      const composerPackage =
        depNamespace ? `${depNamespace.toLowerCase()}/${(depName as string).toLowerCase()}` : (depName as string).toLowerCase();

      // M2: CVE-targeted vulnerable-symbol verification. When a CVE-targeted
      // FrameworkSpec sink loaded for this PDV's CVE, we know the *specific*
      // vulnerable call pattern — verify it is on a call path instead of the
      // weaker "package name appears somewhere" heuristic below.
      let sinkPatterns: string[] | undefined;
      if (options.cveSinkPatterns) {
        for (const osv of candidateOsvIds) {
          const p = options.cveSinkPatterns.get(osv);
          if (p && p.length > 0) { sinkPatterns = p; break; }
        }
      }
      const symbolTokens = [...new Set((sinkPatterns ?? []).flatMap(extractSymbolTokens))];
      let symbolClassified = false;
      if (!devScoped && symbolTokens.length > 0) {
        const matchedToken = symbolTokens.find((tok) => allUsageStrings.some((s) => s.includes(tok)));
        const symMeta = pdMetaMap.get(pdv.project_dependency_id);
        if (matchedToken) {
          // The vulnerable symbol itself is referenced — a genuine function-tier hit.
          level = 'function';
          details = {
            reason: `vulnerable symbol "${matchedToken}" found in project usage`,
            vulnerable_symbols: symbolTokens,
          };
          symbolClassified = true;
        } else if (usageAnalysisProducedOutput && symMeta && symMeta.filesImporting > 0) {
          // The package is imported, but the CVE's specific vulnerable symbol
          // is on no call path the usage extractor could see — down-rank to
          // `unreachable`. Tunable knob: if the M4 corpus surfaces a
          // false-negative, demote this branch to `module` instead.
          level = 'unreachable';
          details = {
            reason: `vulnerable symbol(s) ${symbolTokens.join(', ')} not found on any call path`,
            vulnerable_symbols: symbolTokens,
          };
          symbolClassified = true;
        }
        // else: usage analysis incomplete, or the dep isn't imported at all —
        // fall through to the heuristic ladder; never invent unreachable here.
      }

      if (!devScoped && !symbolClassified) {
      if (depName && isDepUsed(depName)) {
        // Populate details with matching usage data (file, line, methods called)
        const lower = depName.toLowerCase();
        const dotted = lower.replace(/-/g, '.');
        const firstPart = lower.split('-')[0];
        const matchingUsages = (usages ?? []).filter((u: any) => {
          const t = (u.target_type ?? '').toLowerCase();
          const m = (u.resolved_method ?? '').toLowerCase();
          return t.includes(lower) || t.includes(dotted) || m.includes(lower) || m.includes(dotted)
            || (firstPart.length > 3 && (t.includes(firstPart) || m.includes(firstPart)));
        });
        // Bare-common-method guard (precision). The filter above matches on a
        // substring of the dependency name, so a CVE whose vulnerable call is a
        // bare, extremely-common word (`error`, `get`, `handle`, …) is lifted to
        // `function` the moment ANY same-named call exists anywhere — even one
        // on an unrelated class. (symfony/demo CVE-2020-5274 matched the Console
        // `SymfonyStyle->error()` at CheckRequirementsSubscriber.php:67, a call
        // that has nothing to do with the CVE's real TwigBundle sink.) Require a
        // genuine call-path signal before promoting: at least one matched usage
        // whose bare method is distinctive (not a common ambiguous word) OR whose
        // receiver/class carries a distinctive segment of the dependency name
        // (e.g. `…log4j.Logger.error` — `log4j` qualifies the bare `error`).
        // `firstPart`/`lower`/`dotted` tokens that are themselves a common bare
        // word (a dep literally named `send` / `error-handler`) can't self-
        // qualify — they must appear on the *receiver*, not just collide with a
        // bare method. Deserialization verbs (`readValue`, `load`, `unserialize`)
        // and library-specific calls (`template`, `safeLoad`) are distinctive, so
        // a CVE whose sink IS one of those still promotes. When ONLY bare common
        // methods matched, keep the finding at `module` (used-but-unproven) —
        // never invent a `function` verdict from an ambiguous name collision.
        const depQualifierTokens = [lower, dotted, firstPart].filter(
          (t, i, a) => t.length >= 4 && !COMMON_BARE_METHODS.has(t) && a.indexOf(t) === i,
        );
        const strongUsages = matchingUsages.filter((u: any) => {
          const method = bareMethodName(u.resolved_method);
          if (method && !COMMON_BARE_METHODS.has(method)) return true;
          const receiver = (u.target_type ?? '').toLowerCase();
          return depQualifierTokens.some((tok) => receiver.includes(tok));
        });
        if (strongUsages.length > 0) {
          level = 'function';
          const files = [...new Set(matchingUsages.map((u: any) => u.file_path).filter(Boolean))];
          const methods = [...new Set(matchingUsages.map((u: any) => u.resolved_method).filter(Boolean))];
          const locations = matchingUsages
            .filter((u: any) => u.file_path && u.line_number)
            .slice(0, 10)
            .map((u: any) => {
              const loc: any = { file: u.file_path, line: u.line_number, method: u.resolved_method ?? null };
              // Read actual source code around this line
              if (workspaceRoot) {
                const snippet = readCodeSnippet(workspaceRoot, u.file_path, u.line_number);
                if (snippet) loc.code_snippet = snippet;
              }
              return loc;
            });
          details = {
            usage_count: matchingUsages.length,
            impacted_paths: locations.length,
            files,
            methods_called: methods.slice(0, 20),
            locations,
          };
        }
      } else {
        // No usage slices referenced this dep. If it's a transitive dep that
        // nothing in the source imports, classify as `unreachable` (depscore
        // weight 0.0). Direct deps and deps with at least one import stay
        // `module` — we know they're touched, we just don't know the function.
        //
        // Fail-safe: if usage extraction did not produce output (crashed /
        // timed-out — astParsedSuccessfully=false), the absence of slices is
        // NOT evidence of unreachability. Never emit `unreachable` in that
        // case; floor the verdict at `module` so real vulns aren't hidden.
        // `meta` is hoisted to loop top (M1) — reuse it here.
        // v3 precision: when the taint-engine callgraph confirms a CallEdge
        // crossed into this dep's code, demote it from `unreachable` to
        // `module`. Handles the jackson-vs-idna case where a framework's
        // request handler calls jackson on every request even though the app
        // never `import`s it directly. `callgraphRan` treats an empty Set
        // identically to undefined — both mean "no signal", fall back to v2.
        const callgraphRan =
          options.usedTransitives !== undefined && options.usedTransitives.size > 0;
        const callgraphReachedThisDep =
          callgraphRan && depMatchesUsedTransitives(depName, depNamespace, options.usedTransitives!);
        // FRAMEWORK-MEDIATED USAGE (silence-FN recovery). A transitive dep that
        // no app file imports can still be exercised entirely through framework
        // DISPATCH — Spring's Jackson message converters (@RestController /
        // @ResponseBody / @RequestBody) and the actuator endpoints call jackson
        // on the request path with no first-party `import`. Declaring such a dep
        // an orphan `unreachable` is a false negative; floor it at `module`
        // (honest: used-but-unproven) instead. Conservative: fires only for deps
        // in the FRAMEWORK_MEDIATED table (jackson) when the project's dispatch
        // mechanism is present. Requires recognized maven signals — a non-maven
        // / unrecognized project yields mediated=false → unchanged behaviour.
        const frameworkMediatedResult = featureSignals
          ? evaluateFrameworkMediatedUsage({ depName, signals: featureSignals })
          : { mediated: false as const };
        const frameworkMediated = frameworkMediatedResult.mediated;
        // Ecosystems where source code MUST `use`/`import` a package to
        // exercise it. For these, files_importing_count === 0 is strong
        // negative evidence even on a directly-declared dep (composer.json /
        // pyproject.toml / package.json declares many libs the app never
        // actually wires up — e.g. dev-only utilities, optional features
        // gated behind feature flags, packages added for one prototype
        // commit and never removed). Excluded: `gem` (Rails autoload +
        // Bundler.require make files=0 unreliable), `maven`/`golang`/`cargo`/
        // `nuget` (tree-sitter import resolution is partial — we keep the
        // conservative transitive-only gate to avoid false negatives).
        const allowDirectDemotion =
          !!options.ecosystem && EXPLICIT_IMPORT_ECOSYSTEMS.has(options.ecosystem);
        // Client-SPA bundling floor: a browser bundle ships the whole prod
        // dependency graph, so `files_importing_count === 0` is NOT evidence
        // of unreachability for a prod/unknown-scope dep — its vulnerable
        // module is bundled and loaded (dompurify-via-monaco, react-router).
        // Only dev/build-only deps (not bundled) may stay `unreachable` here.
        const clientSpaBundledProdDep =
          !!options.isClientSpaProject && !!meta && (meta.scope ?? null) !== 'dev';
        const heuristicUnreachable =
          graphTrusted &&
          importAnalysisRan &&
          !!meta &&
          (!meta.isDirect || allowDirectDemotion) &&
          meta.filesImporting === 0 &&
          !isFrameworkEmbeddedRuntime(depName) &&
          !isFrameworkRuntimePackage(depName) &&
          !callgraphReachedThisDep &&
          !frameworkMediated &&
          !clientSpaBundledProdDep;
        // R1 — would-be-silenced transitive whose parent version is itself
        // >= `module` reachable (per the gated dependency_version_edges
        // closure above). Floor at `module` instead of `unreachable`: the dep
        // executes via its reachable parent (form-data←axios, qs←express).
        const transitiveOfReachable =
          heuristicUnreachable &&
          !!meta &&
          !!meta.versionId &&
          transitiveOfReachableVersionIds.has(meta.versionId);
        if (transitiveOfReachable) {
          level = 'module';
          details = {
            reason: 'reached through a reachable parent dependency (dependency_version_edges)',
            scope: 'transitive_of_reachable',
            verdict: 'transitive_of_reachable',
          };
        } else if (heuristicUnreachable) {
          level = 'unreachable';
          // A directly-declared dep with zero importers reads differently from a
          // transitive orphan — keep the reason honest. The `verdict`/`scope`
          // tags stay stable (frontend + snapshot consumers key on them).
          const directUnused = !!meta && meta.isDirect;
          details = {
            reason: directUnused
              ? 'declared in the manifest but imported by no source file'
              : 'no source file imports this transitive dependency',
            scope: 'orphan',
            verdict: 'orphan_transitive_unreachable',
          };
        } else if (callgraphReachedThisDep) {
          // The taint-engine callgraph traced a CallEdge into this dep's
          // code. Floor at `module` and stamp provenance so downstream
          // consumers (UI badges, EPD context, audit reports) can tell
          // this verdict apart from a generic direct-dep or
          // framework-embedded-runtime floor.
          level = 'module';
          details = {
            reason: `taint-engine callgraph confirmed a CallEdge into ${depName}`,
            scope: 'callgraph_reached',
            verdict: 'callgraph_reached_transitive',
            callgraph_evidence: { dep_name: depName },
          };

          // FEATURE-PRECONDITION GATE (reachability noise reduction).
          // The callgraph proves the framework runtime is reached, but a CVE in
          // a framework FEATURE the app never enables (WebSocket, AJP, HTTP/2,
          // WebDAV, Digest auth, a TLS cipher connector, a Spring Security
          // filter chain, script-template views, a Realm, CloudFoundry) is
          // provably unreachable. Demote module→unreachable ONLY when the CVE's
          // required feature is PROVABLY ABSENT from the scanned project — the
          // decision function is conservative and fails safe (an unrecognized
          // project, an ambiguous signal, or a summary that names no gated
          // feature all leave the finding at `module`). We only ever demote
          // here, never promote.
          if (featureSignals) {
            const demotion = evaluateFeaturePreconditionDemotion({
              depName,
              summary: (pdv.summary ?? null) as string | null,
              signals: featureSignals,
            });
            if (demotion.demote) {
              level = 'unreachable';
              details = {
                reason: `feature_precondition_absent: ${demotion.feature}`,
                scope: 'feature_precondition_absent',
                verdict: 'feature_precondition_absent',
                feature: demotion.feature,
                matched_summary_pattern: demotion.matchedPattern ?? null,
                demoted_from: 'callgraph_reached_transitive',
              };
            }
          }
        } else if (frameworkMediated) {
          // Reached purely via framework DISPATCH (Jackson message converters /
          // actuator endpoints) — no first-party import, but genuinely on the
          // request path at runtime. Honest floor at `module`; the always-on
          // promotion post-pass below may then lift a *specific* always-on CVE
          // (jackson-core's blocking parser on an exposed actuator JSON-body
          // endpoint) to a visible tier, while the sibling jackson CVEs stay
          // hidden here at `module`.
          level = 'module';
          details = {
            reason: `framework-mediated usage: ${frameworkMediatedResult.id ?? 'framework dispatch'}`,
            scope: 'framework_mediated',
            verdict: 'framework_mediated',
            ...(frameworkMediatedResult.id ? { framework_mediated_by: frameworkMediatedResult.id } : {}),
          };
        } else {
          // Direct deps, deps with >=1 import, and framework-embedded runtime
          // components (servlet container / template engine wired in by a
          // framework starter) floor at `module` — we know they run, we just
          // can't pin the vulnerable function to a call path.
          level = 'module';
        }
      }

      // PHP/SYMFONY FEATURE-PRECONDITION + DEV-ONLY DEMOTION (composer mirror of
      // the Java feature-precondition gate). Applies to ANY composer `module`
      // finding regardless of which branch above produced it (the coarse PHP
      // callgraph stamps nearly everything `callgraph_reached_transitive`, and
      // it overrides the SBOM dev-scope for transitive dev deps). Demote-only,
      // and runs BEFORE the always-on promotion post-pass so a demoted finding's
      // `unreachable` is respected by the `level === 'module'` promotion guard.
      // Fail-safe: unrecognized / non-Symfony signals refuse every demotion —
      // EXCEPT the dev-only lever below, which is composer-generic (keys on the
      // parsed composer.lock, not Symfony recognition) so it also fires on
      // Laravel / plain-PHP apps.
      if (symfonySignals && level === 'module') {
        // 1) Dev-only package (composer.lock `packages-dev`, not in `packages`) —
        //    never shipped to prod, so its CVE is genuinely unreachable. The
        //    strongest lever; needs no summary match. Framework-INDEPENDENT: the
        //    composer.lock packages-dev set is authoritative for any composer app,
        //    so this demotes a Laravel app's phpunit/debugbar/psysh/dev-scoped
        //    symfony/yaml too (the Symfony feature-precondition branch below stays
        //    recognition-gated).
        const devOnly = evaluateComposerDevOnlyDemotion({
          packageName: composerPackage,
          signals: symfonySignals,
        });
        if (devOnly.demote) {
          level = 'unreachable';
          details = {
            reason: `dev_only_dependency: ${devOnly.package} is composer.lock packages-dev (not installed in production)`,
            scope: 'dev',
            verdict: 'dev_only_dependency',
            package: devOnly.package,
            demoted_from:
              details && typeof details === 'object' && typeof details.verdict === 'string'
                ? details.verdict
                : 'module',
          };
        } else {
          // 2) Feature-precondition: the Symfony feature the CVE requires (Twig
          //    sandbox, untrusted-YAML parse, x509 firewall, `unanimous`
          //    strategy, HttpCache, PDO cache adapter, symfony/mailer) is
          //    provably absent from the scanned project.
          const phpDemotion = evaluateSymfonyFeaturePreconditionDemotion({
            depName,
            summary: (pdv.summary ?? null) as string | null,
            signals: symfonySignals,
          });
          if (phpDemotion.demote) {
            level = 'unreachable';
            details = {
              reason: `feature_precondition_absent: ${phpDemotion.feature}`,
              scope: 'feature_precondition_absent',
              verdict: 'feature_precondition_absent',
              feature: phpDemotion.feature,
              matched_summary_pattern: phpDemotion.matchedPattern ?? null,
              demoted_from: 'callgraph_reached_transitive',
            };
          }
        }
      }

      // LARAVEL FEATURE-PRECONDITION DEMOTION (a SECOND composer model beside the
      // Symfony block above — a Laravel app carries no symfony/framework-bundle, so
      // the Symfony model's `recognized` is false there). Demotes a laravel/framework
      // `module` finding to `unreachable` when its CVE's required feature is provably
      // ABSENT (no signed-URL API anywhere → GHSA-crmm unreachable, as on koel). The
      // composer-generic dev-only demotion already ran in the Symfony block. Runs
      // BEFORE the always-on promotion post-pass so a demoted finding's `unreachable`
      // is respected by the `level === 'module'` promotion guard. Fail-safe:
      // unrecognized / non-Laravel signals refuse every demotion.
      if (laravelSignals && level === 'module') {
        const laravelDemotion = evaluateLaravelFeaturePreconditionDemotion({
          depName,
          summary: (pdv.summary ?? null) as string | null,
          signals: laravelSignals,
        });
        if (laravelDemotion.demote) {
          level = 'unreachable';
          details = {
            reason: `feature_precondition_absent: ${laravelDemotion.feature}`,
            scope: 'feature_precondition_absent',
            verdict: 'feature_precondition_absent',
            feature: laravelDemotion.feature,
            matched_summary_pattern: laravelDemotion.matchedPattern ?? null,
            demoted_from: 'callgraph_reached_transitive',
          };
        }
      }

      // RUBY/RAILS FEATURE-PRECONDITION + DEV-ONLY DEMOTION (gem mirror of the
      // Java/PHP feature-precondition gates). Applies to ANY gem `module` finding
      // regardless of which branch produced it (the coarse Ruby callgraph stamps
      // nearly everything `callgraph_reached_transitive` / `transitive_of_reachable`
      // and overrides the SBOM dev-scope for transitive dev gems). Demote-only,
      // and runs BEFORE the always-on promotion post-pass so a demoted finding's
      // `unreachable` is respected by the `level === 'module'` promotion guard.
      // Fail-safe: unrecognized / non-Rails signals refuse every demotion.
      if (railsSignals && level === 'module') {
        // 1) Dev-only gem (Gemfile `:development`/`:test`/`:assets` group, direct
        //    declaration only) — never loaded in production, so its CVE is
        //    genuinely unreachable. The strongest lever; needs no summary match.
        const railsDevOnly = evaluateRailsDevOnlyDemotion({
          depName,
          signals: railsSignals,
        });
        if (railsDevOnly.demote) {
          level = 'unreachable';
          details = {
            reason: `dev_only_dependency: ${railsDevOnly.gem} is a Gemfile development/test/assets group gem (not loaded in production)`,
            scope: 'dev',
            verdict: 'dev_only_dependency',
            package: railsDevOnly.gem,
            demoted_from:
              details && typeof details === 'object' && typeof details.verdict === 'string'
                ? details.verdict
                : 'module',
          };
        } else {
          // 2) Feature-precondition: the Rails gem feature the CVE requires
          //    (Rack::Static/Directory/CommonLogger, Nokogiri XSLT/Schema/JRuby,
          //    Oj streaming parser, ActionPack dev pages, rails-ujs, the S3
          //    encryption client, a Windows-only bug) is provably absent.
          const railsDemotion = evaluateRailsFeaturePreconditionDemotion({
            depName,
            summary: (pdv.summary ?? null) as string | null,
            signals: railsSignals,
          });
          if (railsDemotion.demote) {
            level = 'unreachable';
            details = {
              reason: `feature_precondition_absent: ${railsDemotion.feature}`,
              scope: 'feature_precondition_absent',
              verdict: 'feature_precondition_absent',
              feature: railsDemotion.feature,
              matched_summary_pattern: railsDemotion.matchedPattern ?? null,
              demoted_from: 'callgraph_reached_transitive',
            };
          }
        }
      }

      // GO SUBPACKAGE-IMPORT DEMOTION (the Go-module mirror of the Rails/Symfony
      // feature-precondition gate, but PROVABLE via the import graph rather than a
      // summary heuristic). Applies to ANY `golang` module finding: the classifier
      // floors every imported Go module at `module` (golang is not an
      // EXPLICIT_IMPORT_ECOSYSTEM — its tree-sitter resolution is per-module, so
      // importing ANY subpackage keeps the whole module at `module`). Here we split
      // that using the exact subpackage import set: a CVE whose affected subpackage
      // (x/crypto/ssh, x/net/html) is provably not imported is genuinely
      // `unreachable`. Demote-only, runs BEFORE the promotion post-pass so a demoted
      // finding's `unreachable` is respected by the `level === 'module'` guard.
      // Fail-safe: unrecognized / truncated / non-Go signals refuse every demotion.
      if (goSignals && level === 'module') {
        const goDemotion = evaluateGoSubpackageDemotion({
          depName,
          summary: (pdv.summary ?? null) as string | null,
          signals: goSignals,
        });
        if (goDemotion.demote) {
          // Arc 2: prod_path demotions (requiresTransitiveProof rules) carry
          // their own honest verdict/reason; legacy first_party demotions stay
          // byte-stable (verdict strings are consumer contracts).
          const prodPath = goDemotion.proofStandard === 'prod_path';
          level = 'unreachable';
          details = {
            reason: prodPath
              ? `subpackage_not_on_prod_path: ${goDemotion.subpackage} is not imported by any first-party source file nor compiled in by any package on the production dependency path`
              : `subpackage_not_imported: ${goDemotion.subpackage} is not imported by any first-party source file`,
            scope: 'feature_precondition_absent',
            verdict: prodPath ? 'go_subpackage_not_on_prod_path' : 'go_subpackage_not_imported',
            feature: goDemotion.subpackage,
            matched_summary_pattern: goDemotion.matchedPattern ?? null,
            demoted_from:
              details && typeof details === 'object' && typeof details.verdict === 'string'
                ? details.verdict
                : 'module',
          };
        }
      }

      // PYTHON/DJANGO FEATURE-PRECONDITION + DEV-ONLY DEMOTION (pypi mirror of
      // the Rails/Symfony gates, plus a Go-style SUBMODULE import gate: pypi IS
      // an explicit-import ecosystem, so what survives at `module` is the
      // imported-but-unproven middle — and Python imports are per-PACKAGE while
      // CVEs are scoped to SUBMODULES (`from PIL import Image` keeps ALL of
      // pillow at `module`, including the ImageFont/PdfParser CVEs the app
      // provably never loads). Demote-only, runs BEFORE the promotion post-pass
      // so a demoted finding's `unreachable` is respected by the
      // `level === 'module'` guard. Fail-safe: unrecognized / truncated /
      // non-Django signals refuse every demotion.
      // Runs on `module` AND `function`: a feature-precondition whose vulnerable
      // submodule/API is IMPORT-GATED-absent is unreachable regardless of the
      // package's own tier (the usage classifier stamps `function` when the
      // package's TOP-LEVEL API is called — `tqdm(...)`/`FileLock(...)` — even
      // though the vulnerable submodule `tqdm.cli`/`SoftFileLock` is never
      // touched). The dev-only lever stays `module`-only (higher-risk on a
      // function-reached dep); the feature-precondition applies on `function`
      // ONLY for functionSafe rows.
      if (djangoSignals && (level === 'module' || level === 'function')) {
        // 1) Dev-only package (poetry dev groups / Pipfile dev-packages /
        //    requirements-dev.txt, prod scope wins) — never installed in
        //    production. Needed despite the explicit-import heuristic: a dev
        //    tool's own test files import it, so files_importing_count > 0.
        //    `module`-only: demoting a `function`-stamped dev dep is rarer + riskier.
        const djangoDevOnly =
          level === 'module'
            ? evaluateDjangoDevOnlyDemotion({ depName, signals: djangoSignals })
            : { demote: false as const };
        if (djangoDevOnly.demote) {
          level = 'unreachable';
          details = {
            reason: `dev_only_dependency: ${djangoDevOnly.package} is a dev-scope manifest dependency (not installed in production)`,
            scope: 'dev',
            verdict: 'dev_only_dependency',
            package: djangoDevOnly.package,
            demoted_from:
              details && typeof details === 'object' && typeof details.verdict === 'string'
                ? details.verdict
                : 'module',
          };
        } else {
          // 2) Feature-precondition: the feature the CVE requires (a pillow /
          //    cryptography submodule, django.contrib.humanize, Scrapy for the
          //    brotli path, the h11 parser, setuptools' PackageIndex, the tqdm
          //    CLI, the filelock SoftFileLock) is provably absent. Applies at
          //    `module` always; at `function` ONLY when every matched row is
          //    functionSafe (import-gated on the specific vulnerable submodule/API).
          const djangoDemotion = evaluateDjangoFeaturePreconditionDemotion({
            depName,
            summary: (pdv.summary ?? null) as string | null,
            signals: djangoSignals,
          });
          if (djangoDemotion.demote && (level === 'module' || djangoDemotion.functionSafe)) {
            const priorVerdict =
              details && typeof details === 'object' && typeof details.verdict === 'string'
                ? details.verdict
                : level;
            level = 'unreachable';
            details = {
              reason: `feature_precondition_absent: ${djangoDemotion.feature}`,
              scope: 'feature_precondition_absent',
              verdict: 'feature_precondition_absent',
              feature: djangoDemotion.feature,
              matched_summary_pattern: djangoDemotion.matchedPattern ?? null,
              demoted_from: priorVerdict,
            };
          }
        }
      }

      // Flask/FastAPI (pypi, 7th model) — same two-lever shape as the Django
      // block: dev-only demotion (module-only) then feature-precondition demotion
      // (module always; function only for functionSafe import-gated rows, e.g. a
      // multipart-parser CVE on a pure-JSON FastAPI API that has no form endpoints).
      if (flaskSignals && (level === 'module' || level === 'function')) {
        const flaskDevOnly =
          level === 'module'
            ? evaluateFlaskDevOnlyDemotion({ depName, signals: flaskSignals })
            : { demote: false as const };
        if (flaskDevOnly.demote) {
          level = 'unreachable';
          details = {
            reason: `dev_only_dependency: ${flaskDevOnly.package} is a dev-scope manifest dependency (not installed in production)`,
            scope: 'dev',
            verdict: 'dev_only_dependency',
            package: flaskDevOnly.package,
            demoted_from:
              details && typeof details === 'object' && typeof details.verdict === 'string'
                ? details.verdict
                : 'module',
          };
        } else {
          const flaskDemotion = evaluateFlaskFeaturePreconditionDemotion({
            depName,
            summary: (pdv.summary ?? null) as string | null,
            osvIds: candidateOsvIds,
            signals: flaskSignals,
          });
          if (flaskDemotion.demote && (level === 'module' || flaskDemotion.functionSafe)) {
            const priorVerdict =
              details && typeof details === 'object' && typeof details.verdict === 'string'
                ? details.verdict
                : level;
            level = 'unreachable';
            details = {
              reason: `feature_precondition_absent: ${flaskDemotion.feature}`,
              scope: 'feature_precondition_absent',
              verdict: 'feature_precondition_absent',
              feature: flaskDemotion.feature,
              matched_summary_pattern: flaskDemotion.matchedPattern ?? null,
              demoted_from: priorVerdict,
            };
          }
        }
      }

      // ALWAYS-ON FRAMEWORK-RUNTIME PROMOTION (reachability silence-FN
      // recovery — the mirror image of the feature-precondition DEMOTION gate
      // above). A CVE in framework code that is UNCONDITIONALLY on the request
      // path of a deployed web app (an embedded servlet-container request
      // parser / default servlet, Spring MVC's always-registered static-
      // resource handler) or that executes at every startup (a predictable
      // temp dir) is genuinely reachable, yet the heuristics above can only
      // reach `module` (the app never `import`s the servlet container). Promote
      // such a `module` finding to a visible tier so it isn't silenced.
      //
      // COMPOSITION with the demotion gate (critical — the two models must
      // never fight):
      //   1. The demotion already ran in the callgraph branch; if it fired the
      //      finding is at `unreachable`, so the `level === 'module'` guard
      //      below skips it — feature-gated-absent → unreachable WINS.
      //   2. For a `module` finding produced by a NON-callgraph branch (e.g. a
      //      framework-embedded-runtime floor) the demotion never ran, so we
      //      re-evaluate it here and REFUSE to promote anything it would
      //      silence. This also handles "feature present → genuinely reachable"
      //      correctly (demotion returns false → promotion proceeds).
      // Gated on the deployed-web-app signal — >= 1 HTTP-route entry point, OR the
      // Go deployed-HTTP-server signal (a caddy-shaped server routes via its own
      // module system, so the framework detectors emit 0 routes), OR the Django
      // deployed-app signal (a GraphQL-only Django app may emit 0 detected
      // routes). A library/CLI repo (no routes, no server) never gets a promotion.
      // The `orphan_transitive_unreachable` floor is a HEURISTIC ("direct dep
      // declared in the manifest but imported by no first-party file"), NOT a
      // taint proof — and it is wrong for a dep reached TRANSITIVELY through a
      // used consumer (e.g. idna via requests / email-validator: idna is pinned
      // directly yet only ever called by those libraries). A feature-gated
      // always-on framework promotion whose `requires` precondition holds proves
      // that transitive reach, so let such a promotion override the orphan floor.
      // Only the orphan HEURISTIC is overridable — a taint-proven unreachable is not.
      const isOrphanFloor =
        level === 'unreachable' &&
        !!details &&
        typeof details === 'object' &&
        details.verdict === 'orphan_transitive_unreachable';
      if (
        (level === 'module' || isOrphanFloor) &&
        (hasHttpRouteEntryPoint || goServerReachable || djangoDeployed || flaskDeployed)
      ) {
        const summaryStr = (pdv.summary ?? null) as string | null;
        const wouldDemote =
          (featureSignals
            ? evaluateFeaturePreconditionDemotion({
                depName,
                summary: summaryStr,
                signals: featureSignals,
              }).demote
            : false) ||
          // The gem models' demotions already ran above; this backstop refuses to
          // promote a gem finding whose Rails feature is provably absent or whose
          // gem is dev-only, in case it reached here via a non-callgraph branch.
          (railsSignals
            ? evaluateRailsDevOnlyDemotion({ depName, signals: railsSignals }).demote ||
              evaluateRailsFeaturePreconditionDemotion({
                depName,
                summary: summaryStr,
                signals: railsSignals,
              }).demote
            : false) ||
          // Go backstop: refuse to promote a finding whose affected subpackage is
          // provably not imported (its demotion already ran above).
          (goSignals
            ? evaluateGoSubpackageDemotion({
                depName,
                summary: summaryStr,
                signals: goSignals,
              }).demote
            : false) ||
          // Django backstop: refuse to promote a pypi finding whose package is
          // dev-only or whose required feature is provably absent.
          (djangoSignals
            ? evaluateDjangoDevOnlyDemotion({ depName, signals: djangoSignals }).demote ||
              evaluateDjangoFeaturePreconditionDemotion({
                depName,
                summary: summaryStr,
                signals: djangoSignals,
              }).demote
            : false) ||
          // Laravel backstop: refuse to promote a laravel/framework finding whose
          // required feature is provably absent (its demotion already ran above).
          (laravelSignals
            ? evaluateLaravelFeaturePreconditionDemotion({
                depName,
                summary: summaryStr,
                signals: laravelSignals,
              }).demote
            : false) ||
          // Flask/FastAPI backstop: refuse to promote a pypi finding whose package
          // is dev-only or whose required feature is provably absent (its demotion
          // already ran above; this catches non-callgraph branches).
          (flaskSignals
            ? evaluateFlaskDevOnlyDemotion({ depName, signals: flaskSignals }).demote ||
              evaluateFlaskFeaturePreconditionDemotion({
                depName,
                summary: summaryStr,
                osvIds: candidateOsvIds,
                signals: flaskSignals,
              }).demote
            : false);
        if (!wouldDemote) {
          // Try the Java/Spring always-on model first, then PHP/Symfony, then
          // Ruby/Rails. (Each language's demotion post-pass already ran above, so
          // a finding those would silence is already `unreachable` and never
          // reaches here — the `level === 'module'` guard skips it.)
          const promotion = evaluateAlwaysOnRuntimePromotion({
            depName,
            summary: summaryStr,
            hasHttpRouteEntryPoint,
            signals: featureSignals,
            osvIds: candidateOsvIds,
          });
          const phpPromotion =
            !promotion.promote && symfonySignals
              ? evaluateSymfonyAlwaysOnRuntimePromotion({
                  depName,
                  summary: summaryStr,
                  hasHttpRouteEntryPoint,
                  signals: symfonySignals,
                })
              : { promote: false as const };
          const railsPromotion =
            !promotion.promote && !phpPromotion.promote && railsSignals
              ? evaluateRailsAlwaysOnRuntimePromotion({
                  depName,
                  summary: summaryStr,
                  hasHttpRouteEntryPoint,
                  signals: railsSignals,
                  osvIds: candidateOsvIds,
                })
              : { promote: false as const };
          // Go always-on model (4th) — the x/net/http2 server stack on a deployed
          // Go HTTP server. Gated on its OWN `isDeployedHttpServer` signal (carried
          // inside goSignals), not `hasHttpRouteEntryPoint`, which is 0 for a
          // module-routed server.
          const goPromotion =
            !promotion.promote && !phpPromotion.promote && !railsPromotion.promote && goSignals
              ? evaluateGoAlwaysOnRuntimePromotion({
                  depName,
                  summary: summaryStr,
                  signals: goSignals,
                })
              : { promote: false as const };
          // Django always-on model (5th) — the always-on Django request path +
          // the upload-gated pillow WebP decoder. Passes the finding's full id
          // set (osv_id + aliases): PYSEC-2023-175's summary is the literal
          // string "Summary", so its row matches by advisory ID.
          const djangoPromotion =
            !promotion.promote &&
            !phpPromotion.promote &&
            !railsPromotion.promote &&
            !goPromotion.promote &&
            djangoSignals
              ? evaluateDjangoAlwaysOnRuntimePromotion({
                  depName,
                  summary: summaryStr,
                  osvIds: candidateOsvIds,
                  deployedWebApp: hasHttpRouteEntryPoint || djangoDeployed,
                  signals: djangoSignals,
                })
              : { promote: false as const };
          // Laravel always-on model (6th) — feature-gated laravel/framework
          // promotions: signed-URL path confusion (when the app USES signed URLs,
          // as monica does), file-validation bypass (when it validates uploads).
          const laravelPromotion =
            !promotion.promote &&
            !phpPromotion.promote &&
            !railsPromotion.promote &&
            !goPromotion.promote &&
            !djangoPromotion.promote &&
            laravelSignals
              ? evaluateLaravelAlwaysOnRuntimePromotion({
                  depName,
                  summary: summaryStr,
                  hasHttpRouteEntryPoint,
                  signals: laravelSignals,
                })
              : { promote: false as const };
          // Flask/FastAPI always-on model (7th) — feature-gated pypi promotions:
          // Werkzeug cookie/form parser (always-on / when the app has forms),
          // Starlette/python-multipart form parser (forms), h11 request parser
          // (uvicorn without httptools), Pydantic email-validator ReDoS + idna
          // encode (when the app validates request emails), PyJWT crit-header
          // decode (when the app decodes attacker JWTs).
          const flaskPromotion =
            !promotion.promote &&
            !phpPromotion.promote &&
            !railsPromotion.promote &&
            !goPromotion.promote &&
            !djangoPromotion.promote &&
            !laravelPromotion.promote &&
            flaskSignals
              ? evaluateFlaskAlwaysOnRuntimePromotion({
                  depName,
                  summary: summaryStr,
                  osvIds: candidateOsvIds,
                  deployedWebApp: hasHttpRouteEntryPoint || flaskDeployed,
                  signals: flaskSignals,
                })
              : { promote: false as const };
          const chosen = promotion.promote
            ? promotion
            : phpPromotion.promote
              ? phpPromotion
              : railsPromotion.promote
                ? railsPromotion
                : goPromotion.promote
                  ? goPromotion
                  : djangoPromotion.promote
                    ? djangoPromotion
                    : laravelPromotion.promote
                      ? laravelPromotion
                      : flaskPromotion.promote
                        ? flaskPromotion
                        : null;
          // Orphan-floor scoping: a finding that entered the promotion gate via the
          // `orphan_transitive_unreachable` HEURISTIC (isOrphanFloor) may ONLY be
          // promoted by a rule that PROVABLY implies the orphan dep is transitively
          // reached — i.e. one flagged `overridesOrphanFloor` (currently only the
          // Flask idna-encode rule, where email-validator→idna.encode is a fixed
          // transitive consumer). Any other match leaves it `unreachable`: a
          // workspace signal satisfied by a DIFFERENT library (e.g. python-jose
          // setting usesJwtAuth) must never surface an unused orphan pin (e.g. a
          // leftover PyJWT) as a false positive.
          const chosenOverridesOrphan =
            !!chosen && (chosen as { overridesOrphanFloor?: boolean }).overridesOrphanFloor === true;
          if (
            chosen && chosen.promote && chosen.promoteTo &&
            (!isOrphanFloor || chosenOverridesOrphan)
          ) {
            // Record the pre-promotion verdict honestly: the callgraph branch
            // stamps `callgraph_reached_transitive`; the embedded-runtime /
            // direct floor leaves details null → 'module'.
            const promotedFrom =
              details && typeof details === 'object' && typeof details.verdict === 'string'
                ? details.verdict
                : 'module';
            level = chosen.promoteTo;
            details = {
              reason: `always_on_framework_runtime: ${chosen.sink}`,
              scope: 'always_on_framework_runtime',
              verdict: 'always_on_framework_runtime',
              sink: chosen.sink,
              matched_summary_pattern: chosen.matchedPattern ?? null,
              promoted_from: promotedFrom,
              ...(chosen.threatTag ? { threat_tag: chosen.threatTag } : {}),
            };
          }
        }
      }
      }
    }

    const isReachable = level !== 'unreachable';

    // project_id / project_dependency_id / osv_id are the NOT-NULL columns the
    // upsert's (never-taken) INSERT arm needs; they carry each row's existing
    // values so ON CONFLICT (id) DO UPDATE is a pure update.
    pdvUpdates.push({
      id: pdv.id,
      project_id: projectId,
      project_dependency_id: pdv.project_dependency_id,
      osv_id: pdv.osv_id,
      reachability_level: level,
      reachability_details: details,
      is_reachable: isReachable,
    });

    // M1: snapshot this verdict + its classifier inputs into the silence-event
    // log. Additive — mirrors the value just pushed to `pdvUpdates`, never
    // alters it.
    silenceEvents.push({
      project_id: projectId,
      extraction_run_id: runId,
      pdv_id: pdv.id,
      project_dependency_id: pdv.project_dependency_id,
      dependency_id: dependencyId,
      osv_id: pdv.osv_id,
      reachability_level: level,
      is_reachable: isReachable,
      verdict: details && typeof details === 'object' ? (details.verdict ?? null) : null,
      graph_trusted: graphTrusted,
      ast_parsed: astParsedSuccessfully,
      ecosystem: options.ecosystem ?? null,
      files_importing_count: meta ? meta.filesImporting : null,
      is_direct: meta ? meta.isDirect : null,
      dev_scoped: meta ? isDevScoped(meta.scope) : null,
      callgraph_reached: cgReached,
      classifier_inputs: {
        used_transitives_count: options.usedTransitives?.size ?? null,
        callgraph_ran: (options.usedTransitives?.size ?? 0) > 0,
        is_client_spa: !!options.isClientSpaProject,
        // Arc 2: lets the M2 cross-run differ distinguish "gate refused because
        // the oracle was absent" from "the oracle answered". Counts only — no
        // package lists, no URLs.
        transitive_import_status: options.transitiveImports?.status ?? null,
        transitive_extracted_count: options.transitiveImports?.extractedPackages.size ?? null,
        transitive_failed_count: options.transitiveImports?.failedPackages.length ?? null,
      },
    });

    if (details) detailsSetCount++;
    updatedCount++;
    if (level in levelCounts) levelCounts[level]++;
  }

  for (let i = 0; i < pdvUpdates.length; i += 100) {
    const chunk = pdvUpdates.slice(i, i + 100);
    const { error: updateErr } = await supabase
      .from('project_dependency_vulnerabilities')
      .upsert(chunk, { onConflict: 'id' });
    if (updateErr) {
      console.error(
        `[REACHABILITY] Failed to upsert reachability for ${chunk.length} vuln(s) (chunk ${i}): ${updateErr.message}`,
      );
    }
  }

  // M1 silence-event log flush — a SECOND batched upsert, same Storage surface,
  // chunked by 100, idempotent within a run via (extraction_run_id, pdv_id).
  // PURE OBSERVABILITY: any failure (e.g. table missing on a not-yet-migrated DB,
  // code 42P01) must NEVER fail the run — warn + break, never throw. Same
  // fail-soft posture as the phase23-missing-column fallback above.
  for (let i = 0; i < silenceEvents.length; i += 100) {
    const chunk = silenceEvents.slice(i, i + 100);
    const { error: seErr } = await supabase
      .from('silence_events')
      .upsert(chunk, { onConflict: 'extraction_run_id,pdv_id' });
    if (seErr) {
      await logger.warn(
        'reachability',
        `silence_events write skipped (${chunk.length} rows): ${seErr.message}`,
      );
      break; // table absent / write rejected ⇒ the rest will fail the same way
    }
  }

  // Surface per-level counts so on-call can answer "did any vuln actually get
  // promoted to confirmed in this run?" without running ad-hoc SQL.
  const summary =
    `confirmed=${levelCounts.confirmed} data_flow=${levelCounts.data_flow} ` +
    `function=${levelCounts.function} module=${levelCounts.module} ` +
    `unreachable=${levelCounts.unreachable}`;
  await logger.info('reachability', `Classified ${updatedCount} vuln(s): ${summary}`);

  if (process.env.DEPTEX_CLI_MODE !== '1') {
    console.log(`[REACHABILITY] Updated ${updatedCount} vulns, ${detailsSetCount} with details, ${allUsageStrings.length} usage strings available`);
  }
}

// ---------------------------------------------------------------------------
// Compute files_importing_count from atom usage slices (all ecosystems)
// ---------------------------------------------------------------------------

// Python packages where pip name differs from import name
const PYPI_IMPORT_ALIASES: Record<string, string[]> = {
  pillow: ['pil'],
  pyyaml: ['yaml'],
  'beautifulsoup4': ['bs4'],
  'scikit-learn': ['sklearn'],
  'opencv-python': ['cv2'],
  'opencv-python-headless': ['cv2'],
  'python-dateutil': ['dateutil'],
  'python-dotenv': ['dotenv'],
  'python-jose': ['jose'],
  'python-multipart': ['multipart'],
  'pyjwt': ['jwt'],
  'pycryptodome': ['crypto', 'cryptodome'],
  'pymysql': ['pymysql'],
  'psycopg2-binary': ['psycopg2'],
  'protobuf': ['google.protobuf'],
  'attrs': ['attr'],
  'ruamel.yaml': ['ruamel'],
};

/**
 * Check if a usage slice entry matches a dependency name.
 * Returns true if the target_type or resolved_method contains the dep name
 * using fuzzy matching (hyphen-to-dot, first-segment, aliases, etc.)
 */
function usageMatchesDep(
  targetType: string,
  resolvedMethod: string,
  depNameLower: string,
  depNameDotted: string,
  depFirstPart: string,
  importAliases?: string[],
): boolean {
  const t = targetType.toLowerCase();
  const m = resolvedMethod.toLowerCase();
  // Direct name match
  if (t.includes(depNameLower) || m.includes(depNameLower)) return true;
  // Dotted variant (Java: jackson-databind → jackson.databind)
  if (depNameDotted !== depNameLower && (t.includes(depNameDotted) || m.includes(depNameDotted))) return true;
  // First segment for compound names (log4j-core → log4j), only if segment is meaningful (>3 chars)
  if (depFirstPart.length > 3 && (t.includes(depFirstPart) || m.includes(depFirstPart))) return true;
  // Python import aliases (pillow → PIL, pyyaml → yaml, etc.)
  if (importAliases) {
    for (const alias of importAliases) {
      if (t.includes(alias) || m.includes(alias)) return true;
    }
  }
  // Strip common Python prefixes: py*, python-* → check remainder
  if (depNameLower.startsWith('py') && depNameLower.length > 3) {
    const stripped = depNameLower.slice(2);
    if (t.includes(stripped) || m.includes(stripped)) return true;
  }
  return false;
}

/**
 * Supplemental file-count pass that runs after the tree-sitter extractor has
 * already populated `project_dependencies.files_importing_count` and written
 * `project_usage_slices`. This re-reads the slices with looser name-matching
 * (package-name variants, PyPI distribution↔module aliases) so transitive
 * usages the extractor couldn't map directly still get counted.
 *
 * For npm we treat the tree-sitter count as the floor and only bump upward;
 * for other ecosystems we overwrite with the looser count (or NULL if no
 * slices exist) since the extractor may not have resolved the full import set.
 */
export async function computeImportCountsFromUsageSlices(
  projectId: string,
  runId: string,
  ecosystem: string,
  supabase: Storage,
  logger: LogLike,
): Promise<void> {
  // npm gets special treatment: tree-sitter extractor already ran the precise
  // AST pass, so we never downgrade its count — only bump it upward if this
  // looser matcher finds more files.
  const isNpm = ecosystem === 'npm';

  // Fetch all direct project dependencies for this run only
  const { data: projectDeps } = await supabase
    .from('project_dependencies')
    .select('id, name, dependency_id, files_importing_count')
    .eq('project_id', projectId)
    .eq('is_direct', true)
    .eq('last_seen_extraction_run_id', runId);

  if (!projectDeps || projectDeps.length === 0) return;

  // Fetch usage slices for this run only
  const { data: usages } = await supabase
    .from('project_usage_slices')
    .select('target_type, resolved_method, file_path')
    .eq('project_id', projectId)
    .eq('extraction_run_id', runId);

  if (!usages || usages.length === 0) {
    // No usage data — for non-npm, explicitly set null to indicate "not analyzed".
    // For npm, the tree-sitter extractor's count is authoritative, so don't overwrite.
    if (!isNpm) {
      for (const pd of projectDeps) {
        if (pd.files_importing_count === 0) {
          await supabase
            .from('project_dependencies')
            .update({ files_importing_count: null })
            .eq('id', pd.id);
        }
      }
      await logger.info('import_analysis', 'No usage slices available — import counts not determined');
    }
    return;
  }

  // Pre-compute name variants for each dependency
  const depVariants = projectDeps.map((pd: any) => {
    const lower = (pd.name ?? '').toLowerCase();
    const dotted = lower.replace(/-/g, '.');
    const firstPart = lower.split('-')[0];
    const aliases = PYPI_IMPORT_ALIASES[lower] ?? undefined;
    return { id: pd.id, name: pd.name, lower, dotted, firstPart, aliases, existingCount: pd.files_importing_count ?? 0 };
  });

  // For each usage, find which dependency it belongs to, and track unique files
  const depFileMap = new Map<string, Set<string>>(); // dep id → set of file paths

  for (const usage of usages) {
    const targetType = usage.target_type ?? '';
    const resolvedMethod = usage.resolved_method ?? '';
    const filePath = usage.file_path;
    if (!filePath || (!targetType && !resolvedMethod)) continue;

    for (const dep of depVariants) {
      if (!dep.lower) continue;
      if (usageMatchesDep(targetType, resolvedMethod, dep.lower, dep.dotted, dep.firstPart, dep.aliases)) {
        if (!depFileMap.has(dep.id)) depFileMap.set(dep.id, new Set());
        depFileMap.get(dep.id)!.add(filePath);
      }
    }
  }

  // Update files_importing_count and persist file paths into project_dependency_files
  let updatedCount = 0;
  for (const dep of depVariants) {
    const fileSet = depFileMap.get(dep.id);
    const newCount = fileSet ? fileSet.size : 0;

    if (isNpm) {
      // npm: only bump upward — never downgrade the tree-sitter extractor's count.
      if (newCount > dep.existingCount) {
        await supabase
          .from('project_dependencies')
          .update({ files_importing_count: newCount })
          .eq('id', dep.id);
        updatedCount++;
      }
    } else {
      // Non-npm: set the count directly — the looser matcher is authoritative.
      await supabase
        .from('project_dependencies')
        .update({ files_importing_count: newCount > 0 ? newCount : null })
        .eq('id', dep.id);
      updatedCount++;
    }

    // Persist file paths into project_dependency_files so analyze-usage can fetch real code
    if (fileSet && fileSet.size > 0) {
      const rows = [...fileSet].map(fp => ({ project_dependency_id: dep.id, file_path: fp, extraction_run_id: runId }));
      await supabase
        .from('project_dependency_files')
        .upsert(rows, { onConflict: 'project_dependency_id,file_path,extraction_run_id' });
    }
  }

  // Internal metric — not shown in user-facing logs
}


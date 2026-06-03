/**
 * STEP: SBOM (CRITICAL).
 *
 * Runs cdxgen to produce a CycloneDX SBOM, uploads it to project-imports
 * storage (non-fatal failure path), parses it, patches devDependency
 * detection from on-disk manifest cross-reference, and aborts the pipeline if
 * the SBOM yields zero dependencies (a hard signal something's wrong with the
 * manifest path or supported-ecosystem assumption).
 *
 * Returns the parsed SBOM rows + bom-ref→name@version map so `deps_sync` can
 * upsert without re-parsing.
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { runStage } from '../pipeline-stage-runner';
import { logStepError, classifyError } from '../with-timeout';
import { ScanFailedError } from '../scan-errors';
import {
  parseSbom,
  getBomRefToNameVersion,
  patchDevDependencies,
  npmManifestDeclaresDependencies,
  type ParsedSbomDep,
  type ParsedSbomRelationship,
} from '../sbom';
import { recoverDirectSet, applyRecoveredDirectSet } from '../dependency-graph';
import { resolveGoTransitives } from '../transitive-resolvers/go';
import { resolvePypiTransitives } from '../transitive-resolvers/pypi';
import { resolveComposerTransitives } from '../transitive-resolvers/composer';
import { resolveRubygemsTransitives } from '../transitive-resolvers/rubygems';
import { retry, updateStep, setError, classifyCdxgenError } from '../pipeline-helpers';
import type { PipelineContext } from '../pipeline-types';

function runCdxgen(workspacePath: string, ecosystem?: string): string {
  const outPath = path.join(workspacePath, 'sbom.json');
  // Use relative -o and cwd so cdxgen always writes to workspacePath/sbom.json regardless of
  // how it resolves paths (some environments resolve -o relative to process cwd).
  //
  // `--deep` triggers cdxgen's evidence-gathering pass, which recursively git-clones every
  // transitive dependency to scrape license / provenance metadata. On real OSS repos
  // (express, fastify, next.js, ...) this blows past the 10-15min step budget. We default to
  // shallow SBOM generation; production extraction-worker jobs can opt back into the deep
  // pass by setting `CDXGEN_DEEP=1`. The CLI (DEPTEX_CLI_MODE=1) and OSS corpus harness
  // never set it, so they get the fast path.
  const deepEnabled = process.env.CDXGEN_DEEP === '1' || /^true$/i.test(process.env.CDXGEN_DEEP ?? '');
  const args = [
    '--yes', '@cyclonedx/cdxgen',
    '--path', '.',
    '-o', 'sbom.json',
  ];
  if (deepEnabled) {
    // `--profile research` is only useful in combination with `--deep` (it enables the
    // extra evidence collectors). Keep them paired so the default path stays fully shallow.
    args.push('--profile', 'research', '--deep');
  }
  if (ecosystem) {
    args.push('-t', ecosystem);
  }
  try {
    execSync(`npx ${args.join(' ')}`, {
      cwd: workspacePath,
      stdio: 'pipe',
      timeout: 15 * 60 * 1000,
      maxBuffer: 50 * 1024 * 1024,
    });
  } catch (e: any) {
    throw new Error(`cdxgen failed: ${e.message}`);
  }
  if (!fs.existsSync(outPath)) {
    throw new Error(`cdxgen completed but did not create sbom.json at ${outPath}`);
  }
  return outPath;
}

export interface SbomOutput {
  dependencies: ParsedSbomDep[];
  relationships: ParsedSbomRelationship[];
  bomRefMap: ReturnType<typeof getBomRefToNameVersion>;
}

export async function doSbom(ctx: PipelineContext): Promise<SbomOutput> {
  const { supabase, job, projectId, log, workspaceRoot, jobEcosystem, runId } = ctx;
  await updateStep(supabase, projectId, 'sbom');
  await log.info('sbom', 'Generating software bill of materials...');

  const sbomStart = Date.now();
  const sbomPath = (await runStage({
    name: 'sbom',
    timeoutMs: 15 * 60_000,
    fn: () => retry(() => Promise.resolve(runCdxgen(workspaceRoot, jobEcosystem)), 'cdxgen'),
    supabase,
    jobId: job.jobId,
    projectId,
    log,
    severity: 'error',
    onError: async ({ err }) => {
      const userMsg = classifyCdxgenError((err as Error).message ?? String(err));
      await log.error('sbom', userMsg, err);
      await setError(supabase, projectId, userMsg);
      return { rethrow: true, throwAs: new ScanFailedError(userMsg) };
    },
  })) as string;

  const sbomContent = fs.readFileSync(sbomPath, 'utf8');
  const sbom = JSON.parse(sbomContent) as Parameters<typeof parseSbom>[0];

  const storagePath = `${projectId}/${runId}/sbom.json`;
  try {
    await supabase.storage
      .from('project-imports')
      .upload(storagePath, sbomContent, {
        contentType: 'application/json',
        upsert: true,
      });
  } catch (e: any) {
    await log.warn('sbom', `SBOM storage upload failed; downstream tools may reference missing SBOM: ${e?.message ?? e}`);
    if (job.jobId) {
      const { code, message, stack } = classifyError(e);
      await logStepError(supabase, {
        jobId: job.jobId,
        projectId,
        step: 'sbom',
        code,
        message,
        stack,
        severity: 'warn',
      });
    }
  }

  const { dependencies, relationships, rawComponentCount, droppedVersionlessCount, directSetTrusted } =
    parseSbom(sbom);
  const bomRefMap = getBomRefToNameVersion(sbom);

  // Record whether the cdxgen edge graph was wired — deps_sync keeps
  // transitive dev-scope sticky when it wasn't (propagation skipped).
  ctx.sbomGraphWired = directSetTrusted;

  // cdxgen sometimes returns an unwired CycloneDX `dependencies` graph (no
  // root node / no edges). When that happens `is_direct` on every dep is
  // meaningless, which structurally disables the `unreachable` reachability
  // tier. Rebuild the direct set from the ecosystem's manifest / resolved
  // tree before anything downstream reads it. If recovery is unavailable,
  // `graphTrusted` stays false so the classifier floors at `module` rather
  // than guessing `unreachable`.
  if (!directSetTrusted) {
    try {
      const recovery = recoverDirectSet(jobEcosystem, workspaceRoot);
      if (recovery) {
        const changed = applyRecoveredDirectSet(dependencies, recovery, jobEcosystem);
        ctx.graphTrusted = true;
        await log.info(
          'sbom',
          `cdxgen dependency graph unwired — recovered direct set via ${recovery.method} (${changed} dep(s) reclassified)`,
        );
      } else {
        ctx.graphTrusted = false;
        await log.warn(
          'sbom',
          'cdxgen dependency graph unwired and no manifest/tree available for recovery — reachability floored at module',
        );
      }
    } catch (e: any) {
      ctx.graphTrusted = false;
      await log.warn('sbom', `dependency graph recovery failed (non-fatal): ${e?.message ?? e}`);
    }
  }

  // v3 precision arc — recover transitives via a per-ecosystem resolver
  // when cdxgen emitted a direct-deps-only SBOM. cdxgen --without-deep on
  // gomod / pypi returns the manifest's top-level requires only; without
  // transitives the reachability classifier can't flag `unreachable` at
  // all (it keys on `!is_direct`). The resolver runs ONLY when the entire
  // dep list lacks any !is_direct row, so deep SBOMs (cdxgen --deep on,
  // future cdxgen versions, etc.) are not double-resolved.
  // Match both the cdxgen `-t` flag values (`gomod`, `pypi`) AND the
  // ecosystem strings the corpus harness / scan_jobs.type may carry
  // (`golang`, `pypi`). cdxgen normalizes `-t go` → `golang`-tagged PURLs
  // and `-t gomod` → `golang`-tagged PURLs too; the SBOM PURL ecosystem is
  // always `golang`, but the *job* ecosystem string varies depending on
  // which surface emitted it.
  const RESOLVER_ECOSYSTEMS = new Set(['gomod', 'golang', 'pypi', 'composer', 'gem']);
  const isGo = jobEcosystem === 'gomod' || jobEcosystem === 'golang';
  const isComposer = jobEcosystem === 'composer';
  const isRubygems = jobEcosystem === 'gem';
  // cdxgen-without-`--deep` sometimes emits a sprinkle of transitive rows
  // alongside the directs (e.g. caddy at v2.4.6 returns 31 deps with mixed
  // is_direct flags but the real transitive closure is ~250). The old
  // `every is_direct` gate skipped the resolver in that case. Loosen to:
  // fire when the !is_direct ratio is suspiciously low (< 20% of all rows)
  // — that catches the partial-shallow case while still skipping deep SBOMs
  // where cdxgen already walked the full tree.
  const directRatio =
    dependencies.length > 0
      ? dependencies.filter((d) => d.is_direct === true).length / dependencies.length
      : 1;
  const looksShallow = directRatio > 0.8;
  // composer + gem ALWAYS run the resolver when the lockfile is present,
  // regardless of how complete cdxgen's SBOM looks. composer.lock and
  // Gemfile.lock are deterministic and exhaustive — they are strictly
  // better than cdxgen's partial transitive walk, and the resolver's
  // name@version dedup already prevents double-counting. For go + pypi we
  // keep `looksShallow` as the eligibility gate since their resolvers
  // shell out (go list / pip --dry-run) and we don't want to double-pay
  // on already-deep SBOMs.
  const resolverEligible =
    RESOLVER_ECOSYSTEMS.has(jobEcosystem) &&
    dependencies.length > 0 &&
    (looksShallow || isComposer || isRubygems);
  if (resolverEligible) {
    const before = dependencies.length;
    try {
      const result = isGo
        ? await resolveGoTransitives(workspaceRoot)
        : isComposer
        ? await resolveComposerTransitives(workspaceRoot)
        : isRubygems
        ? await resolveRubygemsTransitives(workspaceRoot)
        : await resolvePypiTransitives(workspaceRoot);
      if (result === null) {
        await log.info(
          'sbom',
          `transitive_resolver_skipped { ecosystem: ${jobEcosystem}, reason: no_manifest }`,
        );
      } else {
        // Dedup by `name@version` against cdxgen-emitted rows — cdxgen
        // wins on coords (it carries license + bom-ref metadata the
        // resolver doesn't). Resolver fills only the gap.
        const seen = new Set(dependencies.map((d) => `${d.name}@${d.version}`));
        let added = 0;
        for (const dep of result.deps) {
          const key = `${dep.name}@${dep.version}`;
          if (seen.has(key)) continue;
          seen.add(key);
          dependencies.push(dep);
          added++;
        }
        // Resolver relationships join onto resolver-emitted bomRefs only —
        // appending unconditionally is safe because cdxgen relationships
        // key on different bomRefs entirely.
        for (const rel of result.relationships) relationships.push(rel);
        await log.info(
          'sbom',
          `transitive_resolver_invoked { ecosystem: ${jobEcosystem}, source: ${result.source}, raw: ${result.rawModuleCount}, added: ${added}, before: ${before}, after: ${dependencies.length} }`,
        );

        // Sidecar: write the resolver-added purls to a JSON file in
        // depscan-reports/ so the OSV-API fallback step can query OSV for
        // them too. cdxgen's SBOM only carries direct deps for the shallow
        // ecosystems, so without this step the resolver expands the dep
        // tree for the reachability classifier but those transitive deps
        // never get vuln-queried — defeating the per-eco lift.
        try {
          const reportsDir = path.join(workspaceRoot, 'depscan-reports');
          fs.mkdirSync(reportsDir, { recursive: true });
          const eco = isGo
            ? 'golang'
            : isComposer
            ? 'composer'
            : isRubygems
            ? 'gem'
            : 'pypi';
          const extraPurls = result.deps
            .map((d) => {
              if (!d.name || !d.version) return null;
              // composer PURLs require the `vendor/name` form; the
              // composer resolver carries `namespace` for exactly this.
              if (isComposer) {
                if (!d.namespace) return null;
                return `pkg:composer/${d.namespace}/${d.name}@${d.version}`;
              }
              if (isRubygems) return `pkg:gem/${d.name}@${d.version}`;
              if (isGo) return `pkg:golang/${d.name}@${d.version}`;
              return `pkg:pypi/${d.name}@${d.version}`;
            })
            .filter((p): p is string => p !== null);
          fs.writeFileSync(
            path.join(reportsDir, 'osv-extra-purls.json'),
            JSON.stringify({ ecosystem: eco, purls: extraPurls }, null, 2),
          );
        } catch (sidecarErr) {
          // Sidecar is a perf optimization — failure here just means OSV
          // won't query the resolver-added transitives. Log and continue.
          await log.warn(
            'sbom',
            `transitive_resolver_sidecar_write_failed { reason: ${(sidecarErr as Error).message} }`,
          );
        }
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      await log.warn(
        'sbom',
        `transitive_resolver_failed { ecosystem: ${jobEcosystem}, reason: ${msg} } — continuing with cdxgen-only SBOM`,
      );
    }
  }

  // Patch devDependency detection by cross-referencing with manifest files,
  // then propagate dev-scope transitively over the dependency graph. The
  // original `directSetTrusted` (not ctx.graphTrusted) gates propagation —
  // it specifically reports whether the cdxgen `dependencies` graph that
  // `relationships` is derived from is wired.
  try {
    patchDevDependencies(dependencies, workspaceRoot, jobEcosystem, relationships, directSetTrusted);
  } catch (e: any) {
    await log.warn('sbom', `devDependency detection failed (non-fatal): ${e.message}`);
  }

  if (droppedVersionlessCount > 0) {
    await log.warn(
      'sbom',
      `${droppedVersionlessCount} SBOM component(s) dropped with no resolvable version — upstream package manager likely failed to resolve (see resolve step warnings)`,
    );
  }

  if (dependencies.length === 0) {
    // We ended up with zero usable dependencies. Two failure shapes collapse
    // here:
    //   1. cdxgen emitted components but every one was versionless
    //      (rawComponentCount > 0, all dropped above) — the package manager
    //      resolved partially but couldn't pin versions.
    //   2. cdxgen emitted nothing at all (rawComponentCount === 0). For npm
    //      specifically this is the "one unresolvable/unpublished dep aborts
    //      the whole `npm install`, and with no committed lockfile cdxgen has
    //      nothing to read" case — a single bad dependency zeroes the tree.
    //
    // If the project actually declared dependencies we couldn't resolve, that's
    // a FAILED scan, not a clean one — every dependency-level scanner (SCA,
    // reachability, malicious-package) would silently report nothing. Fail loudly
    // so the user fixes their manifest, rather than shipping a false "all clear".
    //
    // The trigger is "we declared deps but resolved none", NOT "the install
    // command errored": real repos with a committed lockfile scan fine off the
    // lockfile even when `npm install` hiccups. rawComponentCount > 0 already
    // proves deps were declared (any ecosystem); for npm we additionally parse
    // package.json because its empty SBOM carries no components to count.
    const declaredButUnresolved =
      rawComponentCount > 0 ||
      (jobEcosystem === 'npm' && npmManifestDeclaresDependencies(workspaceRoot));

    if (declaredButUnresolved) {
      const userMsg =
        rawComponentCount > 0
          ? `Unable to resolve your dependencies: the SBOM listed ${rawComponentCount} package(s) but none had a resolvable version. Your package manager likely failed to install a dependency. Make sure your manifest and lockfile are valid and every listed version exists, then re-scan.`
          : `Unable to resolve any dependencies from your manifest. A dependency is likely unpublished, yanked, or otherwise uninstallable (which aborts the whole install). Make sure your manifest and lockfile are valid and every listed dependency and version exists, then re-scan.`;
      await log.error('sbom', userMsg);
      if (job.jobId) {
        await logStepError(supabase, {
          jobId: job.jobId,
          projectId,
          step: 'sbom',
          code: 'dependencies_unresolved',
          message: userMsg,
          severity: 'error',
        });
      }
      // ScanFailedError (not a plain Error): an unresolvable manifest is a
      // recorded, user-facing project outcome — the job loop skips Sentry for it.
      throw new ScanFailedError(userMsg);
    }

    // No manifest, or a manifest that genuinely declares zero dependencies — a
    // docs/config repo or a zero-dep app. Nothing to fail on; SAST + secret
    // scans still cover the code.
    await log.warn(
      'sbom',
      'No dependencies to analyze (no manifest, or an empty dependency list) — continuing with code and secret scanning only',
    );
  }

  await log.success('sbom', 'SBOM generated', Date.now() - sbomStart, {
    components: dependencies.length,
    relationships: relationships.length,
    raw_component_count: rawComponentCount,
    dropped_versionless_count: droppedVersionlessCount,
  });

  return { dependencies, relationships, bomRefMap };
}

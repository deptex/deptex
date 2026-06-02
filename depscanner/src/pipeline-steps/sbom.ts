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
import { logStepError, classifyError, markDegraded } from '../with-timeout';
import {
  parseSbom,
  getBomRefToNameVersion,
  patchDevDependencies,
  recoverNpmManifestDeps,
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

/**
 * Whether the ecosystem's manifest file exists on disk. Used to gate the
 * degraded-on-empty-SBOM flag: an empty SBOM with a manifest present means a
 * resolver/cdxgen failure (degraded), whereas no manifest means there was
 * genuinely nothing to scan (not degraded). Mirrors the manifest names the
 * resolve step keys on.
 */
function hasKnownManifest(workspaceRoot: string, ecosystem: string): boolean {
  const manifests: Record<string, string[]> = {
    npm: ['package.json'],
    maven: ['pom.xml'],
    golang: ['go.mod'],
    gomod: ['go.mod'],
    pypi: ['requirements.txt', 'pyproject.toml', 'setup.py'],
    cargo: ['Cargo.toml'],
    gem: ['Gemfile'],
    composer: ['composer.json'],
  };
  const names = manifests[ecosystem];
  if (!names) return false;
  return names.some((n) => fs.existsSync(path.join(workspaceRoot, n)));
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
      return { rethrow: true, throwAs: new Error(userMsg) };
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
    // Two cases collapse into one symptom here:
    //   1. SBOM was truly empty (rawComponentCount == 0) — manifest unsupported
    //      or genuinely zero-dep project (e.g. a small CLI tool, a library).
    //   2. SBOM had components but they all had no version (rawComponentCount > 0,
    //      all dropped above) — upstream resolver failed (e.g. bundler not in
    //      image, npm install broke on a single unresolvable / unpublished dep).
    //
    // Before giving up, attempt a best-effort manifest parse so one bad
    // dependency doesn't zero the ENTIRE SBOM (npm only for now). cdxgen's edge
    // graph is absent for recovered deps, so mark the graph unwired: the
    // reachability classifier floors at `module` (never guesses `unreachable`).
    let recovered = 0;
    if (jobEcosystem === 'npm') {
      try {
        for (const dep of recoverNpmManifestDeps(workspaceRoot)) {
          dependencies.push(dep);
          recovered++;
        }
        if (recovered > 0) {
          ctx.graphTrusted = true;
          ctx.sbomGraphWired = false;
          await log.info(
            'sbom',
            `Recovered ${recovered} direct dependency(ies) from package.json after the SBOM came back empty`,
          );
        }
      } catch (e: any) {
        await log.warn('sbom', `Manifest-parse fallback failed (non-fatal): ${e?.message ?? e}`);
      }
    }

    // Flag the run degraded — a security-critical step produced no/partial
    // dependency signal. rawComponentCount>0 means the resolver failed
    // (components present but versionless); ==0 with a known manifest on disk
    // means cdxgen + resolve produced nothing despite there being deps to find.
    // A genuinely manifest-less / zero-dep repo (nothing to scan) is NOT flagged.
    const manifestPresent = hasKnownManifest(workspaceRoot, jobEcosystem);
    if (rawComponentCount > 0 || manifestPresent) {
      await markDegraded(ctx, {
        step: 'sbom',
        code: rawComponentCount > 0 ? 'sbom_empty_with_components' : 'sbom_empty_no_manifest',
        detail:
          rawComponentCount > 0
            ? `SBOM had ${rawComponentCount} component(s) but none had a resolvable version — the package manager likely failed to resolve a dependency`
            : 'cdxgen produced an empty SBOM despite a manifest being present',
      });
    }

    const reason =
      rawComponentCount > 0
        ? `SBOM had ${rawComponentCount} component(s) but none had a resolvable version`
        : 'SBOM is empty';
    await log.warn(
      'sbom',
      recovered > 0
        ? `cdxgen returned no usable dependencies (${reason}) — recovered ${recovered} direct dep(s) from the manifest; results are partial`
        : `No dependencies parsed (${reason}) — continuing without dependency analysis; SAST and secret scans will still run`,
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

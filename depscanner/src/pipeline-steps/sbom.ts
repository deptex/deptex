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
import {
  parseSbom,
  getBomRefToNameVersion,
  patchDevDependencies,
  type ParsedSbomDep,
  type ParsedSbomRelationship,
} from '../sbom';
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

  const { dependencies, relationships, rawComponentCount, droppedVersionlessCount } = parseSbom(sbom);
  const bomRefMap = getBomRefToNameVersion(sbom);

  // Patch devDependency detection by cross-referencing with manifest files
  try {
    patchDevDependencies(dependencies, workspaceRoot, jobEcosystem);
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
    //      image, npm install broke on workspace refs).
    // Both are recoverable: semgrep + trufflehog + framework-entry-point
    // detection still produce value on a zero-dep scan. Warn and continue.
    const reason =
      rawComponentCount > 0
        ? `SBOM had ${rawComponentCount} component(s) but none had a resolvable version`
        : 'SBOM is empty';
    await log.warn(
      'sbom',
      `No dependencies parsed (${reason}) — continuing without dependency analysis; SAST and secret scans will still run`,
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

// Deterministic base-image bump for `base_image` and `container` fixes. There's
// no LLM here: we read the AUTHORITATIVE recommendation from the DB (the same
// curated row the user saw), find the matching final-stage `FROM` line in the
// named Dockerfile, and swap the image. Reliable + reviewable — a base-image
// bump should never be a model guess.
//
// container OS-CVEs route here too: you can't patch an OS package baked into an
// image from app code, so the fix is to move the base image. We refuse honestly
// when that isn't possible (pre-built registry image, no curated drop-in, or a
// shell-required Dockerfile with only shell-less alternatives).

import * as fs from 'fs';
import * as path from 'path';
import type { SupabaseClient } from '@supabase/supabase-js';
import type { FixLogger } from './logger';
import { FixPipelineError, type RunFixPipelineResult } from './executor';
import type { TestResult } from './test-runner';

interface BaseImageFixRow {
  fix_type: string;
  project_id: string;
  base_image_rec_id: string | null;
  container_finding_id: string | null;
}

interface ResolvedTarget {
  dockerfilePath: string;
  currentImage: string;
  targetImage: string;
  cveDelta: number | null;
}

// Compare two image references by repository path only (ignore tag + digest),
// so `node:20-bullseye` and `node:20-slim` are "the same image family".
function sameImageFamily(a: string, b: string): boolean {
  const norm = (s: string) => s.split('@')[0].replace(/:[^/:]+$/, '');
  return norm(a) === norm(b);
}

async function resolveTarget(
  supabase: SupabaseClient,
  row: BaseImageFixRow,
): Promise<ResolvedTarget> {
  // Load the recommendation row — directly for base_image, or via the container
  // finding's image for container.
  let rec: any = null;

  if (row.base_image_rec_id) {
    const { data } = await supabase
      .from('project_base_image_recommendations')
      .select('dockerfile_path, current_image, recommended_image, alternatives, shell_compat_verdict, cve_delta')
      .eq('id', row.base_image_rec_id)
      .maybeSingle();
    rec = data;
  } else if (row.container_finding_id) {
    const { data: cf } = await supabase
      .from('project_container_findings')
      .select('image_reference, image_source, extraction_run_id')
      .eq('id', row.container_finding_id)
      .maybeSingle();
    if (!cf) throw new FixPipelineError('Container finding not found.', 'not_fixable');
    if (cf.image_source !== 'dockerfile_base') {
      throw new FixPipelineError(
        `This OS-package CVE is in a pre-built registry image (image_source=${cf.image_source}), which this repository's Dockerfile does not control — it must be patched upstream in that image.`,
        'not_fixable',
      );
    }
    const { data: recs } = await supabase
      .from('project_base_image_recommendations')
      .select('dockerfile_path, current_image, recommended_image, alternatives, shell_compat_verdict, cve_delta')
      .eq('project_id', row.project_id)
      .eq('extraction_run_id', cf.extraction_run_id);
    const ref = String(cf.image_reference ?? '');
    rec = (recs ?? []).find((r: any) => ref && sameImageFamily(String(r.current_image ?? ''), ref)) ?? null;
    if (!rec) {
      throw new FixPipelineError(
        `No curated drop-in base image is available for ${ref} — the OS package must be patched upstream or the image rebuilt.`,
        'not_fixable',
      );
    }
  } else {
    throw new FixPipelineError('No base-image recommendation is linked to this fix.', 'not_fixable');
  }

  if (!rec?.dockerfile_path || !rec?.current_image) {
    throw new FixPipelineError('The base-image recommendation is missing its Dockerfile or current image.', 'not_fixable');
  }

  // Pick the target image: the curated recommendation, else the best shell-safe
  // alternative. recommended_image is already null when the advisor filtered out
  // every alternative for a shell-required Dockerfile.
  let targetImage: string | null = rec.recommended_image ?? null;
  if (!targetImage && Array.isArray(rec.alternatives) && rec.alternatives.length > 0) {
    const best = [...rec.alternatives].sort((a: any, b: any) => (b.drop_in_score ?? 0) - (a.drop_in_score ?? 0))[0];
    targetImage = best?.image ?? null;
  }
  if (!targetImage) {
    const shellNote =
      rec.shell_compat_verdict === 'shell_required'
        ? ' This Dockerfile needs a shell (a RUN in the final stage or a shell-form CMD/ENTRYPOINT), but the hardened alternatives are shell-less (distroless), so none is a safe drop-in. Removing the shell dependency is a manual change.'
        : '';
    throw new FixPipelineError(
      `No safe base-image replacement is available for ${rec.current_image}.${shellNote}`,
      'not_fixable',
    );
  }

  return {
    dockerfilePath: String(rec.dockerfile_path),
    currentImage: String(rec.current_image),
    targetImage,
    cveDelta: typeof rec.cve_delta === 'number' ? rec.cve_delta : null,
  };
}

// Resolve the Dockerfile on disk. Finding paths follow the same convention as
// the code editor (relative to the project subdir), but fall back to the repo
// root so we're robust to either.
function locateDockerfile(workDir: string, repoRoot: string, relPath: string): string | null {
  const candidates = [path.resolve(workDir, relPath), path.resolve(repoRoot, relPath)];
  for (const c of candidates) {
    if (fs.existsSync(c) && fs.statSync(c).isFile()) return c;
  }
  return null;
}

// Swap the image on the matching `FROM` line. Prefer the last FROM whose image
// family matches current_image (the final/runtime stage the advisor targeted);
// fall back to the last FROM line. Preserves any `AS <stage>` suffix and the
// leading indentation.
function bumpFromLine(
  text: string,
  currentImage: string,
  targetImage: string,
): { text: string; oldLine: string; newLine: string } | null {
  const lines = text.split('\n');
  const fromIdxs: number[] = [];
  lines.forEach((ln, i) => {
    if (/^\s*FROM\s+/i.test(ln)) fromIdxs.push(i);
  });
  if (fromIdxs.length === 0) return null;

  const imageOf = (ln: string): string => {
    const m = ln.match(/^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)/i);
    return m ? m[1] : '';
  };
  const matching = fromIdxs.filter((i) => sameImageFamily(imageOf(lines[i]), currentImage));
  const targetIdx = matching.length > 0 ? matching[matching.length - 1] : fromIdxs[fromIdxs.length - 1];

  const oldLine = lines[targetIdx];
  const img = imageOf(oldLine);
  if (!img) return null;
  const newLine = oldLine.replace(img, targetImage);
  if (newLine === oldLine) return null;
  lines[targetIdx] = newLine;
  return { text: lines.join('\n'), oldLine, newLine };
}

export async function runBaseImageBump(
  supabase: SupabaseClient,
  row: BaseImageFixRow,
  opts: {
    workDir: string;
    repoRoot: string;
    logger: FixLogger;
    onPhase?: (phase: 'edit' | 'verify', meta?: { verifiedLocally?: boolean }) => Promise<void>;
  },
): Promise<RunFixPipelineResult> {
  const { workDir, repoRoot, logger, onPhase } = opts;
  const target = await resolveTarget(supabase, row);

  const dockerfile = locateDockerfile(workDir, repoRoot, target.dockerfilePath);
  if (!dockerfile) {
    throw new FixPipelineError(`Dockerfile not found at ${target.dockerfilePath}.`, 'not_fixable');
  }

  const original = fs.readFileSync(dockerfile, 'utf-8');
  const bumped = bumpFromLine(original, target.currentImage, target.targetImage);
  if (!bumped) {
    throw new FixPipelineError(
      `Could not find a FROM line for ${target.currentImage} in ${target.dockerfilePath}.`,
      'not_fixable',
    );
  }
  fs.writeFileSync(dockerfile, bumped.text, 'utf-8');
  await logger.success('edit', `Bumped base image ${target.currentImage} → ${target.targetImage}`);
  await onPhase?.('edit');

  const rawDiff = [
    `--- a/${target.dockerfilePath}`,
    `+++ b/${target.dockerfilePath}`,
    '@@ base image @@',
    `-${bumped.oldLine}`,
    `+${bumped.newLine}`,
  ].join('\n');

  // A Dockerfile edit can't be built in the sandbox (no registry pull / build
  // context), so the PR's CI + image build is the gate. Soft-pass.
  const testResult: TestResult = {
    passed: true,
    exitCode: 0,
    stdout: '',
    stderr: '',
    durationMs: 0,
    timedOut: false,
    noTestSuite: true,
  };
  await onPhase?.('verify', { verifiedLocally: false });

  return { rawDiff, testResult, tokensUsed: 0, toolCalls: 0, repairAttempts: 0 };
}

// Expose the target-image label so the worker can narrate the concrete bump.
export async function describeBaseImageTarget(
  supabase: SupabaseClient,
  row: BaseImageFixRow,
): Promise<{ currentImage: string; targetImage: string; cveDelta: number | null } | null> {
  try {
    const t = await resolveTarget(supabase, row);
    return { currentImage: t.currentImage, targetImage: t.targetImage, cveDelta: t.cveDelta };
  } catch {
    return null;
  }
}

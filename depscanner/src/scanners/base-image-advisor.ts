/**
 * Base-image upgrade advisor (Phase 2, Item J).
 *
 * Given a Dockerfile's final-stage base image, picks the best curated
 * alternative from the catalog and pairs it with a shell-presence
 * compatibility verdict — does this Dockerfile need a shell the hardened
 * image may not have? Produces one recommendation row per Dockerfile per
 * extraction run, ready for upsert into project_base_image_recommendations.
 */

import {
  loadCatalog,
  lookupAlternatives,
  type BaseImageCatalog,
  type CatalogAlternative,
  type CatalogProvider,
} from './base-image-catalog';

// ============================================================
// Shell-presence detection
// ============================================================

export type ShellVerdict = 'shell_required' | 'no_shell_required' | 'unknown';

export interface ShellEvidence {
  dockerfile_parsed: boolean;
  final_stage_has_run: boolean;
  cmd_form: 'exec' | 'shell' | null;
  entrypoint_form: 'exec' | 'shell' | null;
  /** A CMD/ENTRYPOINT whose argv0 is itself a shell. */
  shell_interpreter: boolean;
  [key: string]: unknown;
}

const SHELL_BASENAMES: ReadonlySet<string> = new Set(['sh', 'bash', 'dash', 'ash']);

function basename(p: string): string {
  const parts = p.split('/');
  return parts[parts.length - 1];
}

/** Parse a CMD/ENTRYPOINT argument into exec-form argv, or null for shell form. */
function parseExecForm(arg: string): string[] | null {
  const trimmed = arg.trim();
  if (!trimmed.startsWith('[')) return null;
  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed) && parsed.every((x) => typeof x === 'string')) {
      return parsed as string[];
    }
  } catch {
    /* malformed exec form — treat as shell form below */
  }
  return null;
}

/**
 * Determine whether a Dockerfile's final stage needs a shell at build or run
 * time — the signal that decides if a shell-less hardened base would break it.
 * A `RUN` in the final stage, a shell-form CMD/ENTRYPOINT, or an exec-form
 * directive whose argv0 is a shell all force `shell_required`. Conservative:
 * an unreadable Dockerfile, or one with no CMD/ENTRYPOINT, yields `unknown`.
 */
export function detectShellPresence(dockerfileText: string | null): {
  verdict: ShellVerdict;
  evidence: ShellEvidence;
} {
  const evidence: ShellEvidence = {
    dockerfile_parsed: false,
    final_stage_has_run: false,
    cmd_form: null,
    entrypoint_form: null,
    shell_interpreter: false,
  };
  if (!dockerfileText || dockerfileText.trim().length === 0) {
    return { verdict: 'unknown', evidence };
  }
  evidence.dockerfile_parsed = true;

  // Fold line continuations, then walk directives, resetting at each FROM so
  // only the final stage's directives count.
  const folded = dockerfileText.replace(/\\\r?\n/g, ' ');
  const directiveRe = /^\s*(FROM|RUN|CMD|ENTRYPOINT)\s+(.*)$/i;

  let finalRun = false;
  let cmdArg: string | null = null;
  let entrypointArg: string | null = null;

  for (const line of folded.split(/\r?\n/)) {
    if (/^\s*#/.test(line)) continue;
    const m = directiveRe.exec(line);
    if (!m) continue;
    const directive = m[1].toUpperCase();
    const rest = m[2];
    if (directive === 'FROM') {
      // New stage — discard anything collected for the previous stage.
      finalRun = false;
      cmdArg = null;
      entrypointArg = null;
    } else if (directive === 'RUN') {
      finalRun = true;
    } else if (directive === 'CMD') {
      cmdArg = rest;
    } else if (directive === 'ENTRYPOINT') {
      entrypointArg = rest;
    }
  }

  evidence.final_stage_has_run = finalRun;
  let shellInterpreter = false;
  let shellForm = false;

  for (const [arg, key] of [
    [cmdArg, 'cmd_form'],
    [entrypointArg, 'entrypoint_form'],
  ] as Array<[string | null, 'cmd_form' | 'entrypoint_form']>) {
    if (arg === null) continue;
    const execArgv = parseExecForm(arg);
    if (execArgv === null) {
      evidence[key] = 'shell';
      shellForm = true;
    } else {
      evidence[key] = 'exec';
      const argv0 = execArgv[0] ? basename(execArgv[0]) : '';
      if (SHELL_BASENAMES.has(argv0) || execArgv.includes('-c')) {
        shellInterpreter = true;
      }
    }
  }
  evidence.shell_interpreter = shellInterpreter;

  if (finalRun || shellForm || shellInterpreter) {
    return { verdict: 'shell_required', evidence };
  }
  if (evidence.cmd_form === 'exec' || evidence.entrypoint_form === 'exec') {
    return { verdict: 'no_shell_required', evidence };
  }
  return { verdict: 'unknown', evidence };
}

// ============================================================
// Recommendation generation
// ============================================================

const PROVIDER_PRIORITY: Record<CatalogProvider, number> = {
  chainguard: 1.0,
  wolfi: 0.95,
  dhi: 0.85,
  distroless: 0.7,
  official_slim: 0.5,
};

/** Infer the libc family of the current base image from its name. */
export function inferLibc(imageRef: string): 'glibc' | 'musl' | 'none' {
  const lower = imageRef.toLowerCase();
  if (lower.includes('alpine')) return 'musl';
  if (lower.includes('scratch') || lower.includes('/static')) return 'none';
  return 'glibc';
}

export interface RecommendationInput {
  project_id: string;
  organization_id: string;
  extraction_run_id: string;
  dockerfile_path: string;
  /** Final-stage base image, e.g. `node:20-bullseye`. */
  currentImage: string;
  currentImageDigest: string | null;
  /** Live count of container findings for this image in the current run. */
  currentImageFindingCount: number;
  /** Raw Dockerfile text, for shell-presence detection. Null when unreadable. */
  dockerfileText: string | null;
  catalog?: BaseImageCatalog;
}

export interface RecommendationAlternative {
  image: string;
  provider: CatalogProvider;
  cve_count: number | null;
  drop_in_score: number;
}

/** Row shaped for insert into project_base_image_recommendations. */
export interface BaseImageRecommendationRow {
  project_id: string;
  organization_id: string;
  extraction_run_id: string;
  dockerfile_path: string;
  current_image: string;
  current_image_digest: string | null;
  current_image_cve_count: number | null;
  recommended_image: string | null;
  recommended_image_cve_count: number | null;
  cve_delta: number | null;
  alternatives: RecommendationAlternative[];
  shell_compat_verdict: ShellVerdict;
  shell_compat_evidence: Record<string, unknown>;
  drop_in_score: number;
}

/** Normalized CVE improvement of an alternative, in 0..1. */
function cveDeltaNormalized(currentCount: number, altCveCount: number): number {
  if (currentCount <= 0) return 0;
  const delta = currentCount - altCveCount;
  if (delta <= 0) return 0;
  return Math.min(1, delta / currentCount);
}

function scoreAlternative(alt: CatalogAlternative, currentCount: number): number {
  const ndelta = cveDeltaNormalized(currentCount, alt.cve_count);
  const drop = alt.drop_in_score / 100;
  const prio = PROVIDER_PRIORITY[alt.provider] ?? 0.5;
  return ndelta * 0.5 + drop * 0.3 + prio * 0.2;
}

/**
 * Generate the base-image recommendation for one Dockerfile. Always returns a
 * row: a real recommendation when the catalog has a usable alternative, or an
 * empty-state row (`recommended_image: null`) when there is no catalog match
 * or every alternative is shell-incompatible.
 */
export function generateRecommendation(
  input: RecommendationInput
): BaseImageRecommendationRow {
  const catalog = input.catalog ?? loadCatalog();
  const base: Omit<
    BaseImageRecommendationRow,
    | 'recommended_image'
    | 'recommended_image_cve_count'
    | 'cve_delta'
    | 'alternatives'
    | 'shell_compat_verdict'
    | 'shell_compat_evidence'
    | 'drop_in_score'
  > = {
    project_id: input.project_id,
    organization_id: input.organization_id,
    extraction_run_id: input.extraction_run_id,
    dockerfile_path: input.dockerfile_path,
    current_image: input.currentImage,
    current_image_digest: input.currentImageDigest,
    current_image_cve_count: input.currentImageFindingCount,
  };

  const shell = detectShellPresence(input.dockerfileText);
  const match = lookupAlternatives(input.currentImage, catalog);

  // No catalog entry — empty-state row.
  if (!match) {
    return {
      ...base,
      recommended_image: null,
      recommended_image_cve_count: null,
      cve_delta: null,
      alternatives: [],
      shell_compat_verdict: shell.verdict,
      shell_compat_evidence: { ...shell.evidence, no_catalog_match: true },
      drop_in_score: 0,
    };
  }

  // Drop shell-incompatible alternatives when the Dockerfile needs a shell.
  let candidates = match.alternatives;
  if (shell.verdict === 'shell_required') {
    candidates = candidates.filter((a) => a.has_shell);
  }

  // Every alternative was filtered out — empty-state row, but record why.
  if (candidates.length === 0) {
    return {
      ...base,
      recommended_image: null,
      recommended_image_cve_count: null,
      cve_delta: null,
      alternatives: [],
      shell_compat_verdict: shell.verdict,
      shell_compat_evidence: {
        ...shell.evidence,
        all_alternatives_shell_incompatible: true,
      },
      drop_in_score: 0,
    };
  }

  // Rank, pick the best, keep the next two as alternatives.
  const ranked = [...candidates].sort(
    (a, b) =>
      scoreAlternative(b, input.currentImageFindingCount) -
      scoreAlternative(a, input.currentImageFindingCount)
  );
  const picked = ranked[0];
  const runnersUp = ranked.slice(1, 3);

  const currentLibc = inferLibc(input.currentImage);
  const libcMatch = picked.libc_family === 'none' || picked.libc_family === currentLibc;
  const likelySafe = shell.verdict === 'no_shell_required' && libcMatch;

  return {
    ...base,
    recommended_image: picked.image,
    recommended_image_cve_count: picked.cve_count,
    cve_delta: input.currentImageFindingCount - picked.cve_count,
    alternatives: runnersUp.map((a) => ({
      image: a.image,
      provider: a.provider,
      cve_count: a.cve_count,
      drop_in_score: a.drop_in_score,
    })),
    shell_compat_verdict: shell.verdict,
    shell_compat_evidence: {
      ...shell.evidence,
      family: match.family,
      current_libc: currentLibc,
      recommended_libc: picked.libc_family,
      libc_match: libcMatch,
      likely_safe: likelySafe,
      recommended_notes: picked.notes,
    },
    drop_in_score: picked.drop_in_score,
  };
}

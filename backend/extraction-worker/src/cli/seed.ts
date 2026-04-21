/**
 * Minimal DB seed for local-mode CLI runs.
 *
 * A freshly-booted PGLite has the full schema but no rows. The pipeline
 * assumes org/project/project_repositories exist (updateStep() writes to
 * project_repositories immediately). This helper inserts just enough state
 * to let runPipeline() succeed.
 *
 * Keep this narrow — we only seed what the pipeline reads/writes before
 * finalize_extraction. Anything else (teams, statuses, policies) is out of
 * scope for CLI mode.
 */

import type { Storage } from '../storage';

export interface SeedResult {
  organizationId: string;
  projectId: string;
  projectName: string;
}

export interface SeedOptions {
  /** Identifier used in the project name + project_repositories.repo_full_name. */
  repoLabel: string;
  /** Ecosystem for project_repositories.ecosystem (npm/pypi/maven/golang). */
  ecosystem: string;
  /** Default branch to record (cosmetic for local mode). */
  defaultBranch?: string;
}

const LOCAL_ORG_ID = '00000000-0000-0000-0000-00000000000a';

export async function seedLocalDb(
  storage: Storage,
  opts: SeedOptions,
): Promise<SeedResult> {
  const { repoLabel, ecosystem, defaultBranch = 'main' } = opts;

  // 1) Organization — upsert-by-id so re-seeding the same PGLite is idempotent.
  const { error: orgErr } = await storage.from('organizations').upsert(
    { id: LOCAL_ORG_ID, name: 'local-cli-org' },
    { onConflict: 'id', ignoreDuplicates: true },
  );
  if (orgErr) throw new Error(`seed org failed: ${orgErr.message}`);

  // 2) Project — generated UUID; keep one per CLI invocation so outputs
  //    from repeated runs don't collide in a persisted PGLite.
  const projectId = generateUuid();
  const { error: projErr } = await storage.from('projects').insert({
    id: projectId,
    organization_id: LOCAL_ORG_ID,
    name: repoLabel,
    active_extraction_run_id: null,
    previous_extraction_run_id: null,
  });
  if (projErr) throw new Error(`seed project failed: ${projErr.message}`);

  // 3) project_repositories — updateStep() targets this row every pipeline
  //    step, so it must exist before runPipeline is called.
  const { error: repoErr } = await storage.from('project_repositories').insert({
    project_id: projectId,
    installation_id: 'local',
    repo_id: 0,
    repo_full_name: `local/${repoLabel}`,
    default_branch: defaultBranch,
    status: 'pending',
    ecosystem,
    provider: 'local',
  });
  if (repoErr) throw new Error(`seed project_repositories failed: ${repoErr.message}`);

  return {
    organizationId: LOCAL_ORG_ID,
    projectId,
    projectName: repoLabel,
  };
}

function generateUuid(): string {
  // node:crypto.randomUUID is in core; avoids a dep.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  return require('node:crypto').randomUUID();
}

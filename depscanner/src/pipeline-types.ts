/**
 * Shared pipeline types + the PipelineContext bag passed to every step module.
 *
 * Lives in its own file so the per-step modules under `pipeline-steps/` can
 * type their `do<Step>(ctx)` signatures without circular-importing pipeline.ts.
 */

import type { Storage } from './storage';
import type { ExtractionLogger } from './logger';

/**
 * Logger interface for pipeline; full ExtractionLogger or minimal mock for tests.
 */
export type PipelineLogger = Pick<ExtractionLogger, 'info' | 'success' | 'warn' | 'error'>;

/**
 * One security-critical step that produced no/partial signal this run. Recorded
 * by `markDegraded` and persisted to `scan_degraded_steps` on both
 * `project_repositories` (badge source) and `scan_jobs` (run record). `reason`
 * is the user-facing one-liner the "Scan incomplete" banner shows.
 */
export interface DegradedStep {
  step: string;
  reason: string;
}

export interface ExtractionJob {
  projectId: string;
  organizationId: string;
  repo_full_name: string;
  installation_id: string;
  default_branch: string;
  package_json_path?: string;
  ecosystem?: string;
  provider?: string;
  integration_id?: string;
  /** Set by worker so pipeline can write commit into job payload after clone */
  jobId?: string;
  /**
   * Local-mode only. When set, the pipeline skips the clone step and uses
   * this path as the workspace root. The path is NOT cleaned up on exit.
   * Used by the CLI (bin/extract.ts) so `deptex scan ./my-repo` runs
   * against an already-checked-out tree without any git credentials.
   */
  localWorkspacePath?: string;
}

/**
 * Pipeline result shape. The CLI uses `finalizeSummary` to populate
 * `summary.json.finalize_summary` (the jsonb returned by the
 * `finalize_extraction` RPC: deps_removed, vulns_new, etc.). The production
 * worker discards this — early returns / cancellation paths return undefined.
 */
export interface RunPipelineResult {
  finalizeSummary: unknown;
}

/**
 * Mutable bag of state passed through the pipeline. Each step module receives
 * this via its `do<Step>(ctx)` entry point. The shape mirrors the locals
 * pipeline.ts used to declare inline before refactor #1; consolidating them
 * here is what lets each step body live in its own file without 15-arg
 * signatures.
 *
 * Only fields that legitimately cross step boundaries belong here. Step-local
 * scratch (parsed SBOM rows, vdr file lists, etc.) stays inside the step.
 */
export interface PipelineContext {
  // === Identity / wiring ===
  job: ExtractionJob;
  projectId: string;
  organizationId: string;
  /** Effective ecosystem with default ('npm' fallback). Set after clone validates it. */
  jobEcosystem: string;
  /** Per-extraction id used as extraction_run_id + storage path key. Set in clone step. */
  runId: string;

  // === Infra handles ===
  supabase: Storage;
  /**
   * Loose-typed inside the pipeline so step-internal log step names
   * ('resolve', 'rule_generation', 'iac_scan', 'malicious_scan', etc.)
   * don't have to be added to the `LogStep` enum the public ExtractionLogger
   * uses for DB filtering. The public surface (runPipeline's `logger` param)
   * is still typed via `PipelineLogger`. Matches the original pipeline.ts
   * behavior where the fallback no-op logger was cast `as any`.
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  log: any;
  checkCancelled?: () => Promise<boolean>;
  heartbeat?: () => Promise<void>;

  // === Filesystem state (filled by clone) ===
  /** Repo root (clone target or localWorkspacePath). Cleanup uses this. */
  repoPath: string | null;
  /** repoPath + package_json_path (subdirectory). Most steps operate on this. */
  workspaceRoot: string;

  // === Cross-step scoring inputs ===
  /** Project importance multiplier, in [0.5, 2.0]. Resolved once before
   * depscore-touching steps run. Multiplied into the score as tierWeight. */
  importance: number;

  /**
   * Whether the direct/transitive split on `project_dependencies` is
   * trustworthy. True when cdxgen wired the CycloneDX graph OR the SBOM step's
   * graph recovery rebuilt the direct set from the manifest/tree. False when
   * cdxgen's graph was unwired AND recovery was unavailable — the reachability
   * classifier must then floor at `module` and never emit `unreachable`.
   * Defaults to true; only the SBOM step lowers it.
   */
  graphTrusted: boolean;

  /**
   * Whether cdxgen's CycloneDX `dependencies` graph was wired this run (the
   * original `directSetTrusted` from parseSbom, before recovery). Distinct
   * from `graphTrusted`: recovery can rebuild the direct set without rewiring
   * the edge graph. The SBOM step sets it. deps_sync reads it to keep
   * transitive dev-scope marks sticky when propagation was skipped — without
   * it a flaky cdxgen graph would flip `environment` dev↔null between scans.
   */
  sbomGraphWired?: boolean;

  // === Cross-step counters used by finalize ===
  projectDepsCount: number;
  newDepsToPopulate: Array<{ dependencyId: string; name: string }>;
  /**
   * Set by usage_extraction. Read by finalize to stamp ast_parsed_at on
   * project_repositories so the UI can flag projects with successful AST
   * coverage.
   */
  astParsedSuccessfully: boolean;

  // === Degraded run state ===
  /**
   * True once any security-critical step has failed soft (produced no/partial
   * signal) this run — dep-scan crashed, SBOM empty, SAST/secret binary
   * missing, malicious/IaC scan failed. Flipped only via `markDegraded`, which
   * also write-throughs to scan_jobs so the flag survives a later hard-fail or
   * cancel that never reaches finalize. finalize copies it onto
   * project_repositories (the badge source) on the success path. Defaults false;
   * a clean re-scan overwrites it back to false (the badge self-clears).
   */
  degraded: boolean;
  /** The per-step reasons behind `degraded`, deduped by step+reason. */
  degradedSteps: DegradedStep[];
}

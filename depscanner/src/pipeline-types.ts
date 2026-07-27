/**
 * Shared pipeline types + the PipelineContext bag passed to every step module.
 *
 * Lives in its own file so the per-step modules under `pipeline-steps/` can
 * type their `do<Step>(ctx)` signatures without circular-importing pipeline.ts.
 */

import type { Storage } from './storage';
import type { ExtractionLogger } from './logger';
import type { EntryPointAuthMap } from './taint-engine/match-flow-to-routes';

/**
 * Logger interface for pipeline; full ExtractionLogger or minimal mock for tests.
 */
export type PipelineLogger = Pick<ExtractionLogger, 'info' | 'success' | 'warn' | 'error'>;

export interface ExtractionJob {
  projectId: string;
  organizationId: string;
  repo_full_name: string;
  installation_id: string;
  default_branch: string;
  /**
   * The branch the scan was actually requested against. Webhook pushes to a
   * non-default branch set this to the pushed branch (the backend writes
   * `payload.branch`); manual/initial/scheduled runs leave it unset. The clone
   * step prefers this over `default_branch` so a feature-branch push is scanned
   * on that branch — not silently on the repo default.
   */
  branch?: string;
  /**
   * The exact commit to scan, when pinned. Webhook pushes set this to the
   * pushed commit SHA (the backend writes `payload.commit_sha`); a pinned
   * re-scan sets it too. When present the clone step checks this commit out
   * after cloning the branch (fetching it if the branch tip has since moved),
   * so we scan the requested tree rather than whatever the branch HEAD is now.
   */
  commit_sha?: string;
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

  /**
   * Number of HTTP-route entry points framework detection found this run
   * (`entryPointType === 'http_route'`). Set by usage_extraction from the
   * already-detected entry points (NOT re-detected). Read by the reachability
   * step as the "deployed web app" signal for the always-on framework-runtime
   * promotion: >= 1 HTTP route ⇒ the framework's request-path runtime is live,
   * so a CVE in an always-on component (servlet-container request parser, MVC
   * resource handler) is genuinely reachable. 0 ⇒ a library/CLI repo, and the
   * promotion is disabled (fail-safe). Defaults to 0.
   */
  httpEntryPointCount: number;

  /**
   * Per-file, per-route auth records (entry-point auth classification, T2).
   * Built at usage_extraction from the detected entry points + cross-file
   * postProcess records, keyed by project-relative POSIX path (byte-identical to
   * a flow's `entry_point_file`). The taint engine's `writeFlows` joins each flow
   * against this via `matchFlowToRoutes` to stamp `entry_point_tag`; the fp-filter
   * reads it for route context. In-memory only — never persisted. Empty map until
   * usage_extraction runs (fail-safe: no records ⇒ every flow stamps `unmatched`
   * ⇒ PUBLIC weight, no merge vote).
   */
  entryPointAuth: EntryPointAuthMap;
}

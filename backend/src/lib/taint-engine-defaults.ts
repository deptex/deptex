/**
 * Default values for the per-org taint-engine + reachability rule generator
 * settings rows. Single source of truth referenced by:
 *   - the GET /:orgId/settings route synthesizers (when no row exists yet)
 *   - the frontend cost-cap fallback `??` expressions (mirrored constants)
 *   - unit assertions that the constants match the migration DEFAULTs
 *
 * The migration DEFAULTs ($75 for taint engine, $30 for generator) only fire
 * for orgs that have inserted a settings row. Orgs that have never opened the
 * settings panel have no row at all — the route synthesizes a fake row so the
 * UI renders populated. Without this constant, a hard-coded fallback in the
 * route would silently shadow the migration default.
 */

/** Default monthly cap on Tier-2 AI spend for taint-engine spec inference + fp-filter (per org). */
export const DEFAULT_MONTHLY_AI_COST_CAP_USD = 75;

/** Default monthly cap on Tier-2 AI spend for the reachability rule generator (per org). */
export const DEFAULT_GENERATOR_MONTHLY_BUDGET_USD = 30;

/** Defensive upper bound enforced by both DB CHECK and route validators. */
export const COST_CAP_MAX_USD = 1000;

/**
 * Closed taxonomy of vulnerability classes the taint engine + generator
 * understand. Mirrors `depscanner/src/taint-engine/spec.ts`'s
 * `ALL_VULN_CLASSES` byte-for-byte; the depscanner is its own tsc package
 * (rootDir=./src), so production code in backend/src can't import from
 * depscanner — we duplicate and pin equality with a unit test.
 *
 * Also mirrored in `frontend/src/lib/taint-engine-defaults.ts` for future
 * dropdowns / filter UIs. Adding a new vuln class touches THREE files (the
 * engine, this file, the frontend mirror) and the migration's CHECK list.
 */
export type VulnClass =
  | 'sql_injection'
  | 'ssrf'
  | 'xss'
  | 'path_traversal'
  | 'command_injection'
  | 'prototype_pollution'
  | 'deserialization'
  | 'redos'
  | 'file_upload'
  | 'open_redirect'
  | 'log_injection'
  | 'code_injection'
  | 'weak_crypto'
  | 'auth_bypass';

export const ALL_VULN_CLASSES: readonly VulnClass[] = [
  'sql_injection',
  'ssrf',
  'xss',
  'path_traversal',
  'command_injection',
  'prototype_pollution',
  'deserialization',
  'redos',
  'file_upload',
  'open_redirect',
  'log_injection',
  'code_injection',
  'weak_crypto',
  'auth_bypass',
];

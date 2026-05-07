/**
 * Frontend mirror of backend/src/lib/taint-engine-defaults.ts.
 *
 * Used in `??` fallback expressions where the settings row may not exist yet
 * (org has never opened the panel — backend route synthesizes a default row,
 * but the form input may render before that response arrives). Must stay in
 * sync with the backend constants and the migration DEFAULTs.
 *
 * Unit tests in __tests__/taint-engine-defaults.test.ts assert all three
 * surfaces (migration default, backend constant, frontend constant) match.
 */

export const DEFAULT_MONTHLY_AI_COST_CAP_USD = 75;

export const DEFAULT_GENERATOR_MONTHLY_BUDGET_USD = 30;

/**
 * Closed taxonomy of vulnerability classes the engine + generator understand.
 * Mirrors `backend/src/lib/taint-engine-defaults.ts:ALL_VULN_CLASSES`, which
 * itself mirrors `depscanner/src/taint-engine/spec.ts`. The byte-
 * equality test in backend/src/__tests__/taint-engine-defaults.test.ts pins
 * all three.
 *
 * Adding a new vuln class touches FOUR files: the engine spec.ts, the
 * backend defaults mirror, this frontend mirror, and the migration's
 * vuln_classes_enabled CHECK list.
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
  | 'code_injection';

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
];

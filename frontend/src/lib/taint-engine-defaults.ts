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

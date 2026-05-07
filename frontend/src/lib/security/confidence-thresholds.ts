/**
 * Frontend mirror of `backend/depscanner/src/taint-engine/confidence-thresholds.ts`.
 *
 * MUST stay byte-equal to the worker module. A unit test asserts the values
 * match (`__tests__/confidence-thresholds-mirror.test.ts`); CI fails if they
 * drift. The boundary semantics are documented in the worker module.
 *
 *   - c < HIDE_BELOW                          → hide from UI
 *   - HIDE_BELOW <= c < UNCERTAIN_UPPER       → render "AI uncertain — review"
 *   - c >= UNCERTAIN_UPPER                    → render confident AND vote in MAX
 *
 * MAX_VOTE_THRESHOLD === UNCERTAIN_UPPER on purpose: depscore math and UI
 * rendering use the same threshold so users never see "uncertain" while the
 * score moves anyway.
 */

export const HIDE_BELOW = 0.5;
export const UNCERTAIN_UPPER = 0.75;
export const MAX_VOTE_THRESHOLD = UNCERTAIN_UPPER;

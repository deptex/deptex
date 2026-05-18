/**
 * Confidence thresholds — single source of truth for the cross-file taint
 * pipeline (Phase 6.5 / Patch 8 / OD-10 unification).
 *
 * Boundary semantics (locked):
 *   - c < HIDE_BELOW                          → hide from UI; don't surface to user
 *   - HIDE_BELOW <= c < UNCERTAIN_UPPER       → render "AI uncertain — review"
 *   - c >= UNCERTAIN_UPPER                    → render confident AND vote in MAX
 *
 * MAX_VOTE_THRESHOLD === UNCERTAIN_UPPER on purpose: what the user sees and
 * what depscore math uses MUST agree exactly. A flow whose sanitization
 * verdict is rendered "uncertain" cannot also dictate the PDV-level
 * is_sanitized rollup, otherwise users see "uncertain" but score moves anyway.
 *
 * Imported by:
 *   - epd.ts:aggregateEpdFromFlows (M5 task 28) — filters flows out of the
 *     vote when sanitization confidence < MAX_VOTE_THRESHOLD.
 *   - SanitizerBadge.tsx (M6 task 40, via a frontend-mirror module that
 *     asserts byte-equal at unit-test time).
 *
 * Constants may shift in M0.5c calibration probes or in the first week of
 * telemetry; if they do, update both the backend module here and the
 * frontend mirror in lockstep.
 */

export const HIDE_BELOW = 0.5;
export const UNCERTAIN_UPPER = 0.75;
/** Alias kept distinct so the call site reads MAX vote semantics, not UI render semantics. */
export const MAX_VOTE_THRESHOLD = UNCERTAIN_UPPER;

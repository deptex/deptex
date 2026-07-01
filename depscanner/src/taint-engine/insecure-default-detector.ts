/**
 * Phase 3.3 — insecure-default detector.
 *
 * WIRED INTO PIPELINE: `runner.ts#runDetectors` calls `detectInsecureDefaults`
 * per spec and coerces findings to `Flow` via `detector-flows.ts#insecureDefaultToFlow`.
 *
 * Walks IR call sites looking for call patterns declared in a FrameworkSpec's
 * top-level `insecure_defaults` array. Fires when either:
 *
 *   1. The declared argument is ABSENT and the entry has no
 *      `forbidden_value_shapes` (i.e. the kwarg's default value is itself
 *      insecure — e.g. flask `session_cookie_secure` defaulting to False).
 *   2. The declared argument is PRESENT and its literal text matches one
 *      of `forbidden_value_shapes` (i.e. user explicitly opted into the
 *      insecure shape — e.g. requests `Session(verify=False)`).
 *
 * Mirrors `non-taint-detector.ts` (Phase F4) in spirit but lives at the
 * spec top-level rather than per-sink, so AI rule generation can emit a
 * standalone "this call shape is unsafe" check without needing to author
 * a paired taint sink. Shares `extractCallSitesFromIr` + `CallSite` with
 * F4 so language quirks (Python kwargs vs JS option-objects vs
 * positional-only) are resolved identically.
 *
 * Targets in the 88-CVE corpus:
 *   - CVE-2024-35195 (requests `Session(verify=False)`) — `forbidden_value_shapes: ["False"]`.
 *   - CVE-2023-30861 (flask session-cookie-secure absent) — kwarg absence.
 *
 * Pipeline wiring: `runner.ts#runDetectors` dispatches per-spec
 * (`detectInsecureDefaults({ specs: [spec], callsites })`), maps each finding
 * into `project_reachable_flows` via `insecureDefaultToFlow`, and routes it
 * through the same FP-filter re-check as sub-threshold taint flows.
 */

import type { FrameworkSpec, InsecureDefault, VulnClass } from './spec';
import { matchesCallPattern } from './propagate-core';
import type { CallSite } from './non-taint-detector';

export interface InsecureDefaultFinding {
  /** Stable hash of filePath + line + column + pattern. */
  id: string;
  /** Source-spec framework name (e.g. "requests", "flask"). */
  framework: string;
  /** Vuln class copied from the entry (defaults to 'weak_crypto'). */
  vuln_class: VulnClass;
  /** Sink call-site location. */
  sink_file: string;
  sink_line: number;
  sink_column: number;
  sink_method: string;
  sink_pattern: string;
  /** Which absence / forbidden-value check fired the finding. */
  trigger: {
    argument_name?: string;
    argument_position?: number;
    observed_literal?: string;
    reason: 'absent' | 'forbidden_value';
  };
  /** Engine confidence; baseline 0.85 — same as F4 sanitizer-absence. */
  engine_confidence: number;
  description: string;
}

export interface DetectInsecureDefaultsOptions {
  specs: FrameworkSpec[];
  callsites: CallSite[];
}

/**
 * Detect insecure-default findings by walking the spec's `insecure_defaults`
 * and matching each callsite against `pattern` + the absence/forbidden-value
 * rule above. Dedupes on (file, line, column, pattern) so multi-spec
 * dispatch can't emit two findings at the same callsite for the same rule.
 */
export function detectInsecureDefaults(
  opts: DetectInsecureDefaultsOptions,
): InsecureDefaultFinding[] {
  const findings: InsecureDefaultFinding[] = [];
  const seen = new Set<string>();
  for (const spec of opts.specs) {
    const entries = spec.insecure_defaults;
    if (!entries || entries.length === 0) continue;
    for (const cs of opts.callsites) {
      for (const entry of entries) {
        if (!matchesCallPattern(entry.pattern, cs.calleeText)) continue;
        const trigger = evaluateInsecureDefault(entry, cs);
        if (!trigger) continue;
        const key = `${cs.filePath}|${cs.line}|${cs.column}|${entry.pattern}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          id: hashId(cs.filePath, cs.line, cs.column, entry.pattern),
          framework: spec.framework,
          vuln_class: entry.vuln_class ?? 'weak_crypto',
          sink_file: cs.filePath,
          sink_line: cs.line,
          sink_column: cs.column,
          sink_method: cs.calleeText,
          sink_pattern: entry.pattern,
          trigger: {
            argument_name: entry.argument_name,
            argument_position: entry.argument_position,
            observed_literal: trigger.observed,
            reason: trigger.reason,
          },
          engine_confidence: 0.85,
          description: entry.description,
        });
      }
    }
  }
  return findings;
}

function evaluateInsecureDefault(
  entry: InsecureDefault,
  cs: CallSite,
): { reason: 'absent' | 'forbidden_value'; observed?: string } | null {
  const kwargPresent =
    entry.argument_name !== undefined && cs.kwargNames.includes(entry.argument_name);
  const positionalPresent =
    entry.argument_position !== undefined && cs.argTexts.length > entry.argument_position;
  const present = kwargPresent || positionalPresent;
  const observed = kwargPresent && entry.argument_name
    ? cs.kwargValues?.[entry.argument_name]
    : positionalPresent
      ? cs.argTexts[entry.argument_position as number]
      : undefined;

  const hasForbidden =
    entry.forbidden_value_shapes !== undefined && entry.forbidden_value_shapes.length > 0;

  if (hasForbidden) {
    // Present + value matches one of the forbidden shapes → fire.
    // Absence is treated as the safe default and silently ignored.
    if (present && observed !== undefined && entry.forbidden_value_shapes!.includes(observed)) {
      return { reason: 'forbidden_value', observed };
    }
    return null;
  }
  // No forbidden_value_shapes — absence of the kwarg is itself the unsafe
  // default (the library defaults to an insecure value). Present argument
  // is treated as user opt-in to the safe shape.
  if (!present) return { reason: 'absent' };
  return null;
}

function hashId(filePath: string, line: number, column: number, pattern: string): string {
  let h = 0;
  const s = `${filePath}:${line}:${column}:${pattern}`;
  for (let i = 0; i < s.length; i++) {
    h = (h * 31 + s.charCodeAt(i)) | 0;
  }
  return `idd_${(h >>> 0).toString(16)}`;
}

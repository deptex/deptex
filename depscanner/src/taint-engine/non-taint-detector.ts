/**
 * Non-taint detector regime — Phase F4 prototype (NOT WIRED INTO PIPELINE).
 *
 * The cross-file taint engine answers one question: "does attacker-controlled
 * data reach a dangerous sink along a feasible call chain?". A subset of the
 * 88-CVE corpus (≈8 entries; see `docs/non-taint-detector-regime.md` for the
 * inventory) is genuinely not taint-shaped — there is no source-to-sink data
 * flow to find. Examples:
 *
 *   - CVE-2024-35195 (requests `Session(verify=False)`) — insecure default,
 *     a single AST call where the argument is a literal `False`, no source
 *     to speak of.
 *   - CVE-2022-23539 (jsonwebtoken `jwt.verify(token, key)` without an
 *     `algorithms` allowlist) — sanitizer-absence: a known-dangerous callsite
 *     missing a required argument that, when present, would harden the call.
 *   - CVE-2025-62718 (axios `localhost.` URL parse) — version-comparison +
 *     module-reachability: vulnerable only on a specific version range, and
 *     only if the application calls `axios.get(*)` at all.
 *
 * For the F4 prototype we implement a **single** detector — sanitizer-absence
 * — because it sits cleanly on the existing IR substrate: it walks
 * `Step` lists looking for `call` steps whose callee text matches a sink-
 * shaped pattern, then asserts that one or more *required* arguments are
 * present (and optionally that a specific argument value matches one of a
 * set of "safe" literals).
 *
 * The version-comparison detector — sketched in the docs companion — needs
 * a package-manifest reader and `semver`-range library, plus integration
 * with the SBOM-side data the propagator does not currently see. That work
 * is deferred.
 *
 * IMPORTANT: this file ships as a stand-alone building block. It is not
 * imported by `runner.ts`, `propagator.ts`, or any per-language driver. The
 * unit test in `__tests__/non-taint-detector.test.ts` exercises the public
 * surface with synthetic inputs. Wiring into the actual pipeline (call-site
 * discovery, finding emission, classifier integration, schema-mirror story)
 * is a follow-up tracked in `docs/non-taint-detector-regime.md`.
 */

import type { FrameworkSpec, FrameworkSink, VulnClass } from './spec';

/**
 * A single call site discovered during program walk. Mirrors a tiny subset
 * of `Step` (kind=='call') so this detector can be tested without standing
 * up a full IrFunction. In production the adapter from `IrFunction` →
 * `CallSite[]` lives next to `runner.ts` (see the design doc for the
 * proposed integration point).
 */
export interface CallSite {
  /** Full text of the callee expression, e.g. `jwt.verify` or `requests.Session`. */
  calleeText: string;
  /** Full text of each positional argument, e.g. `['token', 'key']`. */
  argTexts: string[];
  /**
   * Names of keyword/named arguments present at the call. The matcher uses
   * this to decide whether a `required_argument: { name: 'algorithms' }`
   * sanitizer is satisfied. The corresponding value (if needed for
   * literal-matching) is provided via `kwargValues` keyed on the same name.
   */
  kwargNames: string[];
  /** Optional map from kwarg name → literal-arg text (for "value must equal" checks). */
  kwargValues?: Record<string, string>;
  filePath: string;
  line: number;
  column: number;
}

/**
 * Proposed schema extension on `FrameworkSink` — declared here as a
 * structural interface that *augments* the existing sink shape with the
 * optional fields a non-taint detector needs. We do NOT modify `spec.ts`
 * in this prototype; the production rollout (see design doc §"Schema
 * extension") adds these fields directly to `FrameworkSink` so YAML authors
 * can express them naturally.
 *
 *   sinks:
 *     - pattern: jwt.verify(*)
 *       vuln_class: auth_bypass
 *       argument_indices: []      # taint-side empty → non-taint sink
 *       required_arguments:
 *         - name: algorithms       # kwarg form (Python/Node-options-object)
 *           position: 2            # OR positional index
 *           safe_literals: null    # any non-null value satisfies the check
 *       description: "jwt.verify without an explicit algorithm allowlist"
 *
 * `safe_literals` lets a single sink encode both "must pass argument" AND
 * "must pass argument with a value the rule considers safe". E.g. for
 * `requests.Session(verify=False)` the rule wants to fire when `verify` is
 * literally `False`; for `jwt.verify(*)` it wants to fire when `algorithms`
 * is *absent*. The same matcher handles both by reading `match_mode`.
 */
export interface RequiredArgument {
  /** Kwarg name to look for. */
  name: string;
  /** Positional index fallback (0-based). Optional; only used if `name` is unmatched. */
  position?: number;
  /**
   * Detector mode:
   *   - 'required'   : finding fires when the argument is ABSENT
   *   - 'forbidden'  : finding fires when the argument is PRESENT with a
   *                    value matching `unsafe_literals`
   *   - 'must_equal' : finding fires when the argument is PRESENT but its
   *                    literal text is NOT in `safe_literals`
   * Default: 'required'.
   */
  match_mode?: 'required' | 'forbidden' | 'must_equal';
  /** Whitelist of literal-text values that are considered "safe". */
  safe_literals?: string[];
  /** Blacklist for 'forbidden' mode. */
  unsafe_literals?: string[];
}

/** Structural augmentation of `FrameworkSink` for the prototype. */
export interface NonTaintFrameworkSink extends FrameworkSink {
  /**
   * When present (and non-empty), this sink is matched by the non-taint
   * detector regime instead of the taint propagator. `argument_indices`
   * should be left empty (`[]`) — the new detector ignores positional
   * taint flow.
   */
  required_arguments?: RequiredArgument[];
}

/** Output of the non-taint detector — shape mirrors `Flow` (see flow.ts). */
export interface NonTaintFinding {
  /** Stable hash of filePath + line + column + pattern. */
  id: string;
  /** Vuln class copied from the sink spec. */
  vuln_class: VulnClass;
  /** Sink call-site location. */
  sink_file: string;
  sink_line: number;
  sink_column: number;
  sink_method: string;
  sink_pattern: string;
  /** Which required-argument check fired the finding. */
  trigger: {
    argument_name: string;
    match_mode: 'required' | 'forbidden' | 'must_equal';
    /** Literal value that triggered, if applicable. */
    observed_literal?: string;
  };
  /** Engine confidence; baseline 0.85 for sanitizer-absence (highly precise). */
  engine_confidence: number;
  /** OSV id passthrough — CVE-targeted sinks already carry one. */
  osv_id?: string;
  description: string;
}

/**
 * Detect sanitizer-absence findings by walking the spec's sinks and matching
 * each callsite against the sink's pattern + required_arguments contract.
 *
 * The matching is intentionally simple — string-equality on calleeText with
 * trailing-`(*)` stripped. This matches the existing taint engine's
 * `matchesCallPattern` style well enough for a prototype; production wiring
 * would replace this with a call into `pattern-syntax.ts`'s
 * `matchesCallPattern` so wildcard receivers, method chains, and the
 * cross-language quirks all behave identically to taint matching.
 */
export function detectSanitizerAbsence(
  spec: FrameworkSpec,
  callsites: CallSite[],
): NonTaintFinding[] {
  const findings: NonTaintFinding[] = [];
  for (const sink of spec.sinks as NonTaintFrameworkSink[]) {
    if (!sink.required_arguments || sink.required_arguments.length === 0) continue;
    const cleanPattern = stripCallSuffix(sink.pattern);
    for (const cs of callsites) {
      if (cs.calleeText !== cleanPattern) continue;
      for (const req of sink.required_arguments) {
        const mode: 'required' | 'forbidden' | 'must_equal' = req.match_mode ?? 'required';
        const trigger = evaluateRequirement(req, cs, mode);
        if (trigger) {
          findings.push({
            id: hashId(cs.filePath, cs.line, cs.column, sink.pattern),
            vuln_class: sink.vuln_class,
            sink_file: cs.filePath,
            sink_line: cs.line,
            sink_column: cs.column,
            sink_method: cs.calleeText,
            sink_pattern: sink.pattern,
            trigger: { argument_name: req.name, match_mode: mode, observed_literal: trigger.observed },
            engine_confidence: 0.85,
            osv_id: sink.osv_id,
            description: sink.description,
          });
        }
      }
    }
  }
  return findings;
}

function evaluateRequirement(
  req: RequiredArgument,
  cs: CallSite,
  mode: 'required' | 'forbidden' | 'must_equal',
): { observed?: string } | null {
  const kwargPresent = cs.kwargNames.includes(req.name);
  const positionalPresent = req.position !== undefined && cs.argTexts.length > req.position;
  const observed = kwargPresent
    ? cs.kwargValues?.[req.name]
    : positionalPresent
      ? cs.argTexts[req.position as number]
      : undefined;

  if (mode === 'required') {
    // Fire when neither kwarg nor positional is present.
    return !kwargPresent && !positionalPresent ? {} : null;
  }
  if (mode === 'forbidden') {
    if (!kwargPresent && !positionalPresent) return null;
    if (!observed) return null;
    if ((req.unsafe_literals ?? []).includes(observed)) return { observed };
    return null;
  }
  // must_equal
  if (!kwargPresent && !positionalPresent) {
    // Missing argument fails the "must_equal" check just as much as a bad value.
    return {};
  }
  if (!observed) return { observed };
  if ((req.safe_literals ?? []).includes(observed)) return null;
  return { observed };
}

function stripCallSuffix(pattern: string): string {
  return pattern.endsWith('(*)') ? pattern.slice(0, -3) : pattern;
}

function hashId(filePath: string, line: number, column: number, pattern: string): string {
  // Deterministic but cheap; mirrors flow.id's shape without pulling in node's crypto.
  let h = 0;
  const s = `${filePath}:${line}:${column}:${pattern}`;
  for (let i = 0; i < s.length; i++) {
    h = (h * 31 + s.charCodeAt(i)) | 0;
  }
  return `ntd_${(h >>> 0).toString(16)}`;
}

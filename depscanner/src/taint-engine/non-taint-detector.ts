/**
 * Non-taint detector regime — Phase F4.
 *
 * WIRED INTO PIPELINE: `runner.ts` imports `detectSanitizerAbsence` +
 * `extractCallSitesFromIr` and coerces the findings to `Flow` via
 * `detector-flows.ts#sanitizerAbsenceToFlow`. The validate harness +
 * rule-generator/validate.ts exercise the same path.
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
 * Pipeline wiring: `runner.ts#runDetectors` calls `extractCallSitesFromIr`
 * then `detectSanitizerAbsence` per spec and merges the coerced `Flow`
 * records into the engine's detector-flow output. The unit test in
 * `__tests__/non-taint-detector.test.ts` + `test/taint-engine-const-resolver.test.ts`
 * exercise the public surface with synthetic inputs. The version-comparison
 * detector sketched in `docs/non-taint-detector-regime.md` remains deferred.
 */

import type { FrameworkSpec, FrameworkSink, RequiredArgument, VulnClass } from './spec';
import type { IrFunction, Step } from './ir';
import { matchesCallPattern } from './propagate-core';

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
 * Re-export `RequiredArgument` for back-compat with the prototype unit test.
 * The canonical declaration lives on `FrameworkSink` in `./spec.ts`; this
 * alias keeps existing imports working.
 */
export type { RequiredArgument };

/**
 * Back-compat alias — the canonical `FrameworkSink` now carries
 * `required_arguments` directly.
 */
export type NonTaintFrameworkSink = FrameworkSink;

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
 * Matching delegates to the taint engine's own `matchesCallPattern`
 * (propagate-core.ts) so wildcard receivers, method chains, and the
 * trailing-`(*)` stripping behave identically to taint sink matching.
 */
export function detectSanitizerAbsence(
  spec: FrameworkSpec,
  callsites: CallSite[],
  // Accepted for caller API stability (runner.ts / validate.ts / per-language
  // tests pass the project language positionally). Currently unused: pattern
  // matching is language-agnostic (`matchesCallPattern` keys off the YAML's
  // declared separator, not the project language). Kept as a hook for a
  // future receiver-aware matcher.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  language?: 'js' | 'python' | 'java' | 'go' | 'ruby' | 'php' | 'rust' | 'csharp',
): NonTaintFinding[] {
  const findings: NonTaintFinding[] = [];
  for (const sink of spec.sinks) {
    if (!sink.required_arguments || sink.required_arguments.length === 0) continue;
    for (const cs of callsites) {
      if (!matchesCallPattern(sink.pattern, cs.calleeText)) continue;
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

/**
 * Walk a list of lowered `IrFunction`s and emit one `CallSite` per `call`
 * step. This is the runner-side adapter referenced in the design doc.
 *
 * Per-language behaviour:
 *   - `python`: kwarg names come from `Step.kwargNames` (added in Phase F4).
 *               The kwarg value text comes from the parallel `argTexts[i]`.
 *   - `js`: the language doesn't have kwargs syntactically. When a sink
 *           expects a named argument (e.g. `algorithms` on `jwt.verify`),
 *           callers conventionally pass an options object as the last
 *           positional. We parse that argText for top-level `key: value`
 *           pairs using a cheap regex. Tolerates whitespace + line breaks;
 *           does NOT handle nested object literals (the regex is anchored
 *           on top-level commas, which is sufficient for the sanitizer-
 *           absence corpus we ship).
 *   - other languages: positional only — `kwargNames` empty, `kwargValues`
 *           undefined.
 *
 * The detector is intentionally tolerant: false positives from a mis-parsed
 * options object would still need to match the sink's `pattern` exactly, so
 * spurious findings are rare in practice. Gate-2 fixture round-trip
 * (validate.ts) catches anything that slips past.
 */
export function extractCallSitesFromIr(
  irFunctions: IrFunction[],
  language: 'js' | 'python' | 'java' | 'go' | 'ruby' | 'php' | 'rust' | 'csharp',
): CallSite[] {
  const sites: CallSite[] = [];
  for (const fn of irFunctions) {
    for (const step of fn.steps) {
      if (step.kind !== 'call') continue;
      const cs = callSiteFromCallStep(step, language, fn.localOrigins);
      if (cs) sites.push(cs);
    }
  }
  return sites;
}

function callSiteFromCallStep(
  step: Extract<Step, { kind: 'call' }>,
  language: 'js' | 'python' | 'java' | 'go' | 'ruby' | 'php' | 'rust' | 'csharp',
  localOrigins?: Map<string, string>,
): CallSite | null {
  const calleeText = step.callee.calleeText;
  const argTexts = [...step.argTexts];
  const kwargNames: string[] = [];
  const kwargValues: Record<string, string> = {};

  if (language === 'python' && step.kwargNames) {
    for (let i = 0; i < step.kwargNames.length; i++) {
      const name = step.kwargNames[i];
      if (name === null || name === undefined) continue;
      kwargNames.push(name);
      const value = step.argTexts[i];
      if (typeof value === 'string') kwargValues[name] = value;
    }
  } else if (language === 'js' && argTexts.length > 0) {
    // Scan EVERY arg for an inline object literal — option-objects are most
    // commonly the last positional, but jwt.verify(token, key, { algorithms })
    // is also written with the options object inline anywhere. Mirror every
    // top-level `key: value` pair onto kwargNames so the detector can match.
    //
    // Phase 2a: hoisted-const resolution. When argText is a bare identifier
    // (`f(opts)`), look it up in the function's localOrigins map (built by
    // the lowerer from `const opts = { ... }` declarations) and parse THAT
    // literal text instead. Falls back silently if the identifier wasn't a
    // single-assignment literal-init, preserving the existing inline-literal
    // behaviour as the default.
    for (const text of argTexts) {
      const resolved = resolveJsArgText(text, localOrigins);
      const props = parseObjectLiteralProps(resolved);
      for (const [k, v] of Object.entries(props)) {
        if (!kwargNames.includes(k)) {
          kwargNames.push(k);
          kwargValues[k] = v;
        }
      }
    }
  }

  return {
    calleeText,
    argTexts,
    kwargNames,
    kwargValues,
    filePath: step.loc.filePath,
    line: step.loc.line,
    column: step.loc.column,
  };
}

/**
 * Resolve a JS argText through the IR's `localOrigins` map (Phase 2a). When
 * the arg text is a bare identifier AND that identifier was bound by a
 * single-assignment `const x = { ... }` / `const x = [ ... ]` declaration in
 * the same function, return the literal initializer text. Otherwise return
 * the input unchanged so the inline-literal parser can still try.
 */
function resolveJsArgText(text: string, localOrigins?: Map<string, string>): string {
  if (!localOrigins || localOrigins.size === 0) return text;
  const trimmed = text.trim();
  // Bare identifier — JS naming rules.
  if (!/^[A-Za-z_$][\w$]*$/.test(trimmed)) return text;
  const init = localOrigins.get(trimmed);
  return init ?? text;
}

/**
 * Cheap parser for top-level `key: value` pairs inside a JS object literal
 * source text like `{ algorithms: ['HS256'], maxAge: '1h' }`. Returns the
 * pairs found at depth-0; nested braces / brackets / parens are tracked so
 * we don't split inside them, but the returned `value` text is verbatim
 * source. Not a full JS parser — this matches the conservative regime
 * documented above.
 */
function parseObjectLiteralProps(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  const t = text.trim();
  if (!t.startsWith('{') || !t.endsWith('}')) return out;
  const body = t.slice(1, -1);

  // Walk body, splitting at top-level commas.
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch === '{' || ch === '[' || ch === '(') depth++;
    else if (ch === '}' || ch === ']' || ch === ')') depth--;
    else if (ch === ',' && depth === 0) {
      parts.push(body.slice(start, i));
      start = i + 1;
    }
    // Skip string literals (greedy).
    else if (ch === '"' || ch === "'" || ch === '`') {
      const close = ch;
      let j = i + 1;
      let closed = false;
      while (j < body.length) {
        if (body[j] === '\\') { j += 2; continue; }
        if (body[j] === close) { closed = true; break; }
        j++;
      }
      // Unterminated string — the scanner can no longer tell delimiters from
      // string content, so every subsequent comma/colon split is unreliable.
      // Bail the whole parse rather than silently returning a partial prop
      // set (which would under-report kwargs → false sanitizer-absence hits).
      if (!closed) return {};
      i = j;
    }
  }
  if (start < body.length) parts.push(body.slice(start));

  for (const part of parts) {
    const colonIdx = findTopLevelColon(part);
    if (colonIdx < 0) continue;
    const rawKey = part.slice(0, colonIdx).trim();
    const value = part.slice(colonIdx + 1).trim();
    // Strip quotes from quoted keys; reject shorthand-only entries (which have no colon, already skipped).
    const key = rawKey.replace(/^['"]|['"]$/g, '');
    if (!/^[A-Za-z_$][\w$]*$/.test(key)) continue;
    out[key] = value;
  }
  return out;
}

function findTopLevelColon(s: string): number {
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '{' || ch === '[' || ch === '(') depth++;
    else if (ch === '}' || ch === ']' || ch === ')') depth--;
    else if (ch === ':' && depth === 0) return i;
    else if (ch === '"' || ch === "'" || ch === '`') {
      const close = ch;
      let j = i + 1;
      while (j < s.length) {
        if (s[j] === '\\') { j += 2; continue; }
        if (s[j] === close) break;
        j++;
      }
      i = j;
    }
  }
  return -1;
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

/**
 * Phase 3.2 — regex-literal detector (NOT WIRED INTO PIPELINE).
 *
 * Walks source file text looking for regex literals declared in a
 * FrameworkSpec's `unsafe_regex_patterns` array. Emits one finding per
 * unique (file, regex) hit. Unlike the taint engine, this detector
 * fires on the PRESENCE of a known-bad regex literal regardless of
 * source-to-sink dataflow — the CVE's patch baked the regex into the
 * dependency, so the user's reachability question reduces to "is this
 * regex literal present in the code that imports the package?".
 *
 * Targets in the 88-CVE corpus:
 *   - CVE-2017-16137 (debug npm — coloring regex ReDoS).
 *   - CVE-2020-28493 (jinja2 — urlize filter regex ReDoS).
 *
 * Detection rules (intentionally simple in v1):
 *   1. For each FrameworkSpec.unsafe_regex_patterns[i].regex string, scan
 *      every source file's raw text for an exact substring match. Match
 *      is case-sensitive and ignores embedding context (regex literal
 *      vs. plain string vs. comment all count).
 *   2. Emit one finding per (file, regex) pair. Multiple line matches
 *      collapse to the first line.
 *
 * Why text-substring rather than AST-driven? The AI rule generator emits
 * regex strings verbatim from the CVE patch, and the iterate harness's
 * Gate 2 fixtures are short single-file blobs. AST extraction would need
 * per-language regex-literal-recognition (JS `/pat/flags`, Python
 * `re.compile("pat")`, Java `Pattern.compile("pat")`, etc.) — viable but
 * heavier; v1 keeps the surface small and lets the FP corpus precision
 * gate (deferred to Phase 5) tell us whether substring is enough.
 *
 * IMPORTANT: this module ships as a standalone building block. It is not
 * imported by `runner.ts` or `propagator.ts`. Pipeline wiring (per-CVE
 * spec dispatch, finding-shape mapping into `project_reachable_flows`,
 * confidence scoring) is a follow-up tracked alongside the Phase 3
 * detector regime in `.cursor/plans/reachability-90-percent.plan.md`.
 */

import type { FrameworkSpec, UnsafeRegexPattern } from './spec';

export interface RegexLiteralFinding {
  /** File path where the unsafe regex literal was found. */
  filePath: string;
  /** 1-based line number of the FIRST occurrence in this file. */
  line: number;
  /** The literal regex source that matched (FrameworkSpec.unsafe_regex_patterns[i].regex). */
  regex: string;
  /** Human-readable description from the FrameworkSpec entry. */
  description: string;
  /** Source-spec framework name (e.g. "debug", "jinja2"). Carried through
   *  so callers can attribute the finding to the right CVE. */
  framework: string;
}

export interface DetectRegexLiteralsOptions {
  /** Source files to scan. The detector consumes raw bytes; AST parsing
   *  is not required. */
  files: Array<{ filePath: string; content: string }>;
  /** Specs that contribute `unsafe_regex_patterns`. Specs without the
   *  field are silently skipped. */
  specs: FrameworkSpec[];
}

/**
 * Scan files for unsafe regex literals declared by any spec.
 *
 * Algorithm:
 *   for each (file, spec, regex):
 *     find the first 1-based line number where `content.includes(regex)`
 *     emit one finding (deduplicated per file+regex)
 *
 * Complexity is O(files × patterns × bytes) — acceptable since the
 * pattern list is small (≤ a few per spec) and we do a single
 * `indexOf` per pair (not regex-engine evaluation).
 */
export function detectUnsafeRegexLiterals(opts: DetectRegexLiteralsOptions): RegexLiteralFinding[] {
  const findings: RegexLiteralFinding[] = [];
  const seen = new Set<string>(); // dedupe key: `${filePath}|${regex}`
  for (const spec of opts.specs) {
    const patterns: UnsafeRegexPattern[] | undefined = spec.unsafe_regex_patterns;
    if (!patterns || patterns.length === 0) continue;
    for (const file of opts.files) {
      for (const pat of patterns) {
        if (!pat.regex || pat.regex.length === 0) continue;
        const key = `${file.filePath}|${pat.regex}`;
        if (seen.has(key)) continue;
        const idx = file.content.indexOf(pat.regex);
        if (idx < 0) continue;
        seen.add(key);
        const line = lineNumberForOffset(file.content, idx);
        findings.push({
          filePath: file.filePath,
          line,
          regex: pat.regex,
          description: pat.description,
          framework: spec.framework,
        });
      }
    }
  }
  return findings;
}

/** Convert a byte offset to a 1-based line number by counting \n characters. */
function lineNumberForOffset(content: string, offset: number): number {
  let n = 1;
  for (let i = 0; i < offset && i < content.length; i++) {
    if (content.charCodeAt(i) === 0x0a /* \n */) n++;
  }
  return n;
}

/**
 * Framework spec types for the taint engine.
 *
 * A FrameworkSpec describes how a single framework (Express, Fastify, NestJS,
 * etc.) introduces tainted data (sources), where untrusted data should not
 * end up (sinks), and which functions clean tainted data (sanitizers).
 *
 * Specs are persisted as YAML files under src/taint-engine/framework-models/
 * for hand-written specs, and stored in the taint_engine_framework_models
 * table for AI-inferred specs (M6).
 *
 * Pattern matching against AST is intentionally simple in M2: text-based
 * prefix / exact match against the call/access expression's source text.
 * M3+ may upgrade to type-aware matching when the simple form misclassifies.
 */

/**
 * Closed taxonomy of vulnerability classes the engine can detect. Matches
 * the taint_engine_settings.vuln_classes_enabled DEFAULT list (phase26
 * migration; extended in phase28b to add `code_injection`).
 *
 * `code_injection` covers expression / template / eval-style sinks where
 * tainted data is interpreted as code by the runtime — Spring SpEL eval,
 * `eval(*)`, `Function(*)`, server-side template injection, etc. Added
 * because Qwen routinely emits this label for SpEL CVEs (e.g.
 * CVE-2023-34053) and the previous closed enum silently rejected the
 * generated spec under `invalid_schema`. Vuln classes that genuinely fall
 * outside taint flow (DoS, XML expansion, HTTP/2 reset attacks) are
 * surfaced via the `vuln_class_out_of_scope` generator failure code
 * instead of being modelled here.
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

/** Kind label attached to a tainted value as it flows through the program. */
export type TaintKind = 'http_input' | 'env' | 'file' | 'cli' | 'rpc';

/**
 * A source: an expression that introduces tainted data into a function.
 * Examples: `req.body.*` (Express), `process.env.*` (Node), `fs.readFileSync(*)`.
 *
 * Pattern grammar (M2):
 *   - `Foo.bar`        — exact match against the full source text
 *   - `Foo.bar.*`      — prefix match (matches `Foo.bar`, `Foo.bar.x`, `Foo.bar.x.y`, etc.)
 *   - `Foo.bar(*)`     — call expression where the callee text equals `Foo.bar`
 *
 * Sources should resolve to property access or call expressions; the
 * matcher in propagator.ts decides which AST shape applies based on
 * whether the pattern ends in `(*)`.
 */
export interface FrameworkSource {
  pattern: string;
  taint_kind: TaintKind;
  description: string;
}

/**
 * A sink: a function that, when called with a tainted argument at any of the
 * argument_indices positions, indicates a vulnerability of vuln_class.
 *
 * If argument_indices is empty, ANY tainted argument triggers the sink
 * (used for variadic helpers like `console.log` or for functions where
 * every argument is unsafe).
 *
 * `osv_id` is set on sinks loaded from CVE-targeted FrameworkSpec rows
 * (Phase 6.5). The Phase 6 file-loaded framework specs (express.yaml, etc.)
 * leave it undefined — those flows are framework-generic, not CVE-attributed.
 * When set, the propagator stamps it onto `Flow.osv_id` at sink-match so
 * downstream classification + suppression can key on the CVE.
 */
export interface FrameworkSink {
  pattern: string;
  vuln_class: VulnClass;
  argument_indices: number[];
  description: string;
  osv_id?: string;
}

/**
 * A sanitizer: a function whose return value is considered clean (with
 * respect to the listed vuln_classes) regardless of the taint state of
 * its arguments. Equivalent to "the result of validator.escape(x) is no
 * longer a XSS risk even if x was tainted".
 */
export interface FrameworkSanitizer {
  pattern: string;
  vuln_classes: VulnClass[];
  description: string;
}

/** Language a framework spec applies to. Drives runner dispatch — Python
 * specs only apply to PyPI projects, etc. Defaults to 'js' when unset, for
 * backward compatibility with the original Express/Fastify/NestJS/Next/Hono
 * specs that pre-dated multi-language support. */
export type FrameworkLanguage =
  | 'js'
  | 'python'
  | 'java'
  | 'go'
  | 'ruby'
  | 'php'
  | 'rust'
  | 'csharp';

export interface FrameworkSpec {
  framework: string;
  /** Semver range or '*'. M2 doesn't enforce; M6 will dispatch on this. */
  version: string;
  /** Optional; defaults to 'js'. */
  language?: FrameworkLanguage;
  sources: FrameworkSource[];
  sinks: FrameworkSink[];
  sanitizers: FrameworkSanitizer[];
}

/**
 * Filter a spec set to only those applicable to one language. Each per-language
 * propagator calls this at entry so cross-language sanitizers/sinks/sources can
 * never leak (e.g. Rails' `JSON.parse(*)` sanitizer cancelling a Node.js
 * `JSON.parse(*)` deser sink). `runner.ts` already applies the same filter
 * before dispatch, so this is defence-in-depth for any other call site
 * (validate harness, benchmark, ad-hoc scripts).
 */
export function filterSpecsByLanguage(
  specs: FrameworkSpec[],
  language: FrameworkLanguage,
): FrameworkSpec[] {
  return specs.filter((s) => (s.language ?? 'js') === language);
}

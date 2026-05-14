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
 * migration; extended in phase28b to add `code_injection`, and phase28c to
 * add `weak_crypto` + `auth_bypass`).
 *
 * `code_injection` covers expression / template / eval-style sinks where
 * tainted data is interpreted as code by the runtime — Spring SpEL eval,
 * `eval(*)`, `Function(*)`, server-side template injection, etc. Added
 * because Qwen routinely emits this label for SpEL CVEs (e.g.
 * CVE-2023-34053) and the previous closed enum silently rejected the
 * generated spec under `invalid_schema`.
 *
 * `weak_crypto` covers sinks where tainted data influences a cryptographic
 * primitive in a way that breaks its security guarantees — e.g. CVE-2022-
 * 23541 (jsonwebtoken `kid` claim resolves an attacker-controlled key into
 * a verifier), HMAC keys built from untrusted input, predictable IVs, etc.
 *
 * `auth_bypass` covers sinks where tainted data routes around an
 * authentication / authorization decision — e.g. CVE-2022-22978 (Spring
 * Security RegexRequestMatcher newline bypass), URL-normalisation gaps in
 * auth filters, etc.
 *
 * Vuln classes that genuinely fall outside taint flow (DoS, XML expansion,
 * HTTP/2 reset attacks) are surfaced via the `vuln_class_out_of_scope`
 * generator failure code instead of being modelled here.
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
 * Phase F4 (non-taint regime). When attached to a sink, the non-taint
 * detector inspects each call site whose callee matches the sink's pattern
 * and asserts the named-argument contract. See
 * `docs/non-taint-detector-regime.md` for the design + corpus mapping, and
 * `taint-engine/non-taint-detector.ts` for the matcher.
 *
 * Detector modes:
 *   - `required`   : finding fires when the argument is ABSENT
 *                    (CVE-2022-23539 `jwt.verify` missing `algorithms`).
 *   - `forbidden`  : finding fires when the argument is PRESENT with a
 *                    value matching `unsafe_literals`
 *                    (CVE-2024-35195 `requests.Session(verify=False)`).
 *   - `must_equal` : finding fires when the argument is PRESENT but its
 *                    literal text is NOT in `safe_literals`.
 */
export interface RequiredArgument {
  /** Kwarg name (or object-property key for JS option-object calls). */
  name: string;
  /** Positional-index fallback (0-based). Optional. */
  position?: number;
  /** Default 'required'. */
  match_mode?: 'required' | 'forbidden' | 'must_equal';
  /** Whitelist for 'must_equal' mode. */
  safe_literals?: string[];
  /** Blacklist for 'forbidden' mode. */
  unsafe_literals?: string[];
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
 *
 * `required_arguments` (Phase F4) opts the sink into the non-taint detector
 * regime: a call-site walk that flags sanitizer-absence shapes (missing or
 * forbidden options). A sink may participate in BOTH regimes — taint flow
 * (via `argument_indices`) and non-taint (via `required_arguments`).
 */
export interface FrameworkSink {
  pattern: string;
  vuln_class: VulnClass;
  argument_indices: number[];
  description: string;
  osv_id?: string;
  required_arguments?: RequiredArgument[];
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

/**
 * Phase 3.2 — regex-literal detector. The framework spec declares regex
 * literals known to exhibit catastrophic backtracking on attacker-influenced
 * input. The detector walks the codebase for matching regex literals (JS
 * `/pat/` and `new RegExp("pat")`, Python `re.compile("pat")`, etc.) and
 * emits a `redos` finding for each match without requiring a taint flow.
 *
 * Distinct from the taint-flow regime: this fires on the PRESENCE of the
 * unsafe regex literal in the codebase, not on a source→sink edge. The
 * underlying CVE is typically baked into a dependency's regex constant,
 * so the bundled or AI-generated spec encodes which literals are known
 * bad (e.g. debug-17-16137, jinja2-20-28493).
 */
export interface UnsafeRegexPattern {
  /** Exact regex literal source (without surrounding `/.../` delimiters
   *  for JS or quotes for Python). Matched as a substring against the
   *  literal source text emitted by the AST. */
  regex: string;
  description: string;
}

/**
 * Phase 3.3 — insecure-default detector. The framework spec declares call
 * patterns where a named or positional argument's omission, or its value
 * matching one of `forbidden_value_shapes`, indicates a sanitizer-absence
 * vulnerability shape independent of taint flow.
 *
 * Overlaps semantically with FrameworkSink.required_arguments (Phase F4),
 * but lives at the top-level spec rather than per-sink so detectors can
 * be authored without needing a paired taint sink. Used for CVEs whose
 * vuln_class is `weak_crypto` / `weak_default` (e.g. requests-24-35195's
 * `verify=False` shape, flask-23-30861 session-without-secure-cookie).
 */
export interface InsecureDefault {
  pattern: string;
  description: string;
  /** Kwarg name to check. */
  argument_name?: string;
  /** Or positional-index fallback. */
  argument_position?: number;
  /** When set, finding fires if the argument is absent OR its literal text
   *  matches one of these shapes. When omitted (and argument_name/position
   *  set), finding fires only on absence. */
  forbidden_value_shapes?: string[];
  /** vuln_class emitted by the detector. Defaults to `weak_default` if the
   *  enum is extended; until then specs use `weak_crypto`. */
  vuln_class?: VulnClass;
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
  /** Phase 3.2 — regex literals the CVE patch identifies as ReDoS-prone.
   *  Consumed by `regex-literal-detector.ts`. Optional; specs that don't
   *  participate in the regex-literal regime leave it absent. */
  unsafe_regex_patterns?: UnsafeRegexPattern[];
  /** Phase 3.3 — call patterns where a missing kwarg or a forbidden literal
   *  value indicates a sanitizer-absence shape. Consumed by
   *  `insecure-default-detector.ts`. Optional. */
  insecure_defaults?: InsecureDefault[];
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

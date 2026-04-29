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
 * the taint_engine_settings.vuln_classes_enabled CHECK list (M4 migration).
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
  | 'log_injection';

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
 */
export interface FrameworkSink {
  pattern: string;
  vuln_class: VulnClass;
  argument_indices: number[];
  description: string;
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
export type FrameworkLanguage = 'js' | 'python' | 'java' | 'go';

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

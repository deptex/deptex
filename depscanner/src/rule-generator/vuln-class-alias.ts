/**
 * Vuln-class normalization layer for Gate 2 widening (validate.ts).
 *
 * Context. The Gate 2 widening in `validateRule` accepts bundled
 * framework_model sinks whose `vuln_class` matches one declared by the AI
 * rule under generation. The match is exact-string equality on the enum
 * value, which silently rejects pairs that are semantically equivalent
 * but lexically different. Triaged shapes from 2026-05-12:
 *
 *   - AI emits `log_injection`, log4j.yaml emits `code_injection` for the
 *     same `*.info(*)` Logger sink (CVE-2017-16137 debug, Log4Shell family).
 *   - AI emits `ssti` / `template_injection`, jinja2.yaml emits
 *     `code_injection` for `Template.from_string(*)`.
 *   - AI emits `log4shell`, log4j.yaml emits `code_injection`.
 *
 * We normalize at the comparison site only — the persisted spec retains
 * the original `vuln_class` value (still constrained by zod to enum).
 * Canonical targets are picked from `ALL_VULN_CLASSES` in
 * `taint-engine/spec.ts`; we do NOT extend the enum here (Agent E3 owns
 * enum changes). Aliases pointing at non-existent classes are dropped.
 *
 * For inputs not in the alias map, `canonicalVulnClass` is identity, so
 * the function is safe to apply unconditionally at every Gate-2 matching
 * site.
 */

import { ALL_VULN_CLASSES } from '../taint-engine/spec';

/**
 * Aliases mapping alternate-vocabulary vuln_class strings onto the
 * canonical enum value the engine + bundled framework_models actually emit.
 *
 * Targets MUST be members of `ALL_VULN_CLASSES`; the runtime filter below
 * drops any entry whose target isn't in the enum, so accidental drift
 * (e.g. adding `weak_crypto` here before E3 ships the enum value) silently
 * no-ops instead of poisoning the match set.
 */
const RAW_ALIASES: Record<string, string> = {
  // Log-context taint into log frameworks. log4j.yaml emits `code_injection`
  // because the JNDI-as-code-loader path is the load-bearing primitive;
  // Qwen routinely labels the same shape `log_injection` or `log4shell`.
  log_injection: 'code_injection',
  log4shell: 'code_injection',

  // Server-side template injection. jinja2.yaml uses `code_injection` for
  // `from_string` / `Template(*)`; the engine has no separate `ssti`
  // class today (see spec.ts ALL_VULN_CLASSES).
  ssti: 'code_injection',
  template_injection: 'code_injection',

  // ReDoS / generic DoS. Bundled moment/semver-style sinks use `redos`;
  // AI occasionally emits the broader `dos` label. Engine has `redos`,
  // not `dos`, so alias inbound `dos` onto `redos`.
  dos: 'redos',
  // CVE-2022-23837 (rack multipart parser) — Qwen labels DoS-class CVEs as
  // resource_exhaustion. Same canonicalisation target as `dos`: the engine
  // models this as a ReDoS-style sink shape (regex/parser fed untrusted
  // bytes) and treats both alias chains as redos.
  resource_exhaustion: 'redos',

  // CVE-2024-35195 family — TLS verification disabled. The model labels
  // these `improper_cert_validation`; bundled `requests` / `urllib3` /
  // `httpx` specs emit `weak_crypto` for `verify=False` insecure-default
  // shapes. Both refer to the same primitive (broken TLS guarantee).
  improper_cert_validation: 'weak_crypto',
  tls_validation_bypass: 'weak_crypto',

  // CVE-2021-25287 (pillow) — Qwen labels memory-safety bugs that surface
  // through crafted image bytes as `out_of_bounds_read`. The engine has no
  // memory-safety class today; the closest taint-shape primitive is `redos`
  // (parser fed untrusted bytes triggers super-linear / unbounded compute).
  // Same canonicalisation chain as `dos` / `resource_exhaustion`.
  out_of_bounds_read: 'redos',
  buffer_overflow: 'redos',
  memory_corruption: 'redos',
};

/**
 * Resolved alias map, with any target not in the engine enum dropped.
 * Computed eagerly at module load so canonicalVulnClass is allocation-free
 * on the hot path.
 */
const ALIASES: Record<string, string> = (() => {
  const enumSet = new Set<string>(ALL_VULN_CLASSES as readonly string[]);
  const out: Record<string, string> = {};
  for (const [from, to] of Object.entries(RAW_ALIASES)) {
    if (enumSet.has(to)) out[from] = to;
  }
  return out;
})();

/**
 * Normalize a vuln_class label to its canonical engine-enum form. Returns
 * the input unchanged when no alias applies, so callers can apply this
 * unconditionally at every match site.
 */
export function canonicalVulnClass(c: string): string {
  return ALIASES[c] ?? c;
}

/**
 * Exposed for tests / introspection. Snapshot of the resolved alias map
 * after enum-target filtering. Do not mutate.
 */
export function getVulnClassAliases(): Readonly<Record<string, string>> {
  return ALIASES;
}

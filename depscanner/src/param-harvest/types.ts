// Deterministic request-parameter harvest — shared types.
//
// The framework detectors (express, flask in v1) walk each route handler's CST
// during detection and emit the query/header/cookie parameter names the handler
// reads. These persist as project_entry_points.request_params (JSONB) and drive
// the DAST OpenAPI synthesizer's `query` parameters so ZAP injects into them.
//
// Path params are NOT harvested here — they're owned by
// dast/openapi-path-translate.ts (derived from the route string). The LLM
// enrichment + request body fields are a separate fast-follow; the `provenance`
// enum reserves 'decorator' | 'llm' for it.

export type RequestParamIn = 'query' | 'header' | 'cookie';
export type RequestParamType = 'string' | 'integer' | 'number' | 'boolean';
export type RequestParamProvenance = 'ast' | 'decorator' | 'llm';

export interface RequestParam {
  name: string;
  in: RequestParamIn;
  required: boolean;
  schema: { type: RequestParamType };
  provenance: RequestParamProvenance;
}

const IN_ORDER: Record<RequestParamIn, number> = { query: 0, header: 1, cookie: 2 };

/**
 * Canonicalize a harvested param list: dedupe by (name, in) — first occurrence
 * wins — then sort by (in, name). Determinism is a hard requirement (the
 * snapshot suite + Success Criterion #2 depend on byte-stable output across
 * repeated extractions), so this is applied both at harvest time (so detector
 * output is stable) and again in storage (defense in depth).
 */
export function canonicalizeParams(
  params: readonly RequestParam[] | null | undefined,
): RequestParam[] | null {
  if (!params || params.length === 0) return null;
  const seen = new Map<string, RequestParam>();
  for (const p of params) {
    const key = `${p.in}\x00${p.name}`;
    if (!seen.has(key)) seen.set(key, p);
  }
  const out = Array.from(seen.values());
  out.sort((a, b) => {
    const di = IN_ORDER[a.in] - IN_ORDER[b.in];
    if (di !== 0) return di;
    return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
  });
  return out;
}

/** Valid JS/Python identifier-ish param name (defensive: keeps harvest output
 * spec-safe even if a future source shape yields junk). */
export function isPlausibleParamName(name: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(name);
}

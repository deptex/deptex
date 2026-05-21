// Phase 35 (v1.1) — PATCH-time validation of OpenAPI specs supplied via URL.
//
// Two validation surfaces:
//   1. validateSpecSource(input) — string-shape check for the 3 v1.1 enum
//      values. Rejects 'upload' (deferred to v1.2's own migration + UI).
//   2. validateAndFetchSpecUrl(url) — SSRF guard → bounded fetch → strict
//      swagger-parser validate. Returns a typed result the route maps to
//      the canonical error codes from `backend/src/types/dast.ts`.
//
// The worker has its own URL-mode resolver (`depscanner/src/dast/
// openapi-spec-source.ts`) for scan-time fetches; that one soft-fails to
// spider-only. PATCH-time fetch is loud (hard-fail) because the customer
// is sitting at the dialog watching for feedback.

import SwaggerParser from '@apidevtools/swagger-parser';
import { validateExternalUrl } from './url-guard';
import {
  FETCH_TIMEOUT_MS,
  MAX_SPEC_BYTES,
} from './dast-openapi-constants';
import type { DastSpecSource } from '../types/dast';

export type SpecValidationError =
  | { code: 'invalid_spec_source' }
  | { code: 'spec_url_required' }
  | { code: 'spec_url_invalid'; detail: string }
  | { code: 'spec_url_unreachable'; detail: string }
  | { code: 'spec_too_large' }
  | { code: 'spec_parse_failed'; detail: string };

/**
 * Returns the normalized enum value when input is one of the v1.1 strings,
 * or an error code otherwise. Used by the PATCH /spec route + can be
 * imported from tests to verify the rejection set.
 */
export function validateSpecSource(
  input: unknown,
): { ok: true; value: DastSpecSource } | { ok: false; error: SpecValidationError } {
  if (typeof input !== 'string') {
    return { ok: false, error: { code: 'invalid_spec_source' } };
  }
  if (input === 'synthesized' || input === 'url' || input === 'none') {
    return { ok: true, value: input };
  }
  // 'upload' falls through here in v1.1 — reserved for v1.2's own migration.
  return { ok: false, error: { code: 'invalid_spec_source' } };
}

export interface ValidateAndFetchSpecResult {
  ok: true;
  yaml: string;
  endpoint_count: number;
}

/**
 * Validate + fetch + parse a customer-supplied OpenAPI URL at PATCH time.
 * SSRF guard runs first; then a bounded fetch (FETCH_TIMEOUT_MS,
 * MAX_SPEC_BYTES); then swagger-parser in strict mode. All three
 * failure surfaces map to distinct error codes — the frontend's
 * friendlySpecErrorMessage uses these for actionable toast copy.
 */
export async function validateAndFetchSpecUrl(
  url: string,
): Promise<ValidateAndFetchSpecResult | { ok: false; error: SpecValidationError }> {
  const guard = await validateExternalUrl(url);
  if (guard.valid === false) {
    return { ok: false, error: { code: 'spec_url_invalid', detail: guard.reason } };
  }

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), FETCH_TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetch(url, { signal: ac.signal });
  } catch (e) {
    clearTimeout(timer);
    return {
      ok: false,
      error: {
        code: 'spec_url_unreachable',
        detail: e instanceof Error ? e.message : 'unknown fetch error',
      },
    };
  }
  clearTimeout(timer);

  if (!res.ok) {
    return {
      ok: false,
      error: { code: 'spec_url_unreachable', detail: `HTTP ${res.status}` },
    };
  }

  const advertised = res.headers.get('content-length');
  if (advertised) {
    const n = parseInt(advertised, 10);
    if (Number.isFinite(n) && n > MAX_SPEC_BYTES) {
      return { ok: false, error: { code: 'spec_too_large' } };
    }
  }

  let buf: ArrayBuffer;
  try {
    buf = await res.arrayBuffer();
  } catch (e) {
    return {
      ok: false,
      error: {
        code: 'spec_url_unreachable',
        detail: e instanceof Error ? e.message : 'read error',
      },
    };
  }
  if (buf.byteLength > MAX_SPEC_BYTES) {
    return { ok: false, error: { code: 'spec_too_large' } };
  }

  const text = new TextDecoder('utf-8', { fatal: false }).decode(buf);

  const parsed = await validateOpenApiYaml(text);
  if (parsed.ok === false) {
    return { ok: false, error: parsed.error };
  }
  return { ok: true, yaml: text, endpoint_count: parsed.endpoint_count };
}

interface OpenApiPathsMap {
  paths?: Record<string, Record<string, unknown>>;
}

/**
 * Run swagger-parser strict-mode validate over raw YAML/JSON. Accepts
 * OpenAPI 3.0.x, 3.1.x, and Swagger 2.0 — see ACCEPTED_OPENAPI_VERSIONS.
 * Returns the operation count (sum over paths × non-extension method keys)
 * for the row's last_synthesis_endpoint_count.
 */
export async function validateOpenApiYaml(
  rawText: string,
): Promise<
  | { ok: true; endpoint_count: number }
  | { ok: false; error: { code: 'spec_parse_failed'; detail: string } }
> {
  if (!rawText || rawText.length === 0) {
    return {
      ok: false,
      error: { code: 'spec_parse_failed', detail: 'empty body' },
    };
  }

  // swagger-parser accepts an object or a path. We give it the parsed YAML
  // ourselves (js-yaml is already a transitive dep) so the parser doesn't
  // need disk access.
  const yaml = await import('js-yaml');
  let doc: unknown;
  try {
    doc = yaml.load(rawText);
  } catch (e) {
    return {
      ok: false,
      error: {
        code: 'spec_parse_failed',
        detail: (e instanceof Error ? e.message : 'YAML parse error').slice(0, 200),
      },
    };
  }
  if (!doc || typeof doc !== 'object') {
    return {
      ok: false,
      error: { code: 'spec_parse_failed', detail: 'document is not an object' },
    };
  }

  // Strict-mode swagger-parser validates the OpenAPI/Swagger structure and
  // resolves $refs. It mutates the input, so clone first.
  let validated: unknown;
  try {
    // swagger-parser's types want `string | object` — cast to unknown to
    // satisfy its overload.
    validated = await SwaggerParser.validate(JSON.parse(JSON.stringify(doc)) as never);
  } catch (e) {
    return {
      ok: false,
      error: {
        code: 'spec_parse_failed',
        detail: (e instanceof Error ? e.message : 'unknown parse error').slice(0, 200),
      },
    };
  }

  const paths = (validated as OpenApiPathsMap).paths ?? {};
  let count = 0;
  const HTTP_METHODS = new Set([
    'get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace',
  ]);
  for (const item of Object.values(paths)) {
    if (!item || typeof item !== 'object') continue;
    for (const key of Object.keys(item)) {
      if (HTTP_METHODS.has(key.toLowerCase())) count++;
    }
  }
  return { ok: true, endpoint_count: count };
}

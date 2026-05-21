// Phase 35 (v1.1) — resolves a DAST target's `api_spec_source` to a
// concrete OpenAPI YAML on disk plus an optional handler sidecar for the
// cross-link pre-pass. Called from the pipeline AFTER tenant + credential
// guards and BEFORE buildAutomationYaml.
//
// Row-driven gating: target.api_spec_source is the sole source of truth in
// v1.1 (no payload override). The pipeline calls this, gets back a
// `specPath` plus an `ok` flag; if specPath is set, it threads
// openApiSpecPath into yaml-builder. Soft-fail variants leave specPath
// null and surface a status string for the row write.

import * as fs from 'fs';
import * as path from 'path';
import { synthesizeOpenApi } from './openapi-synth';
import { validateExternalUrl } from './url-guard';
import { FETCH_TIMEOUT_MS, MAX_SPEC_BYTES } from './openapi-constants';
import type { EntryPointRow, HandlerSidecar } from './cross-link';

export type SpecSource = 'synthesized' | 'url' | 'upload' | 'none';

/**
 * Worker-side status mapping for the `last_synthesis_ok` boolean + log
 * line. Each soft-fail variant is logged for ops visibility; the DB only
 * stores the boolean. Specific cause is inferable from other row state
 * (source + endpoint_count + last_synthesized_at) per the
 * inference rules in DastSpecPanel.
 */
export type SpecResolveStatus =
  | 'ok'
  | 'synth.no_entry_points'
  | 'url.fetch_failed'
  | 'url.parse_failed'
  | 'storage.write_failed';

export interface ResolveSpecJobInputs {
  /** Target row's api_spec_source. */
  source: SpecSource;
  /** Target row's api_spec_url (required when source='url'). */
  api_spec_url: string | null;
  /** Target's base URL (used as servers[0].url in synthesized doc). */
  targetUrl: string;
  /** Entry points already loaded by the pipeline (filter happens here). */
  entryPoints: EntryPointRow[];
  /** Per-job temp dir where the YAML + sidecar files are written. */
  tmpDir: string;
}

export interface ResolveSpecJobOutput {
  /** Absolute path to the spec YAML on disk; undefined when no spec resolves. */
  specPath?: string;
  /** Sidecar handler map (synthesized mode only); undefined for url/none. */
  sidecar?: HandlerSidecar;
  /** Sidecar serialized to disk alongside specPath (synthesized mode only). */
  sidecarPath?: string;
  /** Count of operations emitted (synthesized mode only). */
  endpointCount: number;
  /** Status discriminator for the worker write to `last_synthesis_ok`. */
  status: SpecResolveStatus;
}

const NO_SPEC: ResolveSpecJobOutput = { endpointCount: 0, status: 'ok' };

// Minimal OpenAPI/Swagger version sniff. Avoids pulling swagger-parser into
// the worker; we just check the top-level `openapi:` / `swagger:` field of
// the loaded YAML/JSON.
function looksLikeOpenApi(rawText: string): boolean {
  if (rawText.length === 0) return false;
  // Don't full-parse — a regex on the first 1 KB is enough.
  const head = rawText.slice(0, 1024);
  if (/(^|\n)\s*openapi\s*:\s*["']?[23]\./.test(head)) return true;
  if (/"openapi"\s*:\s*"[23]\./.test(head)) return true;
  if (/(^|\n)\s*swagger\s*:\s*["']?2\.0/.test(head)) return true;
  if (/"swagger"\s*:\s*"2\.0/.test(head)) return true;
  return false;
}

/**
 * Fetch a URL spec with timeout + size cap. SSRF guard runs first. All
 * failure modes collapse to one of two soft statuses — the caller logs the
 * mapped reason for ops visibility.
 *
 * Explicit mapping (Patch 9 / architect-f6):
 *   - DNS / 5xx / timeout / size-cap  → 'url.fetch_failed'
 *   - non-YAML/JSON body / no openapi or swagger key → 'url.parse_failed'
 */
async function fetchUrlSpec(
  url: string,
): Promise<
  | { ok: true; yaml: string }
  | { ok: false; status: 'url.fetch_failed' | 'url.parse_failed'; reason: string }
> {
  const guard = await validateExternalUrl(url);
  if (guard.valid === false) {
    return {
      ok: false,
      status: 'url.fetch_failed',
      reason: `ssrf_guard: ${guard.reason}`,
    };
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
      status: 'url.fetch_failed',
      reason: `fetch_error: ${e instanceof Error ? e.message : 'unknown'}`,
    };
  }
  clearTimeout(timer);

  if (!res.ok) {
    return {
      ok: false,
      status: 'url.fetch_failed',
      reason: `http_${res.status}`,
    };
  }

  const contentLengthHeader = res.headers.get('content-length');
  if (contentLengthHeader) {
    const advertised = parseInt(contentLengthHeader, 10);
    if (Number.isFinite(advertised) && advertised > MAX_SPEC_BYTES) {
      return {
        ok: false,
        status: 'url.fetch_failed',
        reason: `content-length ${advertised} > MAX_SPEC_BYTES`,
      };
    }
  }

  let buf: ArrayBuffer;
  try {
    buf = await res.arrayBuffer();
  } catch (e) {
    return {
      ok: false,
      status: 'url.fetch_failed',
      reason: `read_error: ${e instanceof Error ? e.message : 'unknown'}`,
    };
  }
  if (buf.byteLength > MAX_SPEC_BYTES) {
    return {
      ok: false,
      status: 'url.fetch_failed',
      reason: `body ${buf.byteLength} > MAX_SPEC_BYTES`,
    };
  }

  const text = new TextDecoder('utf-8', { fatal: false }).decode(buf);
  if (!looksLikeOpenApi(text)) {
    return {
      ok: false,
      status: 'url.parse_failed',
      reason: 'response body is not a recognized OpenAPI/Swagger document',
    };
  }
  return { ok: true, yaml: text };
}

/**
 * Resolve target.api_spec_source → spec YAML on disk + optional sidecar.
 *
 * - `synthesized`: walk entryPoints → synthesizeOpenApi → write YAML +
 *   sidecar to tmpDir. Empty entry-points yield status='synth.no_entry_points'
 *   and no spec.
 * - `url`: SSRF-guard → fetch with timeout + size cap → write to tmpDir.
 *   Any failure yields one of two soft statuses; no spec.
 * - `upload`: treated as `none` in v1.1 (route layer rejects 'upload', so this
 *   branch is defense-in-depth against direct DB writes; future v1.2 work
 *   re-enables it).
 * - `none`: no spec, status='ok'.
 *
 * Caller (pipeline.ts) is responsible for storage-first ordering on the
 * synthesized path: write the YAML to the bucket via writeSynthesizedSpec
 * AFTER scan completion, BEFORE updating the row's last_synthesized_at.
 */
export async function resolveSpecForJob(
  inputs: ResolveSpecJobInputs,
): Promise<ResolveSpecJobOutput> {
  if (inputs.source === 'none' || inputs.source === 'upload') {
    return NO_SPEC;
  }

  if (inputs.source === 'synthesized') {
    const out = synthesizeOpenApi(inputs.entryPoints, { targetUrl: inputs.targetUrl });
    if (!out.yaml || !out.sidecar || out.endpoint_count === 0) {
      return { endpointCount: 0, status: 'synth.no_entry_points' };
    }
    const specPath = path.join(inputs.tmpDir, 'openapi-spec.yaml');
    const sidecarPath = path.join(inputs.tmpDir, 'endpoint_to_handler.json');
    // owner-only mode: the spec doesn't carry credentials but the sidecar
    // contains source-file paths we don't want world-readable on disk.
    fs.writeFileSync(specPath, out.yaml, { encoding: 'utf-8', mode: 0o600 });
    fs.writeFileSync(sidecarPath, JSON.stringify(out.sidecar), { encoding: 'utf-8', mode: 0o600 });
    return {
      specPath,
      sidecar: out.sidecar,
      sidecarPath,
      endpointCount: out.endpoint_count,
      status: 'ok',
    };
  }

  if (inputs.source === 'url') {
    if (!inputs.api_spec_url) {
      return { endpointCount: 0, status: 'url.fetch_failed' };
    }
    const fetched = await fetchUrlSpec(inputs.api_spec_url);
    if (!fetched.ok) {
      return { endpointCount: 0, status: fetched.status };
    }
    const specPath = path.join(inputs.tmpDir, 'openapi-spec.yaml');
    fs.writeFileSync(specPath, fetched.yaml, { encoding: 'utf-8', mode: 0o600 });
    return { specPath, endpointCount: 0, status: 'ok' };
  }

  // Defensive: unknown source value falls back to no spec.
  return NO_SPEC;
}

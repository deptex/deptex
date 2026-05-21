// Phase 35 (v1.1) — pure-function OpenAPI 3.1 synthesizer.
//
// Reads project_entry_points rows + targetUrl, emits an OpenAPI 3.1 YAML doc
// PLUS the handler sidecar that crossLinkFinding consumes for deterministic
// finding-to-handler attribution.
//
// No I/O. The pipeline persists the YAML to a temp file (for ZAP's openapi:
// AF job) and the sidecar to a sibling file before scan start.

import * as yaml from 'js-yaml';
import type { EntryPointRow, HandlerSidecar } from './cross-link';
import { translatePathPattern } from './openapi-path-translate';

export interface SynthesisResult {
  /** Serialized OpenAPI 3.1 YAML, or null when no operations passed the filter. */
  yaml: string | null;
  /** Sidecar map: `${METHOD} ${openApiPath}` → handler attribution. */
  sidecar: HandlerSidecar | null;
  /** Count of operations actually emitted (post-filter + post-dedupe). */
  endpoint_count: number;
}

export interface SynthesizeOpts {
  /** Used as `servers[0].url` in the emitted spec. */
  targetUrl: string;
  /** Optional doc-level title; defaults to a placeholder. */
  title?: string;
}

// Health-check paths excluded from the spec — ZAP active-scanning these
// generates a lot of noise and zero useful security signal. The list is
// the de facto health-probe convention across Kubernetes / Spring Boot
// Actuator / Express middlewares.
const HEALTH_PATH = /^\/(health|_status|livez|readyz|healthz)\/?$/i;

const VALID_HTTP_METHODS = new Set([
  'get', 'post', 'put', 'patch', 'delete', 'head', 'options',
]);

// HTTP methods that may carry a JSON body. We emit an open-object
// requestBody for these — ZAP's openapi AF job uses this to seed
// active-scan payloads.
const BODY_METHODS = new Set(['post', 'put', 'patch']);

function methodLower(m: string | null | undefined): string | null {
  if (!m) return null;
  const lower = m.toLowerCase();
  return VALID_HTTP_METHODS.has(lower) ? lower : null;
}

function fileBasenameForOpId(file_path: string): string {
  const parts = file_path.split(/[/\\]/);
  const last = parts[parts.length - 1] ?? file_path;
  return last.replace(/\.[A-Za-z0-9]+$/, '').replace(/[^A-Za-z0-9_]/g, '_') || 'op';
}

function safeOperationId(handlerName: string | null): string {
  if (!handlerName) return 'operation';
  return handlerName.replace(/[^A-Za-z0-9_]/g, '_') || 'operation';
}

// Map auth_mechanism → OpenAPI securityScheme entry. Emitted once at the
// document root under components.securitySchemes.deptexAuth; operations
// that need auth attach `security: [{ deptexAuth: [] }]`.
function authMechanismToScheme(
  mechanism: string | null | undefined,
): Record<string, unknown> | null {
  if (!mechanism) return null;
  const m = mechanism.toLowerCase();
  if (m.includes('bearer') || m.includes('jwt')) {
    return { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' };
  }
  if (m.includes('cookie') || m.includes('session')) {
    return { type: 'apiKey', in: 'cookie', name: 'session' };
  }
  if (m.includes('basic')) {
    return { type: 'http', scheme: 'basic' };
  }
  if (m.includes('apikey') || m.includes('api_key')) {
    return { type: 'apiKey', in: 'header', name: 'X-API-Key' };
  }
  // Conservative default — most "auth_required" mechanisms in detector output
  // are bearer-shaped.
  return { type: 'http', scheme: 'bearer' };
}

interface ParamForEmit {
  name: string;
  in: 'path';
  required: boolean;
  schema: Record<string, unknown>;
  'x-deptex-wildcard'?: boolean;
}

function buildParameters(
  meta: ReturnType<typeof translatePathPattern>['params'],
): ParamForEmit[] {
  return meta.map((p) => {
    const schema: Record<string, unknown> = { type: p.schema.type };
    if (p.pattern) schema.pattern = p.pattern;
    const out: ParamForEmit = {
      name: p.name,
      in: p.in,
      required: p.required,
      schema,
    };
    if (p.wildcard) out['x-deptex-wildcard'] = true;
    return out;
  });
}

/**
 * Filter, translate, and emit an OpenAPI 3.1 doc + sidecar.
 *
 * Filtering pipeline:
 *   - entry_point_type !== 'http_route' → drop (defensive — current detectors
 *     all emit http_route, but the column allows other values).
 *   - classification === 'OFFLINE_WORKER' → drop (background queue handlers).
 *   - route_pattern empty / http_method missing or non-canonical → drop.
 *   - Health-probe paths (/health, /_status, /livez, /readyz, /healthz) → drop.
 *
 * De-duplication: (method, path) collisions keep the first seen; rest are
 * dropped silently.
 *
 * OperationId: handler_name (sanitized) by default; on collision, suffix
 * with the file basename, then with a numeric counter if still colliding.
 */
export function synthesizeOpenApi(
  entryPoints: EntryPointRow[],
  opts: SynthesizeOpts,
): SynthesisResult {
  const candidates: Array<{ ep: EntryPointRow; method: string }> = [];
  for (const ep of entryPoints) {
    if (ep.entry_point_type && ep.entry_point_type !== 'http_route') continue;
    if (ep.classification === 'OFFLINE_WORKER') continue;
    if (!ep.route_pattern) continue;
    const method = methodLower(ep.http_method);
    if (!method) continue;
    if (HEALTH_PATH.test(ep.route_pattern)) continue;
    candidates.push({ ep, method });
  }

  if (candidates.length === 0) {
    return { yaml: null, sidecar: null, endpoint_count: 0 };
  }

  const paths: Record<string, Record<string, unknown>> = {};
  const sidecar: HandlerSidecar = {};
  const usedOperationIds = new Set<string>();
  const securitySchemes: Record<string, Record<string, unknown>> = {};

  for (const { ep, method } of candidates) {
    const translated = translatePathPattern(ep.framework, ep.route_pattern!);
    const openApiPath = translated.openApiPath || ep.route_pattern!;
    const sidecarKey = `${method.toUpperCase()} ${openApiPath}`;
    if (sidecar[sidecarKey]) {
      // (method, path) duplicate — first wins.
      continue;
    }

    // operationId collision strategy: handler_name → handler_name_basename
    // → handler_name_basename_N. Locked in plan §Locked Decision 13.
    let opId = safeOperationId(ep.handler_name);
    if (usedOperationIds.has(opId)) {
      opId = `${opId}_${fileBasenameForOpId(ep.file_path)}`;
      let suffix = 1;
      let candidateId = opId;
      while (usedOperationIds.has(candidateId)) {
        candidateId = `${opId}_${suffix++}`;
      }
      opId = candidateId;
    }
    usedOperationIds.add(opId);

    const op: Record<string, unknown> = {
      operationId: opId,
      tags: [ep.framework],
      'x-deptex-handler': {
        file_path: ep.file_path,
        function_name: ep.handler_name,
        line_number: ep.line_number,
      },
    };

    const params = buildParameters(translated.params);
    if (params.length > 0) op.parameters = params;

    if (ep.middleware_chain && ep.middleware_chain.length > 0) {
      op['x-deptex-middleware'] = ep.middleware_chain;
    }

    if (BODY_METHODS.has(method)) {
      op.requestBody = {
        required: false,
        content: { 'application/json': { schema: { type: 'object' } } },
      };
    }

    op.responses = { default: { description: 'Default response' } };

    const scheme = authMechanismToScheme(ep.auth_mechanism);
    if (scheme) {
      const schemeKey = 'deptexAuth';
      if (!securitySchemes[schemeKey]) securitySchemes[schemeKey] = scheme;
      op.security = [{ [schemeKey]: [] }];
    }

    if (!paths[openApiPath]) paths[openApiPath] = {};
    paths[openApiPath][method] = op;
    sidecar[sidecarKey] = {
      file_path: ep.file_path,
      function_name: ep.handler_name,
      line_number: ep.line_number,
    };
  }

  const emittedCount = Object.keys(sidecar).length;
  if (emittedCount === 0) {
    return { yaml: null, sidecar: null, endpoint_count: 0 };
  }

  const doc: Record<string, unknown> = {
    openapi: '3.1.0',
    info: {
      title: opts.title ?? 'Synthesized API spec',
      version: '1.0.0',
      description: 'Auto-synthesized by Deptex from project_entry_points.',
    },
    servers: [{ url: opts.targetUrl }],
    paths,
  };
  if (Object.keys(securitySchemes).length > 0) {
    doc.components = { securitySchemes };
  }

  const yamlStr = yaml.dump(doc, {
    lineWidth: 200,
    noRefs: true,
    noCompatMode: true,
    quotingType: '"',
  });

  return { yaml: yamlStr, sidecar, endpoint_count: emittedCount };
}

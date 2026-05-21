/**
 * Phase 35 (v1.1) e2e harness — OpenAPI synthesis + spec-source + cross-link.
 *
 * In-process: walks the synthesizer over a fabricated EntryPoint set, writes
 * the YAML + sidecar to a tmpDir, runs ZAP's openapi: AF job through the
 * yaml-builder, and confirms cross-link via the sidecar pre-pass.
 *
 * NOT in scope here:
 *   - real ZAP spawn (covered ad-hoc in the smoke spike at
 *     depscanner/src/__tests__/zap-openapi-smoke/)
 *   - URL-mode fetch (mocked in dast-openapi-spec-source.test.ts)
 *   - real target server (deferred to the 1-week e2e testing phase per
 *     dast_v1_1_direction)
 *
 * What this catches: integration seams between synth → spec-source →
 * yaml-builder → cross-link sidecar. Any of those modules drifting in
 * shape will break the harness immediately.
 *
 * Local invocation:
 *   cd depscanner
 *   npm run e2e:dast-openapi
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { synthesizeOpenApi } from '../../src/dast/openapi-synth';
import { resolveSpecForJob } from '../../src/dast/openapi-spec-source';
import { buildAutomationYaml } from '../../src/dast/yaml-builder';
import { crossLinkFinding, type EntryPointRow } from '../../src/dast/cross-link';
import type { DastFindingRaw } from '../../src/dast/runner';

let failures = 0;
function check(label: string, ok: boolean, detail?: string): void {
  const tag = ok ? 'PASS' : 'FAIL';
  console.log(`  [${tag}] ${label}${detail ? ` — ${detail}` : ''}`);
  if (!ok) failures++;
}

const entryPoints: EntryPointRow[] = [
  {
    framework: 'express',
    http_method: 'GET',
    route_pattern: '/users',
    handler_name: 'listUsers',
    file_path: 'src/handlers/users.ts',
    line_number: 12,
    entry_point_type: 'http_route',
    classification: 'PUBLIC_UNAUTH',
  },
  {
    framework: 'express',
    http_method: 'POST',
    route_pattern: '/users',
    handler_name: 'createUser',
    file_path: 'src/handlers/users.ts',
    line_number: 47,
    entry_point_type: 'http_route',
    classification: 'AUTH_INTERNAL',
    auth_mechanism: 'bearer_jwt',
  },
  {
    framework: 'flask',
    http_method: 'GET',
    route_pattern: '/users/<int:id>',
    handler_name: 'get_user',
    file_path: 'src/handlers/users.py',
    line_number: 99,
    entry_point_type: 'http_route',
    classification: 'AUTH_INTERNAL',
    auth_mechanism: 'session_cookie',
  },
  {
    framework: 'spring',
    http_method: 'PATCH',
    route_pattern: '/users/{id:\\d+}',
    handler_name: 'updateUser',
    file_path: 'src/main/java/UserController.java',
    line_number: 41,
    entry_point_type: 'http_route',
    classification: 'AUTH_INTERNAL',
  },
  // Filtered out: not http_route
  {
    framework: 'graphql',
    http_method: null,
    route_pattern: '/graphql',
    handler_name: 'gqlResolver',
    file_path: 'src/gql.ts',
    line_number: 1,
    entry_point_type: 'graphql_resolver',
    classification: 'PUBLIC_UNAUTH',
  },
  // Filtered out: health-check route
  {
    framework: 'express',
    http_method: 'GET',
    route_pattern: '/health',
    handler_name: 'healthcheck',
    file_path: 'src/health.ts',
    line_number: 5,
    entry_point_type: 'http_route',
    classification: 'PUBLIC_UNAUTH',
  },
];

async function runHarness(): Promise<void> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dast-openapi-e2e-'));
  console.log(`[e2e:dast-openapi] tmpDir=${tmpDir}`);

  // ─── synth direct ────────────────────────────────────────────────────────
  console.log('[e2e:dast-openapi] synthesizeOpenApi');
  const synth = synthesizeOpenApi(entryPoints, {
    targetUrl: 'https://api.example.com',
  });
  check('synthesizer emits a YAML doc', synth.yaml !== null);
  check('synthesizer emits a sidecar', synth.sidecar !== null);
  check(
    'synthesizer reports 4 endpoints (graphql + health filtered out)',
    synth.endpoint_count === 4,
    `got ${synth.endpoint_count}`,
  );
  check(
    'sidecar carries POST /users with createUser at line 47',
    synth.sidecar?.['POST /users']?.line_number === 47,
  );
  check(
    'sidecar carries GET /users/{id} (Flask <int:id> translated)',
    synth.sidecar?.['GET /users/{id}']?.file_path === 'src/handlers/users.py',
  );
  check(
    'sidecar carries PATCH /users/{id} (Spring regex stripped)',
    synth.sidecar?.['PATCH /users/{id}']?.function_name === 'updateUser',
  );

  // ─── resolveSpecForJob synthesized branch ────────────────────────────────
  console.log('[e2e:dast-openapi] resolveSpecForJob source=synthesized');
  const resolved = await resolveSpecForJob({
    source: 'synthesized',
    api_spec_url: null,
    targetUrl: 'https://api.example.com',
    entryPoints,
    tmpDir,
  });
  check('resolver returns status=ok', resolved.status === 'ok', resolved.status);
  check('resolver writes specPath to disk', !!resolved.specPath && fs.existsSync(resolved.specPath));
  check('resolver writes sidecarPath to disk', !!resolved.sidecarPath && fs.existsSync(resolved.sidecarPath));
  check('resolver endpoint count matches synth', resolved.endpointCount === synth.endpoint_count);

  // ─── empty entry-points soft-fail ────────────────────────────────────────
  console.log('[e2e:dast-openapi] resolveSpecForJob soft-fail (no entry points)');
  const empty = await resolveSpecForJob({
    source: 'synthesized',
    api_spec_url: null,
    targetUrl: 'https://api.example.com',
    entryPoints: [],
    tmpDir,
  });
  check(
    'empty entry-points → status=synth.no_entry_points',
    empty.status === 'synth.no_entry_points',
    empty.status,
  );
  check('empty entry-points → no specPath', empty.specPath === undefined);

  // ─── buildAutomationYaml threads openApiSpecPath through ─────────────────
  console.log('[e2e:dast-openapi] buildAutomationYaml with openApiSpecPath');
  const yamlText = buildAutomationYaml({
    targetUrl: 'https://api.example.com',
    scanProfile: 'api',
    detectedRuntime: 'classic',
    reportRelativePath: 'zap-report.json',
    openApiSpecPath: resolved.specPath,
  });
  check(
    'YAML includes the openapi job',
    /-\s+type:\s+openapi\b/.test(yamlText),
  );
  check(
    'YAML includes activeScan for scanProfile=api',
    /-\s+type:\s+activeScan\b/.test(yamlText),
  );
  check(
    'YAML threads apiFile through to the openapi job',
    yamlText.includes(resolved.specPath!),
  );

  // ─── crossLinkFinding sidecar pre-pass ──────────────────────────────────
  console.log('[e2e:dast-openapi] crossLinkFinding (sidecar pre-pass)');
  const finding: DastFindingRaw = {
    endpoint_url: 'https://api.example.com/users/42',
    http_method: 'GET',
    vulnerability_type: 'SQL Injection',
    severity: 'high',
    cwe_id: '89',
    owasp_top10_ref: 'A03:2021',
    rule_id: '40018-1',
    message: 'SQLi found',
    payload_redacted: null,
    response_evidence_redacted: null,
    confidence: 'medium',
  };
  const link = crossLinkFinding({
    finding,
    entryPoints,
    flows: [],
    pdvByPurl: new Map(),
    projectDependencyByPurl: new Map(),
    sidecar: resolved.sidecar,
  });
  check(
    'sidecar resolves /users/{id} → src/handlers/users.py:99 get_user',
    link.handler_file_path === 'src/handlers/users.py' &&
      link.handler_function_name === 'get_user' &&
      link.handler_line === 99,
    `${link.handler_file_path}:${link.handler_line} ${link.handler_function_name}`,
  );
  check(
    'cross_link_metadata.match_method === "sidecar"',
    (link.cross_link_metadata as { match_method?: string }).match_method === 'sidecar',
  );
  check(
    'cross_link_metadata.via === "sidecar"',
    (link.cross_link_metadata as { via?: string }).via === 'sidecar',
  );

  // ─── fallback path: same finding, NO sidecar, with an express-style
  // route-pattern matchRoute understands. Demonstrates regex_fallback when
  // sidecar isn't present.
  console.log('[e2e:dast-openapi] crossLinkFinding (regex fallback when sidecar missing)');
  const fallbackEntryPoints: EntryPointRow[] = [
    {
      framework: 'express',
      http_method: 'GET',
      route_pattern: '/users/:id',
      handler_name: 'getUserExpress',
      file_path: 'src/express-fallback.ts',
      line_number: 17,
    },
  ];
  const linkNoSidecar = crossLinkFinding({
    finding,
    entryPoints: fallbackEntryPoints,
    flows: [],
    pdvByPurl: new Map(),
    projectDependencyByPurl: new Map(),
  });
  check(
    'regex fallback resolves /users/:id to its handler',
    linkNoSidecar.handler_file_path === 'src/express-fallback.ts' &&
      linkNoSidecar.handler_function_name === 'getUserExpress',
    `${linkNoSidecar.handler_file_path}:${linkNoSidecar.handler_line}`,
  );
  check(
    'regex fallback uses match_method other than "sidecar"',
    (linkNoSidecar.cross_link_metadata as { match_method?: string }).match_method !== 'sidecar',
  );

  // Clean up.
  fs.rmSync(tmpDir, { recursive: true, force: true });

  if (failures > 0) {
    console.error(`\n[e2e:dast-openapi] ${failures} check(s) failed.`);
    process.exit(1);
  }
  console.log('\n[e2e:dast-openapi] all checks passed.');
}

void runHarness();

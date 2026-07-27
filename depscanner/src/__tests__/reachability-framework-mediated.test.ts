/**
 * Framework-mediated usage (silence-FN recovery, fix #3).
 *
 * Two related fixes, one silence false-negative:
 *   1. A transitive dep reached ONLY via framework dispatch (Spring's Jackson
 *      message converters / actuator endpoints) — imported by no app file — is
 *      no longer declared orphan `unreachable`. It lands at `module` (honest).
 *   2. jackson-core's BLOCKING-parser CVE (GHSA-2m67 shape) is promoted to a
 *      visible tier when an actuator JSON-body endpoint is exposed — while the
 *      jackson-databind deserialization CVEs and the other jackson-core parser
 *      variants (DataInput / Async) STAY hidden at `module`.
 *
 * Covers:
 *   - the pure detector `evaluateFrameworkMediatedUsage`,
 *   - the actuator enumeration helpers (`resolveActuatorRoutes`,
 *     `enumerateActuatorEntryPoints`, `readActuatorExposure`),
 *   - end-to-end through `updateReachabilityLevels`.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { updateReachabilityLevels } from '../reachability';
import type { Storage } from '../storage';
import {
  evaluateFrameworkMediatedUsage,
  actuatorWriteJsonEndpointExposed,
  emptySpringFeatureSignals,
  type SpringFeatureSignals,
} from '../reachability-feature-preconditions';
import {
  resolveActuatorRoutes,
  enumerateActuatorEntryPoints,
  readActuatorExposure,
  type ActuatorExposure,
} from '../framework-rules/detectors/spring';

// ---------------------------------------------------------------------------
// Fixtures — the real spring-petclinic shape
// ---------------------------------------------------------------------------

/** Recognized Spring web app: spring-boot-starter-webmvc + actuator include=*. */
function petclinicSignals(over: Partial<SpringFeatureSignals> = {}): SpringFeatureSignals {
  return {
    ...emptySpringFeatureSignals(),
    recognized: true,
    pomArtifacts: new Set([
      'spring-boot-starter-webmvc',
      'spring-boot-starter-actuator',
      'spring-boot-starter-thymeleaf',
      'tomcat-embed-core',
    ]),
    configText: 'database=h2\nmanagement.endpoints.web.exposure.include=*\n',
    // VetController returns JSON via @ResponseBody → Jackson message converter.
    codeText:
      'package org.springframework.samples.petclinic;\n' +
      '@controller class ownercontroller {}\n' +
      '@responsebody public vets showresourcesvetlist() {}',
    ...over,
  };
}

// Real petclinic jackson advisory summaries (from the scan).
const BLOCKING_SUMMARY =
  'Jackson Core: Document length constraint bypass in blocking, async, and DataInput parsers';
const DATAINPUT_SUMMARY =
  'jackson-core has Nesting Depth Constraint Bypass in `UTF8DataInputJsonParser` potentially allowing Resource Exhaustion';
const ASYNC_SUMMARY =
  'jackson-core: Number Length Constraint Bypass in Async Parser Leads to Potential DoS Condition';
const DESER_SUMMARY =
  'jackson-databind has a PolymorphicTypeValidator bypass via generic type parameters that allows arbitrary class deserialization';

// ---------------------------------------------------------------------------
// 1. Pure detector — evaluateFrameworkMediatedUsage
// ---------------------------------------------------------------------------

describe('evaluateFrameworkMediatedUsage', () => {
  it('marks jackson framework-mediated in a Spring web app with message converters', () => {
    const r = evaluateFrameworkMediatedUsage({ depName: 'jackson-databind', signals: petclinicSignals() });
    expect(r.mediated).toBe(true);
    expect(r.id).toBe('spring-jackson-message-converter');
  });

  it('marks jackson framework-mediated via exposed actuator even without @ResponseBody', () => {
    const r = evaluateFrameworkMediatedUsage({
      depName: 'jackson-core',
      signals: petclinicSignals({ codeText: '@controller class ownercontroller {}' }),
    });
    expect(r.mediated).toBe(true);
  });

  it('does NOT mediate when the project is not a Spring web app', () => {
    const r = evaluateFrameworkMediatedUsage({
      depName: 'jackson-databind',
      signals: petclinicSignals({ pomArtifacts: new Set(['spring-boot-starter-batch']) }),
    });
    expect(r.mediated).toBe(false);
  });

  it('does NOT mediate when neither message converters nor actuator are present', () => {
    const r = evaluateFrameworkMediatedUsage({
      depName: 'jackson-databind',
      signals: petclinicSignals({
        configText: 'database=h2\n',
        codeText: '@controller class ownercontroller {}',
      }),
    });
    expect(r.mediated).toBe(false);
  });

  it('does NOT mediate a non-jackson dependency', () => {
    const r = evaluateFrameworkMediatedUsage({ depName: 'commons-lang3', signals: petclinicSignals() });
    expect(r.mediated).toBe(false);
  });

  it('fail-safe: does NOT mediate when signals are unrecognized (non-maven / unreadable)', () => {
    expect(evaluateFrameworkMediatedUsage({ depName: 'jackson-core', signals: emptySpringFeatureSignals() }).mediated).toBe(false);
    expect(evaluateFrameworkMediatedUsage({ depName: 'jackson-core', signals: null }).mediated).toBe(false);
  });
});

describe('actuatorWriteJsonEndpointExposed', () => {
  it('is true for include=* and for an explicit loggers list', () => {
    expect(actuatorWriteJsonEndpointExposed(petclinicSignals())).toBe(true);
    expect(
      actuatorWriteJsonEndpointExposed(
        petclinicSignals({ configText: 'management.endpoints.web.exposure.include=health,loggers,info\n' }),
      ),
    ).toBe(true);
  });

  it('is false when only read-only endpoints are exposed', () => {
    expect(
      actuatorWriteJsonEndpointExposed(
        petclinicSignals({ configText: 'management.endpoints.web.exposure.include=health,info\n' }),
      ),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 2. Actuator enumeration (pure)
// ---------------------------------------------------------------------------

describe('resolveActuatorRoutes', () => {
  it('include=* enumerates the standard endpoints incl. the loggers JSON-body write', () => {
    const routes = resolveActuatorRoutes({ include: '*' });
    const loggersPost = routes.find((r) => r.id === 'loggers' && r.method === 'POST');
    expect(loggersPost).toBeDefined();
    expect(loggersPost?.routeSuffix).toBe('/loggers/{name}');
    expect(loggersPost?.jsonBody).toBe(true);
    expect(routes.some((r) => r.id === 'health')).toBe(true);
    // shutdown is off by default even under `*`.
    expect(routes.some((r) => r.id === 'shutdown')).toBe(false);
  });

  it('an explicit include list exposes only the named endpoints', () => {
    const routes = resolveActuatorRoutes({ include: 'health,loggers' });
    expect(new Set(routes.map((r) => r.id))).toEqual(new Set(['health', 'loggers']));
    expect(routes.some((r) => r.id === 'beans')).toBe(false);
  });

  it('respects exclude and the shutdown enable flag', () => {
    const routes = resolveActuatorRoutes({
      include: '*',
      exclude: 'env,beans',
      enabledFlags: new Set(['shutdown']),
    });
    expect(routes.some((r) => r.id === 'env')).toBe(false);
    expect(routes.some((r) => r.id === 'beans')).toBe(false);
    expect(routes.some((r) => r.id === 'shutdown' && r.method === 'POST')).toBe(true);
  });
});

describe('enumerateActuatorEntryPoints', () => {
  const exposure: ActuatorExposure = {
    include: '*',
    exclude: null,
    basePath: '/actuator',
    enabledFlags: new Set(),
    configFilePath: '/tmp/app/src/main/resources/application.properties',
    configLine: 20,
  };

  it('emits http_route entry points; POST /actuator/loggers/{name} is present + PUBLIC_UNAUTH with no Spring Security', () => {
    const eps = enumerateActuatorEntryPoints({ exposure, springSecurityPresent: false });
    expect(eps.length).toBeGreaterThan(0);
    expect(eps.every((e) => e.entryPointType === 'http_route' && e.framework === 'spring')).toBe(true);
    const loggersPost = eps.find((e) => e.httpMethod === 'POST' && e.routePattern === '/actuator/loggers/{name}');
    expect(loggersPost).toBeDefined();
    expect(loggersPost?.classification).toBe('PUBLIC_UNAUTH');
    expect(loggersPost?.authenticated).toBe(false);
    expect((loggersPost?.metadata as any)?.json_body).toBe(true);
    // handler names are unique per route (dedup key includes handler_name, not method/path).
    const handlers = eps.map((e) => e.handlerName);
    expect(new Set(handlers).size).toBe(handlers.length);
  });

  it('classifies AUTH_INTERNAL when Spring Security is present', () => {
    const eps = enumerateActuatorEntryPoints({ exposure, springSecurityPresent: true });
    expect(eps.every((e) => e.classification === 'AUTH_INTERNAL' && e.authenticated === true)).toBe(true);
  });
});

describe('readActuatorExposure', () => {
  let root: string;
  afterEach(() => {
    if (root && fs.existsSync(root)) fs.rmSync(root, { recursive: true, force: true });
  });

  it('reads include=* from src/main/resources/application.properties', () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'actuator-exposed-'));
    const resDir = path.join(root, 'src', 'main', 'resources');
    fs.mkdirSync(resDir, { recursive: true });
    fs.writeFileSync(
      path.join(resDir, 'application.properties'),
      'database=h2\n# Actuator\nmanagement.endpoints.web.exposure.include=*\n',
    );
    const exp = readActuatorExposure(root);
    expect(exp).not.toBeNull();
    expect(exp?.include).toBe('*');
    expect(exp?.basePath).toBe('/actuator');
    expect(exp?.configLine).toBeGreaterThan(0);
    expect(exp?.configFilePath.endsWith('application.properties')).toBe(true);
  });

  it('returns null when actuator is not exposed', () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'actuator-none-'));
    const resDir = path.join(root, 'src', 'main', 'resources');
    fs.mkdirSync(resDir, { recursive: true });
    fs.writeFileSync(path.join(resDir, 'application.properties'), 'database=h2\nspring.thymeleaf.mode=HTML\n');
    expect(readActuatorExposure(root)).toBeNull();
    expect(readActuatorExposure(undefined)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 3. End-to-end through updateReachabilityLevels
// ---------------------------------------------------------------------------

interface TableState { rows: any[] }

class FakeStorage {
  tables: Record<string, TableState> = {};
  updates: Array<{ table: string; filter: Record<string, unknown>; values: any }> = [];

  set(table: string, rows: any[]) {
    this.tables[table] = { rows };
  }

  from(table: string): any {
    const state = this.tables[table] ?? { rows: [] };
    const filters: Array<{ col: string; val: unknown }> = [];
    const filterRows = () => {
      let rows = state.rows;
      for (const f of filters) rows = rows.filter((r) => r[f.col] === f.val);
      return rows;
    };
    const builder: any = {
      select() { return builder; },
      eq(col: string, val: unknown) { filters.push({ col, val }); return builder; },
      in() { return builder; },
      maybeSingle() { return Promise.resolve({ data: filterRows()[0] ?? null, error: null }); },
      single() {
        const rows = filterRows();
        return Promise.resolve({
          data: rows[0] ?? null,
          error: rows.length === 0 ? { code: 'PGRST116', message: 'not found' } : null,
        });
      },
      insert: () => Promise.resolve({ data: null, error: null }),
      upsert: (rows: any) => {
        const arr = Array.isArray(rows) ? rows : [rows];
        for (const r of arr) this.updates.push({ table, filter: { id: r.id }, values: r });
        return Promise.resolve({ data: null, error: null });
      },
      then(onFulfilled: any) {
        return Promise.resolve({ data: filterRows(), error: null }).then(onFulfilled);
      },
    };
    return builder;
  }
}

const log = {
  info: jest.fn().mockResolvedValue(undefined),
  success: jest.fn().mockResolvedValue(undefined),
  warn: jest.fn().mockResolvedValue(undefined),
  error: jest.fn().mockResolvedValue(undefined),
};

const PROJECT_ID = 'proj-1';
const RUN_ID = 'run-1';

/** Seed one transitive jackson dep with no first-party import (petclinic shape). */
function seedJackson(fsk: FakeStorage, opts: { name: string; osvId: string; summary: string }) {
  fsk.set('project_dependency_findings', [
    {
      id: 'pdv-1',
      project_dependency_id: 'pd-1',
      project_id: PROJECT_ID,
      extraction_run_id: RUN_ID,
      osv_id: opts.osvId,
      aliases: [],
      summary: opts.summary,
    },
  ]);
  fsk.set('project_dependencies', [
    {
      id: 'pd-1',
      project_id: PROJECT_ID,
      last_seen_extraction_run_id: RUN_ID,
      dependency_id: 'dep-1',
      dependency_version_id: 'dv-1',
      is_direct: false,          // transitive (pulled in via spring-boot-starter-json)
      files_importing_count: 0,  // no app file imports com.fasterxml.jackson
      environment: null,
      name: opts.name,
      namespace: opts.name === 'jackson-core' ? 'com.fasterxml.jackson.core' : 'com.fasterxml.jackson.core',
    },
  ]);
  fsk.set('project_reachable_flows', []);
  fsk.set('project_reachable_flow_suppressions', []);
  fsk.set('dependency_version_edges', []);
  fsk.set('project_usage_slices', [
    {
      project_id: PROJECT_ID,
      extraction_run_id: RUN_ID,
      file_path: 'src/main/java/App.java',
      line_number: 1,
      target_name: 'someApp.handler',
      target_type: 'someApp.handler',
      resolved_method: 'someApp.handler',
    },
  ]);
}

function verdictOf(fsk: FakeStorage, pdvId: string): { level?: string; details?: any } {
  const u = fsk.updates.find(
    (x) => x.table === 'project_dependency_findings' && x.filter.id === pdvId && 'reachability_level' in x.values,
  );
  return { level: u?.values.reachability_level, details: u?.values.reachability_details };
}

async function classify(fsk: FakeStorage, over: Record<string, unknown> = {}) {
  await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
    ecosystem: 'maven',
    usedTransitives: new Set(), // NOT callgraph-credited → the heuristic path
    springFeatureSignals: petclinicSignals(),
    httpEntryPointCount: 17, // deployed web app (17 petclinic controllers)
    ...over,
  });
}

beforeEach(() => jest.clearAllMocks());

describe('updateReachabilityLevels — framework-mediated jackson', () => {
  it('PART 1: a jackson-databind deser CVE moves orphan-unreachable → module (framework_mediated)', async () => {
    const fsk = new FakeStorage();
    seedJackson(fsk, { name: 'jackson-databind', osvId: 'CVE-2026-54512', summary: DESER_SUMMARY });
    await classify(fsk);
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('module');
    expect(details?.verdict).toBe('framework_mediated');
    expect(details?.framework_mediated_by).toBe('spring-jackson-message-converter');
  });

  it('CONSERVATISM: keeps the deser CVE hidden at module — never promoted', async () => {
    const fsk = new FakeStorage();
    seedJackson(fsk, { name: 'jackson-databind', osvId: 'CVE-2026-54512', summary: DESER_SUMMARY });
    await classify(fsk);
    expect(verdictOf(fsk, 'pdv-1').level).toBe('module');
  });

  it('PART 3: the jackson-core BLOCKING-parser CVE (GHSA-2m67) is promoted to function', async () => {
    const fsk = new FakeStorage();
    seedJackson(fsk, { name: 'jackson-core', osvId: 'GHSA-2m67-wjpj-xhg9', summary: BLOCKING_SUMMARY });
    await classify(fsk);
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('function');
    expect(details?.verdict).toBe('always_on_framework_runtime');
    expect(details?.sink).toBe('jackson-core-blocking-parser-actuator');
    expect(details?.promoted_from).toBe('framework_mediated');
  });

  it('CONSERVATISM: the jackson-core DataInput CVE (29062) stays hidden at module', async () => {
    const fsk = new FakeStorage();
    seedJackson(fsk, { name: 'jackson-core', osvId: 'CVE-2026-29062', summary: DATAINPUT_SUMMARY });
    await classify(fsk);
    expect(verdictOf(fsk, 'pdv-1').level).toBe('module');
  });

  it('CONSERVATISM: the jackson-core Async CVE (GHSA-72hv) stays hidden at module', async () => {
    const fsk = new FakeStorage();
    seedJackson(fsk, { name: 'jackson-core', osvId: 'GHSA-72hv-8253-57qq', summary: ASYNC_SUMMARY });
    await classify(fsk);
    expect(verdictOf(fsk, 'pdv-1').level).toBe('module');
  });

  it('GATE: the blocking-parser CVE stays at module when no actuator JSON-body endpoint is exposed', async () => {
    const fsk = new FakeStorage();
    seedJackson(fsk, { name: 'jackson-core', osvId: 'GHSA-2m67-wjpj-xhg9', summary: BLOCKING_SUMMARY });
    await classify(fsk, {
      // still framework-mediated (message converters present) but no loggers endpoint
      springFeatureSignals: petclinicSignals({ configText: 'management.endpoints.web.exposure.include=health,info\n' }),
    });
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('module');
    expect(details?.verdict).toBe('framework_mediated');
  });

  it('FAIL-SAFE: with no recognized spring signals, jackson keeps the orphan-unreachable verdict', async () => {
    const fsk = new FakeStorage();
    seedJackson(fsk, { name: 'jackson-databind', osvId: 'CVE-2026-54512', summary: DESER_SUMMARY });
    // No springFeatureSignals + no workspaceRoot → gather returns unrecognized.
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'maven',
      usedTransitives: new Set(),
      httpEntryPointCount: 17,
    });
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('unreachable');
    expect(details?.verdict).toBe('orphan_transitive_unreachable');
  });
});

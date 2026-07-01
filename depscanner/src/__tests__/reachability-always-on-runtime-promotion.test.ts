/**
 * Always-on framework-runtime PROMOTION gate — the mirror image of the
 * feature-precondition DEMOTION gate. PROMOTE a `module` finding to a visible
 * tier when its CVE lives in framework code that is unconditionally on the
 * request path (embedded servlet-container request parser / default servlet,
 * Spring MVC's always-registered static-resource handler) or executes at every
 * web-app startup (a predictable temp dir) AND the project is a deployed web
 * app (>= 1 HTTP-route entry point).
 *
 * Covers:
 *   1. the pure decision function (`evaluateAlwaysOnRuntimePromotion`) — the
 *      promote cases (smuggling → data_flow + fronting-proxy tag; open-redirect
 *      → data_flow; resource-handler → data_flow; startup temp-dir → function
 *      + co-tenant tag) AND the fail-safe cases (no HTTP route → stays module;
 *      owner mismatch → stays module; summary names no always-on class → stays
 *      module; no summary → stays module).
 *   2. end-to-end through `updateReachabilityLevels`:
 *      - promote-when-webapp+summary+owner (tomcat module → data_flow),
 *      - stays-module-when-no-entry-points (library repo),
 *      - demotion-wins-over-promotion (a feature-gated CVE the demotion
 *        silences is never promoted — via BOTH the callgraph→unreachable path
 *        and the non-callgraph `wouldDemote` re-check),
 *      - owner/summary mismatch stays module.
 */

import { updateReachabilityLevels } from '../reachability';
import type { Storage } from '../storage';
import {
  evaluateAlwaysOnRuntimePromotion,
  emptySpringFeatureSignals,
  type SpringFeatureSignals,
} from '../reachability-feature-preconditions';

// ---------------------------------------------------------------------------
// Representative advisory summaries
// ---------------------------------------------------------------------------

const SMUGGLING_SUMMARY =
  'Apache Tomcat mishandled HTTP/1.1 chunked transfer-encoding, enabling HTTP request smuggling.';
// CVE-2026-24880's real advisory phrasing — "Request/Response Smuggling" (a
// slash + "Response" between "Request" and "Smuggling"). The bare `request\s+`
// pattern missed it, leaving this HIGH request-smuggling CVE hidden at module.
const REQUEST_RESPONSE_SMUGGLING_SUMMARY =
  'Apache Tomcat has an HTTP Request/Response Smuggling vulnerability';
const OPEN_REDIRECT_SUMMARY =
  'Apache Tomcat default servlet URL normalization allowed an open redirect to an attacker-controlled host.';
const RESOURCE_HANDLER_SUMMARY =
  'Spring Framework ResourceHttpRequestHandler allowed cache poisoning when serving static resources.';
const TEMPDIR_SUMMARY =
  'Spring Boot created a predictable temporary directory during application startup, letting a local attacker hijack files.';
// Overlaps BOTH the demotion table (WebSocket) and a promotion pattern (request
// smuggling) — the composition test uses it to prove demotion wins.
const WEBSOCKET_SMUGGLING_SUMMARY =
  'Apache Tomcat WebSocket upgrade handler was vulnerable to HTTP request smuggling.';
const JACKSON_SUMMARY =
  'jackson-core allows denial of service via deeply nested JSON objects exceeding the parser depth limit.';

/** A recognized Spring project with NO gated feature enabled (petclinic shape). */
function absentSignals(over: Partial<SpringFeatureSignals> = {}): SpringFeatureSignals {
  return {
    ...emptySpringFeatureSignals(),
    recognized: true,
    pomArtifacts: new Set(['spring-boot-starter-web', 'tomcat-embed-core']),
    configText: 'database=h2\n',
    codeText: 'package org.springframework.samples.petclinic;\n@controller class ownercontroller {}',
    ...over,
  };
}

// ---------------------------------------------------------------------------
// 1. Pure decision function
// ---------------------------------------------------------------------------

describe('evaluateAlwaysOnRuntimePromotion', () => {
  it('promotes a tomcat request-smuggling CVE to data_flow with a fronting-proxy threat tag', () => {
    const r = evaluateAlwaysOnRuntimePromotion({
      depName: 'tomcat-embed-core',
      summary: SMUGGLING_SUMMARY,
      hasHttpRouteEntryPoint: true,
    });
    expect(r.promote).toBe(true);
    expect(r.promoteTo).toBe('data_flow');
    expect(r.sink).toBe('servlet-container-request-smuggling');
    expect(r.threatTag).toBe('requires_fronting_proxy');
  });

  it('promotes a tomcat "Request/Response Smuggling" CVE (CVE-2026-24880 phrasing) to data_flow', () => {
    const r = evaluateAlwaysOnRuntimePromotion({
      depName: 'tomcat-embed-core',
      summary: REQUEST_RESPONSE_SMUGGLING_SUMMARY,
      hasHttpRouteEntryPoint: true,
    });
    expect(r.promote).toBe(true);
    expect(r.promoteTo).toBe('data_flow');
    expect(r.sink).toBe('servlet-container-request-smuggling');
    expect(r.threatTag).toBe('requires_fronting_proxy');
  });

  it('promotes a tomcat open-redirect (default-servlet URL normalization) CVE to data_flow with no threat tag', () => {
    const r = evaluateAlwaysOnRuntimePromotion({
      depName: 'tomcat-embed-core',
      summary: OPEN_REDIRECT_SUMMARY,
      hasHttpRouteEntryPoint: true,
    });
    expect(r.promote).toBe(true);
    expect(r.promoteTo).toBe('data_flow');
    expect(r.sink).toBe('servlet-default-servlet-url-normalization');
    expect(r.threatTag).toBeUndefined();
  });

  it('promotes a spring-webmvc ResourceHttpRequestHandler CVE to data_flow', () => {
    const r = evaluateAlwaysOnRuntimePromotion({
      depName: 'spring-webmvc',
      summary: RESOURCE_HANDLER_SUMMARY,
      hasHttpRouteEntryPoint: true,
    });
    expect(r.promote).toBe(true);
    expect(r.promoteTo).toBe('data_flow');
    expect(r.sink).toBe('spring-mvc-resource-handler');
  });

  it('promotes a spring-boot startup temp-dir CVE to function with a local-co-tenant threat tag', () => {
    const r = evaluateAlwaysOnRuntimePromotion({
      depName: 'spring-boot',
      summary: TEMPDIR_SUMMARY,
      hasHttpRouteEntryPoint: true,
    });
    expect(r.promote).toBe(true);
    expect(r.promoteTo).toBe('function');
    expect(r.sink).toBe('spring-boot-startup-tempdir');
    expect(r.threatTag).toBe('requires_local_cotenant');
  });

  // --- fail-safe: web-app gate ---
  it('does NOT promote without an HTTP-route entry point (a library / CLI repo)', () => {
    const r = evaluateAlwaysOnRuntimePromotion({
      depName: 'tomcat-embed-core',
      summary: SMUGGLING_SUMMARY,
      hasHttpRouteEntryPoint: false,
    });
    expect(r.promote).toBe(false);
  });

  // --- fail-safe: owner mismatch ---
  it('does NOT promote when the owner does not match the always-on surface (jackson)', () => {
    const r = evaluateAlwaysOnRuntimePromotion({
      depName: 'jackson-core',
      summary: SMUGGLING_SUMMARY,
      hasHttpRouteEntryPoint: true,
    });
    expect(r.promote).toBe(false);
  });

  // --- fail-safe: summary names no always-on class ---
  it('does NOT promote a tomcat CVE whose summary names no always-on class', () => {
    const r = evaluateAlwaysOnRuntimePromotion({
      depName: 'tomcat-embed-core',
      summary: JACKSON_SUMMARY,
      hasHttpRouteEntryPoint: true,
    });
    expect(r.promote).toBe(false);
  });

  it('does NOT promote when there is no advisory summary', () => {
    expect(
      evaluateAlwaysOnRuntimePromotion({
        depName: 'tomcat-embed-core',
        summary: null,
        hasHttpRouteEntryPoint: true,
      }).promote,
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 2. End-to-end through updateReachabilityLevels
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

/**
 * Seed one transitive maven dep at `module` (no first-party import). `name` +
 * `summary` drive the classification; `usedTransitives` decides whether it
 * reaches module via the callgraph branch (credited) or the embedded-runtime /
 * heuristic floor (not credited).
 */
function seedModuleDep(fsk: FakeStorage, opts: { name: string; osvId: string; summary: string; filesImporting?: number }) {
  fsk.set('project_dependency_vulnerabilities', [
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
      is_direct: false,
      files_importing_count: opts.filesImporting ?? 0,
      environment: null,
      name: opts.name,
      namespace: null,
    },
  ]);
  fsk.set('project_reachable_flows', []);
  fsk.set('project_reachable_flow_suppressions', []);
  fsk.set('dependency_version_edges', []);
  fsk.set('project_usage_slices', [
    {
      project_id: PROJECT_ID,
      extraction_run_id: RUN_ID,
      file_path: 'src/App.java',
      line_number: 1,
      target_name: 'someApp.handler',
      target_type: 'someApp.handler',
      resolved_method: 'someApp.handler',
    },
  ]);
}

function verdictOf(fsk: FakeStorage, pdvId: string): { level?: string; details?: any } {
  const u = fsk.updates.find(
    (x) => x.table === 'project_dependency_vulnerabilities' && x.filter.id === pdvId && 'reachability_level' in x.values,
  );
  return { level: u?.values.reachability_level, details: u?.values.reachability_details };
}

beforeEach(() => jest.clearAllMocks());

describe('updateReachabilityLevels — always-on framework-runtime promotion', () => {
  it('PROMOTES a tomcat request-smuggling module finding to data_flow on a deployed web app', async () => {
    const fsk = new FakeStorage();
    // tomcat-embed-core is a framework-embedded runtime → floors at module even
    // when the callgraph never credits it (petclinic shape).
    seedModuleDep(fsk, { name: 'tomcat-embed-core', osvId: 'CVE-2026-34500', summary: SMUGGLING_SUMMARY });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'maven',
      usedTransitives: new Set(), // NOT callgraph-credited → embedded-runtime floor
      springFeatureSignals: absentSignals(),
      httpEntryPointCount: 17, // deployed web app
    });
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('data_flow');
    expect(details?.verdict).toBe('always_on_framework_runtime');
    expect(details?.sink).toBe('servlet-container-request-smuggling');
    expect(details?.threat_tag).toBe('requires_fronting_proxy');
    expect(details?.promoted_from).toBe('module');
    expect(String(details?.reason)).toContain('always_on_framework_runtime: servlet-container-request-smuggling');
  });

  it('PROMOTES a tomcat "Request/Response Smuggling" module finding to data_flow (CVE-2026-24880 on petclinic)', async () => {
    const fsk = new FakeStorage();
    seedModuleDep(fsk, {
      name: 'tomcat-embed-core',
      osvId: 'CVE-2026-24880',
      summary: REQUEST_RESPONSE_SMUGGLING_SUMMARY,
    });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'maven',
      usedTransitives: new Set(),
      springFeatureSignals: absentSignals(),
      httpEntryPointCount: 17,
    });
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('data_flow');
    expect(details?.verdict).toBe('always_on_framework_runtime');
    expect(details?.sink).toBe('servlet-container-request-smuggling');
    expect(details?.promoted_from).toBe('module');
  });

  it('preserves the callgraph_reached_transitive verdict in promoted_from when the callgraph credited the dep', async () => {
    const fsk = new FakeStorage();
    // spring-webmvc is NOT an embedded-runtime name, so with a callgraph credit
    // + an import it lands at module via the callgraph branch.
    seedModuleDep(fsk, { name: 'spring-webmvc', osvId: 'CVE-2026-22745', summary: RESOURCE_HANDLER_SUMMARY, filesImporting: 2 });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'maven',
      usedTransitives: new Set(['spring-webmvc']),
      springFeatureSignals: absentSignals(),
      httpEntryPointCount: 17,
    });
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('data_flow');
    expect(details?.verdict).toBe('always_on_framework_runtime');
    expect(details?.sink).toBe('spring-mvc-resource-handler');
    expect(details?.promoted_from).toBe('callgraph_reached_transitive');
  });

  it('STAYS at module when the project is not a deployed web app (0 HTTP-route entry points)', async () => {
    const fsk = new FakeStorage();
    seedModuleDep(fsk, { name: 'tomcat-embed-core', osvId: 'CVE-2026-34500', summary: SMUGGLING_SUMMARY });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'maven',
      usedTransitives: new Set(),
      springFeatureSignals: absentSignals(),
      httpEntryPointCount: 0, // library / CLI repo — no request path
    });
    const { level } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('module');
  });

  it('DEMOTION WINS: a callgraph-reached WebSocket CVE the demotion silences is never promoted (→ unreachable)', async () => {
    const fsk = new FakeStorage();
    // Summary overlaps a promotion pattern (request smuggling) AND the demotion
    // table (WebSocket). WebSocket is absent → demotion fires in the callgraph
    // branch → unreachable → the promotion post-pass never runs.
    seedModuleDep(fsk, { name: 'tomcat-embed-core', osvId: 'CVE-2026-99001', summary: WEBSOCKET_SMUGGLING_SUMMARY });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'maven',
      usedTransitives: new Set(['tomcat-embed-core']), // callgraph branch
      springFeatureSignals: absentSignals(),
      httpEntryPointCount: 17,
    });
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('unreachable');
    expect(details?.verdict).toBe('feature_precondition_absent');
  });

  it('DEMOTION WINS (non-callgraph path): the wouldDemote re-check blocks promotion, leaving module', async () => {
    const fsk = new FakeStorage();
    // Same overlapping summary, but the dep reaches module via the embedded-
    // runtime floor (no callgraph credit), so the demotion never ran in-branch.
    // The post-pass re-evaluates the demotion and REFUSES to promote.
    seedModuleDep(fsk, { name: 'tomcat-embed-core', osvId: 'CVE-2026-99001', summary: WEBSOCKET_SMUGGLING_SUMMARY });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'maven',
      usedTransitives: new Set(), // embedded-runtime floor, not callgraph
      springFeatureSignals: absentSignals(),
      httpEntryPointCount: 17,
    });
    const { level } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('module');
  });

  it('OWNER MISMATCH stays module: a jackson CVE with a smuggling-shaped summary is not promoted', async () => {
    const fsk = new FakeStorage();
    seedModuleDep(fsk, { name: 'jackson-core', osvId: 'CVE-2026-29062', summary: SMUGGLING_SUMMARY });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'maven',
      usedTransitives: new Set(['jackson-core']), // callgraph branch → module
      springFeatureSignals: absentSignals(),
      httpEntryPointCount: 17,
    });
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('module');
    expect(details?.verdict).toBe('callgraph_reached_transitive');
  });

  it('SUMMARY MISMATCH stays module: a tomcat CVE naming no always-on class is not promoted', async () => {
    const fsk = new FakeStorage();
    seedModuleDep(fsk, { name: 'tomcat-embed-core', osvId: 'CVE-2026-88888', summary: JACKSON_SUMMARY });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'maven',
      usedTransitives: new Set(),
      springFeatureSignals: absentSignals(),
      httpEntryPointCount: 17,
    });
    const { level } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('module');
  });
});

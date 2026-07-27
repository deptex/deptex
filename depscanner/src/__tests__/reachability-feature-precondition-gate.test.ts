/**
 * Feature-precondition gate — DEMOTE a `module` /
 * `callgraph_reached_transitive` finding to `unreachable` when the framework
 * feature its CVE requires is PROVABLY ABSENT from the scanned project.
 *
 * Covers:
 *   1. the pure decision function (`evaluateFeaturePreconditionDemotion`) —
 *      a demote case AND the fail-safe cases (feature present → stays module;
 *      unknown/truncated → stays module; unrecognized project → stays module;
 *      generic advisory that names no feature → stays module; owner mismatch →
 *      stays module).
 *   2. the workspace detector (`gatherSpringFeatureSignals`) against a real
 *      temp pom.xml + config + code tree.
 *   3. end-to-end through `updateReachabilityLevels` with injected signals —
 *      a demote case AND the "feature present → stays module" safety case, plus
 *      a protected `module` CVE (jackson) that names no gated feature.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { updateReachabilityLevels } from '../reachability';
import type { Storage } from '../storage';
import {
  evaluateFeaturePreconditionDemotion,
  gatherSpringFeatureSignals,
  emptySpringFeatureSignals,
  type SpringFeatureSignals,
} from '../reachability-feature-preconditions';

// ---------------------------------------------------------------------------
// Signal fixtures
// ---------------------------------------------------------------------------

/** A recognized Spring project with NO feature enabled (petclinic-shaped). */
function absentSignals(over: Partial<SpringFeatureSignals> = {}): SpringFeatureSignals {
  return {
    ...emptySpringFeatureSignals(),
    recognized: true,
    pomArtifacts: new Set([
      'spring-boot-starter-web',
      'spring-boot-starter-actuator',
      'spring-boot-starter-thymeleaf',
      'tomcat-embed-core',
    ]),
    configText: 'database=h2\nmanagement.endpoints.web.exposure.include=*\n',
    codeText: 'package org.springframework.samples.petclinic;\n@controller class ownercontroller {}',
    ...over,
  };
}

const WEBSOCKET_SUMMARY =
  'Improper input validation in Apache Tomcat WebSocket implementation allows denial of service.';
const CIPHER_SUMMARY =
  'Apache Tomcat did not correctly apply the configured TLS cipher order, weakening the negotiated cipher.';
const GENERIC_TOMCAT_SUMMARY =
  'Apache Tomcat request smuggling via inconsistent handling of chunked transfer-encoding.';
const JACKSON_SUMMARY =
  'jackson-core allows denial of service via deeply nested JSON objects exceeding the parser depth limit.';

// ---------------------------------------------------------------------------
// 1. Pure decision function
// ---------------------------------------------------------------------------

describe('evaluateFeaturePreconditionDemotion', () => {
  it('DEMOTES a tomcat WebSocket CVE when the project enables no WebSocket', () => {
    const r = evaluateFeaturePreconditionDemotion({
      depName: 'tomcat-embed-core',
      summary: WEBSOCKET_SUMMARY,
      signals: absentSignals(),
    });
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('tomcat-websocket');
  });

  it('DEMOTES a tomcat TLS-cipher CVE when the project has no server.ssl connector', () => {
    const r = evaluateFeaturePreconditionDemotion({
      depName: 'tomcat-embed-core',
      summary: CIPHER_SUMMARY,
      signals: absentSignals(),
    });
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('tomcat-tls-cipher');
  });

  // --- fail-safe: feature PRESENT → stays module ---
  it('does NOT demote when the WebSocket feature is present via a pom starter', () => {
    const r = evaluateFeaturePreconditionDemotion({
      depName: 'tomcat-embed-core',
      summary: WEBSOCKET_SUMMARY,
      signals: absentSignals({
        pomArtifacts: new Set(['spring-boot-starter-web', 'spring-boot-starter-websocket']),
      }),
    });
    expect(r.demote).toBe(false);
  });

  it('does NOT demote when the WebSocket feature is present via a code annotation', () => {
    const r = evaluateFeaturePreconditionDemotion({
      depName: 'tomcat-embed-core',
      summary: WEBSOCKET_SUMMARY,
      signals: absentSignals({
        codeText: '@serverendpoint("/chat") public class chatendpoint {}',
      }),
    });
    expect(r.demote).toBe(false);
  });

  it('does NOT demote a TLS-cipher CVE when server.ssl.* is configured', () => {
    const r = evaluateFeaturePreconditionDemotion({
      depName: 'tomcat-embed-core',
      summary: CIPHER_SUMMARY,
      signals: absentSignals({
        configText: 'server.ssl.key-store=classpath:keystore.p12\nserver.ssl.enabled=true\n',
      }),
    });
    expect(r.demote).toBe(false);
  });

  // --- fail-safe: ambiguous / uncertain → stays module ---
  it('does NOT demote when the code scan was truncated (absence unproven)', () => {
    const r = evaluateFeaturePreconditionDemotion({
      depName: 'tomcat-embed-core',
      summary: WEBSOCKET_SUMMARY,
      signals: absentSignals({ truncated: true }),
    });
    expect(r.demote).toBe(false);
  });

  it('does NOT demote when the project is unrecognized (no pom parsed)', () => {
    const r = evaluateFeaturePreconditionDemotion({
      depName: 'tomcat-embed-core',
      summary: WEBSOCKET_SUMMARY,
      signals: emptySpringFeatureSignals(), // recognized === false
    });
    expect(r.demote).toBe(false);
  });

  it('does NOT demote when signals are missing entirely', () => {
    expect(
      evaluateFeaturePreconditionDemotion({
        depName: 'tomcat-embed-core',
        summary: WEBSOCKET_SUMMARY,
        signals: null,
      }).demote,
    ).toBe(false);
  });

  // --- fail-safe: no feature named / owner mismatch → stays module ---
  it('does NOT demote a generic tomcat request-path CVE (no feature named)', () => {
    const r = evaluateFeaturePreconditionDemotion({
      depName: 'tomcat-embed-core',
      summary: GENERIC_TOMCAT_SUMMARY,
      signals: absentSignals(),
    });
    expect(r.demote).toBe(false);
  });

  it('does NOT demote a jackson CVE that never names a gated feature', () => {
    const r = evaluateFeaturePreconditionDemotion({
      depName: 'jackson-core',
      summary: JACKSON_SUMMARY,
      signals: absentSignals(),
    });
    expect(r.demote).toBe(false);
  });

  it('does NOT demote when the summary keyword lands on a non-owning dependency', () => {
    // A postgres JDBC CVE that mentions "cipher" must not be treated as the
    // tomcat TLS-cipher CVE — the owner (postgresql) is not a tomcat package.
    const r = evaluateFeaturePreconditionDemotion({
      depName: 'postgresql',
      summary: 'pgjdbc did not verify the server cipher during TLS negotiation.',
      signals: absentSignals(),
    });
    expect(r.demote).toBe(false);
  });

  it('does NOT demote when there is no advisory summary to map', () => {
    expect(
      evaluateFeaturePreconditionDemotion({
        depName: 'tomcat-embed-core',
        summary: null,
        signals: absentSignals(),
      }).demote,
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 2. Workspace detector against a real temp tree
// ---------------------------------------------------------------------------

describe('gatherSpringFeatureSignals', () => {
  let root: string;

  afterEach(() => {
    if (root && fs.existsSync(root)) fs.rmSync(root, { recursive: true, force: true });
  });

  it('parses pom artifacts + config + code and proves feature ABSENCE (petclinic shape)', () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'featgate-absent-'));
    fs.writeFileSync(
      path.join(root, 'pom.xml'),
      `<project><dependencies>
         <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
         <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-actuator</artifactId></dependency>
       </dependencies></project>`,
    );
    const resDir = path.join(root, 'src', 'main', 'resources');
    fs.mkdirSync(resDir, { recursive: true });
    fs.writeFileSync(path.join(resDir, 'application.properties'), 'database=h2\nspring.thymeleaf.mode=HTML\n');
    const javaDir = path.join(root, 'src', 'main', 'java', 'app');
    fs.mkdirSync(javaDir, { recursive: true });
    fs.writeFileSync(path.join(javaDir, 'OwnerController.java'), '@Controller class OwnerController {}');

    const s = gatherSpringFeatureSignals(root);
    expect(s.recognized).toBe(true);
    expect(s.truncated).toBe(false);
    expect(s.pomArtifacts.has('spring-boot-starter-web')).toBe(true);

    // Every gated feature is provably absent → a WebSocket / cipher CVE demotes.
    expect(
      evaluateFeaturePreconditionDemotion({ depName: 'tomcat-embed-core', summary: WEBSOCKET_SUMMARY, signals: s }).demote,
    ).toBe(true);
  });

  it('detects an ENABLED feature from code and refuses the demotion', () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'featgate-present-'));
    fs.writeFileSync(
      path.join(root, 'pom.xml'),
      '<project><dependencies><dependency><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies></project>',
    );
    const javaDir = path.join(root, 'src', 'main', 'java', 'app');
    fs.mkdirSync(javaDir, { recursive: true });
    fs.writeFileSync(
      path.join(javaDir, 'WsConfig.java'),
      '@Configuration @EnableWebSocket public class WsConfig implements WebSocketConfigurer {}',
    );

    const s = gatherSpringFeatureSignals(root);
    expect(s.recognized).toBe(true);
    expect(
      evaluateFeaturePreconditionDemotion({ depName: 'tomcat-embed-core', summary: WEBSOCKET_SUMMARY, signals: s }).demote,
    ).toBe(false);
  });

  it('returns unrecognized signals for a non-Maven / unreadable tree', () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'featgate-none-'));
    fs.writeFileSync(path.join(root, 'package.json'), '{"name":"x"}');
    const s = gatherSpringFeatureSignals(root);
    expect(s.recognized).toBe(false);
    expect(gatherSpringFeatureSignals(undefined).recognized).toBe(false);
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

/**
 * Seed one transitive maven dep that the callgraph credited (so it lands in the
 * `callgraph_reached_transitive` module branch — the gate's input state).
 */
function seedCallgraphReached(fsk: FakeStorage, opts: { name: string; osvId: string; summary: string }) {
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
      is_direct: false, // transitive
      files_importing_count: 0, // no first-party import
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
    (x) => x.table === 'project_dependency_findings' && x.filter.id === pdvId && 'reachability_level' in x.values,
  );
  return { level: u?.values.reachability_level, details: u?.values.reachability_details };
}

beforeEach(() => jest.clearAllMocks());

describe('updateReachabilityLevels — feature-precondition demotion', () => {
  it('demotes a callgraph_reached_transitive tomcat WebSocket CVE to unreachable when WebSocket is absent', async () => {
    const fsk = new FakeStorage();
    seedCallgraphReached(fsk, { name: 'tomcat-embed-core', osvId: 'CVE-2023-42498', summary: WEBSOCKET_SUMMARY });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'maven',
      usedTransitives: new Set(['tomcat-embed-core']), // callgraph credited it
      springFeatureSignals: absentSignals(),
    });
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('unreachable');
    expect(details?.verdict).toBe('feature_precondition_absent');
    expect(details?.feature).toBe('tomcat-websocket');
    expect(details?.demoted_from).toBe('callgraph_reached_transitive');
    expect(String(details?.reason)).toContain('feature_precondition_absent: tomcat-websocket');
  });

  it('SAFETY: keeps the finding at module (callgraph_reached_transitive) when WebSocket IS enabled', async () => {
    const fsk = new FakeStorage();
    seedCallgraphReached(fsk, { name: 'tomcat-embed-core', osvId: 'CVE-2023-42498', summary: WEBSOCKET_SUMMARY });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'maven',
      usedTransitives: new Set(['tomcat-embed-core']),
      springFeatureSignals: absentSignals({
        pomArtifacts: new Set(['spring-boot-starter-web', 'spring-boot-starter-websocket']),
      }),
    });
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('module');
    expect(details?.verdict).toBe('callgraph_reached_transitive');
  });

  it('SAFETY: leaves a callgraph_reached_transitive CVE that names no gated feature at module (jackson)', async () => {
    const fsk = new FakeStorage();
    seedCallgraphReached(fsk, { name: 'jackson-core', osvId: 'CVE-2026-29062', summary: JACKSON_SUMMARY });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'maven',
      usedTransitives: new Set(['jackson-core']),
      springFeatureSignals: absentSignals(),
    });
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('module');
    expect(details?.verdict).toBe('callgraph_reached_transitive');
  });

  it('SAFETY: never demotes when no signals are available (non-maven / no workspace)', async () => {
    const fsk = new FakeStorage();
    seedCallgraphReached(fsk, { name: 'tomcat-embed-core', osvId: 'CVE-2023-42498', summary: WEBSOCKET_SUMMARY });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'maven',
      usedTransitives: new Set(['tomcat-embed-core']),
      // no springFeatureSignals, no workspaceRoot → gather returns unrecognized
    });
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('module');
    expect(details?.verdict).toBe('callgraph_reached_transitive');
  });
});

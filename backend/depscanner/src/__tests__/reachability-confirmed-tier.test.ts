/**
 * Phase 6.5 hardening — confirmed-tier promotion semantics for the
 * reachability classifier.
 *
 * `updateReachabilityLevels()` is the function that turns the per-extraction
 * pile of `project_reachable_flows` rows into the final `reachability_level`
 * stamped on each `project_dependency_vulnerabilities` row. Phase 6.5 added
 * three new behaviors that this test pins:
 *
 *   1. A `taint_engine` flow with a matching `osv_id` promotes the PDV to
 *      `confirmed` (was `data_flow` pre-Phase 6.5; the OR-clause now picks up
 *      `reachability_source IN ('semgrep_taint','taint_engine')`).
 *   2. Drift guard: when `validOsvIds` is provided and a `taint_engine` flow's
 *      `osv_id` is NOT in the set, the flow is dropped from the confirmed
 *      bucket — the PDV demotes to `data_flow` and an `osv_id_drift_rejected`
 *      audit-log row is written.
 *   3. Suppression: a flow whose `flow_signature_hash` matches a row in
 *      `project_reachable_flow_suppressions` is excluded from confirmed-tier
 *      promotion (the dep stays at `data_flow`/lower so the user's
 *      suppress-this-flow click takes effect).
 *
 * The classifier's "fuzzy usage match → function/module/unreachable" branch
 * is exercised by the broader pipeline e2e — here we keep the test focused
 * on the three Phase 6.5 invariants.
 */

import { updateReachabilityLevels } from '../reachability';
import type { Storage } from '../storage';

interface TableState {
  rows: any[];
}

class FakeStorage {
  tables: Record<string, TableState> = {};
  inserts: Array<{ table: string; row: any }> = [];
  updates: Array<{ table: string; filter: Record<string, unknown>; values: any }> = [];

  set(table: string, rows: any[]) {
    this.tables[table] = { rows };
  }

  from(table: string): any {
    const state = this.tables[table] ?? { rows: [] };
    const filters: Array<{ col: string; val: unknown }> = [];
    const inFilters: Array<{ col: string; vals: readonly unknown[] }> = [];

    const filterRows = () => {
      let rows = state.rows;
      for (const f of filters) {
        rows = rows.filter((r) => r[f.col] === f.val);
      }
      for (const f of inFilters) {
        rows = rows.filter((r) => f.vals.includes(r[f.col]));
      }
      return rows;
    };

    const builder: any = {
      select() { return builder; },
      eq(col: string, val: unknown) { filters.push({ col, val }); return builder; },
      in(col: string, vals: readonly unknown[]) { inFilters.push({ col, vals }); return builder; },
      maybeSingle() {
        const rows = filterRows();
        return Promise.resolve({ data: rows[0] ?? null, error: null });
      },
      single() {
        const rows = filterRows();
        return Promise.resolve({
          data: rows[0] ?? null,
          error: rows.length === 0 ? { code: 'PGRST116', message: 'not found' } : null,
        });
      },
      insert: (row: any) => {
        const inserted = Array.isArray(row) ? row : [row];
        for (const r of inserted) this.inserts.push({ table, row: r });
        return Promise.resolve({ data: null, error: null });
      },
      update: (values: any) => {
        const currentFilters: Record<string, unknown> = {};
        for (const f of filters) currentFilters[f.col] = f.val;
        const upBuilder: any = {
          eq: (col: string, val: unknown) => {
            currentFilters[col] = val;
            return upBuilder;
          },
          then: (onFulfilled: any) => {
            this.updates.push({ table, filter: { ...currentFilters }, values });
            return Promise.resolve({ data: null, error: null }).then(onFulfilled);
          },
        };
        return upBuilder;
      },
      then(onFulfilled: any) {
        const rows = filterRows();
        return Promise.resolve({ data: rows, error: null }).then(onFulfilled);
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
const ORG_ID = 'org-1';
const DEP_ID = 'dep-lodash';
const PD_ID = 'pd-1';
const PDV_ID = 'pdv-1';
const CVE = 'CVE-2021-23337';
const SUPPRESSED_HASH = 'a'.repeat(64);

function seedBasePdv(fs: FakeStorage) {
  fs.set('project_dependency_vulnerabilities', [
    {
      id: PDV_ID,
      project_dependency_id: PD_ID,
      project_id: PROJECT_ID,
      extraction_run_id: RUN_ID,
      osv_id: CVE,
    },
  ]);
  fs.set('project_dependencies', [
    {
      id: PD_ID,
      project_id: PROJECT_ID,
      last_seen_extraction_run_id: RUN_ID,
      dependency_id: DEP_ID,
      is_direct: true,
      files_importing_count: 1,
    },
  ]);
  fs.set('project_usage_slices', []);
}

beforeEach(() => {
  jest.clearAllMocks();
});

describe('updateReachabilityLevels — Phase 6.5 confirmed-tier semantics', () => {
  it('promotes PDV to `confirmed` on a matching taint_engine flow', async () => {
    const fs = new FakeStorage();
    seedBasePdv(fs);
    fs.set('project_reachable_flows', [
      {
        project_id: PROJECT_ID,
        extraction_run_id: RUN_ID,
        dependency_id: DEP_ID,
        reachability_source: 'taint_engine',
        osv_id: CVE,
        rule_id: null,
        flow_signature_hash: 'b'.repeat(64),
        entry_point_file: 'src/server.ts',
        entry_point_line: 12,
        entry_point_tag: 'framework-input:PUBLIC_UNAUTH',
        sink_method: 'lodash.template',
      },
    ]);
    fs.set('project_reachable_flow_suppressions', []);

    await updateReachabilityLevels(
      PROJECT_ID,
      RUN_ID,
      fs as unknown as Storage,
      log as any,
      undefined,
      { validOsvIds: new Set([CVE]), organizationId: ORG_ID },
    );

    const update = fs.updates.find(
      (u) => u.table === 'project_dependency_vulnerabilities' && u.filter.id === PDV_ID,
    );
    expect(update).toBeDefined();
    expect(update!.values.reachability_level).toBe('confirmed');
    expect(update!.values.is_reachable).toBe(true);
    expect(update!.values.reachability_details.sources).toContain('taint_engine');
  });

  it('promotes on `semgrep_taint` flows too (legacy path still works)', async () => {
    const fs = new FakeStorage();
    seedBasePdv(fs);
    fs.set('project_reachable_flows', [
      {
        project_id: PROJECT_ID,
        extraction_run_id: RUN_ID,
        dependency_id: DEP_ID,
        reachability_source: 'semgrep_taint',
        osv_id: CVE,
        rule_id: 'lodash-template-rce',
        flow_signature_hash: null,
        entry_point_file: 'src/server.ts',
        entry_point_line: 12,
        entry_point_tag: null,
        sink_method: 'lodash.template',
      },
    ]);
    fs.set('project_reachable_flow_suppressions', []);

    await updateReachabilityLevels(
      PROJECT_ID,
      RUN_ID,
      fs as unknown as Storage,
      log as any,
      undefined,
      // No validOsvIds — legacy callers shouldn't invoke the drift guard.
    );

    const update = fs.updates.find((u) => u.filter.id === PDV_ID);
    expect(update?.values.reachability_level).toBe('confirmed');
    expect(update?.values.reachability_details.rule_ids).toContain('lodash-template-rce');
  });

  it('demotes to `data_flow` and writes osv_id_drift_rejected audit when osv_id is not in validOsvIds', async () => {
    const fs = new FakeStorage();
    seedBasePdv(fs);
    fs.set('project_reachable_flows', [
      // The CVE-tagged taint_engine flow that should be rejected by drift guard.
      {
        project_id: PROJECT_ID,
        extraction_run_id: RUN_ID,
        dependency_id: DEP_ID,
        reachability_source: 'taint_engine',
        osv_id: CVE,
        rule_id: null,
        flow_signature_hash: 'b'.repeat(64),
        entry_point_file: 'src/server.ts',
        entry_point_line: 12,
        entry_point_tag: null,
        sink_method: 'lodash.template',
      },
    ]);
    fs.set('project_reachable_flow_suppressions', []);

    await updateReachabilityLevels(
      PROJECT_ID,
      RUN_ID,
      fs as unknown as Storage,
      log as any,
      undefined,
      // Empty set ⇒ every taint_engine flow's osv_id is "drifted".
      { validOsvIds: new Set<string>(), organizationId: ORG_ID },
    );

    // The PDV still demotes to data_flow because the dep IS still in flowsByDep
    // (the dep is wired into the call graph), the taint flow just doesn't make
    // it into the confirmed bucket.
    const update = fs.updates.find((u) => u.filter.id === PDV_ID);
    expect(update?.values.reachability_level).toBe('data_flow');

    const driftEvent = fs.inserts.find(
      (i) => i.table === 'security_audit_logs' && i.row.action === 'osv_id_drift_rejected',
    );
    expect(driftEvent).toBeDefined();
    expect(driftEvent!.row.organization_id).toBe(ORG_ID);
    expect(driftEvent!.row.metadata.flow_osv_id).toBe(CVE);
    expect(driftEvent!.row.metadata.flow_dependency_id).toBe(DEP_ID);
  });

  it('demotes to `data_flow` when the matching flow is suppressed (hash in project_reachable_flow_suppressions)', async () => {
    const fs = new FakeStorage();
    seedBasePdv(fs);
    fs.set('project_reachable_flows', [
      {
        project_id: PROJECT_ID,
        extraction_run_id: RUN_ID,
        dependency_id: DEP_ID,
        reachability_source: 'taint_engine',
        osv_id: CVE,
        rule_id: null,
        flow_signature_hash: SUPPRESSED_HASH,
        entry_point_file: 'src/server.ts',
        entry_point_line: 12,
        entry_point_tag: null,
        sink_method: 'lodash.template',
      },
    ]);
    fs.set('project_reachable_flow_suppressions', [
      {
        project_id: PROJECT_ID,
        flow_signature_hash: SUPPRESSED_HASH,
      },
    ]);

    await updateReachabilityLevels(
      PROJECT_ID,
      RUN_ID,
      fs as unknown as Storage,
      log as any,
      undefined,
      { validOsvIds: new Set([CVE]), organizationId: ORG_ID },
    );

    // Suppressed flow stays out of the confirmed bucket but the dep is still
    // wired into the call graph, so the PDV lands at data_flow — NOT
    // function/module. The user's intent ("ignore THIS flow") is preserved
    // without collapsing the dep all the way back to module.
    const update = fs.updates.find((u) => u.filter.id === PDV_ID);
    expect(update?.values.reachability_level).toBe('data_flow');
    // No drift audit log on a suppression-only demotion.
    const drift = fs.inserts.find(
      (i) => i.table === 'security_audit_logs' && i.row.action === 'osv_id_drift_rejected',
    );
    expect(drift).toBeUndefined();
  });

  it('confirmed-tier survives an unrelated suppressed flow (only the matching hash is filtered)', async () => {
    const fs = new FakeStorage();
    seedBasePdv(fs);
    const KEEP_HASH = 'c'.repeat(64);
    fs.set('project_reachable_flows', [
      {
        project_id: PROJECT_ID,
        extraction_run_id: RUN_ID,
        dependency_id: DEP_ID,
        reachability_source: 'taint_engine',
        osv_id: CVE,
        rule_id: null,
        // This flow is NOT in the suppressions table.
        flow_signature_hash: KEEP_HASH,
        entry_point_file: 'src/server.ts',
        entry_point_line: 12,
        entry_point_tag: null,
        sink_method: 'lodash.template',
      },
    ]);
    fs.set('project_reachable_flow_suppressions', [
      // Different hash on the same project — must NOT block the promotion.
      { project_id: PROJECT_ID, flow_signature_hash: SUPPRESSED_HASH },
    ]);

    await updateReachabilityLevels(
      PROJECT_ID,
      RUN_ID,
      fs as unknown as Storage,
      log as any,
      undefined,
      { validOsvIds: new Set([CVE]), organizationId: ORG_ID },
    );

    const update = fs.updates.find((u) => u.filter.id === PDV_ID);
    expect(update?.values.reachability_level).toBe('confirmed');
  });
});

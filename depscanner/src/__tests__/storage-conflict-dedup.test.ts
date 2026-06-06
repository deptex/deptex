/**
 * Regression test for the IaC/container re-scan idempotency fix.
 *
 * Before the fix, upsertContainerFindings / upsertIaCFindings forwarded the raw
 * scanner output straight into a batched `INSERT ... ON CONFLICT DO UPDATE`.
 * When the same image emitted the same (digest, package, version, vuln) tuple
 * twice — common for a big base image like node:14.0 across layers — Postgres
 * rejected the whole batch with "ON CONFLICT DO UPDATE command cannot affect
 * row a second time", failing the scan. These tests assert both upserts now
 * collapse to the exact unique-index conflict key, keeping the last occurrence.
 */

import { upsertContainerFindings, upsertIaCFindings } from '../scanners/storage';
import type { ContainerFinding, IaCFinding } from '../scanners/types';

function makeMockSupabase() {
  const calls: Array<{ table: string; rows: any[]; onConflict: string }> = [];
  const client = {
    from(table: string) {
      return {
        upsert: async (rows: any[], opts: { onConflict: string }) => {
          calls.push({ table, rows, onConflict: opts.onConflict });
          return { error: null };
        },
      };
    },
  };
  return { client, calls };
}

const containerBase: ContainerFinding = {
  scanner_version: 'trivy@0.50.0',
  image_reference: 'node:14.0',
  image_digest: 'deadbeef',
  os_package_name: 'libc6',
  os_package_version: '2.31',
  os_package_ecosystem: 'debian',
  osv_id: null,
  cve_id: 'CVE-2021-0001',
  severity: 'HIGH',
  cvss_score: null,
  epss_score: null,
  is_kev: false,
  fix_versions: [],
  layer_digest: null,
  description: null,
  rule_doc_url: null,
  container_fingerprint: 'libc6@CVE-2021-0001',
  reachability_level: null,
  reachability_details: null,
};

const iacBase: IaCFinding = {
  scanner: 'checkov',
  scanner_version: 'checkov@3.2.0',
  rule_id: 'CKV_DOCKER_2',
  framework: 'dockerfile',
  file_path: 'Dockerfile',
  start_line: 5,
  end_line: 6,
  severity: 'HIGH',
  message: null,
  description: null,
  cwe_ids: [],
  code_snippet: null,
  rule_doc_url: null,
  iac_fingerprint: 'fp-1',
  compliance_refs: null,
  metadata: null,
};

describe('upsertContainerFindings conflict-key dedup', () => {
  it('collapses duplicate (digest, package, version, cve) rows and keeps the last', async () => {
    const { client, calls } = makeMockSupabase();
    const dupLast = { ...containerBase, severity: 'CRITICAL' };
    const distinct = {
      ...containerBase,
      cve_id: 'CVE-2021-0002',
      container_fingerprint: 'libc6@CVE-2021-0002',
    };

    const res = await upsertContainerFindings(client as any, 'proj-1', 'run-1', [
      containerBase,
      dupLast,
      distinct,
    ]);

    const upserted = calls.flatMap((c) => c.rows);
    expect(upserted).toHaveLength(2);
    expect(res.inserted).toBe(2);

    const collapsed = upserted.filter(
      (r) => r.os_package_name === 'libc6' && r.cve_id === 'CVE-2021-0001',
    );
    expect(collapsed).toHaveLength(1);
    // Last occurrence wins, matching ON CONFLICT DO UPDATE semantics.
    expect(collapsed[0].severity).toBe('CRITICAL');
  });

  it('collapses rows where both osv_id and cve_id are null on (digest, package, version)', async () => {
    const { client, calls } = makeMockSupabase();
    const n1 = { ...containerBase, osv_id: null, cve_id: null, container_fingerprint: null, severity: 'LOW' };
    const n2 = { ...containerBase, osv_id: null, cve_id: null, container_fingerprint: null, severity: 'MEDIUM' };

    const res = await upsertContainerFindings(client as any, 'proj-1', 'run-1', [n1, n2]);

    const upserted = calls.flatMap((c) => c.rows);
    // Both generate the same vulnerability_id (md5 of digest:pkg:ver) → one row.
    expect(upserted).toHaveLength(1);
    expect(res.inserted).toBe(1);
    expect(upserted[0].severity).toBe('MEDIUM');
  });

  it('targets the run-scoped unique index', async () => {
    const { client, calls } = makeMockSupabase();
    await upsertContainerFindings(client as any, 'proj-1', 'run-1', [containerBase]);
    expect(calls[0].onConflict).toBe(
      'project_id,image_digest,os_package_name,os_package_version,vulnerability_id,extraction_run_id',
    );
  });
});

describe('upsertIaCFindings conflict-key dedup', () => {
  it('collapses duplicate (rule_id, file_path, start_line) rows and keeps the last', async () => {
    const { client, calls } = makeMockSupabase();
    const dupLast = { ...iacBase, severity: 'CRITICAL' };
    const distinct = { ...iacBase, start_line: 9 };

    const res = await upsertIaCFindings(client as any, 'proj-1', 'run-1', [
      iacBase,
      dupLast,
      distinct,
    ]);

    const upserted = calls.flatMap((c) => c.rows);
    expect(upserted).toHaveLength(2);
    expect(res.inserted).toBe(2);

    const collapsed = upserted.filter((r) => r.rule_id === 'CKV_DOCKER_2' && r.start_line === 5);
    expect(collapsed).toHaveLength(1);
    expect(collapsed[0].severity).toBe('CRITICAL');
  });

  it('collapses rows with null start_line (start_line_key = -1)', async () => {
    const { client, calls } = makeMockSupabase();
    const n1 = { ...iacBase, start_line: null, severity: 'LOW' };
    const n2 = { ...iacBase, start_line: null, severity: 'MEDIUM' };

    const res = await upsertIaCFindings(client as any, 'proj-1', 'run-1', [n1, n2]);

    const upserted = calls.flatMap((c) => c.rows);
    expect(upserted).toHaveLength(1);
    expect(res.inserted).toBe(1);
    expect(upserted[0].severity).toBe('MEDIUM');
  });
});

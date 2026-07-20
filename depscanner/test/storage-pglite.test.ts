/**
 * Integration test: exercise the Storage interface against an in-memory
 * PGLite. Proves M1 deliverable — the same chainable call patterns used
 * by pipeline.ts/reachability.ts/ast-storage.ts/etc. also work when the
 * Supabase client is swapped for PGLiteStorage.
 *
 * Run: npx tsx test/storage-pglite.test.ts
 */

import { createPGLiteStorage } from '../src/storage';

let failures = 0;

function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
  }
}

async function main() {
  const t0 = Date.now();
  console.log('Booting PGLiteStorage...');
  const storage = await createPGLiteStorage();
  console.log(`  booted in ${Date.now() - t0}ms\n`);

  const orgId = '11111111-1111-1111-1111-111111111111';
  const projectId = '22222222-2222-2222-2222-222222222222';
  const runId = 'run_integration_test_001';

  // --- Seed ---
  console.log('Seeding organization + project via Storage.insert...');
  {
    const { error } = await storage
      .from('organizations')
      .insert({ id: orgId, name: 'storage-test-org', created_at: new Date().toISOString() });
    assert(error === null, `insert organizations (error=${error?.message ?? 'null'})`);
  }
  {
    const { error } = await storage.from('projects').insert({
      id: projectId,
      organization_id: orgId,
      name: 'storage-test-project',
      active_extraction_run_id: null,
      created_at: new Date().toISOString(),
    });
    assert(error === null, `insert project (error=${error?.message ?? 'null'})`);
  }

  // --- Select with .eq().single() ---
  console.log('\nReading project back via .select().eq().single()...');
  {
    const { data, error } = await storage
      .from('projects')
      .select('id, name, organization_id')
      .eq('id', projectId)
      .single();
    assert(error === null, 'select .single() has no error');
    assert((data as any)?.name === 'storage-test-project', `project name === 'storage-test-project' (got: ${(data as any)?.name})`);
  }

  // --- Select with .in() ---
  console.log('\nBatch-reading via .select().in()...');
  {
    const { data, error } = await storage
      .from('projects')
      .select('id')
      .in('id', [projectId, '99999999-9999-9999-9999-999999999999']);
    assert(error === null, `select .in() error=${error?.message ?? 'null'}`);
    assert(Array.isArray(data) && data.length === 1, `exactly one row returned (got: ${Array.isArray(data) ? data.length : 'not array'})`);
  }

  // --- Insert .. RETURNING via .select() ---
  console.log('\nInsert + RETURNING via .insert().select()...');
  let depId: string | undefined;
  {
    const { data, error } = await storage
      .from('dependencies')
      .insert({ name: 'integration-test-lodash', ecosystem: 'npm', license: 'MIT' })
      .select('id, name');
    assert(error === null, `insert+select (error=${error?.message ?? 'null'})`);
    assert(Array.isArray(data) && data.length === 1, 'got 1 inserted row back');
    depId = (data as any)?.[0]?.id;
    assert(typeof depId === 'string' && depId.length > 0, 'inserted row has uuid id');
  }

  // --- Upsert with onConflict (DO UPDATE) ---
  console.log('\nUpsert with onConflict (DO UPDATE)...');
  {
    // Re-insert same row with new license to verify EXCLUDED-style update.
    const { error } = await storage
      .from('dependencies')
      .upsert(
        { id: depId, name: 'integration-test-lodash', ecosystem: 'npm', license: 'Apache-2.0' },
        { onConflict: 'id' },
      );
    assert(error === null, `upsert (error=${error?.message ?? 'null'})`);
  }
  {
    const { data } = await storage.from('dependencies').select('license').eq('id', depId).single();
    assert((data as any)?.license === 'Apache-2.0', `license updated to Apache-2.0 (got: ${(data as any)?.license})`);
  }

  // --- Upsert with ignoreDuplicates (DO NOTHING) ---
  console.log('\nUpsert with ignoreDuplicates (DO NOTHING)...');
  {
    const { error } = await storage
      .from('dependencies')
      .upsert(
        { id: depId, name: 'integration-test-lodash', ecosystem: 'npm', license: 'MIT' },
        { onConflict: 'id', ignoreDuplicates: true },
      );
    assert(error === null, `upsert ignoreDuplicates (error=${error?.message ?? 'null'})`);
  }
  {
    const { data } = await storage.from('dependencies').select('license').eq('id', depId).single();
    assert((data as any)?.license === 'Apache-2.0', 'license unchanged after ignoreDuplicates upsert');
  }

  // --- Update with .eq() ---
  console.log('\nUpdate via .update().eq()...');
  {
    const { error } = await storage
      .from('dependencies')
      .update({ license: 'BSD-3-Clause' })
      .eq('id', depId);
    assert(error === null, `update (error=${error?.message ?? 'null'})`);
  }
  {
    const { data } = await storage.from('dependencies').select('license').eq('id', depId).single();
    assert((data as any)?.license === 'BSD-3-Clause', 'license updated via .update().eq()');
  }

  // --- Update .. RETURNING + .limit() ---
  console.log('\nUpdate + RETURNING + limit via .update().eq().select().limit()...');
  {
    const { data, error } = await storage
      .from('dependencies')
      .update({ license: 'ISC' })
      .eq('id', depId)
      .select('id, license')
      .limit(1);
    assert(error === null, `update+returning+limit (error=${error?.message ?? 'null'})`);
    assert(Array.isArray(data) && data.length === 1, 'one row returned from RETURNING');
    assert((data as any)?.[0]?.license === 'ISC', 'returned row has new license');
  }

  // --- maybeSingle on empty set ---
  console.log('\n.maybeSingle() on empty set returns { data: null, error: null }...');
  {
    const { data, error } = await storage
      .from('dependencies')
      .select('id')
      .eq('id', '00000000-0000-0000-0000-000000000000')
      .maybeSingle();
    assert(data === null && error === null, 'maybeSingle returns null/null');
  }

  // --- RPC: finalize_extraction (JSONB scalar return) ---
  console.log('\nRPC: finalize_extraction (returns JSONB)...');
  {
    const { data, error } = await storage.rpc<Record<string, unknown>>(
      'finalize_extraction',
      {
        p_job_id: null,
        p_project_id: projectId,
        p_extraction_run_id: runId,
      },
    );
    assert(error === null, `finalize_extraction rpc error=${error?.message ?? 'null'}`);
    assert(data !== null && typeof data === 'object', 'rpc returns a JSONB object');
    assert((data as any)?.extraction_run_id === runId, `summary.extraction_run_id === '${runId}'`);
  }

  // --- text[] column vs JSONB column handling ---
  // Regression: CLI smoke run failed on "malformed array literal" when
  // fixed_versions (text[]) was JSON-stringified.
  console.log('\ntext[] array insertion (fixed_versions)...');
  {
    // Need a parent row for FK — insert one dep + one project_dep.
    const { data: dep } = await storage
      .from('dependencies')
      .insert({ name: 'text-array-test', ecosystem: 'npm' })
      .select('id');
    const parentDepId = (dep as any)?.[0]?.id;
    const { data: pd } = await storage
      .from('project_dependencies')
      .insert({
        project_id: projectId,
        dependency_id: parentDepId,
        name: 'text-array-test',
        version: '1.0.0',
        is_direct: true,
        source: 'dependencies',
      })
      .select('id');
    const pdId = (pd as any)?.[0]?.id;
    assert(typeof pdId === 'string', `inserted project_dependency id (got: ${typeof pdId})`);

    // Hit the exact shape that failed in the CLI run: text[] = ['4.18.0'].
    const { error } = await storage.from('project_dependency_findings').insert({
      project_id: projectId,
      project_dependency_id: pdId,
      osv_id: 'CVE-TEST-0001',
      extraction_run_id: 'run_array_test',
      severity: 'high',
      aliases: ['GHSA-test', 'NVDB-test'],
      fixed_versions: ['4.18.0'],
      is_reachable: false,
      cisa_kev: false,
      reachability_status: 'unreachable',
    });
    assert(error === null, `insert with text[] (error=${error?.message ?? 'null'})`);
  }

  console.log('\njsonb column with array-of-objects (flow_nodes)...');
  {
    const { error } = await storage.from('project_reachable_flows').insert({
      project_id: projectId,
      extraction_run_id: 'run_jsonb_test',
      purl: 'pkg:npm/test@1.0.0',
      flow_nodes: [
        { parentFileName: 'a.js', lineNumber: 1 },
        { parentFileName: 'b.js', lineNumber: 2 },
      ],
      flow_length: 2,
      sink_is_external: true,
    });
    assert(error === null, `insert with jsonb array-of-objects (error=${error?.message ?? 'null'})`);
  }

  // --- Storage bucket upload ---
  console.log('\nstorage.from().upload() writes to outputDir...');
  {
    const { data, error } = await storage.storage
      .from('project-imports')
      .upload(`${projectId}/${runId}/test.txt`, 'hello storage layer', {
        contentType: 'text/plain',
        upsert: true,
      });
    assert(error === null, `upload error=${error?.message ?? 'null'}`);
    assert(data?.path.endsWith('test.txt'), 'returned path ends in test.txt');
  }

  // --- P8: type-aware jsonb vs native-array parameter encoding ---
  // A primitive string[] bound for a jsonb column must be JSON-encoded
  // (["a","b"]), not emitted as the native-array literal {a,b} the type-blind
  // heuristic produced — which Postgres rejects for jsonb. A real text[] column
  // must still bind natively.
  console.log('\nType-aware array encoding (jsonb string[] vs text[])...');
  {
    await storage.db.exec(
      `CREATE TABLE jsonb_array_probe (id text PRIMARY KEY, tags jsonb, names text[]);`,
    );
    // The column-type map is built at boot; refresh so this post-boot table is
    // visible to the binder.
    await storage.refreshColumnTypes();

    const { error: insErr } = await storage.from('jsonb_array_probe').insert({
      id: 'probe-1',
      tags: ['alpha', 'beta', 'gamma'], // jsonb column holding a primitive string[]
      names: ['x', 'y'], // native text[] column
    });
    assert(insErr === null, `insert jsonb string[] succeeds (error=${insErr?.message ?? 'null'})`);

    const { data: probe, error: selErr } = await storage
      .from('jsonb_array_probe')
      .select('tags, names')
      .eq('id', 'probe-1')
      .single();
    assert(selErr === null, `select probe row (error=${selErr?.message ?? 'null'})`);
    const tags = (probe as any)?.tags;
    const names = (probe as any)?.names;
    assert(
      Array.isArray(tags) && tags.join(',') === 'alpha,beta,gamma',
      `jsonb string[] round-trips as a JSON array (got ${JSON.stringify(tags)})`,
    );
    assert(
      Array.isArray(names) && names.join(',') === 'x,y',
      `text[] still round-trips natively (got ${JSON.stringify(names)})`,
    );
  }

  await storage.close();

  console.log(`\n${failures === 0 ? 'ALL TESTS PASSED' : `${failures} TEST(S) FAILED`} in ${Date.now() - t0}ms`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('Unhandled error:', e);
  process.exit(1);
});

/**
 * Sole-writer invariant test for PDV.contextual_depscore.
 *
 * After doReachabilityAndEpd finishes, only two code paths inside the
 * depscanner pipeline mutate `contextual_depscore`:
 *
 *   - epd.ts — via `supabase.from('project_dependency_findings')
 *     .update({ contextual_depscore: ... })` from a handful of compute
 *     helpers (computeAggregate / zeroAggregate / Anthropic + heuristic
 *     fallbacks).
 *   - composition.ts — via the `apply_composition_results` RPC, which
 *     atomically applies `contextual_depscore = ROUND(... * factor, 4)`
 *     gated on (project_id, extraction_run_id) for tenant safety.
 *
 * Any new client-side `.update({ contextual_depscore })` site outside
 * epd.ts is a sole-writer violation. So is any new caller of
 * `apply_composition_results` outside composition.ts.
 *
 * This test grep-greps the depscanner source for both invariants. It
 * catches the bug class the original Rev 4 plan introduced (a
 * naively-added epd.ts overwrite that races composition.ts).
 *
 * NOTE: this test runs against the source file paths visible on disk;
 * it does NOT touch the database. It runs in jest via the backend
 * preset (`roots: [...depscanner/src]` per backend/jest.config.js).
 *
 * NOTE on out-of-band writers: DAST's `confirm_pdvs_from_dast_run` RPC also
 * touches PDVs — it promotes a cross-linked PDV to reachability_level
 * 'confirmed' AND (as of phase67 / SC2) recomputes contextual_depscore to the
 * confirmed tier when it was NULL, so a DAST-proven vuln ranks at its full
 * severity. That RPC lives in SQL, not depscanner TS, so the grep test below
 * does not see it — which is intentional: this enforces the
 * within-depscanner-pipeline scope of the sole-writer invariant. The RPC's
 * recompute is covered by test/dast-confirm-contextual-depscore-pglite.ts.
 */

import * as fs from 'fs';
import * as path from 'path';

/** Walk a tree under base, yielding files whose path matches one of
 *  the suffixes. Skips node_modules and __tests__. */
function* walkTs(base: string): Generator<string> {
  const stack: string[] = [base];
  while (stack.length) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (ent.name === 'node_modules' || ent.name === '__tests__' || ent.name === 'dist') continue;
        stack.push(full);
        continue;
      }
      if (!ent.isFile()) continue;
      if (!ent.name.endsWith('.ts') || ent.name.endsWith('.d.ts')) continue;
      yield full;
    }
  }
}

const DEPSCANNER_SRC = path.resolve(__dirname, '../../..', 'src');

/** Files that contain a `.from('project_dependency_findings')` chain
 *  followed within ~600 chars by a `.update(` or `.upsert(` — i.e. files that
 *  mutate PDVs. (R3 batched the three known per-row UPDATE loops into batched
 *  `.upsert(onConflict:'id')` flushes; they remain the sole PDV mutators.) */
function filesMutatingPdv(): string[] {
  const out: string[] = [];
  // multiline-dot regex: handles chained calls on consecutive lines.
  const re = /\.from\(\s*['"]project_dependency_findings['"]\s*\)[\s\S]{0,600}?\.(?:update|upsert)\(/;
  for (const file of walkTs(DEPSCANNER_SRC)) {
    const text = fs.readFileSync(file, 'utf8');
    if (re.test(text)) {
      out.push(path.relative(DEPSCANNER_SRC, file).split(path.sep).join('/'));
    }
  }
  return out;
}

/** Files containing the literal string `apply_composition_results` — both
 *  the RPC caller AND any wrapper file that references it. */
function filesNamingCompositionRpc(): string[] {
  const out: string[] = [];
  for (const file of walkTs(DEPSCANNER_SRC)) {
    const text = fs.readFileSync(file, 'utf8');
    if (/apply_composition_results/.test(text)) {
      out.push(path.relative(DEPSCANNER_SRC, file).split(path.sep).join('/'));
    }
  }
  return out;
}

/** Files containing supabase.rpc('apply_composition_results', …) calls. */
function filesInvokingCompositionRpc(): string[] {
  const out: string[] = [];
  const re = /\.rpc\(\s*['"]apply_composition_results['"]/;
  for (const file of walkTs(DEPSCANNER_SRC)) {
    const text = fs.readFileSync(file, 'utf8');
    if (re.test(text)) {
      out.push(path.relative(DEPSCANNER_SRC, file).split(path.sep).join('/'));
    }
  }
  return out;
}

/** Files that contain a `.update({ ... contextual_depscore ... })` literal
 *  payload. Catches the bug class where a new caller starts inline-writing
 *  contextual_depscore. epd.ts itself uses a `.update(fields)` indirection
 *  so it does NOT match this pattern; that's deliberate — epd.ts is the
 *  known-good baseline, and this test is a violation-detector for new
 *  callers, not a baseline assertion. */
function filesInlineUpdatingContextual(): string[] {
  const out: string[] = [];
  const re = /\.update\(\s*\{[^}]*?\bcontextual_depscore\b/;
  for (const file of walkTs(DEPSCANNER_SRC)) {
    const text = fs.readFileSync(file, 'utf8');
    if (re.test(text)) {
      out.push(path.relative(DEPSCANNER_SRC, file).split(path.sep).join('/'));
    }
  }
  return out;
}

describe('PDV.contextual_depscore sole-writer invariant', () => {
  test('only known files mutate project_dependency_findings via .update(...)/.upsert(...)', () => {
    const files = new Set(filesMutatingPdv());
    // Allowlist (every PDV-mutation site outside this list is a violation).
    //  R3 batched each per-row UPDATE loop into a single .upsert(onConflict:'id'):
    //  - epd.ts                          writes contextual_depscore + epd_factor + entry_point_*
    //  - pipeline-steps/reachability.ts  writes depscore + base_depscore_no_reachability post-classification
    //  - reachability.ts                 writes reachability_level + reachability_details + is_reachable
    // The "no inline contextual_depscore .update" test below confirms
    // none of these (other than epd.ts via its variable indirection)
    // mutate contextual_depscore.
    expect(files).toEqual(new Set([
      'epd.ts',
      'pipeline-steps/reachability.ts',
      'reachability.ts',
    ]));
  });

  test('no client-side file writes contextual_depscore in an inline .update payload', () => {
    // epd.ts uses .update(fields) with a variable builder, so it
    // does NOT match this pattern by design. Any file matching is a
    // sole-writer scope violation introduced by a new caller.
    const files = new Set(filesInlineUpdatingContextual());
    expect(files).toEqual(new Set());
  });

  test('apply_composition_results RPC is invoked only from composition.ts', () => {
    const callers = new Set(filesInvokingCompositionRpc());
    expect(callers).toEqual(new Set(['scanners/composition.ts']));
  });

  test('apply_composition_results is named only by the impl + the pipeline-step wrapper + the pipeline orchestrator', () => {
    // The wrapper at pipeline-steps/composition.ts and the orchestrator
    // pipeline.ts legitimately reference the RPC name in JSDoc comments
    // describing what the step does. That trio is the closed set —
    // any fourth file mentioning the RPC name is a sole-writer scope
    // violation and should fail this assertion.
    const named = new Set(filesNamingCompositionRpc());
    expect(named).toEqual(new Set([
      'scanners/composition.ts',
      'pipeline-steps/composition.ts',
      'pipeline.ts',
    ]));
  });
});

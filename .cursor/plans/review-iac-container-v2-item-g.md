# Plan Review — iac-container-v2-item-g (Rev 4)

**Verdict:** **REVISE** (substantively close to READY — 4-of-6 personas voted READY; 2 small patches finalize)
**Plan reviewed:** `.cursor/plans/iac-container-v2-item-g.plan.md` Rev 4 (mtime 2026-05-21)
**Generated:** 2026-05-21
**Mode:** lean; debate: off
**Personas:** 6 — `skeptic, pragmatist, scope-cutter, architect, test-strategy-auditor, opportunity-scout`
**Vote tally:** 4 READY / 2 REVISE / 0 REWORK
**Findings:** 1 P0 / 1 P1 / 21 P2 / 9 P3

## Summary

Rev 4 successfully resolved every Rev 3 P0 (epd.ts fold mechanism, pipeline ordering, Math.max scoring blend). Four of six personas voted READY/READY-with-nits; the architecture is sound and the plan is genuinely shippable.

Two remaining issues warrant a quick patch pass before `/create-worktree`:

1. **P0 (skeptic-r4-f1)** — supabase-js `.from().update().eq()` only supports single-row updates. Plan M2 step 2 Step E says "single multi-row `UPDATE … FROM (VALUES …)`" — that shape isn't expressible from a supabase-js client. The PostgreSQL semantics are correct (architect verified); only the JS client expression needs adjustment. **Fix: 3-line plan wording change** — either add a small `apply_composition_results(p_project_id, p_run_id, p_updates jsonb)` RPC to phase30 (~15 lines plpgsql) OR accept per-row update loop matching the existing `epd.ts:1425-1431` pattern. Recommend the RPC for atomicity. The skeptic flagged it P0 but voted REVISE — they explicitly framed it as a 3-line wording fix, not a fundamental flaw.
2. **P1 (test-strategy-auditor-r4)** — "composition is sole post-EPD writer of contextual_depscore" invariant is currently a header comment, not an enforced test. A 15-line grep-based test asserting `.update({...contextual_depscore` appears only in `{epd.ts: 4 sites, composition.ts: 1 site}` turns the documented invariant into a regression guard.

Everything else is P2/P3 polish: cleaner column defaults, more thorough fixture coverage, optional scope cuts, observability tweaks. None block `/implement`.

This is the fourth review on Item G. The trajectory is real: Rev 1 + Rev 2 had architectural errors; Rev 3 had implementation-detail errors; Rev 4 has bookkeeping errors (SQL shape clarification + one missing regression test). The convergence is converging.

## Vote Tally

| Persona | Vote | Top concern | Rationale |
|---|---|---|---|
| skeptic | REVISE | skeptic-r4-f1 | Multi-row UPDATE FROM (VALUES …) not expressible via supabase-js .update().eq() — 3-line wording fix; core direction sound |
| pragmatist | READY | pragmatist-r4-f2 | All R1 patches absorbed; remaining items are micro-optimizations that don't block /implement |
| scope-cutter | READY | scope-cutter-C2 | Six proposed cuts save ~1 day; plan is shippable as-is |
| architect | READY | architect-r4-f1 | No P0/P1 architectural concerns; 7 nits all P2/P3 wording/test additions |
| test-strategy-auditor | REVISE | test-strategy-auditor-r4 | Sole-writer invariant policy-only without grep-based enforcement test — 15-line addition closes the silent-regression hole |
| opportunity-scout | READY | opp-r4-f1 | Three forward-compat hygiene items are P2 polish; no blockers |

## P0 — Fundamental Concerns

### supabase-js multi-row UPDATE shape `[SOLO — skeptic, voted REVISE]`
- **Plan section:** M2 step 2, Step E
- **Claim:** Plan says "single multi-row `UPDATE … FROM (VALUES …)` statement" — but supabase-js client only supports `.from(table).update(fields).eq(col, val)` (single-row WHERE filter). There's no client-side way to ship a multi-row UPDATE in one statement.
- **Evidence:** `grep -rn 'FROM (VALUES' depscanner/src/` returns zero hits. The precedent in `epd.ts:1425-1431` is a per-row for-loop. supabase-js has no client-side transaction primitive; each `.update()` call is its own implicit transaction.
- **Suggested patch:** Lock one of:
  - **(a) RPC route (recommended for atomicity):** phase30 adds:
    ```sql
    CREATE OR REPLACE FUNCTION public.apply_composition_results(
      p_project_id uuid,
      p_run_id text,
      p_updates jsonb  -- [{pdv_id: uuid, factor: numeric}, ...]
    ) RETURNS void AS $$
      UPDATE project_dependency_vulnerabilities pdv
         SET composition_factor = u.factor,
             contextual_depscore = ROUND(pdv.contextual_depscore * u.factor, 4)
        FROM (SELECT (e->>'pdv_id')::uuid AS pdv_id, (e->>'factor')::numeric AS factor
                FROM jsonb_array_elements(p_updates) e) u
       WHERE pdv.id = u.pdv_id
         AND pdv.project_id = p_project_id
         AND pdv.extraction_run_id = p_run_id;
    $$ LANGUAGE sql;
    ```
    composeFindings calls `supabase.rpc('apply_composition_results', { p_project_id, p_run_id, p_updates: [...] })`. Single round-trip, atomic.
  - **(b) Per-row loop route:** composeFindings iterates per PDV: `await supabase.from('project_dependency_vulnerabilities').update({ composition_factor: f, contextual_depscore: existing * f }).eq('id', pdv_id)`. Matches epd.ts pattern but loses atomicity; document partial-failure handling.
- **Recommendation:** (a). The RPC is 15 lines, matches the plan's "single transaction" intent, and the precedent for purpose-built RPCs already exists across phase18b/19_2/22/23_2/24_2/25a.

## P1 — High-Priority Gaps

### Sole-writer invariant has no enforcement test `[SOLO — test-strategy-auditor]`
- **Plan section:** M2 step 2, Step E (`composition.ts is the SOLE writer of composition_factor and the ONLY post-EPD mutator of contextual_depscore. composition.ts header comment documents this invariant.`)
- **Claim:** A comment is documentation, not a regression guard. If a future contributor adds a `contextual_depscore` update in (say) malicious-scan or finalize_extraction, nothing fails. Patch 1's whole premise — "no race, composition is sole post-EPD writer" — rests on this invariant.
- **Suggested patch:** Add `depscanner/src/__tests__/contextual-depscore-writers.test.ts` (~15 lines):
  ```typescript
  test('contextual_depscore is only written by epd.ts and composition.ts', async () => {
    const matches = await grepFromRepoRoot(
      /\.update\(\{[^}]*contextual_depscore/g,
      'depscanner/src/**/*.ts'
    );
    const filesWithWrites = new Set(matches.map(m => m.file));
    expect(filesWithWrites).toEqual(new Set([
      'depscanner/src/epd.ts',
      'depscanner/src/scanners/composition.ts',
    ]));
    // Also verify expected COUNT in epd.ts (4 sites at lines 628, 667, 1318, 1390)
    const epdMatchCount = matches.filter(m => m.file.endsWith('epd.ts')).length;
    expect(epdMatchCount).toBe(4);
  });
  ```
  Documented invariant → enforced invariant. Catches the exact regression the sole-writer comment is meant to prevent.

## P2 — Quality Gaps (selected; ~21 total)

### Implementation detail
| Finding | Section | Claim |
|---|---|---|
| architect-r4-f1 | M2 Step E | VALUES dedup must be explicit — "one VALUES row per pdv_id, with min_factor pre-aggregated in JS." Moot if Patch P0 lands as RPC route. |
| architect-r4-f5 | M2 step 1 | `doComposition` must live inside the `if (!skipOptionalScans)` block at pipeline.ts:162-179 AND early-return if `scannerSummary` is null. Otherwise reachability-corpus harness (DEPTEX_SKIP_OPTIONAL_SCANS=1) hits a needless DB round-trip. |
| architect-r4-f2 | Verified facts §A | DAST v2.1c's `confirm_pdvs_from_dast_run` RPC (`phase25a:117-136`) UPDATEs PDV.reachability_level to 'confirmed' WITHOUT recomputing contextual_depscore. Pre-existing tech debt, not introduced here. **Reword the sole-writer invariant:** "within a given depscanner scan run, after doReachabilityAndEpd, only composition.ts writes contextual_depscore." Acknowledges the DAST out-of-band path. |
| skeptic-r4-f2 | M2 Step E invariant | Sole-writer invariant assumes per-run INSERT pattern; future refactor to UPSERT would silently break composition_factor preservation. Add a TODO comment in epd.ts:applyEpdScoring noting this. |
| skeptic-r4-f5 | Risks #4 | MIN aggregation footgun: when CVE-irrelevant soname is unreachable, suppresses incorrectly (e.g. CVE in libssl path + container libcrypto3 unreachable → MIN picks 0.4 wrongly). **Strengthen Risks #4 wording:** acknowledge as a known false-suppression class; v2 needs CVE→soname mapping (reusable from `reachability-rules/` packs). |
| skeptic-r4-f7 | M2 Step E | "One transaction" claim is unjustified across two tables (INSERT into project_composition_partners + UPDATE on PDV are separate round-trips from supabase-js). Either bundle into the apply_composition_results RPC (Patch P0 option a) or add a consistency counter `pdvs_with_partner_but_no_factor`. |

### Test specificity
| Finding | Section | Claim |
|---|---|---|
| test-r4-multi | M2 step 3/Step E | SQL MIN computation site ambiguous between plan prose (suggests SQL) and JS impl (pre-aggregates). Lock: JS computes MIN; SQL receives pre-folded values. |
| test-r4-onconflict | Data Model | UNIQUE constraint on project_composition_partners but no test for re-run behavior. Either INSERT … ON CONFLICT DO UPDATE OR explicit assertion that re-run of same runId aborts. |
| test-r4-perf | Perf budget | 50-pair fixture is undersized vs realistic 500 PCF × 2000 PDV × 5000 binding scale. Add stress fixture with < 10s budget. |
| test-r4-backfill-name | M2 step 6 | "Backfill invariant" test name doesn't match what it asserts. Rename to "Unpaired-PDV no-write invariant" OR invert the seeding order. |
| architect-r4-f7 | M2 step 5 | Add unit test for irrational-in-binary product (e.g. 1.0 × 0.9 with baseline 33.3333) — confidence check on Number((x).toFixed) rounding direction. |

### Forward-compat hygiene
| Finding | Section | Claim |
|---|---|---|
| opp-r4-f1 | Data Model bindings_evidence | Lock typed shape: `[{ soname, link_method, language_install_path?, os_install_path?, extractor_version }]` (max 20). Document as forward-compat contract. |
| opp-r4-f2 | M1 step 1 | Pre-flight should write committed artifact (`.cursor/plans/iac-container-v2-item-g-preflight.json` with run_date + query + row_count + sample). Per Rev 3 test-r3-f11. |
| opp-r4-f3 | M4 step 2 baseline.json | Record suppression_pct as non-gating drift signal alongside pair-count acceptance. Non-blocking; future regression net. |
| pragmatist-r4-f3 | Data Model | `bindings_evidence JSONB NOT NULL` → make nullable. Best-effort write semantics. |

### Optional scope cuts
| Finding | Section | Claim |
|---|---|---|
| scope-cutter-C1 | Data Model | Drop `bindings_evidence` column entirely (no v1 read path). Forensics can be reconstructed from project_native_bindings join. |
| scope-cutter-C2 | M1 step 8 | Cut 4 of 6 fixtures; keep libssl3 + stripped/whitespace edge. |
| scope-cutter-C4 | M2 step 6 | Cut backfill-invariant test (testing Postgres ADD COLUMN semantics is testing Postgres). |
| scope-cutter-C5 / pragmatist-r4-f6 | Data Model | Drop `idx_pcp_pdv_factor` index (no v1 query reads PCP by factor). |
| scope-cutter-C6 | M4 step 4 | Compress /criticalreview from 5 personas to 3 (composition-correctness, multi-tenancy, regression-hunter). |
| pragmatist-r4-f2 | Data Model | Drop `extractor_version` column (no consumer; phase number + git blame already provide provenance). |

## P3 — Nits & Opportunities

- skeptic-r4-f6 — Off-by-one in plan: "Insert at pipeline.ts:170" — line 170 is `checkCancelled`; real insertion is after line 167/168
- skeptic-r4-f3 — Pair-count acceptance still curated; acknowledge as "smoke gate, not calibration gate" in M4 acceptance language
- skeptic-r4-f4 — "Avoids destructive RPC recreation" framing is misleading (deferred to frontend follow-up, not avoided); reword Patch 5 honestly
- architect-r4-f3, f4, f6 — DROP+CREATE pattern correct, pre-flight SQL valid, multi-partner MIN shape correct (no action)
- opp-r4-f4 — Note that v2 aggregation configurability is read-side only (per-edge factors stored)
- opp-r4-f5 — Confirmed NOT adding separate audit event (join table IS the audit log)
- pragmatist-r4-f1 — composition.ts cohesion OK; keep as one module

## Suggested Plan Amendments (priority order)

### Patch P0 — Lock the supabase-js multi-row UPDATE shape
**Concern:** Plan says shape that supabase-js client can't express.
**Recommended change:** Update M2 step 2 Step E:
> "Apply composed scoring via a single `supabase.rpc('apply_composition_results', { p_project_id, p_run_id, p_updates })` call. phase30 adds the `apply_composition_results(p_project_id uuid, p_run_id text, p_updates jsonb)` PL/pgSQL function (~15 lines) that does the atomic multi-row UPDATE server-side. JS pre-aggregates MIN per PDV and ships an array of `{pdv_id, factor}` rows in `p_updates`."

Also update phase30 migration content to include the new RPC.

### Patch P1 — Add the sole-writer enforcement test
**Concern:** Invariant documented but not enforced.
**Recommended change:** Create `depscanner/src/__tests__/contextual-depscore-writers.test.ts` (~15 lines, grep-based). Asserts only `epd.ts` (4 sites) and `composition.ts` (1 site) write `contextual_depscore` via supabase update. Add as M2 step 8 acceptance criterion.

### Patch P2-A — Lock skipOptionalScans gate
**Concern:** doComposition without scannerSummary null-check wastes round-trips on corpus harness runs.
**Recommended change:** Update M2 step 1: "Insert `doComposition` inside the `if (!skipOptionalScans)` block. composeFindings early-returns if `scannerSummary` is null OR if no PCF rows exist for this runId."

### Patch P2-B — Reword sole-writer invariant
**Concern:** DAST confirm RPC writes reachability_level without recomputing contextual_depscore (pre-existing path).
**Recommended change:** composition.ts header comment + plan §A:
> "Within the depscanner pipeline, after `doReachabilityAndEpd`, only `composition.ts` writes `contextual_depscore`. Out-of-band paths (DAST v2.1c's `confirm_pdvs_from_dast_run` RPC at phase25a:117-136) update `reachability_level` without recomputing `contextual_depscore` — that's pre-existing tech debt, tracked separately."

### Patch P2-C — Strengthen Risks #4 wording
**Concern:** MIN aggregation footgun isn't surfaced honestly.
**Recommended change:** Risks #4: "MIN across partner edges can under-score when the CVE is bound to one soname but the PDV partners with multiple sonames including an unreachable one unrelated to the CVE. The `bindings_evidence` capture makes this auditable. v2 should add CVE→soname mapping (reusable from `reachability-rules/` packs) to gate edges by CVE-relevance."

### Patch P2-D — Lock bindings_evidence shape
**Concern:** No typed contract; foreclosed forensics.
**Recommended change:** Data Model: `bindings_evidence JSONB NOT NULL` with documented shape `[{ soname: string, link_method: 'elf_needed' | 'dpkg_soname', language_install_path?: string, os_install_path?: string, extractor_version: string }]` (max 20 entries). Lock in composition.ts emit logic.

### Optional patches (apply if you want the tightest possible v1)

- Drop `extractor_version` column on project_native_bindings (pragmatist-r4-f2)
- Drop `idx_pcp_pdv_factor` index (pragmatist-r4-f6 / scope-cutter-C5)
- Drop `bindings_evidence` column entirely — keep counters in log instead (scope-cutter-C1; aggressive)
- Cut 4 of 6 soname fixtures (scope-cutter-C2)
- Compress /criticalreview to 3 personas (scope-cutter-C6)

These save ~1 day of work; none block merge.

## Findings by Axis

| Axis | Count | Highest severity |
|---|---|---|
| supabase-js client shape | 1 | P0 |
| Test enforcement (sole-writer invariant) | 1 | P1 |
| Pipeline gating + skipOptionalScans | 1 | P2 |
| Out-of-band reachability writes (DAST confirm) | 1 | P2 |
| MIN aggregation footgun | 1 | P2 |
| Test specificity (multi-partner SQL location, ON CONFLICT, perf, irrational products, backfill name) | 5 | P2 |
| Forward-compat hygiene (bindings_evidence shape, preflight artifact, baseline.json) | 3 | P2 |
| Scope cuts (extractor_version, bindings_evidence column, index, fixtures, /criticalreview) | 6 | P2 |
| Cosmetic (line number, framing, acknowledgments) | 4 | P3 |
| Confirmed-correct (DROP+CREATE, pre-flight SQL, MIN shape) | 3 | P3 |

## Persona Coverage Map

| Persona | R1 findings | R2 +1s | R2 -1s | R2 new | Vote |
|---|---|---|---|---|---|
| skeptic | 7 (1 P0 / 1 P1 / 4 P2 / 2 P3) | — | — | — | REVISE |
| pragmatist | 6 (0 P0 / 0 P1 / 3 P2 / 3 P3) | — | — | — | READY |
| scope-cutter | 6 cuts + 4 keeps (0 P0 / 0 P1 / 5 P2 / 1 P3) | — | — | — | READY |
| architect | 7 (0 P0 / 0 P1 / 4 P2 / 3 P3) | — | — | — | READY |
| test-strategy-auditor | 5 (0 P0 / 1 P1 / 4 P2) | — | — | — | REVISE |
| opportunity-scout | 5 (0 P0 / 0 P1 / 3 P2 / 2 P3) | — | — | — | READY |

## Recommended Next Step

**Apply Patches P0 + P1 + P2-A + P2-B + P2-C + P2-D (~30 minutes of plan text editing) → `/create-worktree iac-container-v2-item-g` → `/implement`.**

Skip the optional scope cuts unless you want the tightest possible v1.

The patches:
1. **P0 (supabase-js shape)**: add `apply_composition_results` RPC to phase30; rewrite M2 step 2 Step E to call it
2. **P1 (sole-writer test)**: add ~15-line grep-based test; new M2 step 8
3. **P2-A (skipOptionalScans gate)**: add early-return in doComposition
4. **P2-B (sole-writer wording)**: acknowledge DAST out-of-band path
5. **P2-C (Risks #4)**: strengthen MIN aggregation footgun honesty
6. **P2-D (bindings_evidence shape)**: lock the typed contract

After patches: no P0, no P1, only P2/P3 polish. Expected re-review verdict: READY.

If you want to skip re-review and just ship: the patches are small enough that you could confidently apply them and go straight to `/create-worktree`. The remaining P2/P3 items will surface naturally during `/implement` and the /criticalreview pass in M4.

# Plan Review v2 — billing-prepaid-rewrite

**Verdict: REVISE** (patches mostly landed clean; 2 multi-persona regressions introduced by v1-patches need a focused 2nd patch round)

Plan reviewed: `.claude/worktrees/billing-prepaid-rewrite/.cursor/plans/billing-prepaid-rewrite.plan.md` (v2; patched 2026-05-22 mtime 12:08)
Previous review: `.cursor/plans/review-billing-prepaid-rewrite.md` v1 (REVISE; 11 P0 + 25 P1)
Mode: lean (8 personas, no debate)
Personas: skeptic, pragmatist, scope-cutter, architect, test-strategy-auditor, opportunity-scout, data-model-auditor, migration-safety-auditor
Vote tally: 0 READY / 6 REVISE / 2 REWORK (identical pattern to v1)
Findings: **12 P0** critical / **19 P1** high / **22 P2** medium / **21 P3** low (94 actionable)

> **Self-disclosure:** Two of the v2 P0s (cluster #1 broken §1 SQL, partial of cluster #2 phantom BILLING_DOUBLE_WRITE env var) are regressions I introduced when writing the v1 patches. These aren't in the original plan; they came from the patch round. Acknowledged + concrete fixes below.
>
> **Verdict downgrade rationale (same as v1):** Per strict rule, ≥2 REWORK votes triggers REWORK. Verdict is downgraded to REVISE because (a) every P0 has a concrete `suggested_patch`, (b) all six REVISE rationales explicitly call the P0s patchable, (c) both REWORK rationales describe fixes ("kill-switch logic clarification," "commit to one cutover path") not redesign. If a second patch round still leaves cluster #1 or #2 unresolved, escalate to REWORK + re-`/plan-feature`.

## Summary

v2 closed the v1 P0/P1 surface broadly: route-mount path-param fixed, e2e uses real depscanner, concurrent-race test uses 2 pg pools with anti-test, trigger has dedup guard + partial unique invariant, no-tier CI grep guard exists, webhook handler wraps idempotency + credit in a single transaction. Architect-f1/f3/f4/f5 all explicitly resolved. Pragmatist/scope-cutter took 9 of 10 Group B cuts.

**What v2 broke:** (a) The §1 PRE-MIGRATION BACKFILL SQL block is dead-but-runnable INSERTs before the CREATE TABLE — the migration aborts on first apply (4 personas independently caught this). (b) M11.3 contains a 5-line hedge admitting the "atomic-cutover via Supabase branch" claim may degrade to a 10-min downtime window at impl time, plus references a phantom `BILLING_DOUBLE_WRITE` env var that's never defined elsewhere. (c) The kill-switch C1 design is internally inconsistent: when `enforcement=off`, ledger rows insert but `deduct_balance` is skipped, which makes `assert_balance_matches_ledger()` provably non-empty during the soak — M11.8's "flip when clean" gate is unfireable as written. (d) `MAX_AEGIS_TURN_ESTIMATE_CENTS=500` exactly equals the $5 signup grant — first Aegis turn passes with 0¢ headroom, and any prior 1¢ scan deduction breaks the wedge.

**What to do:** Apply the Round-2 Group A patches (5 mandatory fixes, all <30 min each) and proceed to `/implement`. Group B in this round is 7 P1 polish items that can land in /implement or be deferred without blocking. **Strongly recommend NOT running a third review round** — we're in diminishing-returns territory and each patch round risks introducing new regressions. The remaining gaps are exactly what `/criticalreview` post-impl catches better than another plan review.

---

## Vote Tally

| Persona | Vote | Top concern | Rationale |
|---|---|---|---|
| skeptic | **REWORK** | skeptic-v2-f3 kill-switch logic | Self-defeating kill-switch + broken §1 SQL + MAX_AEGIS gate exactly equal to grant = structural defects, not polish. Patches needed before /implement. |
| pragmatist | REVISE | cluster-2 M11.3 | All P0s are one-paragraph fixes; direction is right; M2+M6 collapse and dropping `billing_pending_payment_intents` are nice-to-have P1s. |
| scope-cutter | REVISE | billing_pending_payment_intents | Drop the C9 table — Stripe idempotency keys + ledger already cover dedup. Surface area still too wide. |
| architect | REVISE | cluster-1 broken SQL | Two architectural P0s (broken SQL, cutover contradiction) + JSONB-vs-positional convention to document. Design pattern (double-entry + sole-writer RPC) is sound. |
| test-strategy-auditor | REVISE | test-strategy-v2-f1 anti-test | 4 concrete test gaps: anti-test not CI-runnable, webhook TOCTOU + cross-tenant uncovered, pending_pi has no rollback/concurrent/unknown-purpose tests, kill-switch tests too shallow. |
| opportunity-scout | **REWORK** | cluster-2 M11.3 | Cutover-seam ambiguity + phantom env var + kill-switch dead-end + broken SQL = three load-bearing impl-time decisions. Pre-launch zero-user is the cheapest window to commit the design. |
| data-model-auditor | REVISE | data-model-v2 unit/quantity CHECK | Two data-shape bugs (§1 ordering, kill-switch invariant) + missing cross-column CHECK on unit/quantity pairing. Schema design (double-entry + sole-writer RPC) is sound. |
| migration-safety-auditor | REVISE | migration-safety-v2-f3 branch drift | Three migration P0s all fixable in same PR: §1 deletion, M11.3 commitment, Supabase-branch drift risk — recommend committing to 10-min downtime window for pre-launch. |

---

## P0 — Fundamental Concerns (12)

### Multi-persona cluster #1: Broken §1 PRE-MIGRATION BACKFILL SQL `[CONSENSUS 4/8]`
Flagged independently by **skeptic-v2-f1, architect-v2-f5, data-model-auditor-v2-f1, migration-safety-auditor-v2-f1.**
- **Plan section:** Data Model §1 PRE-MIGRATION BACKFILL (lines 173-185)
- **Claim:** §1 contains runnable `INSERT INTO organization_billing ... ON CONFLICT (organization_id) DO UPDATE` BEFORE `CREATE TABLE organization_billing` in §2 (line 192). The trailing line 185 comment "Backfill block moves to after CREATE TABLE; this comment is intent-level" acknowledges the bug but the actual SQL above it is uncommented and will execute. The §3 backfill (lines 311-323) is the correct one. On apply, Postgres raises `relation "organization_billing" does not exist` and the migration aborts.
- **Suggested patch:** Delete lines 173-186 entirely. The §3 block at lines 311-323 already handles backfill correctly post-CREATE TABLE. Replace §1 with a single comment if anything: `-- §1 deferred to §3 (after CREATE TABLE)` or just renumber.
- **Source:** My patch A2 introduced this bug. Mea culpa.

### Multi-persona cluster #2: M11.3 atomic-cutover contradiction `[CONSENSUS 4/8]`
Flagged by **skeptic-v2-f2, architect-v2-f8, pragmatist-v2-f7, migration-safety-auditor-v2-f2.**
- **Plan section:** M11.3 (lines 1176-1179) vs Overview line 22 + Patch log line 16
- **Claim:** M11.3 says "Realistically: pre-launch, the simpler answer is to schedule a 10-min downtime window for the migration to apply and accept the interruption. Document the chosen path here at impl time." This directly contradicts Patch A3's promise of "atomic-cutover via Supabase branch" (Overview line 22, patch log line 16). Plan defers the decision to impl time, then invents a phantom `BILLING_DOUBLE_WRITE` env var that's referenced nowhere else and never defined in Dependencies.
- **Suggested patch:** Pick one path now and rewrite M11.3 to commit:
  - **Option A (recommended):** Commit to 10-min downtime window for pre-launch zero-user state. Drop the Supabase-branch language from Overview + patch log. M11 becomes: maintenance mode → apply migration via MCP → deploy code → smoke test → drop maintenance.
  - **Option B:** Commit to merge_branch path. Specify: deploy with `DEPTEX_BILLING_ENFORCEMENT=off` AND make new code tolerant of "table does not exist" via try/catch + 503 fallback (extend architect-f5 pattern). Add explicit test for "tables-not-yet-migrated" state.
- Delete the `BILLING_DOUBLE_WRITE` reference unless actually wired.

### skeptic-v2-f3: Kill-switch C1 design self-defeating `[SOLO]`
- **Plan section:** Kill-switch C1 semantics (line 105) + M11.8 soak gate (lines 1200-1203) + ledger.test.ts coverage (line 934)
- **Claim:** Line 105 says when enforcement=off, `recordMeterEvent` "log + insert ledger rows but skip the deduction/gate." That means `usage_deduction` rows are inserted with negative `amount_cents` while `organization_billing.balance_cents` is NEVER updated. After 1 week of dogfood, `assert_balance_matches_ledger()` reports drift on EVERY active org by design. M11.8 says "If clean: flip; if drift: investigate." The gate is unfireable as written.
- **Suggested patch:** Pick one of three coherent kill-switch designs:
  - **(a) Shadow ledger** — when enforcement=off, insert `usage_deduction` row AND a paired positive `shadow_adjustment` row (new transaction kind). Invariant holds. At flip-on time, delete `shadow_adjustment` rows in one transaction; balances become real.
  - **(b) No-write** — when enforcement=off, skip the ledger row entirely. M11.8's metric becomes "no Sentry billing alerts during soak" rather than ledger invariant.
  - **(c) Full deduct + reset** — always deduct; pre-launch reset balances to $5+ at flip-on time. Simplest.
- Recommend (b) for pre-launch; (c) for post-launch if needed.

### skeptic-v2-f4: MAX_AEGIS_TURN_ESTIMATE_CENTS exactly = signup grant `[SOLO]`
- **Plan section:** C2 pre-stream gate + MAX_AEGIS_TURN_ESTIMATE_CENTS (lines 797, 1060) + signup_grant (lines 322, 466)
- **Claim:** Both are 500¢. Pre-flight gate requires `balance >= 500` — passes by exactly 0¢ on the FIRST Aegis turn of a fresh org. Any prior 1¢ scan tips the balance to 499 and the gate rejects with 402 BEFORE the user can send their first Aegis message. Breaks the entire $5-free-credit wedge. Also: a 200k-context Opus 4.7 turn at 2x markup ≈ 720¢ charged, so 500¢ is too LOW to actually gate Opus overruns.
- **Suggested patch:** Pick one:
  - **(a)** Raise signup grant to $10 (1000¢) so the gate has headroom.
  - **(b)** Drop the pre-flight gate for Aegis entirely; accept post-stream CHECK abort + Sentry log.
  - **(c)** Make `MAX_AEGIS_TURN_ESTIMATE_CENTS` a function of selected model (Opus=800¢, Sonnet=200¢, Haiku=50¢); default fresh orgs to Haiku until first top-up. **Recommended** — preserves gate semantic AND wedge economics.

### test-strategy-v2-f1: Anti-test for FOR UPDATE removal is local-only `[SOLO]`
- **Plan section:** M2.1 concurrent-deduct race test
- **Claim:** A6 mandated an anti-test (remove FOR UPDATE, confirm test fails) "to know the test has teeth." v2 landed the anti-test as "Run once locally; document outcome in test comment" — NOT CI-runnable. A future refactor silently removing FOR UPDATE could leave the M2.1 test passing forever (because two clients at low contention still serialize at the driver).
- **Suggested patch:** Convert to a CI-runnable mutation test: ship `billing-foruupdate-mutation.test.ts` that creates a temporary `deduct_balance_no_lock` RPC (verbatim copy minus FOR UPDATE), runs the same 2-pool race against it, asserts double-spend observable in N=20 trials. DROP the temp RPC in afterAll. CI now proves BOTH branches: with-lock = no race; without-lock = race observable.

### test-strategy-v2-f2: Webhook tests miss TOCTOU concurrent + cross-tenant PI mismatch `[SOLO]`
- **Plan section:** M5.5 route tests + Patch A10
- **Claim:** A10 demanded FIVE webhook test categories: duplicate event_id, TOCTOU race within ms, out-of-order, missing metadata.purpose, cross-tenant PI/Customer mismatch. v2's M5.5 covers (1) and (3) and (4-via-C9-rewrite). Missing: (2) actually concurrent two-webhook race (the single-transaction test asserts the pattern but doesn't fire two handlers concurrently); (5) cross-tenant (PI metadata says org A but Customer is bound to org B).
- **Suggested patch:** Add to `billing-stripe-webhooks.test.ts`:
  - **TOCTOU:** Fire two `payment_intent.succeeded` handlers in `Promise.all` with same event_id; assert exactly one ledger row + one webhook_events row.
  - **Cross-tenant PI:** INSERT pending row for orgA with PI=pi_X; webhook for pi_X but pi.customer is orgB's stripe_customer_id; assert handler rejects + Sentry-logs + marks event processed.

### test-strategy-v2-f3: billing_pending_payment_intents under-tested `[SOLO]`
- **Plan section:** C9 + M5.5 + M3.1
- **Claim:** C9 added the table but M5.5 only mentions "pending row missing → log + Sentry." Three failure modes missing: (a) topup endpoint creates Stripe PI but pending-row INSERT fails → topup returns success while pending row is missing; (b) duplicate concurrent top-ups racing the pending-row INSERT; (c) unknown `purpose` value (e.g. typo or future enum) → CHECK aborts INSERT → orphan PI in Stripe forever.
- **Suggested patch:** Add tests + the rollback pattern: if pending-row INSERT throws, `paymentIntents.cancel(piId)` in the catch block, then rethrow. Ensures Stripe state doesn't drift from our state.

### test-strategy-v2-f4: Kill-switch tests too shallow `[SOLO]`
- **Plan section:** M1.5 + M1.7
- **Claim:** M1.5 lists only 3 trivial tests for the boolean helper. Missing: (a) `enforcement=off + sufficient balance: recordMeterEvent returns deducted:false but row IS inserted` (depending on Patch B chosen for skeptic-f3); (b) `enforcement=off + zero balance: NOT blocked`; (c) `enforcement=on + sufficient: full deduction`; (d) canCharge returns correct shape in all enforcement states.
- **Suggested patch:** Expand M1.7 enforcement tests per the kill-switch design picked in skeptic-f3.

### migration-safety-v2-f3: Supabase branch can drift from prod `[SOLO]`
- **Plan section:** M1.1 + M11.4
- **Claim:** `mcp__claude_ai_Supabase__merge_branch` REPLAYS migrations, not atomic-applies. If any unrelated migration lands on prod between branch creation (M1.1) and merge (M11.4), the replay can partially fail or produce a different end-state. The committed schema.sql will mismatch live prod, breaking the CI `schema-check.yml` gate on the next PR.
- **Suggested patch:** Resolves via cluster-2 patch (commit to 10-min downtime + direct `apply_migration` to prod). Branch-based cutover adds drift surface without benefit for pre-launch zero-user state.

---

## P1 — High-Priority Gaps (19)

Grouped by axis. Each row: `[finding-id] section — claim → patch`.

### Architecture
- **[architect-v2-f6] Trigger race during cutover window** — WHERE NOT EXISTS + partial unique races when backfill SELECT and trigger INSERT both pass simultaneously; the second hits unique violation, aborts the org INSERT silently. **Patch:** Wrap trigger INSERT in `BEGIN ... EXCEPTION WHEN unique_violation THEN NULL; END;` block.
- **[architect-v2-f7] C9 pending-row race for off-session auto-recharge** — `createPaymentIntent(off_session=true)` can fire `payment_intent.succeeded` BEFORE our INSERT into billing_pending_payment_intents commits. Webhook then sees no pending row → either crashes or treats as fallback. **Patch:** INSERT pending row BEFORE `paymentIntents.create()` (with placeholder PI ID), UPDATE with real PI ID after.
- **[architect-v2-f9] JSONB metadata RPC departs from positional convention** — `deduct_balance(p_event_metadata JSONB)` extracts 13 typed fields via `->>` casts that NULL-or-throw on malformed keys. **Patch:** Document the convention departure in "Patterns to follow" + ensure ledger.ts tests cover malformed JSONB.

### Scope-cutter cluster
- **[scope-cutter-v2-f2 / pragmatist-v2-f1] Drop billing_pending_payment_intents (C9)** — overengineered for pre-launch zero-user. Stripe metadata is reliable. Recommend reverting C9 and using `metadata.purpose` directly. Removes 1 table, 2 lifecycle states, an entire test-coverage class. **Patch:** Revert C9; restore metadata.purpose path; add v1.1 backlog item if metadata-loss is ever observed.
- **[scope-cutter-v2-f7] Collapse M2+M6 into M5/M10** — Test-only milestones don't need separate gates. Net: 11 → 9 milestones. **Patch:** Cosmetic; can be done at /implement.

### Test coverage
- **[test-strategy-v2-f5] Rounding policy ambiguous** — C7's "1000 × 0.6¢ = 600¢" test doesn't cover the 0.5-cent boundary (banker's rounding vs round-half-up). **Patch:** Add `deduct(0.5)`, `deduct(1.5)`, `deduct(0.4)` tests + document banker's rounding in pricing.ts JSDoc.
- **[test-strategy-v2-f6] assert_balance_matches_ledger not gated at CI** — Success Criterion #2 unenforced. **Patch:** Create `backend/vitest.globalTeardown.ts` that calls the function and throws on drift; wire via vitest.config.ts.
- **[test-strategy-v2-f7] MAX_AEGIS_TURN_ESTIMATE_CENTS pathological case** — fresh org with $5 balance + Opus 200k-context turn at $20 charged → orphan meter event with no ledger row. **Patch:** Add `kind='deduction_skipped_insufficient'` ledger row when deduct_balance returns NULL; reconciliation tracks total eaten cost.
- **[test-strategy-v2-f8] No-tier CI grep guard incomplete** — missing `requirePlanLimit`, `requirePlanFeature`, `getOrgPlan`, `getUsageSummary`, `getFeatureAccess`, `invalidatePlanCache`, `TIER_DISPLAY_NAMES`, `FEATURE_REQUIRED_TIER`, `recordActualCost`, `checkMonthlyCostCap`, `checkBillingPermission`. **Patch:** expand the forbidden list per the M6.2 patch.

### Skeptic (carried from v1 + new)
- **[skeptic-v2-f5] assert_balance_matches_ledger CI claim unwired** — same as test-strategy-v2-f6.
- **[skeptic-v2-f10] M11.8 observability of soak missing** — no Slack/email cron during 7-day soak; Henry will forget on day 3. **Patch:** Schedule QStash daily cron that calls assert_balance_matches_ledger() and posts to Slack/email with drift status. If drift=$0 for 7 days, auto-flip enforcement on (or email Henry to flip).
- **[skeptic-v2-f11] Mid-action cost blowup unbounded** — `[500, 720)` balance range can extract a single Opus turn that costs more than the user paid. Pre-launch with ~1 user this is theoretical, but unbounded at any scale. **Patch:** Either tighten gate to actual Opus worst-case (~800), OR carve grant_balance from real_balance (track separately), OR add Risk row documenting the bounded exposure.

### Pragmatist (still relevant)
- **[pragmatist-v2-f3] Kill-switch wiring scattered** — `isBillingEnforcementEnabled()` checks in multiple places. **Patch:** Centralize in `ledger.ts` only (recordMeterEvent + canCharge); routes/Aegis/workers never check.
- **[pragmatist-v2-f6] Loadtest gating merge is over-engineered** — p99 target is decoration without prod calibration. **Patch:** Downgrade from "gates merge" to "report in PR description; hand-investigate regressions > 2x baseline."

### Data-model
- **[data-model-v2-f2] JSONB RPC type safety** — same as architect-v2-f9. **Patch:** Either revert to positional params OR add Zod validation in ledger.ts + EXCEPTION block in plpgsql.
- **[data-model-v2-f4] Cross-column CHECK on unit/quantity pairing** — `event_type='worker_minutes' + unit='input_tokens'` passes today. **Patch:** Add table-level CHECK that pairs unit with event_type.
- **[data-model-v2-f5] auto_recharge_in_progress + _started_at pairing not enforced** — drift case: `in_progress=false + started_at=stale_timestamp`. **Patch:** Add CHECK constraint pairing them.

### Migration safety
- **[migration-safety-v2-f4] subscription_tier CHECK is not idempotent across future migrations** — see C10 patch. **Patch:** Wrap with `DROP CONSTRAINT IF EXISTS` first; or wrap whole phase37 in explicit BEGIN/COMMIT.
- **[migration-safety-v2-f5] billing_pending_payment_intents unbounded growth** — no GC story. **Patch:** Resolved if C9 reverted (scope-cutter-v2-f2). Otherwise: add `DELETE WHERE resolved_at < NOW() - INTERVAL '30 days'` to reconcile script.
- **[migration-safety-v2-f6] Trigger visibility during cutover** — if code deploys before migration applies, `credit_balance` RAISEs on missing billing row. **Patch:** Resolves via cluster-2 (commit to one cutover ordering). Plus: soften the RAISE in `credit_balance` to log+auto-create-row+Sentry instead of hard-RAISE — reverts the over-correction from v1 migration-safety-f6.
- **[migration-safety-v2-f7] schema.sql post-merge drift handling** — if Supabase branch is older than 7 days at merge time, schema.sql may include unrelated parallel-PR migrations. **Patch:** Resolves via cluster-2 (commit to direct apply). Otherwise: add M11.4a "if diff is non-phase37, open immediate follow-up chore PR with refreshed dump."

---

## P2 — Quality Gaps (22)

Truncated for length. Key themes:
- `output_quantity` column has no v1 consumer (could be dropped per scope-cutter-v2-f5)
- Stripe webhook tests miss several malformed-payload categories
- `billing_pending_payment_intents` cleanup missing
- `stripe_default_payment_method_id` drift handling needs lazy Stripe-API self-heal in `getBalance`
- Big-number "Spend this period" summary on Usage screen could be dropped (scope-cutter-v2-f4)
- E2E step 9 only tests happy-path concurrency, not boundary case
- 8 other minor data-integrity / observability items

---

## P3 — Nits & Opportunities (21)

10 opportunity-scout findings (all P3, axis=opportunity):
- Boot-time Slack/email when enforcement-state changes
- Internal `GET /ledger-health` endpoint exposing `assert_balance_matches_ledger()`
- billing_pending_payment_intents captures top-up latency for free (free SLO metric)
- `--alert-on-drift` flag on reconcile script
- Mobile-responsive design unlocked by 4-component frontend (cheap)
- `stripe_receipt_url` link from receipt HTML (~1h, unlocks VAT/expense)
- Soak-preview SQL query during kill-switch enforcement-off window
- Aegis silent-loss Redis counter (~5 LOC, seeds v1.1 telemetry)
- Pre-stage chart data in v1 API (free for v1.1 chart frontend)
- signup_grant created_at is the canonical "real activated org" timestamp

11 architect/data-model/skeptic P3s:
- Drop the `NULL` from `attribution_resource_type IN (...)` literal list (no-op SQL)
- Document banker's rounding in deduct_balance COMMENT
- Drop `subscription_tier` CHECK constraint or broaden to `^[a-z_]+$` (skeptic-v2-f7 vs data-model-v2-f6 — they disagree; keep COMMENT regardless)
- Acknowledge credit-expiry deferred-revenue liability as v1.1 Risk row
- Add `machine_uptime_seconds` column to capture worker cold-boot economics for v1.1 measurement
- Several documentation-only items

---

## Suggested Plan Amendments

### Group A — Mandatory (must land before /implement)

**A1.** Delete lines 173-186 of phase37 SQL (the broken §1 PRE-MIGRATION BACKFILL). §3 already does it correctly. Single edit, ~30 seconds.

**A2.** Rewrite M11.3 to commit to one cutover path:
```
M11.3 — Cutover sequence (atomic, pre-launch zero-user state):
   a. Enable Fly maintenance mode on backend + workers (returns 503).
   b. Apply phase37 migration to PROD via mcp__claude_ai_Supabase__apply_migration (NOT via merge_branch).
   c. Wait for migration to complete (~30s).
   d. Merge PR → Vercel + Fly auto-deploy new code.
   e. Drain maintenance mode.
   f. Smoke test (M11.7).
   g. M11.8 1-week soak with DEPTEX_BILLING_ENFORCEMENT=off (kill-switch design clarified per Patch A3).
```
Delete: the Supabase-branch language from Overview + Patch log + Dependencies; phantom `BILLING_DOUBLE_WRITE` env var (not wired); `merge_branch` from M11.4.

**A3.** Clarify kill-switch C1 semantics. Recommended: enforcement=off skips BOTH the deduct_balance call AND the ledger row insert. M11.8 success metric changes from "ledger invariant clean" to "no Sentry billing errors during soak." Rewrite M1.6 line 105:
```
When enforcement=off, recordMeterEvent logs (console.info) + returns { deducted: false, newBalance: null } without inserting any DB row.
When enforcement=on, recordMeterEvent inserts ledger row + calls deduct_balance + handles result.
```

**A4.** Fix MAX_AEGIS_TURN_ESTIMATE_CENTS:
```
Default model for fresh orgs (subscription_tier IS NULL AND no successful topup): Haiku.
Per-model estimate: { 'claude-haiku-*': 50, 'claude-sonnet-*': 200, 'claude-opus-*': 800, 'gemini-*': 100 } cents.
Pre-flight gate passes if balance_cents >= per-model-estimate.
```

**A5.** Wire `assert_balance_matches_ledger()` to CI. Add `backend/vitest.globalTeardown.ts` that calls it and throws on drift. Reference in M2.3 + Success Criteria #2.

### Group B — Recommended (take or defer)

- **B1.** Revert C9 — drop `billing_pending_payment_intents`. Use Stripe metadata.purpose. (scope-cutter-v2-f2 + pragmatist-v2-f1)
- **B2.** Convert M2.1 anti-test to CI-runnable mutation test. (test-strategy-v2-f1)
- **B3.** Expand no-tier CI grep guard with 11 missing identifiers. (test-strategy-v2-f8)
- **B4.** Add webhook TOCTOU + cross-tenant PI tests. (test-strategy-v2-f2)
- **B5.** Add cross-column CHECK on event_type ↔ unit pairing. (data-model-v2-f4)
- **B6.** Add `auto_recharge_in_progress` + `_started_at` pairing CHECK. (data-model-v2-f5)
- **B7.** Soften `credit_balance` no-billing-row case from RAISE to log+auto-create. (migration-safety-v2-f6)

### Group C — Polish (defer to /implement or v1.1)

- **C1.** Centralize kill-switch wiring in `ledger.ts` only.
- **C2.** Downgrade loadtest from "gates merge" to "reports in PR description."
- **C3.** Document JSONB-vs-positional RPC convention departure.
- **C4.** Several opportunity-scout items worth small inline adds (boot-time Slack on enforcement change, internal `/ledger-health` endpoint, `--alert-on-drift` flag).
- **C5.** All P2/P3 items.

---

## Recommended Next Step

**Apply Group A (5 mandatory patches) → `/implement billing-prepaid-rewrite`.**

Concrete sequence:
1. Open `billing-prepaid-rewrite.plan.md`.
2. Apply **Group A** patches A1-A5 in place.
3. Optionally apply **Group B** patches B1-B7 (recommended; ~15 min each).
4. Skip Group C — let `/implement` and `/criticalreview` handle the residual P2/P3 surface.
5. **Do NOT re-run `/review-plan`** — we're in diminishing-returns territory. Two consecutive rounds of "REVISE with patches that introduce new regressions" suggest the next round will find ~10 more findings, mostly P2/P3, while not closing the residual ambiguity any better than `/criticalreview` would post-implementation.
6. Run `/implement billing-prepaid-rewrite`.

**Why not READY:** Cluster #1 (broken SQL) is a real bug that will literally abort the migration. Cluster #2 (cutover contradiction) will burn implementation time on a decision the plan should commit. These are 5-minute fixes blocking READY.

**Why not REWORK:** The plan's core architecture (in-house Postgres ledger + double-entry + sole-writer RPC + atomic FOR UPDATE + Stripe PI + auto-recharge + kill-switch concept) is sound. Both REWORK voters describe FIXES not REDESIGN. The 12 P0s aggregate to maybe 4 hours of focused editing.

---

## Cross-references

- v1 review: `.cursor/plans/review-billing-prepaid-rewrite.md` (overwritten by this file — committed in plan history if needed)
- Feature brief: `.cursor/plans/feature-brief-billing-prepaid-rewrite.md`
- Plan: `.cursor/plans/billing-prepaid-rewrite.plan.md`
- [[feedback_two_phase_migration_pattern]] — relevant to cluster-2 cutover decision
- [[feedback_schema_dump_rebase]] — relevant to migration-safety-v2-f7
- [[feedback_apply_migrations_via_mcp]] — relevant to cluster-2 (apply_migration vs merge_branch)
- [[feedback_brief_grep_verify]] — drives the CI grep guard expansion in B3

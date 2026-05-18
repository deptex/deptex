# Feature Brief — Reachability Phase 4: EPD Wiring + Gap Closure

> **Historical context (2026-05-09):** This archived plan was authored when AI was BYOK (per-org customer keys via `organization_ai_providers` + AES-256-GCM envelope). BYOK was retired in `phase29_drop_byok.sql` / commit `6705149`. The references to BYOK, `organization_ai_providers`, `encryption.ts` for AI keys, monthly BYOK budget caps, and `AI_ENCRYPTION_KEY` for AI key envelopes are historical only — current AI runs on platform keys.

## Feature Name & One-liner

**Phase 4: EPD Contextual Scoring (Wired)** — Activate the existing `applyEpdScoringFallback()` in the pipeline, plug the entry-point gaps Phase 3 left open, surface the contextual factors in the vulnerability UI, and let org admins set their own AI cost cap.

## Problem Statement

Phase 3 just shipped per-CVE Semgrep taint rules that promote matching vulns to `confirmed` reachability. That's a binary upgrade — but it leaves every confirmed vuln scoring identically regardless of *where the vulnerable code is reached from*. A `confirmed` lodash template-injection in a public unauthenticated HTTP route handler scores the same as the same CVE in an internal cron job that no attacker can hit. EPD (Exploitable Path Dominance) exists to multiply the reachability score by an entry-point weight × path-depth decay, producing a `contextual_depscore` that meaningfully separates "drop-everything" from "schedule for next sprint."

The blocker isn't the scoring math — `epd.ts` (~760 lines) implements all of it: BYOK Anthropic verification, source snippet extraction, sanitization detection, $3/run budget cap, structured JSON output, conservative `PUBLIC_UNAUTH` fallback when no BYOK. The function is just **commented out at `pipeline.ts:1726`**. Two reasons it can't simply be uncommented:

1. **Phase 3 taint flows write `entry_point_tag: null`** at `pipeline.ts:1586`. EPD's heuristic classifier (`classifyFallbackEntryPoint`) reads `entry_point_tag` strings and routes on substrings like `'http'`, `'route'`, `'worker'`. A null tag falls through to `AUTH_INTERNAL` (weight 0.5), which understates risk for the very vulns Phase 3 was built to highlight.
2. **`project_entry_points` (Phase 2 framework detectors) is not joined** to the flow context EPD reads. The taxonomy is there — Express routes, FastAPI handlers, cron jobs, etc. — but EPD never sees it.

Until those gaps close, EPD's heuristic path is unreliable enough that wiring it produces silently-wrong contextual scores. AI verification covers it for orgs with BYOK, but not for the no-BYOK majority.

## Competitive Landscape

| Vendor | EPD-equivalent | UI surface |
|---|---|---|
| **Snyk** | "Priority Score" (0-1000, opaque formula) | Hover-card lists contributing factors: "Reachable: +200", "Exploit Maturity: +150" |
| **Endor Labs** | "Function reachability + EPSS-aware risk" | Named entry point in vuln row: "reachable from public endpoint at `routes/api.ts:42`" |
| **Socket** | Supply-chain risk only — no data-flow EPD | N/A |
| **Semgrep SC** | Binary reachable/unreachable — no contextual factor | N/A |

**Pattern:** vendors who do contextual scoring also *name the entry point* in the UI. Don't bury the multiplier as a number. Phase 4 adopts the **Endor pattern** — entry-point badge per vuln row, color-coded by risk weight — without (yet) the full Snyk-style factor breakdown panel. That's an explicit scope choice, not an oversight; the factor breakdown is a candidate for a later UX pass once we see real adoption.

## User Stories

- **As a security engineer**, I want vulns sorted by `contextual_depscore` (already wired), so the riskiest items surface first regardless of CVSS noise.
- **As a security engineer**, I want a glance-level signal of whether a `confirmed` vuln is reachable from a public unauth endpoint vs. an internal worker, so I can skip ones that aren't actually exploitable from outside.
- **As an org admin** with BYOK Anthropic configured, I want to cap EPD AI spend per extraction so a runaway scan doesn't blow my Anthropic bill.
- **As an org admin without BYOK**, I want EPD to still work in heuristic mode (no AI calls), surfacing a conservative contextual score with appropriate UI disclosure that AI verification was skipped.

## Data Model

**No new tables. One new column.**

```sql
-- backend/database/phase24_epd_org_settings.sql
ALTER TABLE organizations
  ADD COLUMN IF NOT EXISTS epd_max_run_cost_usd NUMERIC(6,2);
COMMENT ON COLUMN organizations.epd_max_run_cost_usd IS
  'Per-extraction EPD AI spend cap in USD. NULL falls back to EPD_MAX_RUN_COST_USD env var (default $3.00). Max enforced server-side at $20.';
```

**No schema change to `project_reachable_flows`** — the gap is wiring, not schema. We populate the existing `entry_point_tag TEXT` column for taint-rule flows.

`use_ai_augmentation` org toggle is **deferred** — chose "run AI when BYOK present, no toggle" in Round 3. Add later if anyone asks.

## API Endpoints

| Method | Route | Auth | Permission | Description |
|---|---|---|---|---|
| `PATCH` | `/api/organizations/:orgId/ai-settings` | `authenticateUser` | `manage_organization_settings` | Add `epd_max_run_cost_usd` to existing AI settings handler. Server-side clamp 0.10–20.00. |
| `GET` | `/api/organizations/:orgId/ai-settings` | `authenticateUser` | `view_ai_spending` | Existing endpoint — extend response to include `epd_max_run_cost_usd`. |

Existing AI settings route lives in `backend/src/routes/organizations.ts` (find via grep on `model_preference`). No new route file needed.

## Frontend Views

**One existing component extended, one new badge component:**

1. **`frontend/src/components/settings/AIConfigurationSection.tsx`** — add a new field below the BYOK provider config: "EPD AI cost cap per extraction" with a number input (default placeholder: $3.00). Disabled unless BYOK is configured. Subtitle: "Maximum spend on AI verification per repository scan. Lower = cheaper but less precise contextual scoring."

2. **`frontend/src/components/security/EntryPointBadge.tsx`** (new) — a small inline badge component:
   ```
   PUBLIC_UNAUTH  → 🔓 Public          (red,    bg-red-500/10 text-red-400)
   AUTH_INTERNAL  → 🔐 Authenticated   (amber,  bg-amber-500/10 text-amber-400)
   OFFLINE_WORKER → ⚙️  Background      (gray,   bg-foreground-secondary/10)
   UNKNOWN        → (no badge — render nothing)
   ```
   Tooltip explains the classification + lists the EPD status (`ai_verified`, `byok_missing`, `ai_error_fallback`, `budget_exceeded`, `fallback_no_ai`).

3. **`VulnerabilityExpandableTable.tsx`** — render `<EntryPointBadge classification={v.entry_point_classification} status={v.epd_status} />` next to the depscore badge in each reachable vuln row. No badge for `unreachable` vulns.

Apply the same badge in **`VersionSidebar.tsx`** vulnerability list (already references `contextual_depscore`).

**Design constraints** (per `feedback_vercel_typography.md` + `feedback_button_style.md`):
- Badge text at full contrast, not opacity-dimmed
- Use bordered pill style consistent with existing severity badges
- Tooltip via existing `<Tooltip>` primitives, no new dependency

## User Flows

### A. New extraction (BYOK present)
1. Worker runs Phase 3 reachability_rules → produces `confirmed` vulns with `entry_point_tag` derived from Semgrep `pattern-source` (e.g. `flask.request.data` → `framework-input:flask`).
2. Worker runs `applyEpdScoringFallback()` after `updateReachabilityLevels()`, before commit.
3. EPD reads top 30 reachable vulns sorted by base depscore. For each: builds context (vuln summary, depth, flow trace, source snippets), calls Anthropic Sonnet 4. Tracks running spend; aborts when org's `epd_max_run_cost_usd` (or env fallback) hit.
4. Each row gets `contextual_depscore`, `entry_point_classification`, `epd_status='ai_verified'`, etc.
5. UI: vuln rows show entry-point badge sourced from AI classification.

### B. New extraction (no BYOK)
1. Same Phase 3 taint flow.
2. EPD enters heuristic-only path. For each reachable vuln:
   - If `entry_point_tag` matches `framework-input:*` or contains `'http'`/`'route'` → classify `PUBLIC_UNAUTH` (weight 1.0).
   - If matches `worker`/`cron`/`batch`/`queue` → classify `OFFLINE_WORKER` (weight 0.2).
   - Otherwise → conservative default `PUBLIC_UNAUTH` (already current behavior at `epd.ts:583`).
3. `epd_status='byok_missing'`, `epd_confidence_tier='low'`.
4. UI: badge still shown, but tooltip says "Heuristic classification — configure BYOK for AI verification."

### C. Existing project (lazy backfill)
- No re-extraction triggered on deploy.
- Next webhook push, manual sync, or daily cron picks up EPD scoring on its natural extraction cycle.
- Until then, existing rows stay at base `depscore` (no `contextual_depscore` set; UI falls back to base — already handled).

## Edge Cases & Error Handling

| Scenario | Behavior |
|---|---|
| BYOK key fails to decrypt | Already handled — `epd.ts:444` logs warn, falls through to heuristic |
| Anthropic API 5xx mid-run | Per-vuln catch logs warn at `epd.ts:664`, marks that row `ai_error_fallback`, continues to next vuln |
| `project_reachable_flows` query fails | Already handled — `epd.ts:502` logs warn, no flow context but still scores all vulns |
| Source snippet read fails / file > 400KB | Already handled — `extractSourceSnippet` returns null snippet, AI runs with less context, confidence demoted |
| Run budget exceeded | Configurable via `EPD_BUDGET_EXCEEDED_BEHAVIOR` env (`fail_job` throws `EpdBudgetExceededError`, anything else logs and continues). Default `fail_job`. **Open Q:** should the per-org cap also default to `fail_job`, or to `continue_with_fallback`? See Open Questions. |
| Org admin sets cost cap below the cost of one AI call | Server-side clamp at $0.10 minimum |
| Phase 3 taint flow has Semgrep `pattern-source` we don't have a tag mapping for | Fall through to `null` tag; heuristic defaults to `PUBLIC_UNAUTH` (worst-case). Not a regression — it's the current behavior. |
| Pipeline is a re-extraction over a project with existing EPD data from a prior run | Soft-switch commit (Phase 19) handles this — new EPD rows under new `extraction_run_id`, old rows preserved until pointer flip. No additional logic needed. |

## Non-Functional Requirements

- **Performance:** EPD adds ~30 AI calls × 2-3s each = ~60-90s to extraction wall time when BYOK present. ~0s additional when not. Acceptable within Fly.io's 90-min hard kill.
- **Cost:** Default $3/extraction cap with BYOK. Approximately $0.001-$0.01 per AI call on Sonnet 4 (3¢/MTok input, 15¢/MTok output).
- **Data volume:** EPD writes columns on `project_dependency_vulnerabilities` rows; no new tables. Volume scales with vuln count, which scales with project size (typically 10-200 reachable vulns/project).
- **Reliability:** EPD failure must NOT fail the extraction. Wrap in try/catch in pipeline.ts; on error, log to `extraction_step_errors` at `severity: 'warn'`, continue to commit phase. Vulns ship with base depscore only. (Same pattern as current Semgrep SAST step.)

## RBAC Requirements

- Reading `contextual_depscore` / `entry_point_classification` — same RBAC as existing vuln data (project read access).
- Setting `epd_max_run_cost_usd` — `manage_organization_settings` permission (matches existing AI settings).
- Viewing `epd_max_run_cost_usd` in settings UI — `view_ai_spending` permission (matches existing BYOK config visibility).
- No new RBAC permissions needed.

## Dependencies

- **Phase 19 (atomic commit / extraction_run_id):** EPD writes scoped to current run via existing PipelineState pattern. No additional work.
- **Phase 2 (tree-sitter framework detectors):** `project_entry_points` table populated. **Not directly joined this phase** — the Round 3 decision was "Map Semgrep pattern-source → tag" rather than "join project_entry_points." Framework data is consumed indirectly via Semgrep rules' own pattern-source declarations, not via DB join. Project_entry_points join is a future enhancement candidate (see Open Questions).
- **Phase 3 (reachability_rules):** Provides the taint flows EPD scores. Phase 4 modifies the taint-flow row construction at `pipeline.ts:1586` to populate `entry_point_tag` from each Semgrep rule's matched `pattern-source`.
- **Existing `epd.ts`:** Reused as-is, only the call site changes. **Modification:** read `epd_max_run_cost_usd` from the org's row (passed in via projectRow query already at `epd.ts:421`) instead of env var when set.

## Success Criteria

- ≥80% of confirmed/data_flow vulns receive a non-null `contextual_depscore` after one extraction (proves EPD is running and producing data)
- For orgs with BYOK: ≥70% of confirmed vulns have `epd_status = 'ai_verified'` (proves AI path works end-to-end)
- For orgs without BYOK: 100% of confirmed vulns have `epd_status = 'byok_missing'` AND `entry_point_classification != null` (proves heuristic path doesn't silently fail)
- Median `contextual_depscore` < median base `depscore` across all reachable vulns (proves EPD actually narrows the noise — if scores stay flat, the multiplier isn't doing anything)
- Zero EPD-related extraction failures over the first 50 extractions post-deploy (proves error handling)
- Entry-point badge visible on ≥80% of reachable vuln rows in the UI

## Open Questions

1. **Per-org budget-exceeded behavior:** Should the per-org cost cap default to `fail_job` (matches env var behavior) or `continue_with_fallback` (more org-friendly — finish the extraction even if AI runs out, fall back to heuristic for remaining vulns)? Recommend the latter for the org-configurable path; it's the difference between an org's daily scan failing vs. degrading gracefully.
2. **Future enhancement: project_entry_points join.** The Round 3 decision was Semgrep-source → tag (precise but only covers CVEs we have rules for). Joining `project_entry_points` by file path would also classify atom-derived flows (Java, Python). Worth its own phase later — flagged in success-criteria measurement.
3. **Backfill trigger.** Lazy was chosen, but if real-world data shows projects sit on stale base scores for weeks (e.g. `sync_frequency=weekly`), revisit auto-backfill in a one-off cron.

## Scope — Milestones

**M1: Wiring + entry-point tag derivation** (~1.5 days)
- Uncomment `applyEpdScoringFallback` at `pipeline.ts:1726`, position after `updateReachabilityLevels`, wrap in try/catch with structured warn-level error logging.
- Modify Phase 3 taint flow row construction at `pipeline.ts:1586` to derive `entry_point_tag` from the matched Semgrep rule's first `pattern-sources` entry (e.g., `flask.request.data` → `framework-input:flask`, `req.body` → `framework-input:express`). New helper in `reachability-rules.ts`.
- Verify EPD's `classifyFallbackEntryPoint` substring matching works against the new `framework-input:*` tags (one-line pattern check).

**M2: Per-org cost cap** (~1 day)
- Migration `phase24_epd_org_settings.sql` adding `organizations.epd_max_run_cost_usd`. Apply via Supabase MCP. Run `npm run schema:dump`.
- Backend: extend `PATCH /api/organizations/:orgId/ai-settings` (or equivalent) to accept and clamp the field.
- `epd.ts`: replace `getRunBudgetCapUsd()` call site with org-aware lookup; env var becomes the org-NULL fallback.

**M3: Frontend disclosure** (~1.5 days)
- New `EntryPointBadge.tsx` component (color-coded pill with tooltip, follows `feedback_button_style.md` outline pattern).
- Render in `VulnerabilityExpandableTable.tsx` next to depscore badge.
- Render in `VersionSidebar.tsx` vuln rows.
- Extend `AIConfigurationSection.tsx` with the `epd_max_run_cost_usd` field.

**M4: Verification + tests** (~1 day)
- Run pipeline against `deptex-test-npm` with BYOK configured: expect `confirmed` vulns to get `epd_status='ai_verified'`, distinct entry-point classifications.
- Run against same project without BYOK: expect `epd_status='byok_missing'` AND non-null entry-point classifications (heuristic path works).
- Manual UI walkthrough: badge renders, tooltip readable, settings field saves and clamps correctly.
- Add regression test in `epd.test.ts` (or new file) for org-cap fallback to env var.

**Out of scope for Phase 4** (deferred):
- `use_ai_augmentation` org toggle (defer until someone asks)
- "Why this score" full factor-breakdown panel (deferred per Round 4 — start with badge only)
- Auto-backfill of existing extractions (deferred per Round 5 — lazy is fine)
- `project_entry_points` join for atom-derived flows (deferred per Open Question #2)
- AI cost telemetry dashboard (already exists at extraction-log level via `epd_status_counts` metadata)

**Total estimated scope:** ~5 days, fits inside the original 1-week plan budget.

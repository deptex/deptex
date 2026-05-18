# Reachability Phase 5 — Per-Org AI Rule Generation Pipeline

> **Historical context (2026-05-09):** This plan was authored when AI was BYOK (per-org customer keys via `organization_ai_providers` + AES-256-GCM envelope). BYOK was retired in `phase29_drop_byok.sql` / commit `6705149`. Where this plan references BYOK, `organization_ai_providers`, `encryption.ts` for AI keys, monthly BYOK budget caps, or `AI_ENCRYPTION_KEY` for AI key envelopes, treat those as historical implementation details — current AI runs on platform keys (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GOOGLE_AI_API_KEY` from worker env). `AI_ENCRYPTION_KEY` itself is still in use, but only for `organization_registry_credentials` (IaC v2 Phase 1).

## Overview

Phase 3 shipped 20 hand-written Semgrep reachability rules. Phase 4 added EPD contextual scoring on top. Phase 5 stops trying to scale rule coverage by hand — instead, we build an Autogrep-style pipeline that auto-generates Semgrep rules per-CVE using LLMs, owned by each org via BYOK, scoped to per-org policy, applied during the customer's own extraction.

This collapses what was originally Phase 5 (hand-write 50 rules) and Phase 6 (build AI rule drafting pipeline) into a single deliverable, replacing both with a working machine.

## Why this shape

OSS research (4 parallel research agents, see `.cursor/reviews/phase5-rule-source-audit-2026-04-27.md` archive) confirmed:
- `semgrep/semgrep-rules` is now under a proprietary Semgrep Rules License v1.0 — non-redistributable. Plus only 6/2,081 rules reference any CVE.
- Trail of Bits / 0xdea / elttam / Bearer / patched-codes — all CWE-keyed generic SAST, zero CVE-keyed reachability rules combined.
- Semgrep registry CVE packs (`p/log4shell`, `p/spring4shell`, etc.) are paid Pro/Supply Chain content; license forbids redistribution; the CVE-reachability mechanism `r2c-internal-project-depends-on` is paid-tier.
- CodeQL has ~20-50 CVE-keyed queries scattered, but Datalog→Semgrep porting is 60-120 min/rule.

**The OSS world has no CVE-keyed Semgrep rule corpus.** Semgrep Inc. specifically gates this as their paid product moat.

The one OSS lever is **lambdasec/autogrep**'s methodology (Apache-2.0): LLM reads OSV patch diff, drafts Semgrep rule, validates against vulnerable-vs-fixed checkout. 39,931 patches → 645 validated rules at 18-25% FP rate (matches hand-written quality). We adopt the methodology, not the corpus (their published rules are commit-keyed and skewed to OSS web apps, not library CVEs).

## Architecture decisions (LOCKED via interview 2026-04-27)

| Decision | Choice | Rationale |
|---|---|---|
| Platform-shipped rule library | 20 existing only | No backfill, no platform AI spend. Cold-start orgs get only the existing 20. |
| AI billing model | BYOK (Phase 5 only) | Long-term direction is platform keys + 1.5× monthly markup. Phase 5 stays on existing Aegis/Aider BYOK plumbing; markup billing is a future phase. |
| Trigger model | Org-configured policy | Org picks severity / KEV / asset tier / newly-discovered filters. No generation without explicit match. |
| Scan timing | **Block current scan until generation completes** | Scan-complete = truth. Worse latency, simpler semantics, better for audit/compliance. |
| Regen with better model | **Replace, with rollback** | New rule overwrites; old YAML + model + timestamp stored in `previous_versions` JSONB. Single active rule, with safety net. |
| No-BYOK behavior | Defer to platform-paid markup phase | Phase 5 just skips silently; long-term plan is platform keys + 1.5× billing. |
| Rule storage | Per-org, RLS-enforced | Tenant-scoped, no cross-org sharing by default. Future "import / share" feature is opt-in both sides. |
| AI provider | Multi-provider via existing `getProviderForOrg()` | Anthropic / OpenAI / Google. Org picks model. |
| Parallelism | In-process within extraction-worker, concurrency-limited `Promise.all` (p-limit 5) | Matches existing Phase 3 (reachability-rules) + Phase 4 (EPD AI) patterns. The extraction-worker already has Semgrep + git + AI SDK installed; generation belongs in the same machine. Spawning new Fly machines per CVE adds 30s cold-start each and is over-engineered at our scale. |

## Pipeline flow

All generation runs **in-process within the extraction-worker Fly machine** — the same machine running clone/sbom/dep-scan/Semgrep. No new Fly machines spawned. Parallelism via concurrency-limited `Promise.all` (p-limit 5).

```
extraction starts (existing pattern: backend queues extraction_jobs row + starts Fly machine)
  ↓
worker claims via claim_extraction_job RPC
  ↓
clone / sbom / dep-scan / tree-sitter / semgrep
  (Semgrep runs with: platform-shipped 20 rules + org's existing generated rules)
  ↓
new step: load org's reachability settings → policy match against scan's vulns
  ↓
deduplicate vulns-needing-rules against:
  • platform-shipped rules (the 20)
  • org's existing generated rules WHERE enabled=true
  ↓
in-process Promise.all (p-limit 5) over remaining vulns matching trigger policy:
  per-CVE generation, each wrapped in try/catch:
    fetch OSV advisory → locate fix commit
    fetch patch diff via GitHub API
    call BYOK provider with prompt
    parse YAML + validate metadata schema (Zod)
    clone source repo at commit BEFORE patch → run rule → must match (≥1 hit)
    clone source repo at commit AFTER patch → run rule → must NOT match (0 hits)
    if both behaviors hold → write to organization_generated_rules
    else → mark validation_status='failed_validation', do not enable
    on any throw → log to extraction_step_errors at warn, this CVE skipped, others continue
  ↓
re-run Semgrep with newly-generated rules merged into rules dir → re-evaluate findings
  ↓
recompute depscores + EPD + reachability levels
  ↓
commit_extraction (atomic) → finalize
  (existing pattern — commit doesn't care if 0 or 20 rules were generated)
```

## Schema additions

### `organization_reachability_settings` (new table)

```sql
CREATE TABLE organization_reachability_settings (
  organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  auto_generate_enabled BOOLEAN NOT NULL DEFAULT false,
  trigger_severities TEXT[] NOT NULL DEFAULT ARRAY['critical','high'],
  trigger_kev BOOLEAN NOT NULL DEFAULT true,
  trigger_asset_tier_max_rank INT NOT NULL DEFAULT 2,
  trigger_newly_discovered BOOLEAN NOT NULL DEFAULT true,
  trigger_reevaluate_existing BOOLEAN NOT NULL DEFAULT false,
  ai_provider TEXT NOT NULL DEFAULT 'anthropic',
  ai_model TEXT NOT NULL DEFAULT 'claude-sonnet-4-6',
  monthly_budget_usd NUMERIC(10,2) NOT NULL DEFAULT 10.00,
  on_budget_exhaustion TEXT NOT NULL DEFAULT 'skip' CHECK (on_budget_exhaustion IN ('skip','fall_back_to_haiku')),
  max_wait_seconds INT NOT NULL DEFAULT 300,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by UUID REFERENCES auth.users(id)
);
ALTER TABLE organization_reachability_settings ENABLE ROW LEVEL SECURITY;
-- policy: org members with manage_organization_settings can read+write
```

### `organization_generated_rules` (new table)

```sql
CREATE TABLE organization_generated_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  cve_id TEXT NOT NULL,
  package_purl TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  affected_version_range TEXT,
  rule_yaml TEXT NOT NULL,
  vulnerable_fixture TEXT NOT NULL,
  safe_fixture TEXT NOT NULL,
  reachability_level TEXT NOT NULL,           -- 'confirmed' | 'function'
  entry_point_class TEXT,                      -- 'PUBLIC_UNAUTH' | 'AUTH_INTERNAL' | 'OFFLINE_WORKER' | NULL
  generated_with_provider TEXT NOT NULL,       -- 'anthropic' | 'openai' | 'google'
  generated_with_model TEXT NOT NULL,
  generation_cost_usd NUMERIC(10,4) NOT NULL,
  validation_status TEXT NOT NULL DEFAULT 'pending'
    CHECK (validation_status IN ('pending','validated','failed_validation','manual_override')),
  validation_log JSONB,                        -- {pre_patch_matches: 3, post_patch_matches: 0, semgrep_stderr: '...'}
  enabled BOOLEAN NOT NULL DEFAULT true,
  previous_versions JSONB NOT NULL DEFAULT '[]'::jsonb,
                                               -- [{rule_yaml, model, generated_at, replaced_at, replaced_by_user_id}]
  generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ,
  use_count INT NOT NULL DEFAULT 0,
  UNIQUE (organization_id, cve_id, package_purl)
);
ALTER TABLE organization_generated_rules ENABLE ROW LEVEL SECURITY;
CREATE INDEX ON organization_generated_rules(organization_id, enabled);
CREATE INDEX ON organization_generated_rules(cve_id);
```

### `extraction_jobs` columns (alter)

```sql
ALTER TABLE extraction_jobs
  ADD COLUMN reachability_rules_matched INT,
  ADD COLUMN reachability_rules_total_detectable INT,
  ADD COLUMN reachability_rules_generated_this_scan INT,
  ADD COLUMN reachability_generation_cost_usd NUMERIC(10,4);
```

## Implementation milestones

### M1 — Schema + AI provider integration (~3 days)
- `phase25_reachability_rule_generation.sql` migration (3 tables/columns above)
- Apply via Supabase MCP, refresh `schema.sql` dump
- Extend `getProviderForOrg()` to accept a `purpose` parameter (`'aegis' | 'aider' | 'rule_generation'`) so cost tracking can be partitioned per use case
- Backend route: `GET/PATCH /api/organizations/:id/reachability-settings`
- Backend route: `GET /api/organizations/:id/generated-rules` (list, paginated)
- Backend route: `PATCH/DELETE /api/organizations/:id/generated-rules/:ruleId`
- Backend route: `POST /api/organizations/:id/generated-rules/:ruleId/regenerate` (queues a regeneration with new model)

### M2 — Autogrep clone, generation core (~5 days)
New library at `backend/extraction-worker/src/rule-generator/`:

- `osv-fetch.ts` — pull advisory from `https://api.osv.dev/v1/vulns/{id}`, locate `references[].type='FIX'`, extract GitHub commit URL
- `patch-fetch.ts` — clone target repo at `commit_sha~1` and `commit_sha`, generate unified diff, capture before/after of changed files
- `prompt-builder.ts` — model-agnostic prompt template emitting our metadata schema (`metadata.osv_id`, `metadata.reachability_level`, `metadata.entry_point_class`)
- `generate.ts` — orchestrator: provider call (Anthropic/OpenAI/Google) → YAML extraction → schema validation via Zod → fixture generation prompt → store
- `validate.ts` — clone source repo at pre/post commits, write rule to temp file, invoke `semgrep --config tmp.yaml --json` against each tree, confirm `pre.matches > 0 && post.matches === 0`
- `index.ts` — public entry: `generateRuleForCve(cveId, packagePurl, orgId): Promise<GenerationResult>`

Quality gates per generation:
1. Schema valid (Zod)
2. YAML compiles in Semgrep (no parse errors)
3. Both fixtures parse in target language
4. Validation passes (pre matches, post doesn't)
5. Cost tracked + persisted

### M3 — Pipeline integration (~3 days)
In `backend/extraction-worker/src/pipeline.ts`:

1. New step `loadOrgReachabilitySettings()` early in pipeline
2. After Semgrep step, new step `runRuleGeneration()` — runs **in-process within the extraction-worker** (same Fly machine, same pattern as Phase 3 reachability-rules step and Phase 4 EPD step):
   - Filter `state.vulnerabilities` against trigger policy
   - Dedupe against existing platform rules + org generated rules
   - Estimate cost via `estimateGenerationCost(vulnsToGenerate.length, model)`
   - Check budget cap; bail-or-fallback-to-haiku per `on_budget_exhaustion`
   - Concurrency-limited `Promise.all` (p-limit 5) over the eligible CVEs:
     ```typescript
     const limit = pLimit(5);
     const results = await Promise.all(
       vulnsToGenerate.map(v =>
         limit(() => withTimeout(generateRule(v, orgSettings), 90_000)
           .catch(err => logStepError({ step: 'rule_generation', cve: v.osv_id, err, severity: 'warn' })))
       )
     );
     ```
   - Each generation has its own try/catch + per-CVE 90s timeout. One failure logs to `extraction_step_errors` at `warn`, the others continue.
3. After all generations complete (or hit timeouts): re-run Semgrep with newly-generated rules merged into the rules dir, re-evaluate findings, recompute depscores + EPD.
4. Commit phase: same atomic `commit_extraction` RPC as today; pipeline doesn't care if 0 or N rules were generated.

**No QStash fan-out, no spawned Fly machines, no coordination table.** Generation is just another in-process pipeline step. The extraction-worker already has Semgrep + git + AI SDK installed; there's no reason to dispatch this work elsewhere.

### M4 — Settings UI (~3 days)
New section in Organization Settings → "Reachability" (sibling to existing AI Configuration):

- **Trigger policy form** — checkboxes matching `organization_reachability_settings` columns:
  - Severity multi-select (Critical, High, Medium, Low)
  - "In CISA KEV catalog" toggle
  - "Project asset tier ≤" picker (rank 1-5)
  - "Newly discovered this scan" toggle
  - "Re-evaluate existing CVEs without rules" toggle (one-time backfill option)
- **AI model picker** — filtered to BYOK-configured providers, shows estimated cost-per-rule
- **Monthly budget cap** — same input pattern as existing EPD budget panel; "On budget exhaustion" radio
- **Generated rules table** — paginated, columns: CVE, package, ecosystem, model, generated_at, status, [view] [regen] [disable] [delete]
- **Rule detail modal** — Monaco YAML preview, fixtures preview, validation log, regen-with-different-model dropdown, version history (from `previous_versions` JSONB)

### M5 — Telemetry + tests (~2 days)
- Extraction logger emits: `rules_matched=42 rules_total_detectable=68 generated_this_scan=3 generation_cost=$0.12`
- Persist to `extraction_jobs` columns
- Unit tests:
  - Trigger policy matcher (severity / KEV / tier / discovery filters)
  - Provider routing (Anthropic vs OpenAI vs Google parameter shapes)
  - Schema validation rejects malformed YAML
  - Validation rejects rules that match post-patch (FP)
- Integration test on `deptex-test-npm`: trigger fires → mock provider returns canned YAML → rule lands in DB → applied to next Semgrep run → finding upgraded
- E2E checklist for Henry: real BYOK + cross-spawn CVE-2024-21538 generation + verify upgraded depscore

## Out of scope for Phase 5

- Platform-paid generation with 1.5× markup billing (separate future phase)
- Cross-org rule sharing / public registry / rule marketplace (future)
- Custom hand-written rule upload UI (future)
- Generation for non-OSV CVEs (we depend on OSV's structured patch-commit data)
- Model-specific prompt tuning per provider (start with one prompt that works across providers)
- Auto-regen on model upgrade ("you used Sonnet 4.6 but Opus 4.7 is now available, regen all?") — manual button only

## Risks & mitigations

| Risk | Mitigation |
|---|---|
| Generation latency blocks scans for 5-10min | Configurable `max_wait_seconds` per org. Org sets aggressive triggers → accepts wait. Conservative triggers → most scans don't fire generation. |
| AI generates a rule that matches everything (catastrophic FP) | Validation step (pre-patch must match, post-patch must NOT) catches the worst cases. Org admin can disable individual rules. Future: org-level "rule disabled by default, must approve" mode. |
| OSV advisory has no patch commit linked | Skip CVE entirely, log to `extraction_step_errors` at `warn` level. Some CVEs (especially old/withdrawn ones) just don't have structured fix data. |
| Source repo too large to clone (e.g., chromium) | Skip generation if repo > 1GB or clone takes > 60s. Log skip reason. |
| BYOK key rate-limited by provider | Existing Aegis rate-limit handling. Per-CVE retry with exponential backoff. |
| Generation cost runs away | Per-org monthly budget cap (existing pattern from EPD). Hard halt at limit. Per-CVE estimated cost shown in extraction logs. |
| Org disables/edits a rule that was working | Soft-disable (`enabled=false`) keeps the row for audit. Hard-delete cascades cleanly via FK. |
| Semgrep validation step is itself slow | Parallel: run pre/post Semgrep concurrently. Cap per-CVE at 90s; if it exceeds, mark `failed_validation` and skip. |

## Files

### New
- `backend/database/phase25_reachability_rule_generation.sql`
- `backend/extraction-worker/src/rule-generator/{osv-fetch,patch-fetch,prompt-builder,generate,validate,index}.ts`
- `backend/src/routes/reachability-settings.ts`
- `backend/src/routes/generated-rules.ts`
- `frontend/src/components/settings/ReachabilitySection.tsx`
- `frontend/src/components/settings/GeneratedRulesTable.tsx`
- `frontend/src/components/settings/GeneratedRuleDetailModal.tsx`
- `frontend/src/lib/api/reachability.ts`

### Modified
- `backend/extraction-worker/src/pipeline.ts` (add 2 steps: load settings, trigger generation)
- `backend/src/index.ts` (register 2 new routers)
- `backend/src/lib/ai/provider.ts` (add `purpose` parameter)
- `frontend/src/app/pages/OrganizationSettings.tsx` (add Reachability section to nav)

## Decision log

- 2026-04-27: Decided block-and-wait over async/retroactive (Henry — "scan-complete = truth").
- 2026-04-27: Decided per-org rule storage over cross-org cache (Henry — model quality varies by org choice; cross-org sharing punishes the model picker).
- 2026-04-27: Deferred no-BYOK behavior to future platform-paid phase (Henry — "ultimately we are going to have our keys and charge users monthly at 1.5× multiplier").
- 2026-04-27: Dropped hand-write 10 KEV rules lane (Henry — "we shouldn't front them anything").
- 2026-04-27: Adopted Autogrep methodology, not corpus (research finding — published 645 rules are commit-keyed + OSS-app-skewed; not useful as imports).
- 2026-04-27: **Corrected** parallelism plan from QStash fan-out to in-process within extraction-worker (Henry — consistency check; my QStash plan was inconsistent with worker-internal pattern). QStash is only used from backend routes, never from inside the extraction-worker. Generation runs in-process via concurrency-limited `Promise.all` (p-limit 5), structurally identical to Phase 3 + Phase 4 steps.

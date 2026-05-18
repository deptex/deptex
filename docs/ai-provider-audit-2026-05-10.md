# AI provider routing audit — 2026-05-10

Snapshot of every AI call site in `depscanner/` + `backend/` (the two packages
this marathon agent owns). `fix-worker/` listed at the bottom for completeness
but out of scope — that worker has its own platform-key resolver that mirrors
`backend/src/lib/aegis/llm-provider.ts`.

The brief uses the phrase "routed through user preferences". After
`phase29_drop_byok.sql` retired BYOK, "user preferences" means org-level
choice in three tables:

| Table | Purpose | Columns the resolver reads |
|---|---|---|
| `organizations` | Aegis default provider + per-model gate | `default_ai_provider`, `default_model`, `enabled_models` |
| `organization_reachability_settings` | Rule-gen + taint provider/model + monthly cap | `ai_provider`, `ai_model`, `monthly_budget_usd` |
| `taint_engine_settings` | fp-filter on/off + monthly cap | `ai_layer_enabled`, `monthly_ai_cost_cap_usd`, `ai_fp_filter_confidence_threshold` |

The "canonical resolver" depscanner is expected to route through is
`organization_reachability_settings` (loaded by
`CveGenerationCoordinator.loadSettings`). `backend/src/lib/aegis/llm-provider.ts`
holds the equivalent for Aegis / fix-planner. No other resolver should be
introduced — call sites that take a raw `process.env.*` are flagged below.

## Matrix

Legend:
- **Routed?** "settings" = goes through `organization_reachability_settings` /
  `taint_engine_settings`; "org" = `organizations.default_*`; "env" = reads
  `process.env.*` directly with no org-pref lookup; "platform" = a fixed
  platform-key feature (intentionally hard-coded provider).
- **ai_usage_logs?** Whether the call writes a row to `ai_usage_logs`.
- **scan_jobs rollup?** Whether the call's tokens + cost roll up into the
  scan's `scan_jobs` row.

### depscanner

| # | File:line | Model / purpose | Routed? | ai_usage_logs? | scan_jobs rollup? |
|---|---|---|---|---|---|
| D1 | `depscanner/src/rule-generator/generate.ts:393` callAnthropic | Anthropic Messages API — CVE FrameworkSpec generation | **settings** (provider+model+apiKey passed in from coordinator) | yes (via `logRuleGenAiUsage` in coordinator) | **partial** — total cost yes (`reachability_generation_cost_usd`), per-model breakdown **no** |
| D2 | `depscanner/src/rule-generator/generate.ts:456` callOpenAI | OpenAI-compat — same generator, openai/qwen path | **settings** | yes | partial (same as D1) |
| D3 | `depscanner/src/rule-generator/generate.ts:520` callGoogle | Google generateContent — same generator, gemini path | **settings** | yes | partial (same as D1) |
| D4 | `depscanner/src/taint-engine/fp-filter.ts:333` filterFlow | DeepInfra Qwen — per-flow taint sanitizer/endpoint triple | **settings** (`taint_engine_settings.ai_layer_enabled`, `monthly_ai_cost_cap_usd`) BUT provider+model are **hard-coded** to DeepInfra Qwen3-235B — no org override of model | yes (`feature='taint_engine_fp_filter'`) | **no** — fp-filter cost is added to the `fpFilterCostUsd` ctx variable but never written to `scan_jobs` |
| D5 | `depscanner/src/epd.ts:321` verifyWithAnthropic | Anthropic Messages — EPD sanitizer/endpoint fallback verifier | **env** — reads `anthropicApiKey` (resolved earlier from `process.env.ANTHROPIC_API_KEY`); `anthropicModel` is hard-coded in caller, **bypasses** `organization_reachability_settings.ai_provider/ai_model` | yes (`feature='taint_engine_anthropic_fallback'`) | no |

### backend

| # | File:line | Model / purpose | Routed? | ai_usage_logs? | scan_jobs rollup? |
|---|---|---|---|---|---|
| B1 | `backend/src/lib/aegis/llm-provider.ts:105` getLanguageModelForOrg | Vercel AI SDK — Aegis chat, fix-planner, title-gen | **org** (canonical) | written elsewhere by AI SDK telemetry hook | n/a — not a scan |
| B2 | `backend/src/lib/aegis/chat.ts:25` generateText | Aegis legacy chat — Gemini 2.5 Flash via `getAegisModel()` (no org override) | **platform** — hard-coded Gemini, no provider/model choice | no | n/a |
| B3 | `backend/src/lib/aegis-v3/title.ts:45` generateText | Auto-generated thread title — same Gemini-only path | **platform** (hard-coded) | no | n/a |
| B4 | `backend/src/lib/aegis-v3/fix-planner.ts:362` generateObject | Fix planner — Vercel AI SDK via `getLanguageModelForOrg(orgId)` | **org** | no | n/a |
| B5 | `backend/src/lib/aegis/executor.ts:109,181` chat.completions.create | Legacy Aegis tool executor — direct OpenAI SDK | **env** — bypasses org prefs | no | n/a |
| B6 | `backend/src/routes/organizations.ts:4898` notification AI assist | OpenAI chat completion — notification-trigger code helper | **env** | no | n/a |
| B7 | `backend/src/routes/organizations.ts:5025` license recommender | OpenAI chat completion — license-allow-list suggestion | **env** | no | n/a |
| B8 | `backend/src/routes/projects.ts:9190` packagePolicy AI | Gemini 2.0 Flash via direct REST — package-policy code helper | **platform** (hard-coded Gemini) | no | n/a |
| B9 | `backend/src/routes/docs-assistant.ts:206` docs assistant | Gemini 2.5 Flash via direct REST | **platform** (hard-coded Gemini) | partial (`logAIUsage` elsewhere in file) | n/a |
| B10 | `backend/src/lib/malicious/explain.ts:137` malicious-explain | Gemini Flash via `getPlatformProvider()` | **platform** | platform stub provider | n/a |
| B11 | `backend/src/lib/taint-engine/spec-inference.ts:200ish` framework spec inference | DeepInfra Qwen — admin re-inference of a FrameworkSpec | **env** — reads `process.env.DEEPINFRA_API_KEY`; **no** org-pref lookup at all (admin tool — operator initiates) | yes (`logAIUsage` write) | n/a (not part of a scan_job) |
| B12 | `backend/src/routes/organizations.ts:5341` (?) `getPlatformProvider().chat(...)` | Wraps Gemini under the platform stub | **platform** | platform stub | n/a |
| B13 | `backend/src/lib/aegis/tools/policy.ts:200` policy AI helper | Gemini via `getPlatformProvider()` | **platform** | platform stub | n/a |
| B14 | `backend/src/routes/projects.ts:5490` (one more `getPlatformProvider()`) | Gemini via platform stub | **platform** | platform stub | n/a |

### fix-worker (out of scope — listed for completeness)

| # | File:line | Routed? |
|---|---|---|
| F1 | `fix-worker/src/llm.ts:74` getLanguageModelForOrg | **org** — own resolver, mirrors B1 |
| F2 | `fix-worker/src/repair.ts`, `fix-worker/src/executor.ts` generateText | **org** via F1 |

## Findings — issues that need fixing

1. **D5 (EPD Anthropic fallback) bypasses `organization_reachability_settings`.**
   The provider is hard-coded Anthropic and the model is read from a worker
   env var (`DEPTEX_EPD_ANTHROPIC_MODEL`) instead of the org's chosen
   `ai_provider/ai_model`. Operationally this is sometimes wanted — the
   fallback is specifically engineered for Anthropic's stronger semantic
   verification — but it's worth flagging explicitly so the doc reflects
   reality. Per the brief this is an **intentional bypass** (Anthropic-only
   fallback) and stays as-is, but the audit calls it out and `docs/depscanner.md`
   "AI provider routing" section now says so.

2. **D4 (fp-filter) hard-codes DeepInfra Qwen.** Same shape as D5 — the
   model is fixed regardless of org pref because the prompt is calibrated for
   Qwen3-235B. Also an intentional bypass; documented.

3. **Per-scan rollup missing.** D1–D5 all write `ai_usage_logs` rows but
   only D1–D3 contribute to a single aggregate column
   (`reachability_generation_cost_usd`). There is no per-model breakdown on
   `scan_jobs` and D4/D5 spend is invisible to the scan row entirely
   (D4 cost is held in-memory in the pipeline ctx; D5 cost is summed into
   `extractionAnthropicCostUsd` and never persisted to the job). This is
   the largest gap.

4. **Per-scan cost cap doesn't exist.** Only monthly caps exist:
   `organization_reachability_settings.monthly_budget_usd` (rule-gen) and
   `taint_engine_settings.monthly_ai_cost_cap_usd` (taint). An operator
   running a manual scan against a noisy repo has no way to bound the
   single-scan AI spend short of disabling AI entirely.

5. **B5, B6, B7 (legacy Aegis executor + organizations.ts OpenAI helpers)
   bypass org prefs.** These predate `getLanguageModelForOrg`. Not in this
   marathon's scope (Aegis-v2-legacy retirement), but recorded so a future
   pass can route them.

## What this PR changes

- Adds `ai_total_prompt_tokens`, `ai_total_completion_tokens`,
  `ai_total_cost_usd`, `ai_per_model`, `ai_cost_cap_usd` to `scan_jobs`
  (`phase33_scan_jobs_ai_telemetry.sql`, staged FILE only).
- Wires every depscanner AI call (D1–D5) through a single
  `recordScanJobAiUsage()` helper that does an atomic UPDATE on the
  `scan_jobs` row holding running totals + per-model breakdown JSON.
- Adds a per-scan cap check inside `recordScanJobAiUsage()` and at each
  AI call site so a budget-exhausted scan emits a structured
  `ai_cost_cap_exceeded` `extraction_step_errors` row and aborts the
  next call. EPD Anthropic fallback and fp-filter both honour the cap.
- Adds `aiCostCapUsd?: number` to `queueExtractionJob()` and a backend
  route + frontend setting so an operator can attach a cap when
  triggering a sync.
- Does NOT change provider routing for the intentional bypasses (D4
  DeepInfra Qwen, D5 Anthropic fallback). They are documented as
  intentional in `docs/depscanner.md`.

## Audit summary

- **Total AI call sites surveyed:** 21 (5 depscanner, 14 backend, 2 fix-worker
  out of scope).
- **Pre-fix — routed through user prefs:** D1–D4 (4/5 depscanner),
  B1+B4 (2/14 backend); the remaining backend sites are platform-only
  helpers where hard-coding is the intended design (B2/B3/B8–B14) or are
  legacy Aegis-v2 / org-admin helpers (B5–B7, B11) outside this marathon's
  scope.
- **Post-fix — depscanner routing:** D1–D4 unchanged + D5 documented as
  intentional Anthropic bypass. Every depscanner AI call writes per-scan
  telemetry and respects the per-scan cap.
- **Backend routing changes:** none in this PR (out-of-scope routes will
  follow in a separate Aegis-v2-retirement pass).

# DAST Spec Param Enrichment — LLM + Breadth (fast-follow) — Plan Stub

> Split out of `dast-spec-param-enrichment.plan.md` per `/review-plan` (REVISE). Do NOT start until the deterministic v1 ships. Captures the deferred scope + the locked AI-hardening decisions from the review so they aren't lost.

## Scope (deferred from v1)
1. **LLM enrichment pass** — recover validation-schema-defined + dynamically-accessed params (zod/Joi/express-validator/Pydantic/class-validator/DRF/Spring DTO) the deterministic harvest can't see. Mirrors StackHawk/Aikido Code2Swagger.
2. **`request_body_schema`** column + synth body emission (POST/PUT/PATCH field names) — `phase49` migration.
3. **Breadth:** the other 6 frameworks (fastify, django, gin, rails, + the annotation frameworks fastapi/spring/nestjs). NOTE the annotation frameworks' params live in signatures/decorators, so they're mostly a **decorator/signature** deterministic pass + the LLM, not member-access — budget separately.
4. `provenance:'decorator'|'llm'` values (the v1 enum already reserves them).

## Locked AI-hardening decisions (from review amendment 7 — non-negotiable for the LLM pass)
- **Billing:** meter spend via `backend/src/lib/meter-event.ts` (`recordMeterEvent`, idempotency-keyed) → the prepaid ledger. **Do NOT** reuse `cost-cap` (the retired legacy Redis cap). `ai_usage_logs` telemetry reuse is fine.
- **Per-scan cap:** a hard `MAX_ENRICH_HANDLERS` count cap + `checkScanJobCostCap` pre-flight per call; rank public/unauth routes first; log truncation (no silent cap). Per-CVE cap math does NOT model "every route."
- **Prompt-injection / output allowlist:** nonce-wrap (copy `fp-filter.makeUntrustedWrapper`) is necessary but **not sufficient** — also (a) reject param names not matching a strict identifier regex, (b) cap params-per-handler + total length, (c) ground names against a grep of the re-read source (drop/flag names that never textually appear). Mirror `fp-filter.validateSanitizerLine` discipline.
- **Import-resolution depth (decide BEFORE build):** handler file + **1-hop direct imports only**, restricted to known validator packages or same-dir relative paths; hard cap total files + wrapped chars (injection surface = files pulled in).
- **Pipeline placement:** the LLM step must NOT run inside `usage-extraction`'s single shared 5-min `runStage` timeout. Either its own `withTimeout`+`AbortSignal` (forwarded into the client) with a separate budget, or gate it on a DAST target existing so non-DAST extractions aren't taxed. Mutate `result.files[*].entryPoints` in-memory before `storeEntryPoints` (the two stores are one runStage over in-memory data — no DB re-read).
- **Idempotency:** on job retry (max 3 attempts), skip handlers already enriched for this `runId` (check existing `provenance:'llm'`) so retries don't double-spend.
- **Merge:** deterministic wins on `(name,in)` presence; LLM may UPGRADE `schema.type` only when deterministic is the default `'string'`; hard type contradiction → keep deterministic + warn.
- **Prompt shape:** JSON-mode per provider (reuse `rule-generator/generate.ts` per-provider request shapes), a system directive (untrusted-data warning + output schema), few-shot per validator dialect, schema-fail retry with concrete feedback (mirror `generateRuleForCve`).
- **Injection telemetry:** emit a structured signal when an output param is dropped by the allowlist (mirror fp-filter's off-candidate warnings).

## Opportunities (from review, cheap on top of the pass)
- Emit per-param `example` values so ZAP seeds past type/format guards.
- `param_counts` (by provenance ast/decorator/llm) on `SynthesisResult` + scan log → Success-Criterion "split" report + regression signal.
- Expose `request_params` in the Aegis entry-point projection.
- Round-trip `provenance`/`confidence` as `x-deptex-*` extensions for ZAP-replay debugging.

## Next Step
Start only after v1 merges. `/plan-feature` to flesh this stub into a full plan (re-run the AI-cost + prompt-injection lenses).

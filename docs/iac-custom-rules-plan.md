# IaC Custom Rules Plan

**Status:** Plan-only. No code changes proposed in this document — every PR-class change below is a separate ship that follows Section 10's roadmap.
**Audience:** Henry. Decisions queued in Section 11.
**Worktree:** `C:\Coding\Deptex\.claude\worktrees\depscanner-hardening\`
**Owning thesis:** Per `docs/depscanner-hardening-report.md:323,333,426`, **custom IaC rules are the single most-cited "you're missing X" gap** vs Snyk / Wiz / KICS / Tenable / Bridgecrew. We already have a hardened policy-as-code surface (`package_policy_code` + `pr_check_code` + `project_status_code` running in `isolated-vm`); the natural extension is `iac_policy_code` evaluated against the `project_iac_findings` rows we already persist on every extraction. The PRs are small, the moat is the existing flow-code-sandbox, and the feature ships before any of v2 Phase 2's reachability moat work — which it does not conflict with.

---

## Section 0 — Grounding (every reference grep-verified 2026-05-09)

| Claim | File:line |
|---|---|
| Custom IaC rules called out as #1 IaC gap (table-stakes vs Snyk/Wiz/KICS/Tenable/Bridgecrew) | `docs/depscanner-hardening-report.md:323` |
| Quick-win recommendation literally names `iac_policy_code` parallel to `package_policy_code` | `docs/depscanner-hardening-report.md:333` |
| Hardening report's PR backlog ranks "IaC custom rules (S, table stakes)" | `docs/depscanner-hardening-report.md:426` |
| IaC v2 Phase 2 plan scope: OS-package reachability + base-image upgrade advisor (Items F + J) — does NOT touch policy surface | `.cursor/plans/iac-container-v2-phase2.plan.md:7-10,46-71` |
| `project_iac_findings` schema (one row per Trivy/Checkov misconfig with framework, file_path, severity, rule_id, compliance_refs, metadata) | `backend/database/schema.sql:1166-1198` |
| IaC framework canonical 9-value union | `depscanner/src/scanners/types.ts:5-17` |
| `IaCFinding` worker-side shape (scanner, rule_id, framework, file_path, start_line, end_line, severity, message, cwe_ids, code_snippet, rule_doc_url, iac_fingerprint, compliance_refs, metadata) | `depscanner/src/scanners/types.ts:21-42` |
| Checkov parser reads `metadata.benchmark` for compliance refs (CIS / SOC2 / NIST / PCI / HIPAA) | `depscanner/src/scanners/checkov.ts:96-127` |
| Bulk upsert path for IaC findings (worker → backend, runs once per extraction) | `depscanner/src/scanners/storage.ts:80-120` |
| IaC orchestration step in extraction pipeline (Checkov + Trivy config in parallel, then `upsertIaCFindings`) | `depscanner/src/scanners/orchestrator.ts:909-1018` |
| Sandbox engine — `isolated-vm` v5+, fresh isolate per call, 32MB / 30s caps, 256KB return cap, 10 fetch/run | `backend/src/lib/policy-engine.ts:222-256,294-313,343-389` |
| `executePolicyFunction` exposed for reuse beyond legacy 3 callers | `backend/src/lib/policy-engine.ts:268-275` |
| `validatePolicyCode` — 3-step (syntax / shape / fetch-resilience) save-gate | `backend/src/lib/policy-engine.ts:580-690` |
| Validation route — `POST /api/organizations/:id/validate-policy` | `backend/src/routes/projects.ts:8436-8475` |
| Codetype dispatch table (org-level write path: `package_policy` / `project_status` / `pr_check`) | `backend/src/routes/organizations.ts:3773-3789` |
| Change-history table — single `code_type`-keyed feed, CHECK constraint enforces enum | `backend/database/schema.sql:616-626,6065` |
| Org policy table pattern (one-row-per-org, `code_type` column, `updated_at`, `updated_by_id`) | `backend/database/schema.sql:579-585` (`organization_package_policies`) |
| Frontend Monaco editor primitive | `frontend/src/components/PolicyCodeEditor.tsx:1-9` |
| Existing PoliciesPage tab structure (sub-tabs by code_type, `wrapPackagePolicyBody` / `wrapPrCheckBody`, validate-then-commit flow) | `frontend/src/app/pages/PoliciesPage.tsx:128,418-479,512,564-689` |
| Flow-code-sandbox doc — "what's exposed at runtime" + "what NOT to change without security review" | `docs/flow-code-sandbox.md:54-77,114-127` |

**What does NOT exist today:**

- No `iac_policy_code` table, route, function name, or sandbox contract.
- No IaC-finding-shaped sample context in `buildSampleContext` (`policy-engine.ts:694-782`); validation can't run today even if we hand-wired the rest.
- No frontend tab or wrapper-body helper for IaC.
- No worker → policy hook in `orchestrator.ts:909-1018`. The Trivy/Checkov path goes straight from raw findings → DB; no policy filter, allow-list, or risk-decision step.
- No org-level "ignore CKV_AWS_145 globally" surface. Every customer who wants to silence a noisy Checkov rule today is stuck either (a) suppressing per-finding via `project_iac_findings.suppressed = true`, or (b) running a fork. This is the gap.

---

## Section 1 — Why this is the gap (4 bullets max)

1. **Every IaC competitor lets the customer extend rules; we don't.** Snyk Cloud (Custom Rules), Wiz (Custom Policies, Rego), KICS (custom queries), Tenable (Bridgecrew Custom Policies), Aqua-Trivy (`--config`), Anchore (Gates) — all expose either Rego or a vendored DSL. Hardening report flags this as **the most common "you're missing X" head-to-head finding** (`depscanner-hardening-report.md:323`).
2. **The plumbing already exists.** `executePolicyFunction` is hardened (32MB heap / 30s CPU / SSRF-safe `fetch()` / fail-closed startup), already used by 3 production code-types, audited in `docs/flow-code-sandbox.md`, and the `flow-code/sandbox.ts` wrapper has a clean contract pattern. The marginal cost of a 4th code-type is ~95% reuse — the only new code is a new contract entry, a new sample context, a new validator, and the one place we call it from.
3. **The data is already there.** Every extraction emits typed `IaCFinding` rows (`scanners/types.ts:21-42`) and persists them via `upsertIaCFindings` (`storage.ts:80-120`). Customers want to act on rule_id / framework / file_path / severity / compliance_refs — which are exactly the columns we already store. No detector work needed.
4. **No conflict with v2 Phase 2.** The IaC v2 Phase 2 plan is scoped to OS-package CVE reachability (Item F) + base-image upgrade advisor (Item J) on `project_container_findings` (`iac-container-v2-phase2.plan.md:7-10`). Custom-rules touches `project_iac_findings` and adds an org-level table. Zero schema overlap, zero pipeline-stage overlap. Both can ship in parallel.

---

## Section 2 — Architecture

```
Extraction pipeline (orchestrator.ts:909-1018 — existing)
  └─ Checkov + Trivy config run in parallel
     └─ IaCFinding[] (scanner, rule_id, framework, file_path, severity, …)
        └─ NEW Step 11.5: IaC POLICY EVALUATION
           ├─ load org's iac_policy_code
           │   (from organization_iac_policies; effective_iac_policy_code on project)
           ├─ for each finding:
           │   runIaCPolicy(code, finding, project, tier)
           │   └─ executePolicyFunction({ functionName: 'iacPolicy', context: {finding, project, tier} })
           │       └─ returns IaCPolicyResult: { decision: 'block'|'allow'|'review', reasons, severity_override?, status_override? }
           └─ writes back to project_iac_findings:
              .policy_decision = decision
              .policy_reasons  = reasons
              .severity         = severity_override ?? severity (if 'block' or 'review')
              .status            = 'open' | 'allowed_by_policy' | 'review_required' | 'blocked_by_policy'
        └─ upsertIaCFindings (existing, unchanged) writes the decorated rows

Frontend org Policies page (PoliciesPage.tsx — existing)
  └─ NEW 4th sub-tab: 'iac_policy' between pr_check and change_history
     └─ Same PolicyCodeEditor + same validate-then-commit flow
     └─ Same change-history feed (organization_policy_changes filtered by code_type='iac_policy')

Backend API (additive only)
  ├─ GET  /api/organizations/:id/policy-code       — extended response (already returns 3, becomes 4)
  ├─ PUT  /api/organizations/:id/policy-code/:codeType — case 'iac_policy' added (organizations.ts:3775-3789)
  ├─ POST /api/organizations/:id/validate-policy   — codeType='iac_policy' added (projects.ts:8464-8467)
  └─ POST /api/organizations/:id/projects/:pid/iac-policy/test  — NEW: re-run policy against last-N findings (no extraction)
```

**Two architectural notes:**

1. **Policy evaluation runs in the worker, not the backend.** Same pattern as `evaluateProjectPolicies` for SCA — except SCA's evaluation is triggered by a separate QStash hop after extraction completes (because licenses + OpenSSF are populated async via `populate-dependencies`). IaC findings have everything they need to be policy-evaluated **the moment they're produced** — every input field is on the `IaCFinding` itself, no async enrichment. So we evaluate inline in the orchestrator, immediately before `upsertIaCFindings`. One DB roundtrip per extraction, no extra QStash queue.
2. **The "test runner" is the editor's canary.** Mirror Snyk Cloud's "test against my last scan" UX. Customer writes a rule → clicks Test → backend pulls the last 50 IaC findings for the project they're scoped to → runs the rule against each in the sandbox (5s validation timeout, not the 30s prod timeout) → returns a verdict table. Closes the "save = passes Test = runs at runtime" promise from `flow-code-sandbox.md:8-11` for IaC.

---

## Section 3 — Reuse of existing flow-code-sandbox

This is the load-bearing decision. Target reuse: **~95%**. Concrete mapping:

| Surface | Source | Reused as-is | Need to extend | New |
|---|---|---|---|---|
| Sandbox engine (isolate creation, snapshot, caps, dispose) | `policy-engine.ts:222-256,275-427` | yes |  |  |
| SSRF-protected `fetch()` | `policy-engine.ts:97-176` | yes |  |  |
| Helper functions (`isLicenseAllowed`, `daysSince`, `semverGt`, `semverLt`, `isLicenseBanned`) | `policy-engine.ts:180-220` | yes (`daysSince` is useful for "block findings older than N days") |  |  |
| `executePolicyFunction` entry point | `policy-engine.ts:275` | yes |  |  |
| `validatePolicyCode` 3-step gate | `policy-engine.ts:580-690` |  | add `'iac_policy'` to the codeType union (4 lines) |  |
| `buildSampleContext` validator fixture | `policy-engine.ts:694-782` |  | add `'iac_policy'` branch with one synthesized `IaCFinding` |  |
| `runPackagePolicy` style wrapper |  |  |  | `runIaCPolicy` (~30 lines, mirror lines 434-456) |
| Result validator (shape check) | `policy-engine.ts:514-575` |  |  | `validateIaCPolicyResult` (~25 lines) |
| Org-write route `/policy-code/:codeType` | `organizations.ts:3733-3841` |  | add `'iac_policy'` case to the `switch` (3 lines: tableName + columnName) |  |
| Change-history table | `organization_policy_changes` |  | extend CHECK constraint to include `'iac_policy'` (1 SQL line) |  |
| Frontend Monaco editor | `PolicyCodeEditor.tsx` | yes |  |  |
| PoliciesPage tab structure | `PoliciesPage.tsx:128,512,564-689` |  | add a 4th `subTab` value + branch (~80 lines, mirror lines 573-647) |  |
| Wrap-body helper (Monaco shows function body, not full `function packagePolicy(ctx) { ... }` shell) | `wrapPackagePolicyBody` |  |  | `wrapIaCPolicyBody` (~10 lines) |
| API client | `frontend/src/lib/api.ts` |  | add `iac_policy` to existing union types in `validatePolicyCode` + `updateOrganizationPolicyCode` |  |
| `getProviderForOrg` / Tier-2 BYOK | n/a | n/a (this code is sandboxed JS, not LLM-generated) | | |
| Pipeline integration | `orchestrator.ts:1018` |  |  | new `evaluateIaCFindings()` call before `upsertIaCFindings` (~50 lines) |
| Testing lane (run-against-last-N-findings) | n/a |  |  | new endpoint + worker-side helper (~120 lines total) |

**~95%-reuse audit summary:** ~280 lines of new TypeScript total across worker + backend. Engine, validator scaffolding, frontend editor, change-history surface, RBAC plumbing — all reused.

**Anti-patterns explicitly avoided** (per `flow-code-sandbox.md:114-127` "what NOT to change without a security review"):

- Do **NOT** add new top-level identifiers to the sandbox. `daysSince` is enough; if a customer needs `regex_match`, suggest `RegExp` (already in V8 globals).
- Do **NOT** raise the 256KB return cap. An IaC policy that returns a 500-finding decision array is mis-shaped — it should return one decision per finding, called per-finding.
- Do **NOT** introduce a "batch" mode that takes `findings: IaCFinding[]` and returns `IaCPolicyResult[]`. The per-call sandbox cost (1-3ms p50, per the doc's bench) is fine for the typical 50-300 IaC findings/extraction; batch mode introduces state-leak risk between findings within one isolate.

---

## Section 4 — Data model

**No new findings tables.** All decoration lives on the existing `project_iac_findings`.

### 4.1 Additive columns on `project_iac_findings` (one small migration)

```sql
-- phaseXX_iac_policy_decoration.sql (additive, ~6 LOC)
ALTER TABLE public.project_iac_findings
  ADD COLUMN IF NOT EXISTS policy_decision TEXT
    CHECK (policy_decision IS NULL OR policy_decision IN ('block', 'allow', 'review')),
  ADD COLUMN IF NOT EXISTS policy_reasons TEXT[] NOT NULL DEFAULT '{}'::text[],
  ADD COLUMN IF NOT EXISTS policy_evaluated_at TIMESTAMPTZ;
```

**Why three columns and not a single `policy_result` JSONB:** explicit columns let the `project_iac_findings` list view filter / sort by decision in PostgREST without a JSONB index, mirroring how `is_compliant` lives on `projects` rather than nested in `policy_result`. `policy_reasons` is a flat array because the existing `policy_result` JSONB pattern from `package_policy` already carries `reasons: string[]`.

The existing `status` column (default `'open'`) stays as the canonical "is this finding open / suppressed / risk-accepted / closed" axis. **`policy_decision` does NOT mutate `status`** — they're orthogonal. A finding can be `policy_decision='block'` and `status='risk_accepted'` (humans override automation, same as today's `risk_accepted_by` audit trail).

### 4.2 Org-level policy code table (parallel to `organization_package_policies`)

```sql
CREATE TABLE IF NOT EXISTS public.organization_iac_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  iac_policy_code TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ DEFAULT now(),
  updated_by_id UUID REFERENCES auth.users(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX organization_iac_policies_organization_id_key
  ON public.organization_iac_policies (organization_id);
```

Identical shape to `organization_package_policies` (`schema.sql:579-585`). One row per org, code as text, audit columns. PUT semantics handled by the existing `/policy-code/:codeType` route (just add `case 'iac_policy'` to the dispatch table at `organizations.ts:3775-3789`).

### 4.3 Change-history reuse

The CHECK constraint at `schema.sql:6065` (`organization_policy_changes_code_type_check`) currently restricts `code_type` to `('package_policy', 'project_status', 'pr_check')`. Extend to four values. **No new history table.** The existing GET route at `organizations.ts:3843-3919` filters by `code_type` query param and already works for arbitrary types — adding the 4th value is purely additive.

### 4.4 Project-level effective code (mirror existing pattern)

The pattern at `schema.sql:1572` is `projects.effective_package_policy_code TEXT` (overrides org default). For symmetry, add `effective_iac_policy_code TEXT` to `projects` if-and-when project-level overrides become a customer ask. **Recommend: defer to a follow-up PR.** Org-level is sufficient for the v1 ship — no customer signal yet that per-project IaC overrides are needed (per the same logic that `pr_check` doesn't have a project override either).

### 4.5 Input contract (the `finding` object passed into the sandbox)

The contract argument is exactly the persisted `IaCFinding` shape (`depscanner/src/scanners/types.ts:21-42`), enriched with `project` + `tier` context. TypeScript:

```ts
interface IaCPolicyContext {
  finding: {
    /** 'trivy' or 'checkov' — `IaCScanner` (types.ts:19) */
    scanner: 'trivy' | 'checkov';
    /** e.g. 'CKV_AWS_145' or 'AVD-AWS-0089' — vendor rule id */
    rule_id: string;
    /** 9-value canonical union (types.ts:5-17) */
    framework: 'terraform' | 'kubernetes' | 'dockerfile' | 'helm'
             | 'cloudformation' | 'arm' | 'bicep' | 'serverless' | 'github_actions';
    /** repo-relative path */
    file_path: string;
    start_line: number | null;
    end_line: number | null;
    /** 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' — vendor severity */
    severity: string | null;
    /** Human-readable check name */
    message: string | null;
    description: string | null;
    cwe_ids: string[];
    /** Code excerpt from the IaC file at the violation site */
    code_snippet: string | null;
    rule_doc_url: string | null;
    /** Compliance ref map: {cis_aws_v1_4: ['1.1.1','1.2.3'], soc2: ['CC6.1']} */
    compliance_refs: Record<string, string[]> | null;
    /** Vendor-emitted metadata blob (Checkov resource_id, Trivy provider, etc.) */
    metadata: Record<string, unknown> | null;
  };
  project: {
    name: string;
    /** Asset tier name (e.g. 'Crown Jewels' / 'Internal' / 'Non-Production') */
    asset_tier: string;
    /** Asset tier rank — lower = more critical */
    tier: { name: string; rank: number; multiplier: number };
  };
}
```

This shape mirrors the documented `package_policy` contract pattern (`policy-engine.ts:26-37`). All fields are populated from `IaCFinding` columns + `projects.asset_tier_id` lookup (same lookup `evaluateProjectPolicies` already does at `policy-engine.ts:809-820`).

### 4.6 Output contract

```ts
interface IaCPolicyResult {
  /** Required. block = customer wants this finding to fail PRs / block deploys.
   *  allow = customer marks this as accepted (silences UI noise).
   *  review = customer wants a human to look at it before deciding. */
  decision: 'block' | 'allow' | 'review';
  /** Required. Free-form prose explaining the decision. Mirrors `package_policy.reasons`. */
  reasons: string[];
  /** Optional. Override the vendor severity. e.g. customer says
   *  "CKV_AWS_145 (S3 KMS) is CRITICAL in our prod tier even though Checkov says HIGH". */
  severity_override?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
}
```

Mirror of `runPackagePolicy`'s `{allowed, reasons}` (`policy-engine.ts:434-456`) widened to 3-state because IaC has a real "review" outcome that doesn't exist for binary "allowed: true/false" license decisions. Validation at `validateIaCPolicyResult` (~25 LOC parallel to `validatePackagePolicyResult` at `policy-engine.ts:514-535`).

---

## Section 5 — Trigger points

When does the policy run?

| Trigger | Where | Frequency |
|---|---|---|
| **Every extraction** | `orchestrator.ts:1018` (right before `upsertIaCFindings`) | Per extraction run |
| **Editor "Test" button** | NEW backend route `POST /:id/projects/:pid/iac-policy/test` | On-demand from UI |
| **Code save (validation)** | `validatePolicyCode` (`policy-engine.ts:580`) extended | On every save click |
| **Org policy code change** | NEW QStash hop: re-evaluate every project's open IaC findings | On `policy_code_updated` event for `code_type='iac_policy'` |

The fourth trigger is load-bearing for "I just wrote a rule, why isn't it applied to existing findings?" The current SCA pattern has the equivalent at `organizations.ts:3833` (`emitEvent({ type: 'policy_code_updated' })`). For IaC, that emit kicks a per-org QStash job that streams `project_iac_findings WHERE organization_id = $1 AND status = 'open'` and re-runs each through the new code. Defensible bound: cap at ~50K findings/org; if a tenant exceeds, run in batches of 1000 with heartbeat. (Realistically: a typical org has <1000 open IaC findings; cap is paranoia.)

**What does NOT trigger the policy:** finding-status changes (`suppressed = true`, `risk_accepted = true`). Status changes are user-driven decisions that override automation; re-running the policy on them would be a write-loop.

---

## Section 6 — Starter rule library

Ship 8 canonical examples in `frontend/src/components/policy-monaco-setup.ts` as autocomplete snippets (the existing `package_policy` setup already does this — the `BeforeMount` hook adds typedefs + sample bodies). Each is ~10-20 lines, demonstrates one common axis, and is verbatim-runnable.

| # | Rule | Logic | Demonstrates |
|---|---|---|---|
| 1 | **Block public S3 buckets in prod tier** | `if (rule_id === 'CKV_AWS_53' && tier.rank <= 2) return {decision:'block', reasons:['Public S3 not allowed in prod']}` | Tier-aware decisions; rule_id matching |
| 2 | **Require KMS-encrypted RDS** | `if (rule_id === 'CKV_AWS_16' && project.asset_tier !== 'Non-Production') return {decision:'block', reasons:['RDS must use KMS']}` | Asset-tier branching by name |
| 3 | **Deny privileged Kubernetes containers** | `if (rule_id === 'CKV_K8S_16') return {decision:'block', reasons:['Privileged containers banned']}` | Framework-agnostic global rule |
| 4 | **Allow public LBs only in `infra/public/`** | `if (framework === 'terraform' && rule_id === 'CKV_AWS_91' && !file_path.startsWith('infra/public/')) return {decision:'block'}` | File-path scoping |
| 5 | **Downgrade noisy Trivy info-level Dockerfile checks** | `if (scanner === 'trivy' && severity === 'INFO' && framework === 'dockerfile') return {decision:'allow', reasons:['Dockerfile INFO triaged out']}` | Allow-list pattern; noise reduction |
| 6 | **Mandate CIS AWS controls** | `if (compliance_refs?.cis_aws_v1_4?.length > 0) return {decision:'block', reasons:['CIS AWS finding — must remediate']}` | `compliance_refs` consumption |
| 7 | **Force "review" on github_actions findings** | `if (framework === 'github_actions') return {decision:'review', reasons:['CI changes need human eyes']}` | `review` state demo |
| 8 | **Severity escalation in Crown Jewels** | `if (tier.rank === 1 && severity === 'MEDIUM') return {decision:'block', severity_override:'HIGH', reasons:['Tier 1 escalates MEDIUM to HIGH']}` | `severity_override` |

These ship as the editor's example dropdown (mirror `exampleBodies` in flow-code's `NODE_CODE_CONTRACTS` — `flow-code-sandbox.md:81-91`). They double as the IaC policy E2E test fixture corpus — every example becomes one row in `policy-engine.test.ts` for `iac_policy`.

---

## Section 7 — Trigger integration in orchestrator

```ts
// depscanner/src/scanners/orchestrator.ts (NEW step, ~50 LOC, between :1018 and the existing upsert)

// Before upsertIaCFindings, decorate iacFindings[] with policy decisions:
if (iacFindings.length > 0 && switches.iacPolicyEnabled) {
  try {
    const decorated = await evaluateIaCFindings(
      ctx.supabase,
      ctx.organizationId,
      ctx.projectId,
      iacFindings,
    );
    iacFindings.length = 0;
    iacFindings.push(...decorated);
  } catch (err: any) {
    // Fail-OPEN — a broken policy must not block extraction. Log and proceed.
    summary.warnings.push(`iac_policy_failed:${err?.message ?? 'unknown'}`);
    await logStepError(ctx.supabase as any, {
      jobId: ctx.jobId ?? 'unknown',
      projectId: ctx.projectId,
      step: 'iac_policy_eval',
      ...classifyError(err),
      severity: 'warn',
    });
  }
}
```

`evaluateIaCFindings(supabase, orgId, projectId, findings)`:

1. Loads `organization_iac_policies.iac_policy_code` (one query). If empty → return `findings` unchanged with `policy_decision = null`.
2. Loads `projects` row + `organization_asset_tiers` once (mirror `evaluateProjectPolicies:801-820`).
3. For each finding: `runIaCPolicy(code, finding, project, tier, organizationId)` → mutate finding's eventual upsert payload to include `policy_decision`, `policy_reasons`, `severity` (overridden), `policy_evaluated_at`.
4. Return decorated array.

`upsertIaCFindings` (`storage.ts:80-120`) then writes the policy fields alongside everything else — additive on the existing row payload.

**Fail-open rationale.** The `package_policy` path also fails-open at `runPackagePolicy:451-455` (catches errors, returns `{allowed: false, reasons: [error]}`). For IaC the cost of fail-CLOSED is worse: a broken `iac_policy_code` would leave the customer with **zero** IaC findings displayed (because we'd skip the upsert entirely). Fail-open means findings appear undecorated; the warning surfaces in the logs + extraction step errors view.

---

## Section 8 — Frontend changes

The PoliciesPage at `frontend/src/app/pages/PoliciesPage.tsx` already has the structural pattern; the IaC tab is a near-mechanical mirror.

| Change | Where | Effort |
|---|---|---|
| Add `'iac_policy'` to the `SubTab` union | `:128` | 1 line |
| Add `{ id: 'iac_policy', label: 'IaC Policy' }` to `subTabs[]` | `:512` | 1 line |
| New `iacPolicyCode` / `iacPolicyOriginal` / `iacPolicyDirty` state | mirror :128-area | ~6 lines |
| Branch in `handleCommitClick` for `'iac_policy'` | `:418` | ~6 lines |
| Branch in `handleCommitSubmit` for `'iac_policy'` | `:444` | ~6 lines |
| Code-type label table | `:481-488` | 1 line |
| New `<PolicyCodeEditor>` panel mirroring `:573-647` | new block | ~80 lines |
| New typedefs in `policy-monaco-setup.ts` for `IaCFinding` + `IaCPolicyContext` (autocomplete) | extend file | ~60 lines |
| `wrapIaCPolicyBody(body)` helper (Monaco shows body, server stores `function iacPolicy(ctx) {…}`) | mirror `wrapPackagePolicyBody` | ~10 lines |
| API client extensions in `frontend/src/lib/api.ts` (extend codeType union) | `validatePolicyCode` + `updateOrganizationPolicyCode` types | ~4 lines |

**Plus a new "Test" panel.** Adjacent to the Monaco editor, a button + collapsible result table mirroring Snyk Cloud's "Run policy on last scan" UX:

- Click "Test on last 50 findings" → backend route `POST /:id/projects/:pid/iac-policy/test`
- Backend pulls top 50 IaC findings for that project, runs the policy in the sandbox (5s timeout each), returns table: `{rule_id, file_path, decision, reasons}`.
- Frontend renders inline below the editor.

Why "last 50" and not "all": predictable cost ceiling, fast feedback. Customer can run multiple times to walk through their corpus if they want.

---

## Section 9 — RBAC

Use the **existing** `manage_compliance` permission (the same one that gates `package_policy_code` write — `organizations.ts:3759`). No new permission. `iac_policy_code` write inherits the same gate. Read of effective code requires plain org membership (mirror `organizations.ts:3700-3731`).

---

## Section 10 — PR-by-PR roadmap

Six PRs, smallest-first. Each independently mergeable; later PRs assume earlier ones merged.

| # | PR title | Effort | Depends on | Risk | Notes |
|---|---|---|---|---|---|
| 1 | `feat(backend): iac_policy code-type — engine + validator + sample context` | S (~1d) | nothing | Low | Pure-policy-engine library work. New `runIaCPolicy` + `validateIaCPolicyResult` + `'iac_policy'` branch in `validatePolicyCode`. Add `'iac_policy'` to `validate-policy` route's `validTypes`. No DB, no UI. Shippable behind no flag — nobody calls it yet. |
| 2 | `feat(db): organization_iac_policies + project_iac_findings policy columns` | S (~0.5d) | PR 1 | Low | Migration `phaseXX_iac_policy.sql` (~25 LOC): new `organization_iac_policies` table + 3 additive columns on `project_iac_findings` + extended CHECK on `organization_policy_changes`. Run `cd depscanner && npm run schema:dump` in same PR (per CLAUDE.md). |
| 3 | `feat(backend): iac_policy write/read routes + change history` | S (~0.5d) | PR 2 | Low | One-line addition to `organizations.ts:3775-3789` switch; one-line to `policy-code` GET response shape; nothing else. |
| 4 | `feat(depscanner): evaluateIaCFindings inline in orchestrator` | M (~1.5d) | PR 1+2 | Med | Wires the library into the worker. Fail-open behavior. New env switch `SCANNERS_IAC_POLICY_ENABLED=true` (default true; off for the first deploy as canary). |
| 5 | `feat(frontend): IaC Policy tab + Monaco typedefs + Test runner` | M (~2d) | PR 3 | Low | All UI work. Monaco autocomplete for `IaCFinding` shape; 8 starter rules in dropdown; Test-on-last-50 panel. |
| 6 | `feat: re-evaluate findings on policy_code_updated event` | S (~1d) | PR 1-5 | Low | The QStash hop: emit `policy_code_updated` for `iac_policy`, worker subscribes, batches `project_iac_findings` per org, re-runs through `runIaCPolicy`. Closes the "I changed my rule, why are old findings un-decorated?" gap. |

**Total path-to-customer-visible (PRs 1-5):** ~5-6 dev-days. PR 6 is independently shippable but increases velocity of customer feedback (without it, decorate-on-policy-edit takes one extraction cycle to apply).

---

## Section 11 — Open questions for Henry

### 11.1 Decision vocabulary — three states or two?

Plan proposes `'block' | 'allow' | 'review'`. SCA's `package_policy` is binary `allowed: boolean`. The `'review'` state is genuinely useful for IaC because Checkov rules like `CKV_GIT_2` (CI workflow lacks pin) are often "we want a human to assess" rather than "auto-block" or "auto-silence." But three states is more contract surface. **Question:** ship 3-state, or start 2-state and add `'review'` in a follow-up if customers ask?

Recommend **3-state from day 1**. It's ~5 LOC of validation code and ~1 column-value for the lifetime of the codetype.

### 11.2 Severity override — keep it, or drop it?

`severity_override` is a real customer ask (Crown Jewels tier "MEDIUM is actually HIGH for us") but it muddles the audit trail (the persisted severity differs from the vendor severity). Two options:
- **(a)** Keep on the `severity` column. Vendor severity is recoverable from `metadata`.
- **(b)** Add a new `policy_severity` column; keep `severity` as vendor-emitted; UI shows policy_severity if set, else severity.

**Recommend (b)** for cleaner audit. Cost: 1 extra column. **Question:** confirm (b) over (a).

### 11.3 Re-evaluation on policy edit — mandatory v1 or punt to PR 6?

PR 6 is shippable independently of PRs 1-5. Without it, the shipped flow is "edit code → next extraction picks up the change." Most customers will tolerate this for a v1; some (Snyk power-users) will treat it as a bug. **Recommend ship PR 6 in v1.** It's ~1 day of work and the QStash hop pattern is well-trodden in this codebase.

### 11.4 Project-level overrides?

Mirroring `effective_package_policy_code` on `projects` would let teams override the org-default. Real signal: `package_policy` has it (`schema.sql:1572`); `pr_check` does not. The `package_policy` path also has a full **policy change request** workflow (`project_policy_changes` table at `routes/projects.ts:2876+`) where project owners propose code, org admins approve. **Recommend defer.** Org-level is the v1 ship; the change-request workflow is heavy. Add as v2 if customers ask.

### 11.5 What about `dockerfile` IaC findings — overlap with v2 P2's container-reachability decoration?

v2 Phase 2 adds `reachability_level` to `project_container_findings` (the OS-package CVE table — different table). Dockerfile **IaC** findings (rule_id `DS001` etc) live on `project_iac_findings` and represent misconfigs (`USER root`, `ADD http://…`, etc), not OS CVEs. **Verified zero overlap.** Custom-rules can target `framework='dockerfile'` IaC findings without touching v2 P2's surface. No coordination required.

### 11.6 Compliance bench tier — reserve for future?

Nothing in this plan blocks a future "compliance bench" feature where pre-canned rule packs ("SOC2 baseline", "HIPAA baseline") ship as installable templates. The Monaco editor's "Examples" dropdown is the v1 surface for this; a future PR can promote it to a `organization_iac_policy_packs` table with one-click install. **Question:** worth reserving table-name space, or speculative?

Recommend **defer naming**. Don't prematurely commit table-name vocabulary.

---

## Section 12 — Future work (not in this plan)

- **Rego / OPA support.** Snyk Cloud and Wiz both support Rego natively. The flow-code-sandbox is JS-only by design (and that's a feature — one engine, one threat model). A Rego runner would require its own sandbox, evaluator, and threat model. Out of v1 scope; reconsider if customer signal materializes (likely 2027).
- **Checkov-graph custom rules.** Checkov's "graph queries" are more powerful than per-finding evaluation (cross-resource invariants like "every S3 bucket has a paired KMS key in the same module"). Requires Trivy/Checkov subprocess work to expose the graph; not the policy engine. Track separately.
- **Shared rule marketplace.** "Install the OWASP K8s Top 10 ruleset" as a one-click. Depends on the starter-rule library proving its value first; not v1.
- **Auto-suggest rules from finding clusters.** When 50 findings of the same `rule_id` get suppressed across an org, prompt "do you want to add an `allow` rule for this?" — Tier-1 AI play (Gemini Flash). Cheap; defer until manual mode is proven.
- **`iac_policy_code` signing.** Sign rule packs with sigstore so customers can verify a pack came from Deptex (or a partner). Future moat play; out of v1.
- **`pr_check` integration.** When a PR introduces a new IaC finding, the existing `pr_check` codetype could query `iac_policy` decisions. Today `pr_check` doesn't have visibility into IaC findings — that's a separate plumbing PR. Tractable but not in scope.
- **Per-environment overrides** (e.g. "this rule blocks in `production` workspace, allows in `staging`"). Real customer ask, but requires workspace-aware extraction context that doesn't exist today. Track for after workspaces become first-class.

---

## Appendix — files referenced (grep-verified)

**Will create:**
- `backend/database/phaseXX_iac_policy.sql` (~25 LOC; additive only)
- `frontend/src/lib/iac-policy-typedefs.ts` (~60 LOC, mirror `policy-monaco-setup.ts` typedef block)

**Will edit:**
- `backend/src/lib/policy-engine.ts` (add `runIaCPolicy` ~30 LOC; `validateIaCPolicyResult` ~25 LOC; `'iac_policy'` branch in `validatePolicyCode` ~5 LOC; `'iac_policy'` branch in `buildSampleContext` ~30 LOC; export `evaluateIaCFindings` ~50 LOC)
- `backend/src/routes/projects.ts:8464-8467` (extend `validTypes` array — 1 LOC)
- `backend/src/routes/organizations.ts:3775-3789` (add `case 'iac_policy'` to switch — 4 LOC)
- `backend/src/routes/organizations.ts:3716-3726` (extend GET response shape — 3 LOC)
- `depscanner/src/scanners/orchestrator.ts:1018` (call `evaluateIaCFindings` before `upsertIaCFindings` — ~50 LOC)
- `depscanner/src/scanners/storage.ts:80-120` (extend `IaCRow` + payload to include `policy_decision`, `policy_reasons`, `policy_evaluated_at` — ~10 LOC)
- `depscanner/src/scanners/types.ts:21-42` (extend `IaCFinding` with optional policy fields — ~5 LOC)
- `frontend/src/app/pages/PoliciesPage.tsx:128,418-479,512,564-689` (new sub-tab + handlers + editor panel — ~110 LOC)
- `frontend/src/lib/api.ts` (extend `codeType` union — 4 LOC)
- `frontend/src/components/policy-monaco-setup.ts` (autocomplete typedefs + 8 starter snippets — ~80 LOC)

**Will read (no edits):**
- `backend/src/lib/policy-engine.ts:222-256,275-427,580-690` (sandbox engine + validator pattern)
- `backend/database/schema.sql:1166-1198` (project_iac_findings columns)
- `depscanner/src/scanners/types.ts:5-42` (IaCFramework + IaCFinding canonical shapes)
- `depscanner/src/scanners/orchestrator.ts:909-1018` (existing IaC scan stage)
- `docs/flow-code-sandbox.md` (sandbox security review checklist; consult before PR 1)
- `docs/depscanner-hardening-report.md:318-342,426` (competitive intel + leverage ranking)

**Total expected diff:** ~280 LOC of new TypeScript + ~25 LOC of new SQL (1 migration) + ~250 LOC of new frontend code (mostly mirrored from existing PoliciesPage). Engine changes are surgical; ~95% of the surface is reused.

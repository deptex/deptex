# Aegis Fix Agent — Implementation Plan

## Overview

Replace the dialog-based `aider-worker/` with a plan-then-execute coding agent. User triggers a fix from Aegis chat or a finding card → backend planner produces a structured Markdown plan against the org's chosen platform model → user approves the plan → new `fix-worker` (Fly.io scale-to-zero) clones the repo, applies the plan with an architect-then-editor edit tool, runs language-appropriate tests with a 2-cycle repair sub-loop, and opens a PR via the existing GitHub App. Multi-language: JS/TS + Python + Go must work end-to-end at v1 ship; the other 5 ecosystems land incrementally before public launch.

This is the foundation for all future Aegis write tools. Get this right and `bump_dependency`, `update_project_policy`, etc. become small additions on top of the same pipeline.

## Competitive Research & Design Rationale

Full research lives in `feature-brief-aegis-write-fix-tool.md`. Headline decisions and rationale:

| Choice | Why |
|---|---|
| Single-threaded linear agent | [Cognition's published "Don't Build Multi-Agents"](https://cognition.ai/blog/dont-build-multi-agents) — multi-agent collaboration produces fragile systems. For tight scope (one finding → one PR) it's pure complexity. |
| Markdown plan with current/desired bullets | [Copilot Workspace's editable spec UX](https://githubnext.com/projects/copilot-workspace) maps cleanly onto vuln fixes ("vulnerable: lodash@4.17.20 / patched: 4.17.21"). Markdown is 34-38% more token-efficient than JSON ([improvingagents.com](https://www.improvingagents.com/blog/best-nested-data-format/)). |
| Aider-style architect-then-editor with `udiff` edit format | [Aider edit-formats research](https://aider.chat/docs/more/edit-formats.html) — udiff prevents code elision; architect/editor split gives best correctness across models. |
| Container sandbox on Fly.io, not microVM | Reuse `extraction-worker` base image. microVMs (E2B/Firecracker) earn their keep on untrusted forks; for "fix our own org's repo" container is fine with default-no-network + allow-list. |
| Per-plan approval, not per-step | Per-step (Cursor) is too noisy for async work. Per-PR (Devin) lands first, asks later. Per-plan = real veto with one click. |
| Default-no-network during execution | [Jules](https://embracethered.com/blog/posts/2025/google-jules-vulnerable-to-data-exfiltration-issues/) and [Antigravity](https://cyberscoop.com/google-antigravity-pillar-security-agent-sandbox-escape-remote-code-execution/) shipped with prompt-injection→exfil paths in 2025. Codex went default-off; we follow. |
| Wall-clock + step + diff-size caps with circuit breaker | Devin's catastrophic failures are 200-min unbounded runs. Cap at single-digit minutes / ~30 tool calls / 500 LOC diff. |
| Few thoughtful tools, high-signal errors | SWE-agent's ACI insight + [Anthropic's tool-writing guidance](https://www.anthropic.com/engineering/writing-tools-for-agents). Tool descriptions outweigh tool count. |

## Codebase Analysis

### What we reuse (no changes)

| Surface | File path | What we use |
|---|---|---|
| Worker pattern | `backend/extraction-worker/src/index.ts` | Poll loop, heartbeat, claim-via-RPC, scale-to-zero |
| GitHub App helpers | `backend/src/lib/github.ts` lines 415-504 | `createBranch`, `createOrUpdateFileOnBranch`, `createPullRequest`, `cloneRepository` |
| Vuln context gathering | `backend/src/lib/ai-fix-engine.ts` line 200+ | `gatherVulnerabilityContext` — we'll wrap and extend it |
| Cost cap | `backend/src/lib/ai/cost-cap.ts` | Redis-based monthly cap check + record |
| Provider resolution | `backend/src/lib/aegis/llm-provider.ts` | `getLanguageModelForOrg(orgId)` — planner uses org's platform default |
| Aegis tool registry | `backend/src/lib/aegis-v3/tool-types.ts`, `tools/` | `AegisToolEntry` shape; we register `request_fix`, `approve_fix`, etc. as new tools |
| Realtime logs | `backend/extraction-worker/src/logger.ts` pattern + `extraction_logs` table | Stream fix-worker logs to UI |
| Existing `project_security_fixes` table | schema.sql line 1062 | Status, heartbeat, PR fields, payload all present — we just add new columns |
| Existing `claim_fix_job` RPC | schema.sql line 2463 | Atomic FOR UPDATE SKIP LOCKED job claim |

### What we extend

| Surface | Change |
|---|---|
| `project_security_fixes` table | Add `plan`, `plan_generated_at`, `plan_base_sha`, `approved_at`, `approved_by_user_id`, `approval_token` columns. Extend status enum values. |
| `gatherVulnerabilityContext` | Reuse for the planner's input; add Semgrep + secret finding paths if missing. |

### What we replace entirely

| Surface | Why |
|---|---|
| `backend/aider-worker/` (entire directory) | Aider-CLI subprocess + dialog model. Architectural mismatch with plan-based agentic flow. |
| `backend/src/lib/ai-fix-engine.ts` `requestFix()` orchestration | Currently dispatches direct-to-executor. New flow goes planning-first. |

### What's net new

```
backend/
  fix-worker/                          # NEW. Replaces aider-worker.
    Dockerfile                         # extends extraction-worker image
    package.json
    src/
      index.ts                         # poll loop, heartbeat, scale-to-zero
      job-db.ts                        # claim, heartbeat, status updates
      sandbox.ts                       # clone, language-aware bootstrap
      executor.ts                      # apply Plan via architect-then-editor + udiff
      edit-tool.ts                     # udiff parser + applier with validation
      test-runner.ts                   # detect + run tests per language
      repair.ts                        # 2-cycle repair sub-loop with LLM
      pr.ts                            # branch + commit + push + PR
      logger.ts                        # structured logs to extraction_logs

  src/
    lib/
      aegis-v3/
        fix-planner.ts                 # NEW. generateFixPlan(orgId, findingId)
        plan-types.ts                  # Plan / PlanFileChange / PlanFinding / etc.
        tools/
          fix.ts                       # NEW. request_fix, approve_fix, reject_fix, check_fix_status

    routes/
      aegis-fix.ts                     # NEW. POST /api/aegis/fix/request, PATCH /:id/approve, /:id/reject, GET /:id

  database/
    aegis_fix_agent_v1.sql             # NEW migration

frontend/
  src/
    components/
      aegis/
        PlanCard.tsx                   # NEW. Renders a plan in chat, with Approve/Reject buttons + staleness warning
        FixStatusCard.tsx              # NEW. Renders execution progress in chat
      findings/
        FixWithAegisButton.tsx         # NEW. "Fix with Aegis" trigger on vuln + Semgrep cards
    lib/
      api.ts                           # add: requestFix, approveFix, rejectFix, getFix, listPendingFixes
```

### Aegis chat message-parts integration

Existing chat flow (from `MessageBubble.tsx`): assistant message has a `parts: any[]` array. Each part has `type` (`'text' | 'dynamic-tool' | 'tool-*'`) and rendering branches on type.

New part types we add (all under `dynamic-tool` umbrella so existing buffering still groups them):
- `tool-request_fix` — when the agent calls `request_fix`. Buffered into the existing tool-call group line.
- `tool-approve_fix`, `tool-reject_fix` — buffered.
- A new top-level part type `'fix-plan'` with `{type: 'fix-plan', fixId, plan, status, baseSha, currentHeadSha?}` — rendered as a `<PlanCard>`. Goes outside the tool-call group so it gets visual prominence.
- `'fix-status'` part `{type: 'fix-status', fixId, status, prUrl?, errorMessage?}` — rendered as `<FixStatusCard>`.

This keeps the existing tool-grouping logic in `MessageBubble.tsx:33-50` untouched and adds two new top-level part renderers.

## Data Model

### Migration: `backend/database/aegis_fix_agent_v1.sql`

```sql
-- Aegis Fix Agent v1: extend project_security_fixes for plan-then-approve-then-execute flow.
-- Replaces the legacy aider-worker direct-execute model.

-- Wipe legacy aider-worker rows per Henry's interview answer (clean slate).
TRUNCATE TABLE project_security_fixes;

-- Schema additions
ALTER TABLE project_security_fixes
  ADD COLUMN plan jsonb,
  ADD COLUMN plan_generated_at timestamptz,
  ADD COLUMN plan_base_sha text,
  ADD COLUMN plan_base_branch text,
  ADD COLUMN approved_at timestamptz,
  ADD COLUMN approved_by_user_id uuid,
  ADD COLUMN approval_token text,
  ADD COLUMN rejected_at timestamptz,
  ADD COLUMN rejected_by_user_id uuid,
  ADD COLUMN rejection_reason text;

-- Status enum widens: planning → awaiting_approval → approved → executing → completed/failed/rejected.
-- Old: 'queued'|'running'|'completed'|'failed'|'cancelled' (CHECK wasn't enforced — text column).
-- We add a CHECK now to harden state transitions.
ALTER TABLE project_security_fixes
  ADD CONSTRAINT project_security_fixes_status_check
    CHECK (status IN (
      'planning',
      'awaiting_approval',
      'approved',
      'executing',
      'completed',
      'failed',
      'rejected'
    ));

ALTER TABLE project_security_fixes ALTER COLUMN status SET DEFAULT 'planning';

-- Index for pending-approval lookups (Aegis inbox, plan-card refreshes).
CREATE INDEX IF NOT EXISTS idx_psf_org_status_pending
  ON project_security_fixes (organization_id, status)
  WHERE status IN ('planning', 'awaiting_approval');

-- Index for fix-worker job claim (single-org or cross-org poll).
CREATE INDEX IF NOT EXISTS idx_psf_status_approved
  ON project_security_fixes (status, approved_at)
  WHERE status = 'approved';

-- Replace claim_fix_job RPC to claim only 'approved' rows.
CREATE OR REPLACE FUNCTION public.claim_fix_job(p_machine_id text)
RETURNS TABLE(
  id uuid,
  project_id uuid,
  organization_id uuid,
  payload jsonb,
  plan jsonb,
  attempts integer
)
LANGUAGE plpgsql AS $$
DECLARE
  v_job_id uuid;
BEGIN
  SELECT psf.id INTO v_job_id
    FROM project_security_fixes psf
    WHERE psf.status = 'approved'
      AND psf.attempts < psf.max_attempts
    ORDER BY psf.approved_at ASC
    LIMIT 1
    FOR UPDATE SKIP LOCKED;

  IF v_job_id IS NULL THEN
    RETURN;
  END IF;

  UPDATE project_security_fixes
    SET status = 'executing',
        machine_id = p_machine_id,
        heartbeat_at = NOW(),
        started_at = NOW(),
        attempts = attempts + 1
    WHERE id = v_job_id
    RETURNING
      project_security_fixes.id,
      project_security_fixes.project_id,
      project_security_fixes.organization_id,
      project_security_fixes.payload,
      project_security_fixes.plan,
      project_security_fixes.attempts
    INTO id, project_id, organization_id, payload, plan, attempts;

  RETURN NEXT;
END;
$$;

-- Stuck-job recovery (mirrors recover_stuck_extraction_jobs pattern).
-- 5-min heartbeat timeout reverts executing rows back to 'approved' for re-claim.
CREATE OR REPLACE FUNCTION public.recover_stuck_fix_jobs()
RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
  v_count integer;
BEGIN
  UPDATE project_security_fixes
    SET status = 'approved',
        machine_id = NULL,
        heartbeat_at = NULL,
        error_message = COALESCE(error_message, '') ||
          E'\n[recovered from stuck state at ' || NOW()::text || ']'
    WHERE status = 'executing'
      AND heartbeat_at < NOW() - INTERVAL '5 minutes';
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END;
$$;

-- Update schema.sql via `cd backend/extraction-worker && npm run schema:dump` after applying.
```

### Plan JSONB shape

Stored in `project_security_fixes.plan`:

```typescript
interface FixPlan {
  // Header
  summary: string;                          // 1-2 sentence human-readable summary
  finding: {
    type: 'vulnerability' | 'semgrep' | 'secret';
    id: string;                             // osv_id / semgrep_finding_id / secret_finding_id
    severity?: string;
  };

  // Editable spec sections (Copilot Workspace pattern)
  currentState: string[];                   // bullets — what's wrong today
  desiredState: string[];                   // bullets — what we want after fix

  // Concrete changes
  fileChanges: Array<{
    path: string;                           // repo-relative path
    action: 'modify' | 'create' | 'delete';
    description: string;                    // 1-line per file
  }>;

  // Test plan
  testCommand: string;                      // e.g. "npm test", "pytest", "go test ./..."
  language: 'js' | 'ts' | 'python' | 'go' | 'java' | 'ruby' | 'php' | 'rust' | 'csharp';

  // Execution constraints
  estimatedDiffSize: 'small' | 'medium' | 'large';  // <100 / 100-500 / >500 LOC
  walkClockBudgetSec: number;               // 300 default

  // Refusals (when planner can't fix)
  refusal?: {
    reason: string;                         // "no patched version available"
    manualSuggestion?: string;              // free-text suggestion
  };
}
```

If `refusal` is set, status goes directly `planning → failed` (skips `awaiting_approval`); the plan is shown as an explanation, not approvable.

## API Design

### Endpoints

| Method | Route | Auth | Permission | Description |
|---|---|---|---|---|
| POST | `/api/aegis/fix/request` | `authenticateUser` | `trigger_fix` | Body `{findingType, findingId, projectId}`. Cost-cap check. Create row with `status=planning`. Synchronously generate plan (or refusal). Return `{fixId, plan, status}`. |
| GET | `/api/aegis/fix/:fixId` | `authenticateUser` | org member | Read fix state + plan. Used by inbox + plan card refresh. |
| GET | `/api/aegis/fix/:fixId/staleness` | `authenticateUser` | org member | Fetch repo HEAD via GitHub App, compare to `plan_base_sha`. Return `{commitsAhead, isStale}`. Used by PlanCard staleness warning. |
| PATCH | `/api/aegis/fix/:fixId/approve` | `authenticateUser` | `trigger_fix` | Body `{token}`. Validate signed approval token. Set `status=approved`, record `approved_by_user_id` + `approved_at`. Worker picks up via `claim_fix_job`. |
| PATCH | `/api/aegis/fix/:fixId/reject` | `authenticateUser` | `trigger_fix` | Body `{reason?}`. Set `status=rejected`. |
| GET | `/api/aegis/fix/pending` | `authenticateUser` | `trigger_fix` | List org's `awaiting_approval` rows for the inbox. Paginated. |
| POST | `/api/aegis/fix/:fixId/regenerate` | `authenticateUser` | `trigger_fix` | Used when plan is stale. Same as `request_fix` but reuses the row, re-runs planner with current HEAD context. |

The agentic chat-side trigger uses Aegis tool `request_fix(findingType, findingId)` which calls the same backend route. Approve/Reject from chat use `approve_fix(fixId)` / `reject_fix(fixId, reason?)` tools — but those are also exposed as buttons in `<PlanCard>`, so chat-only and finding-card-only flows both work.

### Internal: worker → backend webhooks

| Method | Route | Auth | Description |
|---|---|---|---|
| POST | `/api/internal/fix-worker/log` | `INTERNAL_API_KEY` | Stream structured log lines. Inserts into `extraction_logs`. |
| PATCH | `/api/internal/fix-worker/:fixId/status` | `INTERNAL_API_KEY` | Update completed/failed status, set `pr_url`, `pr_number`, `diff_summary`, `tokens_used`, `error_*`. |

### TypeScript types

```typescript
// backend/src/lib/aegis-v3/plan-types.ts

export type PlanLanguage = 'js' | 'ts' | 'python' | 'go' | 'java' | 'ruby' | 'php' | 'rust' | 'csharp';
export type PlanDiffSize = 'small' | 'medium' | 'large';
export type FindingType = 'vulnerability' | 'semgrep' | 'secret';

export interface PlanFileChange {
  path: string;
  action: 'modify' | 'create' | 'delete';
  description: string;
}

export interface FixPlan {
  summary: string;
  finding: { type: FindingType; id: string; severity?: string };
  currentState: string[];
  desiredState: string[];
  fileChanges: PlanFileChange[];
  testCommand: string;
  language: PlanLanguage;
  estimatedDiffSize: PlanDiffSize;
  wallClockBudgetSec: number;
  refusal?: { reason: string; manualSuggestion?: string };
}

export interface FixRecord {
  id: string;
  organizationId: string;
  projectId: string;
  status: 'planning' | 'awaiting_approval' | 'approved' | 'executing' | 'completed' | 'failed' | 'rejected';
  finding: { type: FindingType; id: string };
  plan: FixPlan | null;
  planGeneratedAt: string | null;
  planBaseSha: string | null;
  planBaseBranch: string | null;
  prUrl: string | null;
  prNumber: number | null;
  diffSummary: string | null;
  errorMessage: string | null;
  approvedAt: string | null;
  rejectedAt: string | null;
  createdAt: string;
}
```

### Performance considerations

- **Plan generation latency**: synchronous LLM call, p95 target 30s. Frontend shows a "Generating plan…" placeholder card immediately on POST `/request`; server returns when the plan is in.
- **Inbox query**: indexed on `(organization_id, status) WHERE status IN ('planning','awaiting_approval')`. Cardinality ≪ all fixes.
- **Worker claim**: indexed on `(status, approved_at) WHERE status='approved'`. Same pattern as `claim_extraction_job`, proven at scale.
- **Staleness query**: 1 GitHub API call per `<PlanCard>` mount (cached 60s). Compare HEAD SHA vs `plan_base_sha`. Negligible load.

## Frontend Design

### Pages & components

No new pages. The fix flow lives inside the existing Aegis chat surface and finding cards.

| Component | File | Responsibility |
|---|---|---|
| `<PlanCard>` | `frontend/src/components/aegis/PlanCard.tsx` | Renders a plan in chat. Shows summary, current/desired state bullets, file change list, test command, status badge, staleness warning, Approve/Reject buttons. |
| `<FixStatusCard>` | `frontend/src/components/aegis/FixStatusCard.tsx` | Renders post-approval execution status (executing → completed). PR link when done, error diag when failed. |
| `<FixWithAegisButton>` | `frontend/src/components/findings/FixWithAegisButton.tsx` | "Fix with Aegis" button on vuln + Semgrep finding cards. Calls POST `/request`, opens chat panel scoped to the new fix. |
| `<AegisInboxPlans>` | extend existing inbox | New section listing org's pending plans. Click a row → opens the originating chat thread. |

### `<PlanCard>` design specification

Reference style: existing `<ToolCallGroup>` minimalism + the design skill's card patterns.

Layout:
```
┌────────────────────────────────────────────────────┐
│ Plan — Bump lodash 4.17.20 → 4.17.21               │   ← title row, 14px semibold
│ CVE-2024-XXXX · Critical                           │   ← subtitle, foreground-secondary
├────────────────────────────────────────────────────┤
│ Current state                                      │   ← uppercase 10px label, fg-secondary
│ • lodash@4.17.20 in package.json                   │   ← 12px bullets
│ • Imported by 3 files (utils.ts, ...)              │
│                                                    │
│ Desired state                                      │
│ • lodash@4.17.21 (patched)                         │
│ • Lockfile regenerated                             │
│                                                    │
│ Files to change                                    │
│ • package.json — bump version                      │
│ • package-lock.json — regenerate                   │
│                                                    │
│ Tests: npm test                                    │
│                                                    │
│ ⚠ This plan is based on commit a1b2c3d. Branch     │   ← (only if stale; warning color)
│   is now 4 commits ahead. Regenerate?              │   [Regenerate plan]
├────────────────────────────────────────────────────┤
│  [Reject]                              [Approve →] │   ← outline + primary buttons
└────────────────────────────────────────────────────┘
```

Tailwind:
- Container: `rounded-lg border border-border bg-background-card overflow-hidden`
- Header: `px-5 py-3.5 border-b border-border`
- Body: `px-5 py-4 space-y-4`
- Section labels: `text-[10px] uppercase tracking-wider text-foreground-secondary mb-1.5`
- Bullets: `text-sm text-foreground space-y-1` with `•` prefix
- Test row: `text-sm text-foreground-secondary font-mono`
- Staleness warning: `mt-2 rounded-md border border-warning/30 bg-warning/5 px-3 py-2 text-xs text-warning`
- Footer: `px-5 py-3 bg-background-card-header border-t border-border flex justify-between`
- Reject button: `<Button variant="outline" size="sm">Reject</Button>`
- Approve button: `<Button size="sm" className="bg-primary text-primary-foreground">Approve</Button>`

States:
- `status='planning'` (plan still generating) → show skeleton with pulse animation, no buttons.
- `status='awaiting_approval'` → full card with Approve/Reject.
- `status='approved' | 'executing' | 'completed' | 'failed' | 'rejected'` → buttons replaced with status pill (matches `<ToolCallGroup>`'s spinner/check/alert vocabulary). After completion, the `<FixStatusCard>` follows in the chat thread.

### `<FixStatusCard>` design

Renders the execution lifecycle. Mirrors the visual language of `<ToolCallGroup>` (gray + spinner + chevron expand).

```
▶ Executing fix · 2 of 5 steps    ⟳         ← collapsed, gray text + spinner
  ↓ (when expanded)
  ✓ Cloned payments-service
  ✓ Bumped lodash to 4.17.21
  ✓ Regenerated lockfile
  ⟳ Running npm test
  ⏳ Open PR
```

When status flips to `completed`: top line becomes `✓ Fix complete · PR #142` with a link. Failed: red top line with diagnostic in the expanded view.

Realtime updates via Supabase postgres_changes subscription on `project_security_fixes` filtered by org + fix id.

### `<FixWithAegisButton>` placement

Vulnerability detail cards: button row alongside existing "Mark resolved" / "Suppress" buttons.
Semgrep finding cards: same row.

On click:
1. POST `/api/aegis/fix/request` with finding context.
2. Open Aegis chat panel (existing chat surface).
3. Inject a synthetic user message: "Fix [finding summary]" + the just-created `<PlanCard>` from the response.

This way the chat-trigger and finding-card-trigger paths converge on identical chat thread state.

### Staleness warning logic

`<PlanCard>` mounts → `useEffect` calls GET `/api/aegis/fix/:id/staleness` → if `commitsAhead > 0`, render the warning + a "Regenerate plan" button that calls POST `/api/aegis/fix/:id/regenerate`. Polled every 60s while the card is visible (cheap: 1 GitHub API call cached server-side per fix per minute).

### Empty states

- **Aegis inbox with no pending plans**: existing inbox empty state covers this; no new copy needed.
- **First-time user clicks "Fix with Aegis" with `trigger_fix` perm but no AI provider configured**: backend returns 412 with a CTA link to Org Settings → AI. Frontend toasts the error.
- **Planner returns `refusal`**: `<PlanCard>` renders "Aegis can't safely fix this" header, the refusal reason, and (if present) the manual suggestion. No Approve button.

## Implementation Tasks

### M1 — Migration + clean cutover (S)

**Goal**: Schema changes applied, legacy aider-worker rows wiped, `claim_fix_job` RPC redefined.

**Files**:
- New: `backend/database/aegis_fix_agent_v1.sql`
- Modified: `backend/database/schema.sql` (regenerated)

**Steps**:
1. Apply migration via Supabase MCP.
2. Run `cd backend/extraction-worker && npm run schema:dump`.
3. Verify in DB: new columns present, `claim_fix_job` RPC redefined, status CHECK enforces enum.
4. Confirm `project_security_fixes` is empty.

**Acceptance**: `claim_fix_job('test-machine')` returns nothing (no approved rows yet) without errors.

---

### M2 — Backend types + plan generator (M)

**Goal**: `FixPlan` TS types, `generateFixPlan(orgId, findingId)` server-side function. No worker yet, no UI yet.

**Files**:
- New: `backend/src/lib/aegis-v3/plan-types.ts`
- New: `backend/src/lib/aegis-v3/fix-planner.ts`
- Modified: `backend/src/lib/ai-fix-engine.ts` (refactor `gatherVulnerabilityContext` for reuse + extend to Semgrep findings if missing)

**`generateFixPlan` shape**:
```typescript
async function generateFixPlan(
  orgId: string,
  findingType: FindingType,
  findingId: string,
  projectId: string,
): Promise<{ plan: FixPlan; baseSha: string; baseBranch: string }> {
  // 1. Fetch context (vuln/semgrep/secret + project + repo + reachability + manifest paths)
  // 2. Fetch HEAD SHA from GitHub App for baseSha
  // 3. Build planner system prompt (architect role, Markdown plan output schema)
  // 4. Call getLanguageModelForOrg(orgId) for model resolution
  // 5. Use generateObject with strict Zod schema for FixPlan, OR generateText + parse + Zod validate
  // 6. If finding can't be fixed (no patched version, ambiguous), planner returns refusal
  // 7. Return plan + base sha
}
```

**Acceptance**: Unit test (mock supabase + mock LLM via MockLanguageModelV3) — passing a vuln context produces a valid `FixPlan`. Refusal path returns refusal field.

---

### M3 — Backend routes + Aegis tools (M)

**Goal**: All 7 user-facing endpoints + 4 Aegis tools (`request_fix`, `approve_fix`, `reject_fix`, `check_fix_status`).

**Files**:
- New: `backend/src/routes/aegis-fix.ts`
- New: `backend/src/lib/aegis-v3/tools/fix.ts`
- Modified: `backend/src/index.ts` (mount router)
- Modified: `backend/src/lib/aegis-v3/tools/index.ts` (register fix tools)

**Aegis tools**:
- `request_fix({findingType, findingId, projectId})` — calls planner, persists row, returns `{fixId, plan, status}`. Permission: `trigger_fix`.
- `approve_fix({fixId})` — server-validates user permission + signed token, sets status. Tool's response includes "Fix approved, executing now."
- `reject_fix({fixId, reason?})` — same.
- `check_fix_status({fixId})` — read-only, returns current status.

**Approval token**: HMAC-signed with `INTERNAL_API_KEY` over `(fixId, orgId, generatedAt)`. Stored in `approval_token` column, validated on PATCH `/approve`. Prevents stale links from being reused after rejection or completion.

**Acceptance**: Backend integration tests for happy path (request → approve → claim) and refusal path (planner returns refusal → status straight to failed). 403 tests for missing `trigger_fix`.

---

### M4 — Frontend plan card + finding card button (M)

**Goal**: User can trigger a fix from a finding card, see a `<PlanCard>` render in chat, and approve/reject.

**Files**:
- New: `frontend/src/components/aegis/PlanCard.tsx`
- New: `frontend/src/components/aegis/FixStatusCard.tsx`
- New: `frontend/src/components/findings/FixWithAegisButton.tsx`
- Modified: `frontend/src/lib/api.ts` (add `requestFix`, `approveFix`, `rejectFix`, `getFix`, `getFixStaleness`, `regenerateFixPlan`)
- Modified: `frontend/src/components/aegis/MessageBubble.tsx` (handle new `'fix-plan'` and `'fix-status'` part types)
- Modified: vuln detail card + Semgrep finding card components to mount `<FixWithAegisButton>`

**Acceptance**: Manual browser test — clicking "Fix with Aegis" on a vuln card opens chat with a plan, Approve persists status change. Realtime status updates as worker executes.

---

### M5 — Fix-worker scaffolding (L)

**Goal**: New Fly.io worker that claims approved jobs, clones repo, applies plan, runs tests, opens PR. JS/TS only at this milestone.

**Files**:
- New: `backend/fix-worker/Dockerfile`
- New: `backend/fix-worker/package.json`
- New: `backend/fix-worker/src/index.ts` (poll loop, mirrors `extraction-worker/src/index.ts`)
- New: `backend/fix-worker/src/job-db.ts`
- New: `backend/fix-worker/src/sandbox.ts` (clone, npm install)
- New: `backend/fix-worker/src/edit-tool.ts` (udiff parser + applier)
- New: `backend/fix-worker/src/executor.ts` (orchestrates: setup → architect-then-editor → diff apply)
- New: `backend/fix-worker/src/test-runner.ts` (run `npm test` + parse failures)
- New: `backend/fix-worker/src/repair.ts` (2-cycle repair sub-loop)
- New: `backend/fix-worker/src/pr.ts` (uses `backend/src/lib/github.ts` helpers via shared import or copied helper)
- New: `backend/fix-worker/src/logger.ts`
- Modified: `backend/src/lib/fly-machines.ts` (add FIX_CONFIG entry)
- New: `fly.fix-worker.toml` (Fly.io config)

**Architectural notes**:
- Sandbox network: default-off. Allow-list: npm registry + GitHub clone host during setup phase.
- Wall-clock cap from plan, hard-fail at limit. Default 5 min.
- Diff-size cap: 500 LOC. Hard-fail with diagnostic.
- Token + cost tracking: aggregate across planner + repair calls, write to `project_security_fixes.tokens_used` + `estimated_cost`.
- Heartbeat every 60s, claim only `status='approved'` rows.

**Acceptance**: End-to-end manual test on a JS/TS project — request fix on a real CVE, approve, worker opens PR with green tests.

---

### M6 — Multi-language: Python + Go (M)

**Goal**: `sandbox.ts` and `test-runner.ts` handle Python (`pip install` + `pytest`) and Go (`go mod download` + `go test ./...`). Tests pass end-to-end.

**Files**:
- Modified: `backend/fix-worker/src/sandbox.ts` (language-aware bootstrap)
- Modified: `backend/fix-worker/src/test-runner.ts` (per-language test detection)
- Modified: `backend/fix-worker/Dockerfile` (ensure python3, pip, go, etc. in image — likely already present from extraction-worker base)
- Modified: `backend/src/lib/aegis-v3/fix-planner.ts` (planner system prompt covers all languages)

**Acceptance**: End-to-end test for one Python finding and one Go finding. PRs open with green tests.

---

### M7 — Repair sub-loop + safety caps (M)

**Goal**: When tests fail, agent gets a 2-cycle repair budget. Safety caps enforced.

**Files**:
- Modified: `backend/fix-worker/src/repair.ts`
- Modified: `backend/fix-worker/src/executor.ts` (wire repair budget)

**Repair loop**:
```
attempt = 0
while attempt < 2:
  apply_plan_or_repair()
  test_result = run_tests()
  if test_result.passed: break
  if attempt == 1: break  # last attempt failed, give up
  repair_patch = call_llm_for_repair(test_result.failures, current_diff, plan)
  attempt++
```

**Safety caps**:
- Wall-clock: from plan (default 300s).
- Tool calls: hard cap 30 LLM calls per fix.
- Diff size: hard cap 500 LOC. If exceeded → fail with "diff too large; suggest splitting."

**Acceptance**: Synthetic failure injection — first test fails, repair fixes it, PR opens. Second case: both attempts fail, status=failed with diagnostic.

---

### M8 — Stretch languages + retire aider-worker (S)

**Goal**: Java/Ruby/PHP/Rust/C# bootstrap scripts added behind a `LANGUAGE_GATE` env. Aider-worker directory deleted.

**Files**:
- Modified: `backend/fix-worker/src/sandbox.ts`, `test-runner.ts`
- Deleted: `backend/aider-worker/` (entire directory)
- Modified: `backend/src/lib/fly-machines.ts` (remove AIDER_CONFIG)
- Modified: `backend/src/lib/ai-fix-engine.ts` (remove old direct-execute path)
- Modified: `fly.toml` references to old worker

**Behavior**: Stretch languages call planner; if `language` not in active set, return refusal "v1 doesn't support this language yet."

**Acceptance**: Aider-worker is gone, fix-worker handles requests for at least JS/TS + Python + Go. Dockerfile build still passes for all 8 language detection paths even if not validated end-to-end.

---

### M9 — Smoke + acceptance test (S)

**Goal**: Real end-to-end run of all Phase 1 acceptance criteria.

**Steps**:
1. Pick a real CVE on a Deptex test repo.
2. From Aegis chat: "Fix CVE-X in Y." → plan card appears. Approve. PR opens.
3. From finding card: click "Fix with Aegis." → chat opens with plan. Approve. PR opens.
4. Force a planner refusal (a finding with no patched version) → refusal card shows.
5. Force a test failure → repair loop runs once → succeeds OR fails cleanly.
6. Stale plan: leave a plan unapproved overnight, push a commit → reload, staleness warning shows. Click Regenerate → new plan appears.
7. Wipe AI keys for one provider → request fix → 412 with CTA toast.
8. Confirm structured logs render in real-time in the existing extraction_logs subscription pattern.

## Testing & Validation Strategy

- **Backend unit**: `fix-planner.ts` with `MockLanguageModelV3` (existing pattern from aegis-v3 tests). Cover happy + refusal + bad-shape responses.
- **Backend integration**: `aegis-fix.ts` routes via supertest with the existing supabase mock pattern. Cover request → approve → execute happy path; 403 missing perms; staleness math; approval token validation.
- **Worker unit**: `edit-tool.ts` udiff parser + applier with golden-file fixtures (one per language).
- **Worker integration**: spin up a temp container with a fixture repo, run executor with a known plan, assert PR-equivalent diff is correct.
- **Frontend**: `<PlanCard>` rendering for each status state (planning → awaiting_approval → approved → executing → completed → failed → rejected → refused). Vitest snapshots fine.
- **Performance**:
  - Plan generation p95 < 30s.
  - Worker job: clone + setup + plan execution + tests + PR < 5 min for v1 acceptance set.
  - Inbox query < 50ms (indexed).
  - Staleness check < 200ms (cached GitHub call).
- **Regression**:
  - Existing `/api/aegis/chat` flow unaffected.
  - `extraction_logs` realtime subscription still works for extraction (don't crowd the channel).
  - `project_security_fixes` other consumers (e.g. activity log) handle new statuses gracefully.

## Risks & Open Questions

### Risks (with mitigations)

| Risk | Mitigation |
|---|---|
| **Prompt-injection → sandbox escape → exfil** (Jules / Antigravity / Claude Code all shipped this in 2025) | Network default-off in fix-worker. Allow-list registries during setup phase only. No secrets mounted into sandbox. |
| **Bad PR lands** | HITL plan approval (locked). Diff-size cap (500 LOC hard). Test-must-pass before push. PR description tagged "Generated by Aegis." |
| **Devin-style infinite loop** | Wall-clock cap, tool-call cap (30), repair budget = 2. Circuit breaker on consecutive identical errors. |
| **Multi-language complexity** | Single fat image based on extraction-worker. Per-job setup script. Stretch languages refuse-with-message until validated. |
| **Stale plan applied to changed code** | `plan_base_sha` recorded; `<PlanCard>` shows staleness warning. Worker re-checks SHA before executing — if drifted, fail with "regenerate plan." |
| **Sonnet 4.5 premature task termination** ([Cognition's documented issue](https://cognition.ai/blog/devin-sonnet-4-5-lessons-and-challenges)) | Cap context usage well below model window. Repeat key instructions at start AND end of system prompt. |
| **Vague trigger → bloated plan** | Planner system prompt strict-scope: "patch finding ID X to resolution Y, nothing else." `estimatedDiffSize` self-check. |
| **Fly.io machine boot latency** | Same as extraction-worker today (~30s cold). Acceptable for async approve flow. Pre-warm during planning phase if it's a UX issue (defer optimization). |

### Residual open questions (close during implementation)

1. **Per-fix cost cap value** — start at $1.00, observable via `estimated_cost`. Tune after early data.
2. **Wall-clock cap default** — 300s for v1. Tune after early data.
3. **Plan card visual final tuning** — implement, iterate per Henry's feedback (he flagged AI page polish; same eye on this).
4. **Inbox surfacing** — extend existing inbox component vs new tab. Defer to M4 implementation.
5. **Log-stream channel** — reuse `extraction_logs` table or new `fix_logs` table? Suggest reusing `extraction_logs` with `job_type='fix'` filter. Confirm during M5.
6. **Setup-script format** — hand-written per language vs LLM-driven Dockerfile synthesis (Repo2Run pattern) for edge cases. Start hand-written for JS/Python/Go; revisit for stretch languages.

## Dependencies

- **AI Settings / platform-default provider** — already shipped (M1-M5 of `feature-brief-aegis-write-fix-tool.md`'s prereqs). `getLanguageModelForOrg()` resolves planner model.
- **GitHub App** — already integrated. `backend/src/lib/github.ts` helpers handle clone + branch + PR.
- **Aegis v3 tool registry** — already exists. New tools register normally.
- **Aegis chat surface** — already exists with `parts` array support; we add 2 new part types.
- **Existing `project_security_fixes` table + `claim_fix_job` RPC** — extended, not replaced.
- **`extraction_logs` table + Supabase Realtime subscription** — used for fix-worker streaming logs.
- **Cost cap (Redis)** — already wired; reuse for per-fix budget tracking.

## Success Criteria

1. **From Aegis chat**: User types "Fix CVE-XYZ in project A" → plan card renders within 30s → user clicks Approve → fix-worker executes → PR opens within 5 min for v1 ship languages (JS/TS, Python, Go).
2. **From finding card**: Same flow, originating from a "Fix with Aegis" button on a vuln or Semgrep finding card. Identical chat thread state result.
3. **Refusal path**: When Aegis can't fix (no patched version, ambiguous), the user sees a clear "no fix possible" card with reason and optional manual suggestion. No bad PR generated.
4. **Stale plan path**: Approving a plan that's drifted from HEAD shows a staleness warning. Regenerate produces a fresh plan.
5. **Failure path**: Test failure inside the 2-cycle repair budget either resolves or fails cleanly with diagnostic. No PR opened on failure. Status reflects accurately in chat thread + finding card.
6. **Sandbox safety**: Network default-off during exec. No secrets mounted. Diff-size cap enforced.
7. **Observability**: Every fix job has structured logs viewable in real-time via the existing extraction_logs subscription. Cost + token usage recorded.
8. **No regressions**: existing Aegis chat, vuln list, finding cards, and other write surfaces unaffected.
9. **Aider retired**: `backend/aider-worker/` deleted, all callers migrated, Fly.io app `deptex-aider-worker` decommissioned.

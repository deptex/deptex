# Findings Status Model & Lifecycle — Feature Brief

_Brainstorm output, 2026-06-19. Supersedes the premature `findings-status-foundation.plan.md` draft. Feeds `/plan-feature`._

## Problem Statement
Deptex has no real, unified status lifecycle for security findings. Triage today is a **client-side `autoTriageRow()` hack** recomputed at render, mirrored in **`backend/.../finding-triage.ts`** (so Aegis agrees), and **re-implemented a third time in SQL** (`security_summary_counts`, `phase48`–`phase52`) so the count pills line up. Three copies of the same reachability logic = constant drift risk. Manual disposition is fragmented across four vocabularies (`status`, `suppressed`, `risk_accepted`, DAST `'closed'`) over 7 finding tables. There's no way to push a finding to a tracker, and no audit of who set what aside or why. We want one persisted status model that powers per-row actions (ignore, send-to-tracker, copy link) and is the single source of truth for the count pills.

## Current State in Deptex
- **Partial status already exists:** `status ('open'|'ignored')` on `project_dependency_vulnerabilities` / `project_secret_findings` / `project_semgrep_findings` (`findings_status.sql`); `suppressed` bool + `risk_accepted` on PDV/IaC/container/malicious; DAST uses `status ('open'|'closed')`.
- **Stable-identity carry-forward is proven** for 3 types: `finalize_extraction` already carries user state across rescans by `(dep_name, osv_id)` (PDV), fingerprint (semgrep), and secret status.
- **The hack:** reachability auto-triage in 3 places — `autoTriageRow()` (`VulnerabilityExpandableTable.tsx`), `vulnAutoIgnoreReason()` (`finding-triage.ts`, used by Aegis `issues.ts`), and the `security_summary_counts` RPC.
- Findings are scoped to `extraction_run_id = active run`; gone-from-latest-scan ⇒ absent. No tracker-link concept (`aegis-v3/tools/issues.ts` is read-only).

## Competitive Landscape
### Snyk
- States: Open / Ignored (with reason + optional expiry) / Resolved (auto when no longer found). Ignored+resolved hidden by default, shown via a status filter. ([docs](https://docs.snyk.io/integrations/jira-and-slack-integrations/snyk-security-in-jira-cloud-integration))
- Jira: "Create issue" / "Link issue" from a finding; **auto-closes the Jira ticket when the vuln resolves** (JQL search + Transition to Done). One-directional Snyk→Jira. ([Snyk auto Jira closure](https://support.snyk.io/hc/en-us/articles/18936234355357-Automatic-Jira-issue-closure))
### Aikido
- Open / **Snooze** (1d/1w/1mo/1yr/custom — temporary) / **Ignore** (permanent; scoped single / by-path / by-CVE / by-rule) / Closed (auto when a scan no longer reports it, or manual). ([snooze](https://help.aikido.dev/getting-started/core-functionalities/snooze-issues-for-later), [ignore](https://help.aikido.dev/getting-started/core-functionalities/ignore-issues-to-remove-issues-from-main-feed))
- Auto-closes linked GitHub issues when the vuln resolves. ([why solved](https://help.aikido.dev/getting-started/core-functionalities/why-was-an-issue-marked-as-solved)) Auto-triage to set aside findings "that don't affect you."
### Endor Labs
- Exception policies: choose a **reason** (In Triage / False Positive / Risk Accepted / Resolved) and a **required expiration**. Findings with exceptions are filtered out of reports by default. ([exception policies](https://docs.endorlabs.com/managing-policies/exception-policies/))
### GitHub Code Scanning / Dependabot
- Open / Dismissed (reason; reopenable) / **Auto-dismissed** (curated patterns + context) / Fixed (auto, not reopenable). **Auto-dismissed alerts auto-REOPEN when context changes** (e.g. dependency scope makes it relevant again). ([auto-triage](https://docs.github.com/en/code-security/dependabot/dependabot-auto-triage-rules/about-dependabot-auto-triage-rules), [reopen](https://github.blog/changelog/2022-03-07-reopen-dismissed-dependabot-alerts/))

## Landscape Synthesis
- **Table-stakes:** open / ignored(reason) / resolved-auto-when-gone + a noise auto-triage layer + create-ticket integration.
- **Frontier:** (1) auto-triage that **auto-reopens** on context change (GitHub); (2) **finding→ticket auto-close** sync (Snyk, Aikido); (3) **time-boxed** dismissals everywhere (Aikido snooze, Snyk/Endor expiry — Endor *requires* it); (4) **scoped/bulk** ignore by CVE/path/rule (Aikido).
- **Whitespace / Deptex ahead:** our `auto_ignored` is **reachability-graded** (confirmed/data_flow/function/module), richer than GitHub's pattern auto-dismiss. Moat play: reachability auto-triage that auto-reopens + **Aegis fix → auto-resolve writeback**.
- **Deptex behind:** unified status + tracker sync. Carry-forward infra already half-built (3/7 types).
- **Feasibility:** low-risk. It's mostly a data-model unification + moving one already-written triage computation into the worker. Biggest risk = defining a `finding_key` that's stable across benign rescans for all 7 types (must match the existing finalize carry-forward keys). Tracker integrations (Jira/Linear OAuth) are standard but net-new plumbing.

## User Stories
- As a **security engineer**, I want to ignore a finding with a reason so it stays out of my Open list across rescans and stops inflating the counts.
- As a **security engineer**, I want a finding that becomes reachable in a later scan to automatically reappear, so a deferred-as-unreachable risk isn't silently buried forever.
- As a **developer**, I want to push a finding to Jira/Linear and see a link back, so I can work it in my normal tracker — and have the ticket auto-close when the fix lands.
- As an **org admin**, I want one number on the count pills that exactly matches the Open list, with an audit of who ignored what and why.

## Locked Scope Decisions
1. **Unified `status ∈ {open, ignored, resolved}`** on all 7 finding tables, keyed to a stable **`finding_key`** that survives rescans (carried forward in `finalize_extraction`). _Why: matches every incumbent; carry-forward already proven for 3 types._
2. **`auto_ignored` (+ reason) is a per-scan derived field, recomputed every scan, NEVER carried forward.** A finding that becomes reachable auto-reopens to Open. _Why: GitHub auto-dismiss reopen pattern; our reachability is inherently per-scan (round 1)._
3. **Manual ignore is permanent — no expiry/snooze for v1.** _Why: Henry's call; he's the minority vs incumbents but wants simplicity. Revisit expiry in v2 (round 1)._
4. **Ignore reasons: `false_positive` / `wont_fix` / `accepted_risk`** + optional free-text note. Folds in the old "risk accepted." _Why: matches Snyk/GitHub core reasons (round 2)._
5. **Per-finding ignore only for v1** — no bulk by-CVE/path/rule. _Why: ships fastest, covers ~90%; bulk needs a rules table + scan-time matching (round 1)._
6. **`resolved` = auto when not in the latest scan OR on Aegis fix writeback.** Drops out of the active view but is kept in history. _Why: "it disappears" model + metrics need the record._
7. **Keep a `finding_status_events` audit log + resolved history.** _Why: powers MTTR / resolved-over-time, "who ignored & why", and correct re-open when a finding flaps back (round 2)._
8. **Tracker links ride alongside status; the ticket never drives the finding.** Closing a Jira/Linear ticket does NOT resolve the finding. _Why: only a rescan proves a vuln is gone (research-confirmed: incumbent sync is finding→ticket, not ticket→finding)._
9. **One-directional finding→ticket auto-close:** when a finding resolves, transition its linked ticket to Done. _Why: Snyk + Aikido both do it; it's the valuable half of the sync (round 1)._
10. **Tracker providers v1 = Jira + Linear** (the security-team target market), with **GitHub Issues** as a cheap opportunistic add (GitHub App already exists). Architecture stays generic ("show the connected integrations they have"). _Why: Henry's target market; security workflows live in Jira/Linear (round 2)._
11. **New permission key `manage_findings`** gates ignore + create-ticket; viewing is open to anyone who can view findings. _Why: finer-grained triage rights separate from full project management (round 2)._
12. **Kill the 3-place triage duplication:** store `auto_ignored` once at scan time; `autoTriageRow()` / `finding-triage.ts` / the count-pill RPC all become readers of the stored verdict.

## Data Model (what & why — bodies are /plan-feature's job)
- **All 7 finding tables:** add `finding_key TEXT` (stable identity), unify `status ∈ {open,ignored,resolved}`, add `ignore_reason` / `ignored_by` / `ignored_at`, add `auto_ignored BOOLEAN` + `auto_ignore_reason` (per-scan). Backfill existing `suppressed`/`risk_accepted` → `status='ignored'`+reason. Index `(project_id, finding_key)` + `(project_id, status)`.
- **`finding_tracker_links`** (new): org/project/finding_type/finding_key, provider, external_id, external_url, external_status, created_by, created_at. Unique per (project, finding_type, finding_key, provider).
- **`finding_status_events`** (new): finding_type/finding_key/project, old→new status, reason, actor, created_at.
- **Worker:** compute `finding_key` + `auto_ignored` at scan time; extend `finalize_extraction` carry-forward of manual status to all 7 by `finding_key`.
- **RPC:** simplify `security_summary_counts` to `count(active_run AND NOT auto_ignored AND status='open')`.

## API Endpoints
| Method | Route | Auth | Permission | Description |
|---|---|---|---|---|
| PATCH | `/organizations/:id/findings/:type/:findingKey/status` | JWT | `manage_findings` | Set open/ignored (+reason); writes a status event |
| POST | `/organizations/:id/findings/:type/:findingKey/tracker` | JWT | `manage_findings` | Create issue in a connected tracker; store link |
| DELETE | `/organizations/:id/findings/:type/:findingKey/tracker/:linkId` | JWT | `manage_findings` | Unlink a tracker ticket |
| GET (existing, extended) | findings reads | JWT | view | Return `status`, `auto_ignored`, tracker links |
| (internal) | finding→ticket auto-close on resolve | INTERNAL_API_KEY | — | Worker/QStash transitions linked tickets when a finding resolves |

Copy-link is pure frontend (existing `openFindingId` deep link).

## Frontend Surface
- **Status pill:** Open (violet "New" badge when first-seen = latest scan) · Ignored (muted + reason tooltip) · auto_ignored (dimmed in "All"). Resolved simply absent.
- **Row actions** (trailing actions column / hover overflow, gated on `manage_findings`): Ignore → reason dialog (shadcn `<Dialog>`, reason select + note, green confirm) · Un-ignore · Create issue → connected-provider picker · Copy link.
- **Tracker chip** in the row (provider icon + external id, links out).
- **Filter:** the Open/All toggle becomes a real **Open / Ignored / All** segmented control backed by status.

## User Flows
1. **Ignore:** click Ignore → pick reason (+ note) → optimistic hide from Open + decrement count → server persists + event → carried forward on every future scan by `finding_key`.
2. **Send to tracker:** click Create issue → pick connected provider (Jira/Linear/GitHub) → ticket created → chip appears → finding stays Open. On later resolve → ticket auto-transitions to Done.
3. **Auto-reopen:** scan N marks a vuln `auto_ignored` (unreachable); scan N+1 finds it reachable → recomputed `auto_ignored=false` → back in Open automatically.
4. **Resolve:** fix lands → next scan doesn't find it → `resolved`, drops from active view, event logged, linked ticket auto-closed.

## Edge Cases & Failure-Mode Policy
- **Manually-ignored finding reappears in a later scan** → stays ignored (sticky via `finding_key` carry-forward).
- **Ignored finding disappears** → becomes resolved (resolved supersedes; history keeps both transitions).
- **`finding_key` instability** (file moved/renamed) → ignore could be lost → key design must tolerate benign churn; soft-fail (worst case the finding reappears as Open, never a crash).
- **Tracker API failure on create** → surface an error, finding unchanged; never block triage. Status-mutation failure → optimistic rollback + refetch server truth.
- **Linked ticket already closed/deleted when finding resolves** → auto-close is best-effort, log + move on.
- **User lacks `manage_findings`** → read-only: pills + statuses visible, action buttons hidden (server still enforces).

## Non-Functional Requirements
- Findings table + count pills are hot paths → `finding_key` + `status` indexed; the RPC reads a stored verdict (no per-row recompute).
- Scan-time triage adds negligible worker cost (the verdict is already computed today — just persist it).
- Data volume: thousands of findings per org; tens of thousands across large orgs.
- Tracker calls are async/best-effort; never on the findings-read path.

## RBAC Requirements
- New permission key **`manage_findings`** in `organization_roles.permissions` (owner always passes). Seed into default roles via migration (decision for /plan-feature: grant to `owner` only, or `owner`+`member`?). Gates: set status (ignore/un-ignore), create/unlink tracker. View is ungated beyond existing findings-view access.

## Dependencies
- Migration must land before API/UI.
- Worker deploy (Henry) for `finding_key` + `auto_ignored` to populate on fresh scans.
- Jira + Linear OAuth apps registered + secrets in worker/backend env before those adapters function.
- `schema:dump` after the migration (CI gate).

## Success Criteria
- `autoTriageRow()` + `finding-triage.ts` + the `phase48–52` SQL re-impl are **deleted**; one stored `auto_ignored` verdict, read everywhere.
- Count pills exactly equal the table's Open count — **zero drift** (the original pain).
- Ignoring a finding (with reason) keeps it out of Open + counts across rescans; un-ignore restores it.
- A finding can be pushed to Jira/Linear; chip links out; resolving the finding auto-closes the ticket.
- An auto-ignored finding that becomes reachable reappears in Open without manual action.

## Open Questions
- **`finding_key` definition per type** must exactly match the existing `finalize_extraction` carry-forward keys — _blocks /plan-feature (needs nailing down there)._
- **Default-role grant for `manage_findings`** (owner-only vs owner+member) — _can defer to /plan-feature._
- **Visible "Resolved" filter/tab** vs history-only — _can defer to /implement (UX detail)._
- **Backfill strategy** for existing `suppressed`/`risk_accepted` rows — _can defer to /plan-feature._
- Jira/Linear OAuth app registration — _informational/ops._

## Recommended Next Step
`/plan-feature` on this brief. (Separate, non-blocking track: richer Source→Sink trace in `VulnerabilityOrgSidebarExpandedContent.tsx` — also lifts the landing "trace the path" section.)

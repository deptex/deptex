---
name: ""
overview: ""
todos: []
isProject: false
---

# Usage Screen Redesign — Plan & Implementation Guide

## 1. Accuracy: Are We Showing the Right Limits?

**Current state**

- **Backend source of truth:** `backend/src/lib/plan-limits.ts` — `PLAN_LIMITS` and `getUsageSummary()` (counts from DB).
- **What the Usage screen shows today:** 5 metrics only:
  - Projects (current / limit)
  - Members (current / limit)
  - Syncs this period (current / limit)
  - Watched packages (watchtower) (current / limit)
  - Teams (current / limit)

**Plan limits in code (aligned with Plan & Billing copy)**


| Tier       | Projects | Members | Syncs | Watchtower | Teams | Notification rules | Integrations | Automations |
| ---------- | -------- | ------- | ----- | ---------- | ----- | ------------------ | ------------ | ----------- |
| Free       | 3        | 5       | 10    | 1          | 1     | 3                  | 5            | 0           |
| Pro        | 15       | 20      | 100   | 5          | 5     | 10                 | 10           | 5           |
| Team       | 50       | ∞       | 1000  | 20         | 20    | 25                 | 15           | 20          |
| Enterprise | ∞        | ∞       | ∞     | ∞          | ∞     | ∞                  | ∞            | ∞           |


**Conclusion**

- The numbers we show (projects, members, syncs, watchtower, teams) are **accurate** and come from the same limits the API enforces.
- We do **not** currently show: notification rules, integrations, automations (or API RPM). Decide:
  - **Option A:** Add these to the Usage screen so “usage” matches all plan limits.
  - **Option B:** Keep only the five we have and document that the rest are “internal” limits (still enforced by API).

**Recommendation:** Add at least **Notification rules** and **Integrations** to the Usage screen so it feels complete; automations (and API RPM) can stay backend-only unless you want them visible.

---

## 2. What the New Usage Screen Should Include

### 2.1 Header (top of page)

- **Title:** e.g. “Current usage” or “Usage this period” (not just “Usage”).
- **Plan + period in one line:** e.g. “**Free plan** · 1 Mar 2026 – 1 Apr 2026” (use `plan.current_period_start` / `plan.current_period_end` from API; if only `current_period_end` exists, show “Resets 1 Apr 2026” or “This period ends 1 Apr 2026”).
- **Billing cycle selector (future):** Dropdown “Current billing cycle” with option “Current” only until we have historical data. Later: “Mar 2026”, “Feb 2026”, etc. (requires backend to store or compute past periods.)

### 2.2 Main usage block (Supabase-style)

- **Card or section** with a short subtitle: e.g. “Usage against your plan limits. Resets at the end of the billing period.”
- **One row per metric:** each row has:
  - **Label** (e.g. “Projects”, “Members”, “Syncs this period”, “Watched packages”, “Teams”, and optionally “Notification rules”, “Integrations”).
  - **Progress bar:** horizontal bar showing `current / limit` (or “unlimited” with a different treatment).
  - **Numeric:** e.g. “2 / 3” or “2 / ∞”.
  - **Percentage** when not unlimited: e.g. “67%”.
- **Visual style:** Bar height ~8–12px, rounded, muted track; fill color by usage (e.g. green < 80%, amber 80–99%, red at 100%). Optional: circular progress (e.g. small ring) next to each row for a “spinner-like” look.
- **Hover tooltip on each row:** Short explanation (e.g. “Projects are repositories you’ve connected. Free plan includes 3.”) and optionally “Resets at period end.” Use existing `Tooltip` from `@/components/ui/tooltip.tsx` (Radix).

### 2.3 Teams breakdown (scroll down)

- **Section title:** “Usage by team” or “Teams”.
- **Content:** List of teams in the org with a simple usage indicator per team (e.g. “Projects: 2”, “Members: 3”). Data: from existing APIs (e.g. teams list + project counts per team). No new backend required if we already have team list and project counts.
- If we don’t have “usage per team” yet, show at least **team count** and **list of team names** with a note “Usage by team coming soon.”

### 2.4 Optional: graph “Teams over the month”

- **Idea:** Small chart: X = time (e.g. last 30 days or “this billing period”), Y = number of teams (or projects). Requires either:
  - Backend: snapshot or event log of “team count (and optionally project count) per day”, or
  - Frontend: only “current” snapshot (no history) — then we can’t draw a real time series; we could show a single “current” bar or skip the graph until we have history.
- **Recommendation:** Phase 1: skip graph or show a single “Current: X teams” summary. Phase 2: add a `usage_snapshots` or `billing_period_usage` table and daily/weekly snapshots, then add a small line or bar chart.

---

## 3. Data We Have vs What We Need


| Feature                 | Have today                     | Need for redesign                                                                               |
| ----------------------- | ------------------------------ | ----------------------------------------------------------------------------------------------- |
| Plan tier & limits      | Yes (plan from API)            | Nothing                                                                                         |
| Current usage counts    | Yes (usage from API)           | Nothing                                                                                         |
| Period end (reset date) | Yes (`current_period_end`)     | Optional: `current_period_start` for range                                                      |
| Period start            | In DB (`current_period_start`) | **Not currently in API** — add to getOrgPlan/plan response so frontend can show "1 Mar – 1 Apr" |
| Previous billing cycles | No                             | New table or derived from Stripe/history                                                        |
| Per-team usage          | Team list + project counts     | Optional: API that returns usage per team                                                       |
| Historical graph        | No                             | New snapshot/history table (Phase 2)                                                            |


---

## 4. Styling Guidelines (not “insane”, but not plain)

- **Layout:** Max-width content area; clear hierarchy (title → period → usage card → teams).
- **Cards:** Use existing `Card` (or equivalent) with subtle border and padding so the usage block and “Usage by team” feel like distinct sections.
- **Progress bars:** Rounded, 8–12px height; track `bg-muted`; fill `bg-primary` (or success/warning/danger by %). No tiny 1.5px bars.
- **Typography:** Keep existing font stack; use a clear “Usage” page title and a smaller “Free plan · 1 Mar – 1 Apr 2026” line; metric labels medium weight, numbers tabular.
- **Tooltips:** Use Radix Tooltip; dark theme friendly; one sentence + optional “Resets at period end.”
- **Spacing:** Consistent vertical rhythm (e.g. space-y-6 between sections, space-y-4 inside the usage list).

---

## 5. Implementation Checklist

- **Backend:** Ensure GET `/api/organizations/:id/billing/plan` (or equivalent) returns `current_period_start` and `current_period_end` so the frontend can show “1 Mar 2026 – 1 Apr 2026”.
- **Backend (optional):** Add notification_rules, integrations (and optionally automations) to the usage/limits payload if we want them on the Usage screen.
- **Frontend – Header:** Replace plain “Usage” with “Current usage” + one line: “[Plan name] plan · [period start] – [period end]” (or “Resets [date]” if no start).
- **Frontend – Billing cycle dropdown:** Add a select with one option “Current period” (and later hook up “Previous periods” when we have data).
- **Frontend – Usage card:** One card with subtitle; for each metric: label, progress bar (thick, rounded), “current / limit”, optional %, and tooltip on hover.
- **Frontend – Tooltips:** Define short copy per metric (Projects, Members, Syncs, Watchtower, Teams, etc.) and wrap each row (or label) in `Tooltip`.
- **Frontend – Teams section:** Below the usage card, “Usage by team” with team list and per-team project (and optionally member) count; or “X teams” + list of names.
- **Frontend – Optional graph:** Defer or implement a single “Current: X teams” until we have history; then add a small chart (e.g. recharts) when backend provides time-series data.

---

## 6. Prompt for Stitch AI (or Another AI) to Implement the Screen

Copy the block below into Stitch AI or another AI assistant to implement the Usage screen.

```
We're redesigning the "Usage" screen in Organization Settings (React + Tailwind + Radix UI).

Location: In OrganizationSettingsPage.tsx, the Usage tab renders UsageSectionContent. 
Data: We get plan + usage from usePlan() (PlanContext), which fetches GET /api/organizations/:id/billing/plan. 
The response includes: plan.tier, plan.usage (projects, members, syncs, watchtower, teams, notification_rules, integrations, automations), plan.limits (same keys), plan.current_period_end, plan.current_period_start (if backend sends it), plan.syncs_reset_at.

Requirements:

1. Header
   - Page title: "Current usage" (not just "Usage").
   - One line below: "[Plan name] plan · [period]" — e.g. "Free plan · 1 Mar 2026 – 1 Apr 2026". Use current_period_start and current_period_end if available; otherwise "Resets [current_period_end]".
   - Optional: a dropdown "Billing cycle" with single option "Current period" (for now).

2. Main usage section (Supabase-style)
   - One Card (or section with border/padding) containing:
     - Subtitle: "Usage against your plan limits. Resets at the end of the billing period."
     - For each of: Projects, Members, Syncs this period, Watched packages, Teams (and optionally Notification rules, Integrations):
       - Row with: label (left), progress bar (horizontal, 8–12px height, rounded), and "current / limit" (or "current / ∞") plus percentage when not unlimited.
       - Progress bar: muted background; fill color by usage (e.g. default primary; amber when ≥80%; red when ≥100%).
       - Wrap each row (or the label) in a Tooltip (from @/components/ui/tooltip) with a short explanation (e.g. "Projects are connected repositories. Free plan includes 3. Resets each billing period.").
   - Use plan.usage and plan.limits from usePlan(). Handle -1 (unlimited) so we don't show a percentage and show "∞" for the limit.

3. Teams section (below the usage card)
   - Section title: "Usage by team".
   - List teams in this organization with a brief usage line (e.g. "2 projects, 3 members" per team). If we don't have per-team usage from the current API, show the list of team names and "X teams" summary; we can add per-team counts later.
   - Teams can be fetched from the existing org/teams API or a similar endpoint used elsewhere in the app.

4. Styling
   - Use existing design system: Card, Tooltip, typography (text-foreground, text-foreground-secondary), spacing (space-y-4, space-y-6). Make progress bars clearly visible (not 1.5px). Keep the layout clean and readable; no clutter.

5. Don't break existing behavior
   - Keep loading and error states (skeleton, "Failed to load" + Try again). Keep usePlan() as the single source for plan/usage. If current_period_start is missing, derive or show only "Resets [date]".
```

---

## 7. Summary

- **Accuracy:** What we show (projects, members, syncs, watchtower, teams) is correct and matches `PLAN_LIMITS`. Optionally add notification_rules and integrations to the UI.
- **Redesign:** Clear header with plan + period, one main usage card with thick progress bars and tooltips, then a “Usage by team” section; billing cycle dropdown and historical graph can follow once we have the data.
- **Implementation:** Use the checklist in §5 and the Stitch AI prompt in §6 to implement the new Usage screen without changing backend behavior except optionally exposing period start and extra limit types.


---
name: Phase 15 - Security SLA Management
overview: Define per-severity remediation SLAs, track adherence across all projects, alert on approaching/breached deadlines, SLA compliance dashboard for audits, Aegis SLA-aware prioritization.
todos:
  - id: phase-15-slas
    content: "Phase 15: Security SLA Management - Org-configurable SLA thresholds per severity (critical 48h, high 7d, medium 30d, low 90d), per-vulnerability SLA timer tracking, breach detection via background cron, SLA countdown badges on vulnerability nodes/sidebars, SLA compliance dashboard in org settings with adherence rates and MTTR metrics, Aegis SLA-aware prioritization (approaching deadline = higher urgency), Phase 9 notification events for SLA warnings/breaches, exportable SLA compliance reports for SOC 2/ISO 27001/PCI DSS audits, Team+ tier feature gating, 40-test suite"
    status: pending
isProject: false
---
## Phase 15: Security SLA Management

**Goal:** Enable organizations to define maximum remediation timeframes (SLAs) per vulnerability severity, track adherence across all projects in real time, alert when deadlines approach or breach, and export SLA compliance data for regulatory audits. This is the #1 feature enterprises require for SOC 2, ISO 27001, and PCI DSS compliance.

**Prerequisites:** Phase 6 (Security tab with vulnerability tracking + `project_vulnerability_events` timeline), Phase 7B (Aegis with tool system + automations), Phase 9 (notification events), Phase 13 (plan tier gating -- SLAs available on Team+ plans).

**Timeline:** ~2-3 weeks. Mostly database + cron logic + dashboard UI. Leverages existing vulnerability tracking infrastructure heavily.

### What Is a Security SLA?

A Security SLA (Service Level Agreement) defines the maximum time allowed to remediate a vulnerability after detection, based on severity:

- **Critical**: Must be fixed within **48 hours** (2 days)
- **High**: Must be fixed within **7 days**
- **Medium**: Must be fixed within **30 days**
- **Low**: Must be fixed within **90 days**

"Fixed" means: the vulnerability no longer appears in the project after a re-extraction (package upgraded, code patched, or risk formally accepted with justification). SLA timers start at the `detected` event in `project_vulnerability_events`.

These thresholds are what auditors ask for. SOC 2 Type II requires demonstrating a "defined process for timely remediation of vulnerabilities." ISO 27001 Annex A.12.6 requires "timely identification and remediation." PCI DSS Requirement 6.3.3 requires patching critical vulns within 30 days (we default to stricter). Having configurable SLAs with tracked adherence is what turns "we fix things" into auditable evidence.

### 15A: SLA Configuration

**Database:**

```sql
CREATE TABLE organization_sla_policies (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  severity TEXT NOT NULL, -- 'critical', 'high', 'medium', 'low'
  max_hours INTEGER NOT NULL, -- remediation deadline in hours from detection
  warning_threshold_percent INTEGER DEFAULT 75, -- alert when X% of time elapsed
  enabled BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(organization_id, severity)
);

-- Seed defaults when an org enables SLAs
-- critical: 48h, high: 168h (7d), medium: 720h (30d), low: 2160h (90d)
```

**API Endpoints:**

- `GET /api/organizations/:id/sla-policies` -- list SLA thresholds (requires `manage_compliance`)
- `PUT /api/organizations/:id/sla-policies` -- update all thresholds at once (batch update, requires `manage_compliance`)
- `GET /api/organizations/:id/sla-policies/compliance` -- SLA compliance summary across all projects

**Frontend -- Org Settings:**

New "Security SLAs" section in Organization Settings (between "AI Configuration" and "Notifications"), gated by Team+ plan tier:

- Four rows, one per severity: severity badge + editable threshold input (hours or "Xd Yh" display) + warning threshold slider (default 75%) + enable/disable toggle
- "Reset to Defaults" link
- Info card: "SLAs define maximum remediation timeframes per severity. Timers start when a vulnerability is first detected. Aegis will prioritize fixes approaching their SLA deadline."
- If org is on Free/Pro: show locked state with "Upgrade to Team for Security SLAs" upgrade prompt

### 15B: SLA Timer Tracking

Each vulnerability in `project_dependency_vulnerabilities` gets SLA tracking fields:

```sql
ALTER TABLE project_dependency_vulnerabilities
  ADD COLUMN sla_deadline_at TIMESTAMPTZ,       -- computed: detected_at + max_hours
  ADD COLUMN sla_status TEXT DEFAULT 'on_track', -- 'on_track', 'warning', 'breached', 'met', 'exempt'
  ADD COLUMN sla_breached_at TIMESTAMPTZ,       -- when SLA was breached (if applicable)
  ADD COLUMN sla_met_at TIMESTAMPTZ,            -- when vuln was resolved within SLA
  ADD COLUMN sla_exempt_reason TEXT;             -- if manually exempted, the reason
```

**SLA computation flow:**

1. When a vulnerability is detected (extraction creates pdv row), look up the org's SLA policy for that severity
2. Compute `sla_deadline_at = detected_at + max_hours`
3. Set `sla_status = 'on_track'`
4. Background cron (15C) updates status as time passes

**SLA resolution events:**

When a vulnerability is resolved (pdv row removed or `resolved` event in timeline):
- If `NOW() <= sla_deadline_at`: set `sla_status = 'met'`, `sla_met_at = NOW()`
- If `NOW() > sla_deadline_at`: set `sla_status = 'breached'` (was already breached, now resolved late)

When a vulnerability is suppressed or risk-accepted:
- Set `sla_status = 'exempt'`, `sla_exempt_reason = 'Suppressed by [user]'` or `'Risk accepted by [user]: [reason]'`
- Exempt vulns are excluded from SLA compliance calculations but tracked separately for audit

**Backfill:** When an org first enables SLAs, run a one-time backfill that computes `sla_deadline_at` for all existing open vulnerabilities based on their `detected_at` (from `project_vulnerability_events`). Some may already be breached -- that's expected and shows the org their current state honestly.

### 15C: SLA Background Checker

Lightweight cron job (runs every 15 minutes via QStash):

```typescript
async function checkSLADeadlines() {
  // Find vulns approaching warning threshold
  const approaching = await supabase.rpc('get_sla_approaching_warning');
  for (const vuln of approaching) {
    await updateSLAStatus(vuln.id, 'warning');
    await emitNotificationEvent('sla_warning', {
      project_id: vuln.project_id,
      osv_id: vuln.osv_id,
      severity: vuln.severity,
      deadline_at: vuln.sla_deadline_at,
      hours_remaining: vuln.hours_remaining,
    });
  }

  // Find vulns that have breached SLA
  const breached = await supabase.rpc('get_sla_newly_breached');
  for (const vuln of breached) {
    await updateSLAStatus(vuln.id, 'breached');
    await supabase.from('project_dependency_vulnerabilities')
      .update({ sla_breached_at: new Date().toISOString() })
      .eq('id', vuln.id);
    await emitNotificationEvent('sla_breached', {
      project_id: vuln.project_id,
      osv_id: vuln.osv_id,
      severity: vuln.severity,
      deadline_at: vuln.sla_deadline_at,
      hours_overdue: vuln.hours_overdue,
    });
  }
}
```

**Supabase RPC functions:**

```sql
CREATE OR REPLACE FUNCTION get_sla_approaching_warning()
RETURNS TABLE(id UUID, project_id UUID, osv_id TEXT, severity TEXT,
              sla_deadline_at TIMESTAMPTZ, hours_remaining NUMERIC) AS $$
  SELECT pdv.id, pdv.project_id, pdv.osv_id, pv.severity, pdv.sla_deadline_at,
         EXTRACT(EPOCH FROM (pdv.sla_deadline_at - NOW())) / 3600 AS hours_remaining
  FROM project_dependency_vulnerabilities pdv
  JOIN project_vulnerabilities pv ON pdv.vulnerability_id = pv.id
  JOIN organization_sla_policies osp
    ON osp.organization_id = (SELECT organization_id FROM projects WHERE id = pdv.project_id)
    AND osp.severity = pv.severity AND osp.enabled = true
  WHERE pdv.sla_status = 'on_track'
    AND NOW() >= pdv.sla_deadline_at - (osp.max_hours * osp.warning_threshold_percent / 100.0 * INTERVAL '1 hour')
    AND NOW() < pdv.sla_deadline_at;
$$ LANGUAGE sql;

CREATE OR REPLACE FUNCTION get_sla_newly_breached()
RETURNS TABLE(id UUID, project_id UUID, osv_id TEXT, severity TEXT,
              sla_deadline_at TIMESTAMPTZ, hours_overdue NUMERIC) AS $$
  SELECT pdv.id, pdv.project_id, pdv.osv_id, pv.severity, pdv.sla_deadline_at,
         EXTRACT(EPOCH FROM (NOW() - pdv.sla_deadline_at)) / 3600 AS hours_overdue
  FROM project_dependency_vulnerabilities pdv
  JOIN project_vulnerabilities pv ON pdv.vulnerability_id = pv.id
  WHERE pdv.sla_status IN ('on_track', 'warning')
    AND NOW() > pdv.sla_deadline_at;
$$ LANGUAGE sql;
```

**Notification events (Phase 9 integration):**

- `sla_warning` -- vulnerability approaching SLA deadline. Default delivery: Slack channel + in-app.
- `sla_breached` -- SLA deadline passed without remediation. Default delivery: Slack DM to project owner + email to org admin + in-app. High urgency.

### 15D: SLA UI Integration

**Vulnerability nodes (Security tab graph):**

- When a vulnerability is in `warning` status: small clock icon badge (amber-500) on the node with tooltip "SLA: 6h remaining"
- When `breached`: clock icon turns red-500 with tooltip "SLA: breached 2 days ago"
- Sorting: SLA-approaching vulns float to the top of any vulnerability list

**Vulnerability Detail Sidebar (6D):**

New "SLA Status" card between the Risk Badges Row and the Risk Assessment Card:

- **On track**: green clock icon + "SLA: 5 days remaining" + thin progress bar (green-500, width = % elapsed)
- **Warning**: amber clock icon + "SLA: 6 hours remaining" + progress bar (amber-500, nearly full) + pulse animation
- **Breached**: red clock icon + "SLA BREACHED: 2 days overdue" + red banner + "Immediate action required"
- **Met**: green check + "SLA met: resolved in 3 days (deadline was 7 days)"
- **Exempt**: gray shield + "SLA exempt: Risk accepted by [user] on [date]"

**Dependency Detail Sidebar (6E):**

Under "Current Vulnerabilities" list: each vulnerability row shows a small SLA indicator (colored clock icon + "Xd left" or "BREACHED" text).

**Project Security Sidebar (6F):**

New "SLA Summary" card:
- "SLA Compliance: 87%" (green/amber/red based on threshold)
- Breakdown: "0 breached, 2 warning, 14 on track, 3 exempt"
- "View SLA Dashboard" link

**Org/Team Security pages:**

- Aggregate SLA stats per project node: "SLA: 2 breached" in red text below the project name
- Filter bar: add "SLA Status" filter (On Track / Warning / Breached / Exempt)

### 15E: SLA Compliance Dashboard

New page or section accessible from:
- Org Settings > Security SLAs > "View Dashboard" button
- Org Security page > "SLA Compliance" tab
- Aegis screen (Aegis can link to it)

**Dashboard layout:**

Top row -- three metric cards:
- "Overall SLA Compliance": percentage of vulns resolved within SLA in the selected period. Color-coded (>90% green, 70-90% amber, <70% red).
- "Current Breaches": count of open vulns currently past their SLA deadline. Red if > 0.
- "Average MTTR": mean time to remediation across all resolved vulns, broken down by severity.

Middle row -- SLA adherence chart:
- Stacked bar chart by month (last 6 months): green = met within SLA, amber = met late (after breach), red = still open and breached, gray = exempt.
- Shows trend over time -- are we getting better or worse?

Table -- Current SLA violations:
- Columns: Project, Vulnerability (OSV ID), Severity, Detected, Deadline, Overdue By, Assignee (who triggered the last fix attempt), Status (active fix? PR open?)
- Sorted by most overdue first
- Each row clickable: navigates to the vulnerability detail sidebar
- "Fix with AI" bulk action: select multiple breached vulns and trigger a sprint

Bottom row -- Per-team breakdown:
- Table: Team name, Total vulns, On track %, Warning count, Breached count, Avg MTTR
- Helps identify which teams need help

**Export:**
- "Export SLA Report" button: generates a PDF/CSV with all SLA compliance data for the selected period
- Suitable for attaching to SOC 2 Type II audit evidence packages
- Integrates with Aegis `generateAuditPackage` tool (Phase 7B-H): SLA report automatically included in audit packages

**Stitch AI Prompt for SLA Compliance Dashboard:**

> Design an SLA Compliance Dashboard page for Deptex (dark theme: bg #09090b, cards #18181b, borders #27272a 1px, text #fafafa, secondary #a1a1aa, accent green #22c55e, warning amber #f59e0b, breach red #ef4444). This is a full-width page accessible from Org Settings > Security SLAs and from the Org Security page. Font: Inter body, JetBrains Mono for numbers/timestamps/percentages. 8px border-radius. No gradients, no shadows. Ultra-minimal Linear/Vercel style.
>
> **Page header** (px-6, py-5, border-b zinc-800):
> - Left: "SLA Compliance" title in 22px semibold + clock icon (zinc-400). Below: "Track remediation deadlines and compliance across all projects." in 14px zinc-400.
> - Right: time range selector -- segmented control with "30 Days" / "90 Days" / "6 Months" / "1 Year" (zinc-800 bg, zinc-700 border, 13px, 32px tall, rounded-lg, active segment: zinc-700 bg white text). Far right: "Export Report" button (zinc-700 bg, download icon, 13px zinc-200 text, rounded-md, 32px height).
>
> **Top row -- Metric cards** (px-6, py-4, three cards side-by-side, equal width, 12px gap):
>
> - Card 1 (zinc-900 bg, zinc-800 border, rounded-lg, p-4): "Overall SLA Compliance" label 11px uppercase zinc-500 tracking-wider. Main number: "87%" in 36px semibold (color: green-500 if >90%, amber-500 if 70-90%, red-500 if <70%). Below: "142 of 163 vulnerabilities resolved within SLA" in 12px zinc-400. Thin divider (zinc-800, my-3). "vs last period: +4%" in 12px green-500 (or red-500 if negative), with up/down arrow icon.
>
> - Card 2: "Current Breaches" label. Main number: "3" in 36px semibold red-500 (or "0" in green-500). Below: "2 critical, 1 high" in 12px zinc-400 (or "All vulnerabilities within SLA" in 12px green-500). Thin divider. "Oldest breach: 48h overdue" in 12px red-400.
>
> - Card 3: "Average MTTR" label. Main number: "4.2 days" in 36px semibold zinc-200. Below breakdown by severity in 12px zinc-400: "Critical: 1.8d | High: 3.5d | Medium: 12.4d | Low: 28.1d" with color-coded dots (red, amber, yellow, green) before each. Thin divider. "vs last period: -1.3 days" in 12px green-500.
>
> **Middle row -- SLA Adherence Trend** card (mx-6, mt-4, zinc-900 bg, zinc-800 border, rounded-lg, p-5):
>
> - Header: "SLA Adherence Over Time" 15px semibold left. Right: legend -- four colored squares (8px rounded-sm) with labels: "Met" (green-500), "Met Late" (amber-500), "Breached" (red-500), "Exempt" (zinc-600). Labels 12px zinc-400.
> - Stacked bar chart (full width, 180px height). X-axis: months (12px zinc-500, "Oct", "Nov", "Dec", "Jan", "Feb", "Mar"). Y-axis: count (12px zinc-500). Bars: stacked vertically with colors from legend. Bar width ~40px, rounded-t-sm on top bar, 8px gap between months. Tooltip on hover: "February 2026: 48 met, 3 met late, 2 breached, 5 exempt".
>
> **Table -- Current SLA Violations** card (mx-6, mt-4, zinc-900 bg, zinc-800 border, rounded-lg, p-5):
>
> - Header: "Current Violations" 15px semibold left. Count badge right of title (red-500 bg, white text, 11px, min-w-5, rounded-full, centered). Right: "Fix Selected with AI" button (green-500 bg, white text, sparkle icon, 13px, rounded-md, 32px height, disabled/zinc-700 when no rows selected).
> - Table. Columns: checkbox (16px), "Project" (13px zinc-200 semibold, project icon), "Vulnerability" (JetBrains Mono 12px green-500, clickable link), "Severity" (pill: critical=red-500, high=amber-500, medium=yellow-500, 10px rounded-full px-2), "Detected" (JetBrains Mono 12px zinc-400 "Feb 12"), "Deadline" (JetBrains Mono 12px zinc-400 "Feb 14"), "Overdue By" (JetBrains Mono 12px semibold red-500 "2d 6h" -- larger/bolder for more overdue), "Assignee" (user avatar 20px + name 12px zinc-400, or "Unassigned" in zinc-600), "Status" (pill: "Active Fix" green-500/15 bg green-500 text with spinner, "PR Open" blue-500/15 bg, "No Action" zinc-700 bg zinc-400 text).
> - Rows: zinc-800/50 border. Hover: bg-zinc-800/30. Click: navigates to vulnerability detail sidebar. Sorted by "Overdue By" descending (most overdue first).
> - Selected rows: checkbox checked, subtle green-500/5 row bg.
> - Empty state: "No SLA violations -- all vulnerabilities are within their remediation deadlines." in 14px zinc-500 centered with green check-circle icon above.
>
> **Bottom row -- Per-Team Breakdown** card (mx-6, mt-4, mb-6, zinc-900 bg, zinc-800 border, rounded-lg, p-5):
>
> - Header: "Team Performance" 15px semibold left. Right: sort dropdown ("Sort by: Breached count" / "On Track %" / "Avg MTTR", zinc-800 bg, 12px).
> - Table. Columns: "Team" (14px semibold zinc-200, team icon), "Total Vulns" (JetBrains Mono 13px zinc-400), "On Track" (percentage with colored bar -- green-500 bar, 80px wide 4px tall, JetBrains Mono 12px), "Warning" (count, amber-500 text if > 0), "Breached" (count, red-500 text if > 0, semibold), "Avg MTTR" (JetBrains Mono 12px zinc-400, "3.2d").
> - Rows: zinc-800/50 border. Hover: bg-zinc-800/30.
> - Row with breaches: subtle red-500/5 bg to highlight teams needing help.

### 15F: Aegis SLA-Aware Prioritization

Aegis's `suggestFixPriority` tool already ranks vulnerabilities by Depscore. With SLAs, add SLA urgency as a top-level factor:

**Priority ranking formula (updated):**

```
urgency = (
  sla_approaching_weight * (1 - hours_remaining / max_hours)  // 0-1, higher = more urgent
  + depscore_weight * (depscore / 100)                         // 0-1
  + reachability_weight * reachability_factor                  // 0-1
)
```

Where `sla_approaching_weight = 0.4` (SLA is the strongest signal), `depscore_weight = 0.35`, `reachability_weight = 0.25`.

A breached SLA vuln always ranks above non-breached, regardless of Depscore.

**Aegis proactive behavior:**

- Daily briefing automation (7B-E template) includes SLA section: "3 vulnerabilities approaching SLA deadline in the next 24 hours. Recommend starting a fix sprint for [project]."
- When user asks "what should I fix first?", Aegis explicitly mentions SLA status: "CVE-2024-XXXX should be your top priority -- it breaches SLA in 6 hours."
- Autopilot mode: Aegis can auto-trigger fixes for vulnerabilities approaching SLA breach (configurable in Aegis management console)

**New Aegis tools:**

- `getSLAStatus(projectId?)` -- returns SLA compliance summary, breached items, approaching items
- `getSLAReport(timeRange?)` -- generates exportable SLA compliance report

### 15G: Phase 15 Test Suite

#### Backend Tests (`backend/src/__tests__/security-slas.test.ts`)

Tests 1-8 (SLA Configuration):
1. Creating SLA policies for all four severities stores correct `max_hours` values
2. Updating SLA threshold changes `sla_deadline_at` for all affected open vulnerabilities
3. Disabling an SLA severity sets affected vulns to `sla_status = 'exempt'` with reason "SLA disabled"
4. Only `manage_compliance` permission can modify SLA policies
5. Free/Pro tier orgs cannot access SLA endpoints (returns 403 with upgrade message)
6. Backfill computes correct deadlines for existing open vulnerabilities
7. Backfill correctly identifies already-breached vulns (detected_at + max_hours < now)
8. Default thresholds seeded correctly on first enable (48h/168h/720h/2160h)

Tests 9-16 (SLA Tracking):
9. New vulnerability detection sets `sla_deadline_at = detected_at + max_hours`
10. Vulnerability resolved before deadline: `sla_status = 'met'`, `sla_met_at` set
11. Vulnerability resolved after deadline: `sla_status = 'breached'`, both `breached_at` and `met_at` set
12. Suppressed vulnerability: `sla_status = 'exempt'`, `sla_exempt_reason` contains user and action
13. Risk-accepted vulnerability: `sla_status = 'exempt'`, reason contains user and justification
14. Background checker transitions `on_track` to `warning` at correct threshold
15. Background checker transitions `warning`/`on_track` to `breached` when deadline passes
16. `sla_warning` and `sla_breached` notification events emitted with correct payloads

Tests 17-24 (SLA Dashboard):
17. Compliance percentage calculated correctly: met / (met + breached) * 100
18. Exempt vulns excluded from compliance calculation
19. MTTR computed correctly from detected_at to resolved event timestamp
20. Per-team breakdown aggregates correctly across team projects
21. Monthly adherence chart data returns correct counts per bucket (met/late/breached/exempt)
22. Export generates valid CSV with all required audit fields
23. SLA report included in Aegis `generateAuditPackage` output
24. Dashboard data filtered by date range correctly

#### Frontend Tests (`frontend/src/__tests__/security-slas-ui.test.ts`)

Tests 25-32 (SLA UI):
25. SLA configuration section visible only on Team+ plans, shows upgrade prompt on Free/Pro
26. Vulnerability node shows amber clock badge when SLA status is `warning`
27. Vulnerability node shows red clock badge when SLA status is `breached`
28. Vulnerability Detail Sidebar renders SLA status card with correct state and countdown
29. Project Security Sidebar shows SLA compliance percentage and breakdown
30. Org Security page shows aggregate SLA breach counts per project node
31. SLA filter in filter bar correctly shows/hides vulns by SLA status
32. SLA compliance dashboard renders all sections with correct metrics

Tests 33-40 (Aegis SLA Integration):
33. `suggestFixPriority` ranks breached vulns above non-breached regardless of Depscore
34. `suggestFixPriority` ranks approaching-deadline vulns higher (SLA weight 0.4)
35. Aegis daily briefing includes SLA section with approaching deadlines
36. Aegis responds to "what should I fix?" with SLA context in the recommendation
37. `getSLAStatus` tool returns correct compliance summary
38. `getSLAReport` tool generates exportable report
39. Aegis autopilot auto-triggers fix for vuln within 6 hours of SLA breach
40. Aegis mentions SLA when user asks about a specific vulnerability that's approaching deadline

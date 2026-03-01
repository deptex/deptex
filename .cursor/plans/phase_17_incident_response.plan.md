---
name: Phase 17 - Incident Response Orchestration
overview: Multi-phase security incident playbooks with automated containment, assessment, communication, remediation, verification, and reporting. Customizable playbooks for zero-day, supply chain compromise, secret leak, and compliance breach scenarios.
todos:
  - id: phase-17-incident-response
    content: "Phase 17: Incident Response Orchestration - 6-phase IR framework (Contain, Assess, Communicate, Remediate, Verify, Report), 4 pre-built playbook templates (zero-day, supply chain compromise, secret exposure, compliance breach), custom playbook builder via Aegis chat or management console, playbook execution as aegis_task with per-phase steps, automated containment actions (emergency package lock, branch protection), stakeholder communication templates (Slack, email, status page), multi-project parallel assessment, remediation via Phase 7 fix sprints, verification via re-extraction, auto-generated incident post-mortem report, incident timeline with audit trail, Aegis autonomous mode for time-critical incidents, incident history dashboard, 36-test suite"
    status: pending
isProject: false
---
## Phase 17: Incident Response Orchestration

**Goal:** Transform Aegis's existing zero-day rapid response (7B-I) into a full incident response framework with multi-phase playbooks, automated containment, stakeholder communication, and post-mortem generation. When a critical security event occurs -- zero-day CVE, supply chain compromise, leaked secret, compliance breach -- Aegis executes a structured playbook that handles everything from locking down affected packages to generating the final incident report.

**Prerequisites:** Phase 7 (fix engine), Phase 7B (Aegis task system + tools + automations + Slack), Phase 8 (PR webhooks for branch protection), Phase 9 (notification events for alerting), Phase 15 (SLAs for deadline-aware triage).

**Timeline:** ~3-4 weeks. Builds heavily on the existing Aegis task system (7B-C) -- playbooks are specialized task types with domain-specific steps.

### The 6-Phase Incident Response Model

Every security incident, regardless of type, follows the same six phases:

```
CONTAIN --> ASSESS --> COMMUNICATE --> REMEDIATE --> VERIFY --> REPORT
  (stop       (what's      (tell           (fix          (confirm     (document
  bleeding)   affected?)   people)         it)           it's fixed)  everything)
```

Each phase maps to Aegis tools and actions. Playbooks define which tools run in each phase, in what order, and what decisions require human approval.

### 17A: Incident & Playbook Data Model

```sql
CREATE TABLE incident_playbooks (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  trigger_type TEXT NOT NULL,           -- 'zero_day', 'supply_chain', 'secret_exposure',
                                        -- 'compliance_breach', 'custom'
  trigger_criteria JSONB,               -- auto-trigger conditions (e.g., severity >= critical AND kev = true)
  phases JSONB NOT NULL,                -- ordered array of phase definitions (see below)
  auto_execute BOOLEAN DEFAULT false,   -- if true, runs autonomously when triggered
  requires_approval_at TEXT[],          -- which phases need human approval before proceeding
  notification_channels JSONB,          -- per-phase notification config
  is_template BOOLEAN DEFAULT false,    -- pre-built templates
  enabled BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE security_incidents (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  playbook_id UUID REFERENCES incident_playbooks(id),
  task_id UUID REFERENCES aegis_tasks(id),        -- the Aegis task executing this incident
  title TEXT NOT NULL,
  incident_type TEXT NOT NULL,
  severity TEXT NOT NULL,                           -- 'critical', 'high', 'medium'
  status TEXT NOT NULL DEFAULT 'active',            -- 'active', 'contained', 'remediating',
                                                    -- 'verifying', 'resolved', 'closed'
  current_phase TEXT NOT NULL DEFAULT 'contain',    -- which IR phase we're in
  trigger_source TEXT,                              -- what triggered: 'cve_alert', 'watchtower',
                                                    -- 'manual', 'aegis_automation'
  trigger_data JSONB,                               -- the triggering event data
  
  -- Scope
  affected_projects UUID[],                         -- projects impacted
  affected_packages TEXT[],                         -- package names
  affected_cves TEXT[],                             -- CVE/OSV IDs
  
  -- Metrics
  time_to_contain_ms BIGINT,
  time_to_remediate_ms BIGINT,
  total_duration_ms BIGINT,
  fixes_created INTEGER DEFAULT 0,
  prs_merged INTEGER DEFAULT 0,
  
  -- Output
  post_mortem TEXT,                                 -- generated post-mortem markdown
  post_mortem_url TEXT,                             -- link to stored PDF
  
  declared_at TIMESTAMPTZ DEFAULT NOW(),
  contained_at TIMESTAMPTZ,
  remediated_at TIMESTAMPTZ,
  resolved_at TIMESTAMPTZ,
  closed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE incident_timeline (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  incident_id UUID NOT NULL REFERENCES security_incidents(id) ON DELETE CASCADE,
  phase TEXT NOT NULL,
  event_type TEXT NOT NULL,    -- 'phase_started', 'action_taken', 'approval_requested',
                               -- 'approval_granted', 'notification_sent', 'fix_started',
                               -- 'fix_completed', 'verification_passed', 'note_added'
  description TEXT NOT NULL,
  actor TEXT,                  -- 'aegis', user name, or 'system'
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_si_org_status ON security_incidents(organization_id, status);
CREATE INDEX idx_it_incident ON incident_timeline(incident_id, created_at);
```

**Phase definition structure** (stored in `incident_playbooks.phases` JSONB):

```typescript
interface PlaybookPhase {
  phase: 'contain' | 'assess' | 'communicate' | 'remediate' | 'verify' | 'report';
  name: string;
  steps: PlaybookStep[];
  requiresApproval: boolean;
  timeoutMinutes?: number;    // auto-escalate if phase takes too long
}

interface PlaybookStep {
  id: string;
  tool: string;               // Aegis tool name
  params: Record<string, any>; // tool parameters (can reference incident context via $variables)
  condition?: string;          // skip if condition is false (e.g., "$affected_projects.length > 5")
  onFailure: 'continue' | 'pause' | 'abort';
}
```

### 17B: Pre-Built Playbook Templates

**1. Zero-Day CVE Response** (`trigger_type: 'zero_day'`):

Auto-trigger: critical CVE with `cisa_kev = true` or EPSS > 0.7 affecting any org project.

| Phase | Steps | Approval |
|-------|-------|----------|
| Contain | `emergencyLockdownPackage` -- pin affected package across all projects to prevent further spread | Yes (dangerous) |
| Assess | `assessBlastRadius` -- which projects, how used, reachable?; `getSLAStatus` -- any approaching SLA deadlines? | No |
| Communicate | `sendSlackMessage` to #security with blast radius summary; `sendEmail` to org admins; create `incident_timeline` entry | No |
| Remediate | `createSecuritySprint` for affected projects ranked by Depscore; execute sprint (sequential fixes) | Propose mode: Yes |
| Verify | `triggerExtraction` for each affected project; verify CVE no longer appears in results | No |
| Report | `generateSecurityReport` for the incident; compute MTTR; generate post-mortem | No |

**2. Supply Chain Compromise** (`trigger_type: 'supply_chain'`):

Auto-trigger: Watchtower anomaly score > 80 for a package, or malicious indicator detected.

| Phase | Steps |
|-------|-------|
| Contain | `emergencyLockdownPackage` -- block the compromised version org-wide; flag in all PRs |
| Assess | `assessBlastRadius` -- full usage analysis across org; check if malicious payload was executed (via atom reachability) |
| Communicate | Alert: "Potential supply chain compromise detected in [package]"; include confidence level and evidence |
| Remediate | If safe version exists: sprint to downgrade/remove; if no safe version: `remove_unused` or `add_wrapper` strategies |
| Verify | Re-extract all affected projects; verify compromised version no longer in dependency tree |
| Report | Supply chain incident report with: detection timeline, affected scope, actions taken, residual risk |

**3. Secret Exposure** (`trigger_type: 'secret_exposure'`):

Auto-trigger: TruffleHog finding with `is_verified = true` (confirmed active credential).

| Phase | Steps |
|-------|-------|
| Contain | Alert: "Active credential exposed in [repo]"; guidance: "Rotate this credential immediately" |
| Assess | Check if secret is in git history only or current code; identify all repos that might share the credential |
| Communicate | Notify project owner + security team; include redacted finding details (never the actual secret) |
| Remediate | `remediate_secret` strategy to replace hardcoded value with env var; remind user to rotate the actual credential |
| Verify | Re-extract; verify `is_current = false` for the finding |
| Report | Secret exposure report with: detection time, exposure window, rotation confirmation |

**4. Compliance Breach** (`trigger_type: 'compliance_breach'`):

Auto-trigger: policy evaluation changes a project's status from passing to non-passing, OR SLA breach occurs.

| Phase | Steps |
|-------|-------|
| Contain | Identify scope: which projects, which policies, which violations |
| Assess | Impact analysis: "12 packages across 3 projects are now non-compliant due to new GPL policy" |
| Communicate | Notify compliance team; include violation details and estimated remediation effort |
| Remediate | Generate exception requests for low-risk items; create sprint for remaining violations |
| Verify | Re-run policy evaluation; confirm all projects back to passing |
| Report | Compliance incident report with: root cause, scope, actions, time to resolution |

### 17C: Playbook Execution Engine

Playbooks execute as specialized Aegis tasks (reuses 7B-C task system):

```typescript
async function executePlaybook(incident: SecurityIncident, playbook: IncidentPlaybook) {
  // Create Aegis task
  const task = await createAegisTask({
    title: `Incident Response: ${incident.title}`,
    mode: playbook.auto_execute ? 'autonomous' : 'plan',
    plan_json: playbook.phases,
  });
  
  // Update incident with task reference
  await updateIncident(incident.id, { task_id: task.id });
  
  for (const phase of playbook.phases) {
    // Log phase start
    await addTimelineEvent(incident.id, phase.phase, 'phase_started', `Starting ${phase.name}`);
    await updateIncident(incident.id, { current_phase: phase.phase });
    
    // Check if approval is needed
    if (phase.requiresApproval) {
      await requestApproval(incident, phase);
      // Pause until approved -- approval comes via Aegis approval system (7B-B)
    }
    
    // Execute steps
    for (const step of phase.steps) {
      // Evaluate condition
      if (step.condition && !evaluateCondition(step.condition, incident)) {
        await addTimelineEvent(incident.id, phase.phase, 'action_taken', 
          `Skipped ${step.tool}: condition not met`);
        continue;
      }
      
      // Resolve $variables in params
      const resolvedParams = resolveVariables(step.params, incident);
      
      // Execute the Aegis tool
      const result = await executeTool(step.tool, resolvedParams);
      
      await addTimelineEvent(incident.id, phase.phase, 'action_taken',
        `${step.tool}: ${result.success ? 'success' : 'failed'}`);
      
      if (!result.success && step.onFailure === 'pause') {
        await pauseIncident(incident, step, result.error);
        break;
      }
      if (!result.success && step.onFailure === 'abort') {
        await abortIncident(incident, step, result.error);
        return;
      }
    }
    
    // Update phase timestamp
    if (phase.phase === 'contain') await updateIncident(incident.id, { contained_at: new Date() });
    if (phase.phase === 'remediate') await updateIncident(incident.id, { remediated_at: new Date() });
    
    // Phase timeout escalation
    if (phase.timeoutMinutes) {
      scheduleEscalation(incident.id, phase.phase, phase.timeoutMinutes);
    }
  }
  
  // Incident resolved
  await updateIncident(incident.id, {
    status: 'resolved',
    resolved_at: new Date(),
    total_duration_ms: Date.now() - incident.declared_at.getTime(),
  });
}
```

### 17D: Incident UI

**Aegis screen integration:**

Incidents appear as high-priority items in the Aegis left sidebar, above Active Tasks:

- "ACTIVE INCIDENTS" section with red indicator when any incident is active
- Each incident card: severity badge (red/amber) + title + current phase badge + time since declared
- Clicking opens the incident detail view in the main panel

**Incident detail view** (replaces chat view when incident selected):

- Header: incident title + severity badge + status badge + declared time + "Resolve" / "Close" buttons
- Phase progress bar: six segments (Contain -> Assess -> Communicate -> Remediate -> Verify -> Report), current phase highlighted, completed phases green
- Timeline: full chronological event log from `incident_timeline`. Each event: timestamp + phase badge + actor (Aegis/user) + description. Expandable for metadata.
- Right panel: affected projects list, affected packages, affected CVEs (clickable to their detail sidebars)

**Incident history:**

Accessible from Aegis management console > new "Incidents" tab:

- Table of past incidents: date, type, severity, duration, affected projects count, resolution
- Click to view full timeline and post-mortem
- Filter by type, severity, date range
- Export for audit purposes

**Stitch AI Prompt for Incident Detail View (Aegis Screen):**

> Design an incident response detail view within the Aegis three-panel screen for Deptex (dark theme: bg #09090b, cards #18181b, borders #27272a 1px, text #fafafa, secondary #a1a1aa, accent green #22c55e, critical red #ef4444, high amber #f59e0b). This view replaces the chat view in the main panel when an incident is selected from the left sidebar. Font: Inter body, JetBrains Mono for timestamps/IDs. 8px border-radius. No gradients, no shadows.
>
> **Left sidebar context (already rendered by Aegis screen):** Above the "Active Tasks" section, add a new "ACTIVE INCIDENTS" section header (11px uppercase, red-400, tracking-wider, with a red pulsing dot left of the text when incidents exist). Below: incident cards (zinc-900 bg, red-500/10 border-l-2, rounded-r-md, p-3, mb-1). Each card: severity pill (red-500 bg "Critical" or amber-500 bg "High", 10px font, rounded-full, px-2) + title (13px semibold white, max 1 line truncate) on first line. Second line: current phase badge ("Remediate" in amber-500/15 bg, amber-500 text, 10px, rounded-sm, px-1.5) + "12m ago" in zinc-500 11px. Active/selected card: bg-zinc-800, white left border instead of red.
>
> **Main panel -- Incident Detail View:**
>
> Header bar (border-b zinc-800, px-6, py-4, flex between):
> - Left: severity badge (large, 12px, rounded-sm, px-2 py-0.5, red-500 bg white text for critical, amber-500 bg for high) + incident title "Zero-Day: CVE-2024-XXXX in lodash" in 18px semibold + status badge ("Active" with pulsing amber dot, or "Resolved" with green check, zinc-700 bg, 12px, rounded-full, px-2.5).
> - Right: "Declared 42m ago" in 13px zinc-400. Below: two buttons side-by-side -- "Resolve" (green-500 bg, white text, 13px, rounded-md, 32px height, check icon) and "Close" (zinc-700 bg, zinc-300 text, same size, x icon).
>
> Phase progress bar (px-6, py-4, border-b zinc-800):
> - Six connected segments in a horizontal row, each ~120px wide, 40px tall.
> - Each segment: rounded-md, 1px border. Content: phase icon (16px) above phase name (11px semibold uppercase).
> - Segment states: Completed = green-500/15 bg, green-500 border, green-500 text, green check icon. Current = amber-500/15 bg, amber-500 border, amber-500 text, animated spinner icon. Upcoming = zinc-900 bg, zinc-800 border, zinc-500 text, circle icon.
> - Between segments: thin connecting line (2px, zinc-700, green-500 if segment before it is completed).
> - Phases in order: Contain (shield icon), Assess (search icon), Communicate (megaphone icon), Remediate (wrench icon), Verify (check-circle icon), Report (file-text icon).
>
> Timeline section (flex-1, overflow-y-auto, px-6, py-4):
> - Each event is a row with left-aligned layout:
>   - Left column (60px): timestamp in JetBrains Mono 11px zinc-500. Format: "14:30" for same day, "Feb 28 14:30" for older.
>   - Vertical timeline line: 2px zinc-800 connecting all events. Event dots: 8px circles on the line. Green for completed actions, amber for current, red for failures.
>   - Content column: phase badge (same style as progress bar but smaller, 10px, inline) + actor badge ("Aegis" with sparkle icon in green-500/15 bg, or user name in zinc-700 bg, 10px) + description text (13px zinc-200).
>   - Expandable: events with metadata show a "Details" link (zinc-400, 11px). Expands to show JSON or structured data in a zinc-950 bg code block with JetBrains Mono 11px.
> - Events grouped by phase with a subtle phase header between groups (11px uppercase zinc-600, border-b zinc-800/50).
>
> **Right panel (conditional, ~320px):**
> - Header: "Affected Scope" 14px semibold, zinc-300.
> - Section 1 -- "Projects" (count badge): list of affected project names with colored dots (red if still affected, green if remediated). Click navigates to project.
> - Section 2 -- "Packages" (count badge): affected package names with version in JetBrains Mono 12px zinc-400.
> - Section 3 -- "Vulnerabilities" (count badge): OSV IDs as clickable links (green-500, JetBrains Mono 12px) that open the vulnerability detail sidebar.
> - Section 4 -- "Fixes" (appears during/after Remediate phase): list of fix jobs with status badges (running spinner, completed check, failed x).

**Stitch AI Prompt for Incidents Tab (Management Console):**

> Design an "Incidents" tab inside the Aegis AI management console for Deptex (dark theme: bg #09090b, cards #18181b, borders #27272a 1px, text #fafafa, secondary #a1a1aa, accent green #22c55e, critical red #ef4444, high amber #f59e0b). This tab is one of 9 tabs in the management console. Content area is ~900px wide. Font: Inter body, JetBrains Mono for timestamps/IDs. 8px border-radius.
>
> **Top row -- Incident metrics** (three cards side-by-side, zinc-900 bg, zinc-800 border, p-4, equal width):
> - Card 1: "Active Incidents" -- count in 28px semibold (red-500 if > 0, green-500 if 0). Below: severity breakdown "1 critical, 1 high" in 12px zinc-400. If 0: "No active incidents" in 12px green-500.
> - Card 2: "Avg Resolution Time" -- "4h 12m" in 28px semibold zinc-200. Below: "across 14 incidents" in 12px zinc-400.
> - Card 3: "Incidents This Month" -- count in 28px semibold. Below: "X resolved, Y active" in 12px zinc-400.
>
> **Section 1 -- "Playbooks"** card (zinc-900 bg, zinc-800 border, rounded-lg, p-5):
>
> - Header: "Response Playbooks" 15px semibold left. Right: "Create Playbook" button (green-500 bg, white text, plus icon, rounded-md, 32px height, 13px).
> - List of playbook cards (zinc-800/50 border between rows, py-3):
>   - Left: playbook icon (shield for zero-day, box for supply chain, key for secret, clipboard for compliance, puzzle for custom) in zinc-500. Name "Zero-Day CVE Response" in 14px semibold zinc-200. Below: trigger criteria summary "Triggers on: critical CVE with CISA KEV = true or EPSS > 0.7" in 12px zinc-400.
>   - Center: "Auto-execute" toggle (green-500 when on, zinc-600 when off) with label "Auto" in 11px zinc-500.
>   - Right: "Used 5 times" in 12px zinc-400. Overflow menu (...): Edit, Dry Run, Duplicate, Delete.
> - 4 pre-built templates shown first (labeled "Template" pill in zinc-700 bg, 10px), then custom playbooks.
>
> **Section 2 -- "Incident History"** card (zinc-900 bg, zinc-800 border, rounded-lg, p-5):
>
> - Header: "Incident History" 15px semibold left. Right: filter row -- type dropdown ("All Types"), severity dropdown ("All Severities"), date range picker. Far right: "Export" button (zinc-700 bg, download icon, 12px).
> - Table layout. Columns: "Date" (JetBrains Mono 12px zinc-400, "Feb 28, 2026"), "Incident" (title in 13px zinc-200 semibold, truncate at 40 chars), "Type" (pill: "Zero-Day" red-500/15 bg red-400 text, "Supply Chain" amber-500/15 bg amber-400 text, "Secret" purple-500/15 bg purple-400 text, "Compliance" blue-500/15 bg blue-400 text), "Severity" (pill, same style as type badges but red/amber), "Duration" (JetBrains Mono 12px zinc-400 "4h 12m"), "Projects" (count, 12px zinc-400), "Resolution" ("Resolved" green-500, "Active" amber-500, "Aborted" red-500 in 12px semibold).
> - Rows: hover bg-zinc-800/30. Click opens incident detail (navigates to Aegis screen with incident selected).
> - Pagination: "Showing 1-20 of 42" with prev/next (zinc-700 bg, 28px rounded-md).
> - Empty state: "No incidents recorded yet. Incidents are created automatically when playbook triggers fire, or manually via Aegis chat." in 14px zinc-500 centered.

### 17E: Post-Mortem Generation

After an incident is resolved, Aegis auto-generates a structured post-mortem document:

```markdown
# Security Incident Report: [Title]

## Summary
- **Type**: Zero-Day CVE Response
- **Severity**: Critical
- **Declared**: 2026-02-28 14:30 UTC
- **Resolved**: 2026-02-28 18:45 UTC
- **Duration**: 4h 15m

## Impact
- **Affected Projects**: 5 (payments-api, user-service, admin-dashboard, ...)
- **Affected Package**: lodash@4.17.15
- **Vulnerability**: CVE-2024-XXXX (Prototype Pollution, Depscore 94)
- **Reachable**: Yes, confirmed data-flow in 3 projects

## Timeline
| Time | Phase | Action |
|------|-------|--------|
| 14:30 | Contain | Emergency lockdown: lodash pinned to 4.17.21 across all projects |
| 14:32 | Assess | Blast radius: 5/12 projects affected, 3 with confirmed reachability |
| 14:35 | Communicate | Slack alert sent to #security, email to org admins |
| 14:40 | Remediate | Security sprint started: 5 fixes queued |
| 15:10 | Remediate | 4/5 fixes completed (1 requires manual review) |
| 16:00 | Verify | Re-extraction completed for all 5 projects |
| 18:45 | Report | All projects verified clean. Incident resolved. |

## Metrics
- **Time to Contain**: 2 minutes
- **Time to Remediate**: 4 hours 10 minutes
- **Fixes Created**: 5 (4 auto-merged, 1 manual)
- **SLA Status**: All within SLA (critical = 48h deadline)

## Root Cause
[Auto-generated by Aegis based on CVE details and impact analysis]

## Recommendations
[Auto-generated based on incident patterns and prevention opportunities]
```

Stored as markdown in `security_incidents.post_mortem` and as PDF in Supabase storage (`post_mortem_url`). Included in audit packages generated by `generateAuditPackage` tool.

### 17F: Custom Playbook Builder

Users can create custom playbooks via:

1. **Aegis chat**: "Create an incident response playbook for when a critical CVE affects our Crown Jewels projects." Aegis generates a playbook definition using the template structure, user reviews and approves.

2. **Management console**: "Incidents" tab > "Create Playbook" button > step-by-step form:
   - Name + description
   - Trigger type (from presets or custom)
   - Auto-trigger criteria (optional, JSON builder or natural language via Aegis)
   - Per-phase step configuration: pick tools from the Aegis tool registry, configure parameters, set approval requirements
   - Notification channels per phase
   - Test playbook with dry run (simulates execution without taking actions)

### 17G: Phase 17 Test Suite

#### Backend Tests (`backend/src/__tests__/incident-response.test.ts`)

Tests 1-8 (Playbook Execution):
1. Zero-day playbook executes all 6 phases in correct order
2. Phase with `requiresApproval = true` pauses until approved
3. Step with failed condition is skipped and logged
4. Step failure with `onFailure: 'pause'` pauses the incident
5. Step failure with `onFailure: 'abort'` aborts the entire incident
6. Incident timestamps set correctly at each phase completion
7. `total_duration_ms` computed correctly on resolution
8. Playbook execution creates correct `incident_timeline` entries

Tests 9-14 (Pre-Built Playbooks):
9. Zero-day template: `emergencyLockdownPackage` called during contain phase
10. Zero-day template: `assessBlastRadius` returns affected projects list
11. Supply chain template: Watchtower anomaly > 80 auto-triggers playbook
12. Secret exposure template: notification includes redacted values only (never raw secret)
13. Compliance breach template: exception requests generated for low-risk items
14. All templates produce valid post-mortem reports on completion

Tests 15-20 (Auto-Trigger):
15. Critical CVE with CISA KEV auto-triggers zero-day playbook (if auto_execute enabled)
16. Malicious indicator auto-triggers supply chain playbook
17. Verified secret finding auto-triggers secret exposure playbook
18. SLA breach auto-triggers compliance breach playbook
19. Auto-trigger respects org's `operating_mode` (readonly = no auto-trigger)
20. Auto-trigger creates incident record with correct `trigger_source` and `trigger_data`

Tests 21-24 (Post-Mortem):
21. Post-mortem includes all timeline events in chronological order
22. Post-mortem metrics (time-to-contain, time-to-remediate) computed correctly
23. Post-mortem stored as markdown and PDF
24. Post-mortem included in `generateAuditPackage` output

#### Frontend Tests (`frontend/src/__tests__/incident-response-ui.test.ts`)

Tests 25-32 (Incident UI):
25. Active incident appears in Aegis left sidebar with red indicator
26. Incident detail view shows 6-phase progress bar with current phase highlighted
27. Timeline renders all events with correct phase badges and timestamps
28. Right panel shows affected projects, packages, and CVEs
29. Approval request card appears inline when phase needs approval
30. "Resolve" button transitions incident to resolved state
31. Incident history table renders past incidents with correct data
32. Custom playbook builder form creates valid playbook definition

Tests 33-36 (Integration):
33. Incident notification events dispatch correctly via Phase 9
34. Incident remediation phase triggers Phase 7 fix sprint
35. Incident verification phase triggers re-extraction and checks results
36. Incident SLA integration: triage considers SLA deadlines from Phase 15

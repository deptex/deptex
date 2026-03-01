---
name: Phase 6 - Security Tab Overhaul
overview: Tab rename, Depscore graph, Semgrep/TruffleHog, Aegis Copilot, BYOK.
todos:
  - id: phase-6-vulns
    content: "Phase 6: Security Tab Overhaul (renamed from Vulnerabilities) - Tab rename, Depscore-based graph coloring, richer graph nodes (Depscore/EPSS/KEV/reachability), Semgrep+TruffleHog parsing (with is_current flag), 3 clickable sidebars with banned version integration, advanced filtering, two-tier AI model (BYOK for Aegis/fixes + Gemini Flash for platform features), AI usage logging + admin dashboard, Tier 1 rate limits, Aegis AI Security Copilot panel with contextual actions, Org & Team Security page overhaul (No Team bug fix), background vuln monitoring with batching, historical timeline, safety cutoffs & runaway prevention, Stitch AI prompts, test suite"
    status: pending
isProject: false
---
## Phase 6: Security Tab Overhaul (Renamed from "Vulnerability Tab Overhaul")

**Goal:** Transform the "Vulnerabilities" tab into a comprehensive "Security" tab with richer graph nodes, clickable sidebars for all graph elements, Semgrep/TruffleHog code-level findings, advanced filtering, an Aegis AI Security Copilot panel, BYOK infrastructure, background vulnerability monitoring, and historical tracking.

**Key changes from original Phase 6:**

- Tab renamed from "Vulnerabilities" to "Security" (encompasses dependency vulns + Semgrep code issues + TruffleHog secrets)
- All graph nodes (center, dependency, vulnerability) are now clickable and open contextual sidebars
- Semgrep and TruffleHog output (already generated during extraction but stored as raw JSON) now parsed into tables and displayed
- Aegis AI Security Copilot embedded as a collapsible right panel with full vulnerability context
- BYOK (Bring Your Own Keys) infrastructure for LLM access (shared with Phase 7)
- `interact_with_aegis` permission added to org permission system

### 6A: Tab Rename + Graph Node Enrichment

**Rename "Vulnerabilities" to "Security" across the app:**

- Navigation: update [ProjectTabs](frontend/src/components/ProjectTabs.tsx), route definitions in [routes.tsx](frontend/src/app/routes.tsx), breadcrumbs
- Route: `/organizations/:orgId/projects/:projectId/security` (add redirect from old `/vulnerabilities` route)
- Page component: rename `ProjectVulnerabilitiesPage.tsx` to `ProjectSecurityPage.tsx` (or update title/references)
- Org sidebar, team tabs: update label to "Security"
- All internal references and test files

**Switch graph coloring from severity-based to Depscore-based:**

Current coloring uses `getWorstSeverity()` which maps CVSS severity (critical/high/medium/low/none) to node border/glow colors. Replace with Depscore-based coloring throughout the security graph:

- **Depscore color brackets**: 75-100 = red (urgent), 40-74 = orange (moderate), 0-39 = gray (low), no vulns = green (healthy)
- Replace `getWorstSeverity()` with `getWorstDepscore()` that returns the highest Depscore among child vulnerabilities. When Depscore data is unavailable (e.g., before extraction has computed it), fall back to severity-based coloring.
- **Vulnerability node** border/glow: Depscore bracket color
- **Dependency node** border: worst Depscore of child vulnerability nodes
- **Project node** border/glow: worst Depscore across all child deps
- **Team node** (org graph): worst Depscore across all child projects
- **Edge colors**: match the Depscore bracket of the target vulnerability node
- Update `VulnProjectNode` severity map to use Depscore brackets instead of CVSS severity
- Update `buildDepAndVulnNodesAndEdges` edge coloring logic
- Update `reachableVulns()` to return Depscore alongside is_reachable for coloring calculations

**Enrich Vulnerability Nodes** ([VulnerabilityNode.tsx](frontend/src/components/supply-chain/VulnerabilityNode.tsx)):

Current: severity badge, OSV ID, aliases, summary.

Add:

- **Depscore badge** (primary color indicator): reuse existing `getDepscoreBadgeClass` -- this now drives the node border color too
- **Severity badge**: kept as a secondary indicator (smaller, inside the node)
- **EPSS percentage**: small gray badge, e.g., "EPSS 3.2%"
- **CISA KEV indicator**: red flame icon when `cisa_kev === true`
- **Reachability indicator**: shield icon - green outline if not reachable, red fill if reachable
- **"Fix available" indicator**: small green check icon if `fixed_versions` is non-empty

Data flow: the `VulnGraphDepNode.vulnerabilities[]` already has `is_reachable` but is missing `depscore`, `epss_score`, `cvss_score`, `cisa_kev`, `fixed_versions`. Update `loadProjectVulnerabilityGraphData` in [vulnerability-graph-data.ts](frontend/src/lib/vulnerability-graph-data.ts) to include these fields from `ProjectVulnerability`.

**Enrich Dependency Nodes** ([DependencyNode.tsx](frontend/src/components/supply-chain/DependencyNode.tsx) in vuln graph context):

Current: name, version, license, "not imported" badge.

Add:

- **Vulnerability count breakdown**: compact badges "3C 1H 2M" showing severity counts from child vulnerability nodes
- **Worst Depscore**: small badge showing the highest depscore of child vulns (color-coded by Depscore bracket -- this also drives node border color)
- **Clickable cursor**: `cursor-pointer` class when in security graph context

**Enrich Center Node** ([ProjectCenterNode.tsx](frontend/src/components/vulnerabilities-graph/ProjectCenterNode.tsx)):

Current: project name, worst severity glow, framework.

Add:

- **Security issue counts**: text below project name: "X vulns | Y code issues | Z secrets" (from Semgrep + TruffleHog counts)
- **Depscore-based glow**: border/glow color driven by worst Depscore (replaces worst severity glow)
- **Clickable cursor**: `cursor-pointer` class

**Make all nodes clickable:**

Add `onClick` handlers to each node component. The security page manages sidebar state:

- `selectedVulnerability: string | null` (vuln ID)
- `selectedDependency: string | null` (dep ID)
- `showProjectSidebar: boolean`

Only one sidebar open at a time. Clicking a different node type closes the current sidebar and opens the new one.

### 6B: Semgrep + TruffleHog Parsing and Display

**Database Tables:**

```sql
CREATE TABLE project_semgrep_findings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  rule_id TEXT NOT NULL,
  file_path TEXT NOT NULL,
  start_line INTEGER,
  end_line INTEGER,
  severity TEXT, -- ERROR, WARNING, INFO
  message TEXT,
  cwe_ids TEXT[],
  owasp_ids TEXT[],
  category TEXT, -- e.g., "security", "correctness"
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(project_id, rule_id, file_path, start_line)
);

CREATE TABLE project_secret_findings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  detector_type TEXT NOT NULL, -- e.g., "AWS", "GitHub", "GenericPassword"
  file_path TEXT NOT NULL,
  start_line INTEGER,
  is_verified BOOLEAN DEFAULT false,
  is_current BOOLEAN DEFAULT true, -- true if found in HEAD, false if only in git history
  description TEXT,
  redacted_value TEXT, -- first 4 + last 4 chars only, never the full secret
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(project_id, detector_type, file_path, start_line)
);
```

**Extraction Worker Changes** ([pipeline.ts](backend/extraction-worker/src/pipeline.ts)):

After running Semgrep (output already saved as `semgrep.json` in Supabase Storage), add parsing step:

```typescript
const semgrepPath = path.join(reportsDir, 'semgrep.json');
if (fs.existsSync(semgrepPath)) {
  const semgrepOutput = JSON.parse(fs.readFileSync(semgrepPath, 'utf8'));
  const findings = (semgrepOutput.results ?? []).map((r: any) => ({
    project_id: projectId,
    rule_id: r.check_id,
    file_path: r.path,
    start_line: r.start?.line,
    end_line: r.end?.line,
    severity: r.extra?.severity ?? 'INFO',
    message: r.extra?.message,
    cwe_ids: r.extra?.metadata?.cwe ?? [],
    owasp_ids: r.extra?.metadata?.owasp ?? [],
    category: r.extra?.metadata?.category ?? 'security',
    metadata: r.extra?.metadata ?? {},
  }));
  // Delete old findings for this project, insert new
  await supabase.from('project_semgrep_findings').delete().eq('project_id', projectId);
  if (findings.length > 0) {
    await supabase.from('project_semgrep_findings').upsert(findings, { onConflict: 'project_id,rule_id,file_path,start_line' });
  }
  log('scan', `Parsed ${findings.length} Semgrep findings`);
}
```

After running TruffleHog (output already saved as `trufflehog.json`), add parsing step:

```typescript
const trufflePath = path.join(reportsDir, 'trufflehog.json');
if (fs.existsSync(trufflePath)) {
  const content = fs.readFileSync(trufflePath, 'utf8');
  // TruffleHog outputs one JSON object per line (JSONL format)
  const findings = content.trim().split('\n').filter(Boolean).map((line: string) => {
    const f = JSON.parse(line);
    const raw = f.Raw ?? '';
    const redacted = raw.length > 8 ? `${raw.slice(0, 4)}...${raw.slice(-4)}` : '****';
    return {
      project_id: projectId,
      detector_type: f.DetectorName ?? 'Unknown',
      file_path: f.SourceMetadata?.Data?.Filesystem?.file ?? f.SourceMetadata?.Data?.Git?.file ?? 'unknown',
      start_line: f.SourceMetadata?.Data?.Filesystem?.line ?? f.SourceMetadata?.Data?.Git?.line ?? null,
      is_verified: f.Verified ?? false,
      is_current: true, // Set during HEAD scan; historical-only findings (git history) set to false
      description: `${f.DetectorName ?? 'Secret'} detected`,
      redacted_value: redacted,
    };
  });
  await supabase.from('project_secret_findings').delete().eq('project_id', projectId);
  if (findings.length > 0) {
    await supabase.from('project_secret_findings').upsert(findings, { onConflict: 'project_id,detector_type,file_path,start_line' });
  }
  log('scan', `Parsed ${findings.length} TruffleHog findings`);
}
```

**New API Endpoints:**

- `GET /api/projects/:id/semgrep-findings` - returns parsed Semgrep findings
- `GET /api/projects/:id/secret-findings` - returns parsed TruffleHog findings (redacted values only)

**Frontend Display:**

- Findings shown in the Project Security Sidebar (6F) when clicking the center node
- Each Semgrep finding: severity badge + rule category + file path:line + message
- Each TruffleHog finding: detector type badge + file path:line + verified/unverified indicator
- Counts displayed on the center node badge

### 6C: Advanced Filtering

Replace the single `ShowOnlyReachableCard` toggle with a full filter bar styled like the Dependencies tab filter dropdown:

**Filter options:**

- **Severity**: Checkboxes for critical, high, medium, low (multi-select)
- **Depscore Range**: Slider or threshold input (e.g., "Show only >= 40")
- **EPSS Threshold**: Input (e.g., "Show only >= 1%")
- **CISA KEV**: Toggle "Only KEV listed"
- **Fix Available**: Toggle "Has fix available"
- **Reachable Only**: Toggle (replaces current `ShowOnlyReachableCard`)
- **Dependency Type**: Dropdown - Direct / Transitive / Both
- **Date Range**: Date pickers for "Discovered after" / "Discovered before"

**Implementation:**

- Filter state managed in URL search params for shareability (`?severity=critical,high&depscore_min=40&kev=true`)
- Filtering logic applied in `useVulnerabilitiesGraphLayout.ts` - nodes that don't match are either hidden or dimmed (opacity 0.2 + non-interactive)
- Filter bar positioned at top of the Security page, below the project tabs
- "Active filters" count badge on the filter button
- "Clear all" button to reset

### 6D: Vulnerability Detail Sidebar

Create `VulnerabilityDetailSidebar.tsx` following existing sidebar patterns (like [CreateRoleSidebar](frontend/src/components/CreateRoleSidebar.tsx) with slide-in animation from right):

**Trigger:** Click any vulnerability node in the graph.

**Sidebar sections:**

1. **Header**: OSV ID (linked to external advisory) + close button
2. **Risk Badges Row**: Severity badge + Depscore badge + EPSS percentage + CISA KEV warning (red banner if active)
3. **Risk Assessment Card** (collapsible):
  - Reachability: "Imported in X files" or "Not directly imported" (with confidence level)
  - Asset Tier context: tier name + multiplier effect on Depscore
  - Exploit maturity: CISA KEV status, EPSS interpretation ("top 5% likelihood of exploitation")
4. **Description** (collapsible):
  - Full advisory text from `summary` field
  - "Explain with Aegis" button - sends CVE context to Aegis panel for plain-English explanation
5. **Affected Code** (collapsible) -- **enhanced by Phase 6B**:
  - **When atom reachability data is available** (Phase 6B): Full `CodeImpactView` component showing:
    - Entry point in user code (file, line, method) with "framework-input" tag badge if applicable
    - Data-flow arrows tracing through intermediate calls
    - Vulnerable dependency code at the sink
    - Each step has syntax-highlighted code with the relevant line highlighted
    - Multiple flow paths shown if more than one entry point reaches the vulnerability
  - **Fallback (no atom data)**: List of affected project dependencies with: name, version, direct/transitive badge. Under each dependency: list of files that import it (from `files_importing` on project_dependencies). File paths are clickable if we can link to the repo.
  - Both views show a "View in Aegis" button to get AI explanation of the code impact
6. **Fix Options** (collapsible):
  - **Fix classification badges**:
    - "Same-major fix" (green badge) - fixed version available within the current major version (non-breaking)
    - "Major version bump" (yellow badge with warning icon) - fix requires a major version upgrade (potentially breaking)
    - "Workaround available" (blue badge) - advisory includes a documented workaround or mitigation
    - "No fix yet" (gray badge) - no fixed version available, only code-level mitigation possible
    - "Dev dependency" (dim badge) - vuln is in a dev dependency only (lower priority)
  - **Fix impact preview** (from `project_version_candidates` data): "Upgrading [package] to v4.17.21 also resolves: CVE-B (High), CVE-C (Medium)" -- shows all OTHER vulnerabilities in the same package that this fix would resolve. Cross-references all PDV rows for the same package where `fixed_versions` includes the candidate version. Helps users see the ROI of a single fix action.
  - **Recommended version** (from smart version recommendation engine, 6L): Shows the OSV-verified same-major safe version with "Fixes X/Y CVEs, 0 known new CVEs" label. Expandable to show release notes snippet. **Banned version guard**: if the recommended version is banned by the org or team, it is skipped and the next-best non-banned candidate is shown. If the ONLY safe version is banned, show: "Safe version v4.17.21 exists but is banned by your organization. Contact an admin or choose a different strategy." with a link to the ban policy.
  - **"Fix with AI"** primary button (green, prominent) - triggers Phase 7 Aider flow with full reachability context from 6B. Auto-selects the recommended version. **Never auto-selects a banned version** -- if recommended is banned, prompts user to pick manually. Disabled if org has no BYOK key configured (shows tooltip "Configure AI keys in Organization Settings")
  - **"Bump Version"** secondary button - navigates to the dependency's supply chain tab
  - **"Pin Transitive"** option (shown only for transitive deps) - adds a resolution/override to lock the transitive dependency to a safe version
  - If no fixed version exists: "No fix available yet" with "Patch with AI" option (Aider adds input validation or wrapper around the vulnerable call, using atom flow data to know exactly which call to wrap)
7. **Timeline** (collapsible):
  - Published date (from `published_at`)
  - Detected in project date (from `created_at` on pdv row)
  - MTTR metric if resolved (from `project_vulnerability_events`)
8. **References**:
  - NVD link (if CVE alias exists)
  - OSV link
  - GHSA link (if GHSA alias exists)
9. **Actions Footer** (sticky at bottom):
  - "Suppress" button - marks `suppressed = true` on the pdv row (hides from default view, visible with filter)
  - "Accept Risk" button - marks `risk_accepted = true` with audit trail (user ID + timestamp)
  - "Fix with AI" button (duplicate of section 6 for quick access)

**New backend endpoint:**

`GET /api/projects/:projectId/vulnerabilities/:osvId/detail`

Returns:

- Full vulnerability data from `project_dependency_vulnerabilities`
- Affected project dependencies (joined from `project_dependencies`)
- Files importing each affected dependency (from import analysis)
- Fix version analysis
- Timeline events from `project_vulnerability_events`

**Schema additions to `project_dependency_vulnerabilities`:**

```sql
ALTER TABLE project_dependency_vulnerabilities
  ADD COLUMN suppressed BOOLEAN DEFAULT false,
  ADD COLUMN risk_accepted BOOLEAN DEFAULT false,
  ADD COLUMN risk_accepted_by UUID REFERENCES auth.users(id),
  ADD COLUMN risk_accepted_at TIMESTAMPTZ;
```

### 6E: Dependency Detail Sidebar

Create `DependencySecuritySidebar.tsx`:

**Trigger:** Click any dependency node in the security graph.

**Sidebar sections:**

1. **Header**: Package name + version badge + license badge + ecosystem icon (npm/PyPI/Maven/etc.) + close button
2. **Usage in Your Project** (collapsible):
  - Type: "Direct dependency" or "Transitive (via X â†’ Y â†’ this)"
  - Import count: "Imported in X files"
  - File list: each file path that imports this package (from import analysis)
  - If zombie (imported but unused in code): yellow "Not imported in your code" badge
3. **Current Vulnerabilities** (collapsible, sorted by Depscore descending):
  - Each vulnerability row: [Depscore badge] [Severity badge] CVE-ID + "fix available" green check if applicable
  - Click a vulnerability row â†’ switches to the Vulnerability Detail Sidebar (6D)
4. **Recommended Versions** (collapsible) -- powered by smart version recommendation engine (see 6L):
  - **Remove this package** (shown prominently at top if atom usage analysis shows 0 usage slices): "This package is not used in your code. Remove it to eliminate X vulnerabilities." Green "Remove with AI" button.
  - **Current version**: version badge + vulnerability count + "X reachable" sub-count
  - **Same-major safe** (if available): version badge + "Fixes X/Y current CVEs" + "0 known new CVEs" green verified badge (or "Z known CVEs" yellow warning). Expandable to show release notes. "Bump with AI" button. **If this version is banned by the org/team**: show red "Banned" badge alongside the version, disable "Bump with AI" button, show tooltip "This version is banned by your organization."
  - **Fully safe** (if different from same-major): version badge + "Fixes all Y current CVEs" + verification status. "MAJOR UPGRADE" warning badge if major version bump. Expandable to show release notes + breaking change warnings. Same banned badge logic applies.
  - **Latest**: version badge + vulnerability count from OSV + publish date. Same banned badge logic.
  - **Fix impact summary** at bottom: "Upgrading to v4.17.21 resolves: CVE-A, CVE-B, CVE-C" (aggregated across all vulns for this package)
  - "View All Versions" link â†’ navigates to supply chain tab's version sidebar
  - **Banned version data source**: fetch `banned_versions` (org-level) and `team_banned_versions` (team-level for the project's owner team) via existing API endpoints. Cache per sidebar open.
5. **Watchtower Signals** (collapsible, only shown if package is on org's watchtower):
  - Anomaly score with color indicator (green/yellow/red)
  - Security checks: Registry integrity, Install scripts, Entropy (pass/warn/fail icons)
  - Last checked timestamp
  - "View Forensics" link â†’ navigates to Watchtower tab
6. **Actions Footer**:
  - "View Full Detail" button â†’ navigates to `/organizations/:orgId/projects/:projectId/dependencies/:depId`
  - "Bump to vX.Y.Z" button (if safe version exists) â†’ triggers version bump flow

**New backend endpoint:**

`GET /api/projects/:projectId/dependencies/:depId/security-summary`

Returns:

- Dependency info (name, version, license, ecosystem, is_direct)
- Import analysis (file paths importing this package)
- Vulnerabilities affecting this dependency (with depscore, severity, fix status)
- Safe version recommendation
- Watchtower summary (if on watchtower)

### 6F: Project Security Sidebar (Center Node)

Create `ProjectSecuritySidebar.tsx`:

**Trigger:** Click the center (project) node in the graph.

**Sidebar sections:**

1. **Header**: Project name + overall security status badge + close button
2. **Vulnerability Summary** card:
  - Breakdown by severity: Critical (count), High (count), Medium (count), Low (count)
  - Total count + "X reachable" sub-count
  - Color-coded bars or mini chart
3. **Depscore Distribution** card:
  - Three buckets: 75-100 (urgent, red), 40-74 (moderate, yellow), 0-39 (low, gray)
  - Count in each bucket
4. **Code Issues (Semgrep)** (collapsible):
  - Count badge in header (red if any critical/high)
  - List of top findings (max 5, sorted by severity): severity badge + rule category + file path:line + message
  - Each finding expandable to show a mini code snippet (3-5 lines around the issue, with the vulnerable line highlighted). Semgrep output includes the affected code -- we store this in `project_semgrep_findings.metadata` and render it with syntax highlighting.
  - Each finding has an **"Ask Aegis"** button -- sends the Semgrep finding (rule, code context, CWE) to Aegis for explanation and fix suggestion. Aegis analyzes the finding and either: (a) explains what's wrong and how to fix it manually, or (b) offers "Want me to try fixing this?" which triggers an Aider code_patch job targeting the specific file/lines.
  - "View all X findings" expandable
5. **Exposed Secrets (TruffleHog)** (collapsible):
  - Count badge in header (red if any verified)
  - List of findings: detector type badge + file path:line + verified/unverified badge
  - Each finding expandable to show a mini code snippet (3-5 lines around the secret, with the secret value **redacted** in the display -- replaced with `[REDACTED]`). Shows file context so the user understands where the secret is.
  - Each finding has an **"Ask Aegis"** button -- Aegis explains the risk (e.g., "This AWS key at config.js:15 is committed to source control and verified as active") and suggests remediation steps (rotate the key, move to environment variable, add to .gitignore). Aegis does NOT directly modify .env files or handle secrets -- it provides guidance and can offer to replace the hardcoded value in the source code with an env var reference (e.g., `process.env.AWS_KEY`) via an Aider job.
  - CRITICAL: never show actual secret values, only redacted
  - Verified secrets get a red "Active" badge
6. **Priority Actions** card:
  - Pre-computed top 3 most urgent items (computed during extraction or on-demand):
  1. "Fix X critical reachable vulnerabilities" (if any)
  2. "Rotate X verified exposed secrets" (if any)
  3. "Address X high-severity code issues" (if any)
    ch item is clickable (navigates to relevant section)
7. **Actions Footer**:
  - "Re-evaluate" button (triggers extraction re-scan, same as compliance tab)
  - "Export Security Report" button (generates PDF/markdown summary)
  - "Ask Aegis" button (opens/focuses the Aegis panel with project context)

### 6G: Two-Tier AI Model + BYOK + Aegis Security Copilot Panel

#### AI Architecture: Two-Tier Model

Deptex uses two tiers of AI, each with a different funding model and purpose:

**Tier 1 -- Platform AI (Deptex-funded, built into the product):**

Lightweight, pre-computed, or batch AI features that work out of the box for all organizations without any configuration:

- "Analyze usage with AI" on dependency overview pages
- AI policy assistant suggestions (PolicyAIAssistant.tsx)
- Action items computation during extraction
- AI-generated security report summaries
- Dependency review summaries (Phase 11)
- Anomaly detection explanations (Phase 11)

Provider: **Gemini 2.5 Flash** via a Deptex-managed API key (`DEPTEX_GEMINI_KEY` environment variable on the backend). Cost to Deptex: ~$0.0001-0.0003 per call, estimated **$5-15/month** across all orgs for a typical deployment. This is so cheap it's effectively free to operate.

Tier 1 features do NOT require the org to configure BYOK. They work immediately. However, they ARE gated by the `interact_with_aegis` permission -- users without this permission don't see any AI buttons or features (see AI Permission section below).

**Tier 2 -- BYOK (Org-funded, Bring Your Own Keys):**

Interactive, high-value AI features where the organization gets direct value and pays their own LLM provider:

- Aegis Security Copilot chat (conversational)
- AI-powered fixes via Aider (Phase 7)
- Security Sprints (Phase 7B)
- "Explain this vulnerability" / "Explain this finding" in sidebars
- Any conversational or agentic AI interaction

Provider: whatever the org configures (OpenAI, Anthropic, or Google). Cost is billed directly by the provider to the org. Typical costs per interaction: ~$0.001-0.05 depending on model choice.

**Backend - Platform AI Provider** (`ee/backend/lib/ai/platform-provider.ts`):

```typescript
function getPlatformProvider(): AIProvider;
// Returns a Gemini Flash client using DEPTEX_GEMINI_KEY
// Used by all Tier 1 features
// Falls back gracefully if key not configured (Tier 1 features show "AI unavailable" instead of crashing)
```

#### BYOK Infrastructure (Tier 2, shared with Phase 7)

**Database Table:**

```sql
CREATE TABLE organization_ai_providers (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider TEXT NOT NULL, -- 'openai', 'anthropic', 'google'
  encrypted_api_key TEXT NOT NULL,
  model_preference TEXT, -- e.g., 'gpt-4o', 'claude-sonnet-4-20250514', 'gemini-2.5-flash'
  is_default BOOLEAN DEFAULT false,
  monthly_cost_cap NUMERIC(8, 2) DEFAULT 100.00, -- configurable monthly spend limit in USD
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(organization_id, provider)
);
```

**Backend - Key Encryption:**

- Use Node.js `crypto.createCipheriv` with AES-256-GCM
- Server-side `AI_ENCRYPTION_KEY` environment variable (32-byte key)
- Keys encrypted at rest in Supabase, decrypted only when needed for API calls
- Never returned to the frontend (only provider name + model shown)
- **Deletion guard**: before deleting a BYOK key, check for active fix jobs or sprints using this provider. If any exist, show warning: "X fix jobs are currently using this provider. Deleting the key will cause them to fail. Proceed?"

**Backend - Provider Abstraction** (`ee/backend/lib/ai/provider.ts`):

Unified interface for all LLM providers (both tiers use this interface):

```typescript
interface AIProvider {
  chat(messages: Message[], options?: ChatOptions): Promise<string>;
  chatWithTools(messages: Message[], tools: Tool[], options?: ChatOptions): Promise<ToolCallResult>;
  streamChat(messages: Message[], options?: ChatOptions): AsyncIterable<string>;
}

function getProviderForOrg(orgId: string): Promise<AIProvider>;
// Fetches org's default BYOK AI provider, decrypts key, returns configured client
// Supports: OpenAI, Anthropic, Google (via their respective SDKs)
// All three providers support function calling / tool use for Aegis actions

function getPlatformProvider(): AIProvider;
// Returns Gemini Flash client for Tier 1 features
```

Update existing Aegis executor ([executor.ts](ee/backend/lib/aegis/executor.ts)) to use `getProviderForOrg()` instead of hardcoded `getOpenAIClient()`.

**Backend - API Endpoints:**

- `POST /api/organizations/:id/ai-providers` - add/update a provider key (requires `manage_integrations` permission)
- `GET /api/organizations/:id/ai-providers` - list configured providers (returns provider names + models, NOT keys)
- `DELETE /api/organizations/:id/ai-providers/:providerId` - remove a provider (warns if active jobs exist)
- `POST /api/organizations/:id/ai-providers/test` - test connection (sends a simple prompt, returns success/error)
- `GET /api/organizations/:id/ai-usage` - get AI usage stats (requires `manage_integrations`)
- `GET /api/organizations/:id/ai-usage/logs` - paginated AI usage logs (requires `manage_integrations`)

**Frontend - Org Settings UI:**

New "AI Configuration" section in [OrganizationSettingsPage.tsx](frontend/src/app/pages/OrganizationSettingsPage.tsx):

- Provider cards: OpenAI, Anthropic, Google - each with "Connect" button or "Connected" badge
- On connect: modal with API key input (masked), model selector dropdown, "Test Connection" button
- Default provider selector (radio buttons)
- Monthly cost cap input per provider (USD, default $100)
- Cost note: "Aegis and AI fixes use your own API keys. Costs are billed directly by your provider. Built-in AI features (analysis, summaries) are included in Deptex at no extra cost."

#### AI Rate Limits

**Tier 1 (Platform AI) rate limits** -- prevents abuse of Deptex-funded features:

- "Analyze usage with AI" (dependency overview): max 5 calls per package per user per day
- Policy AI assistant chat: max 20 messages per conversation, max 50 messages per user per day
- Security report generation: max 3 per project per day
- Action items computation: automated (runs once per extraction), no user-facing limit
- When limit hit: toast message "You've reached the daily limit for this feature. Try again tomorrow." Button becomes disabled with cooldown timer.

**Tier 2 (BYOK) rate limits** -- protects against runaway costs, but generous since the org is paying:

- Monthly cost cap: configurable per org (default $100/month). Before each AI call, estimate cost and check against remaining budget. If exceeded: "Monthly AI budget reached ($X/$Y). An admin can increase the limit in Organization Settings > AI Configuration."
- Per-conversation token budget: max 200K tokens per Aegis chat thread (prevents single runaway conversations). When approaching limit: "This conversation is getting long. Start a new thread for best results."
- Max concurrent Aegis sessions: 10 per org (prevents parallel abuse)
- Per-user daily Aegis messages: 200 per user per day (generous but bounded)

#### AI Usage Logging

Every AI call (both tiers) is logged for transparency and cost tracking:

```sql
CREATE TABLE ai_usage_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id),
  feature TEXT NOT NULL, -- 'aegis_chat', 'ai_fix', 'analyze_usage', 'policy_assistant', 'security_report', 'sprint', 'explain_vuln', 'explain_semgrep', 'explain_secret'
  tier TEXT NOT NULL, -- 'platform' or 'byok'
  provider TEXT NOT NULL, -- 'gemini', 'openai', 'anthropic'
  model TEXT NOT NULL, -- 'gemini-2.5-flash', 'gpt-4o', 'claude-sonnet-4-20250514', etc.
  input_tokens INTEGER NOT NULL,
  output_tokens INTEGER NOT NULL,
  estimated_cost NUMERIC(8, 6), -- in USD, computed from provider pricing
  context_type TEXT, -- 'vulnerability', 'dependency', 'project', 'policy', 'semgrep', 'secret'
  context_id TEXT, -- relevant ID (osv_id, dep_id, project_id, finding_id)
  duration_ms INTEGER, -- response time
  success BOOLEAN DEFAULT true,
  error_message TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_aul_org_created ON ai_usage_logs(organization_id, created_at DESC);
CREATE INDEX idx_aul_user_created ON ai_usage_logs(user_id, created_at DESC);
CREATE INDEX idx_aul_org_feature ON ai_usage_logs(organization_id, feature);
```

**Logging implementation**: wrap every `AIProvider.chat()` / `chatWithTools()` / `streamChat()` call in a logging middleware that records input/output token counts (from the provider's response metadata), computes estimated cost based on known per-token pricing, and inserts into `ai_usage_logs`. Both tiers log through the same table with `tier = 'platform'` or `tier = 'byok'`.

#### AI Usage Dashboard

New subsection within the "AI Configuration" area of Org Settings. Only visible to users with `manage_integrations` permission.

**Dashboard sections:**

1. **Monthly Summary Card**: Total tokens this month (input + output), estimated total cost, comparison to monthly cap (progress bar)
2. **Cost Breakdown by Feature**: Bar chart showing cost per feature (Aegis chat, AI fixes, sprints, analysis, etc.)
3. **Cost Breakdown by User**: Table showing per-user token consumption and estimated cost this month, sorted by usage descending
4. **Daily Usage Chart**: Line chart showing daily token consumption over the past 30 days, split by tier (platform vs BYOK)
5. **Recent Activity Log**: Paginated table of recent AI calls: timestamp, user, feature, model, tokens, cost, success/error. Expandable rows to see context details.

**Data source**: Aggregate queries on `ai_usage_logs` table. Pre-aggregated daily summaries can be materialized if performance becomes an issue at scale.

**API endpoint**: `GET /api/organizations/:id/ai-usage?period=30d` returns the aggregated stats. `GET /api/organizations/:id/ai-usage/logs?page=1&limit=50` returns paginated raw logs.

#### AI Permission (`interact_with_aegis`)

- Add `interact_with_aegis` to the org-level permission system (like `manage_compliance`, `manage_integrations`)
- This permission gates **ALL AI features across the entire app** (both Tier 1 and Tier 2):
  - **Aegis Security Copilot panel** (Security tab + Supply Chain tab) -- panel tab hidden entirely
  - **"Explain with Aegis"** buttons in Vulnerability Detail Sidebar (6D) -- hidden
  - **"Ask Aegis"** buttons in Project Security Sidebar (6F) on Semgrep/TruffleHog findings -- hidden
  - **"Fix with AI"** buttons in all sidebars (6D, 6E) -- hidden
  - **"Analyze usage with AI"** on dependency overview pages (Tier 1) -- hidden
  - **AI policy assistant** (PolicyAIAssistant.tsx) -- hidden
  - **"View in Aegis"** / context-send buttons -- hidden
  - **Sprint triggers** that involve AI -- hidden
- Users WITHOUT this permission see the sidebars normally but without any AI buttons or sections. The sidebars still show all non-AI data (vulnerability details, versions, code snippets, etc.) -- just no AI actions.
- Default: granted to all roles (can be restricted per org by removing from specific roles)
- The permission is checked on both frontend (hide UI elements) and backend (API endpoints return 403 if permission missing)

#### Aegis Security Copilot Panel

Embedded as a **collapsible right panel** on the Security tab (and Supply Chain tab in Dependencies). Design inspired by Cursor's AI panel.

**Panel layout:**

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ âš¡ Aegis    Context: [Project Overview] â–¾  â”€ âœ• â”‚
â”‚ â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”‚
â”‚                                       â”‚
â”‚ [Chat message history area]           â”‚
â”‚                                       â”‚
â”‚ ðŸ’¬ Based on your project's security   â”‚
â”‚ posture, I recommend fixing these     â”‚
â”‚ first:                                â”‚
â”‚                                       â”‚
â”‚ 1. **CVE-2024-XXXX** in lodash       â”‚
â”‚    Depscore 92, reachable, CISA KEV  â”‚
â”‚    Fix: npm install lodash@4.17.21   â”‚
â”‚                                       â”‚
â”‚ 2. Rotate AWS key in                  â”‚
â”‚    .env.production:3 (verified)      â”‚
â”‚                                       â”‚
â”‚ â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”‚
â”‚ Quick: [Explain] [Fix Priority] [Report] â”‚
â”‚ â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”‚
â”‚ [Ask Aegis about your project's security...] âŽ â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

**Context switching behavior:**

- When user clicks a vulnerability node â†’ sidebar context shifts to that CVE. Header shows "Context: CVE-2024-XXXX". Quick actions become: "Explain this vulnerability", "Is this exploitable?", "How do I fix this?"
- When user clicks a dependency node â†’ context shifts to that package. Header shows "Context: [lodash@4.17.15](mailto:lodash@4.17.15)". Quick actions become: "Assess this dependency", "Suggest upgrade", "Show forensics"
- When on main graph view (no node selected) â†’ context is full project. Header shows "Context: Project Overview". Quick actions become: "What should I fix first?", "Generate security report", "Summarize risks"
- Context indicator is a dropdown so user can manually switch context

**Panel state:**

- Collapsed by default (shows a small "Aegis" tab on the right edge)
- Click to expand to ~350px width
- **No-BYOK state**: If the org has no BYOK key configured, the panel tab still appears but clicking it shows a setup card: "Configure AI keys in Organization Settings to use Aegis" with a direct link to the AI Configuration section. The chat interface is not shown. Tier 1 (platform AI) features like "Analyze with AI" still work independently since they use Deptex's Gemini Flash key.
- Chat history stored in existing `aegis_chat_threads` / `aegis_chat_messages` tables with additional `project_id` and `context_type` / `context_id` fields
- Streaming responses using Server-Sent Events (SSE) from the backend, rendered incrementally (NOT the "Thinking..." pattern from PolicyAIAssistant)

**Streaming markdown rendering** (different from PolicyAIAssistant):

PolicyAIAssistant uses a "Thinking..." approach: hides content until the `done` event, then renders the full message at once using the custom `renderAISupabaseStyle()` function. This works for short policy suggestions but is frustrating for longer Aegis conversations.

Aegis streams content live, rendering incrementally as chunks arrive. Implementation:

1. Use `react-markdown` + `remarkGfm` (already in the project, used by `DependencyNotesSidebar`) for rendering the accumulated text. This handles markdown properly: bold, lists, code blocks, links, headers.
2. **Streaming fence guard**: Before passing the accumulated text to react-markdown, run a pre-processor that detects and strips incomplete markdown constructs:
  - Unclosed code block: if count of `

``` `is odd, strip everything from the last` 

``` ` onward (don't render the partial code block)

- Unclosed bold: if count of `**` is odd, strip the trailing `**` and subsequent text
- Unclosed inline code: if count of single backticks is odd, strip the trailing backtick
- This prevents raw markdown syntax from flashing on screen during streaming

1. Show a blinking cursor (small green-500 bar, `animate-pulse`) at the end of the last rendered line while streaming is active
2. When the `done` event fires, render the full final content without guards
3. Action cards (e.g., "Patch Proposal Generated" with Apply Fix / Review Diff buttons) are sent as special SSE events (`type: 'action_card'`) and rendered as structured card components, not markdown

**Also available on:**

- Supply Chain tab in Dependencies (same panel, context automatically set to the dependency being viewed)

#### New Aegis Security Actions

Extend the existing action registry at `ee/backend/lib/aegis/actions/`:

Create new file `ee/backend/lib/aegis/actions/security.ts`:

- `getProjectVulnerabilities(projectId)` - list vulns with depscore, sorted by priority
- `getVulnerabilityDetail(vulnId)` - full detail for one vulnerability including atom reachable flows and code snippets
- `explainVulnerability(vulnId)` - AI generates plain-English explanation using atom flow data and dep-scan LLMPrompts context
- `suggestFixPriority(projectId)` - AI analyzes all vulns, Semgrep findings, and secret findings, returns prioritized fix list with reasoning
- `analyzeReachability(vulnId)` - assess actual risk using atom data-flow reachability, usage slices, and code patterns
- `getSemgrepFindings(projectId)` - return code issues with severity context and code snippets
- `explainSemgrepFinding(findingId)` - AI explains the code vulnerability, its risk, and how to fix it. If auto-fixable, offers "Want me to try fixing this?" which triggers `fix_semgrep` strategy.
- `getSecretFindings(projectId)` - return exposed secrets (redacted values only, NEVER the actual secret)
- `explainSecretFinding(findingId)` - AI explains the risk of the exposed secret and provides remediation guidance (rotate, move to env var). Offers to trigger `remediate_secret` strategy to replace the hardcoded value with an env var reference.
- `triggerAiFix(fixType, targetId, strategy)` - connects to Phase 7 fix engine. Supports all fix types: vulnerability (by osvId), Semgrep (by findingId), and secret (by findingId). Returns the fix job ID for progress tracking.
- `generateSecurityReport(projectId)` - generate comprehensive security report (markdown format) including vuln summary, reachability analysis, Semgrep findings, and secret findings

**System Prompt Update** (extend [systemPrompt.ts](ee/backend/lib/aegis/systemPrompt.ts)):

Add security-specific context to the system prompt:

- Security engineer role for vulnerability triage and remediation
- Available security actions
- When a specific vulnerability or dependency is in context, inject its data into the prompt (CVE details, depscore, reachability, affected files)
- Project-level security summary (vuln counts by severity, semgrep count, secrets count)
- Keep context injection under 4K tokens to leave room for conversation

### 6H: Background Vulnerability Monitoring

Uses the same scale-to-zero Fly Machine pattern from Phase 2:

1. Create a lightweight **"vuln-check"** job type in the extraction worker (reuses same machine pool - no separate app needed)
2. Backend schedules jobs via QStash cron - enqueues to Supabase `extraction_jobs` table with `job_type = 'vuln-check'` + starts a Fly Machine
3. Runs every 24h per project (configurable in project settings)
4. Job steps:
  **Vulnerability monitoring (existing):**
  - Fetch project's current dependency list from `project_dependencies`
  - Query OSV API for each dependency (batch endpoint: `POST https://api.osv.dev/v1/querybatch`)
  - Query CISA KEV catalog for CVE updates
  - Fetch latest EPSS scores from FIRST API
  - Diff against existing `project_dependency_vulnerabilities` - identify new vulns, score changes
  - Upsert updated records, recalculate Depscore where needed
  - Log events to `project_vulnerability_events` table
  **Version monitoring (new):**
  - For each vulnerable package, query the package registry (npm/PyPI/etc.) for the latest available version
  - If a new version exists that wasn't previously available, check if it fixes any current CVEs (compare against `fixed_versions[]`)
  - Verify the new version against OSV: query `querybatch` to check for known CVEs in the new version
  - If a new verified-safe fix version is available: update `project_version_candidates` with the new candidate
  - Log event: `fix_available` type in `project_vulnerability_events` with metadata `{ version, fixes_cves, package_name }`
  - **Notification trigger**: "A safe fix is now available: lodash 4.17.22 fixes CVE-A, CVE-B (0 known new CVEs)" -- more actionable than "new vulnerability detected"
5. Sends notifications for:
  - New vulnerabilities detected (connects to Phase 9 notification rules)
  - **New safe fix versions available** (e.g., "lodash 4.17.22 is now available and fixes 3 CVEs with 0 known new vulnerabilities")
  - CISA KEV additions (high urgency)
  - Significant EPSS score changes (>10%)
6. Cost: negligible - job runs for ~30-60 seconds, uses only API calls (no clone, no scan), costs fractions of a cent per check

**Scaling for large organizations:**

- **Staggered scheduling**: jobs are spread across the 24h window (not all at midnight). Each project's check time is offset by `hash(project_id) % 86400` seconds from the cron anchor. This prevents thundering herd on the Fly.io machine pool.
- **Batched execution**: multiple projects per machine invocation. Since each job is lightweight API calls (~30-60s per project), a single machine can check 10-20 projects sequentially before stopping. Group by org to reuse API rate limit budgets.
- **Configurable frequency**: default 24h, configurable in project settings to 12h / 24h / 48h / weekly. Lower-tier projects can check less frequently.
- **Registry API rate limiting**: when checking for new versions, max 50 registry API calls per job invocation. If a project has >50 vulnerable packages, paginate: check the first 50 (sorted by Depscore descending, highest priority first), defer the rest to the next run. Use the existing `NPM_DELAY_MS = 600` pattern for npm, similar delays for PyPI/Maven.
- **Org with 500 projects**: ~25 machine invocations per day (20 projects each), spread across 24h = ~1 per hour. Total compute cost: ~$0.25/day.

### 6I: Historical Vulnerability Timeline

**Database Table:**

```sql
CREATE TABLE project_vulnerability_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  osv_id TEXT NOT NULL,
  event_type TEXT NOT NULL, -- 'detected', 'resolved', 'suppressed', 'accepted', 'unsuppressed', 'kev_added', 'epss_changed', 'depscore_changed'
  metadata JSONB, -- event-specific data: { old_depscore, new_depscore } or { accepted_by, reason } etc.
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_pve_project_id ON project_vulnerability_events(project_id);
CREATE INDEX idx_pve_osv_id ON project_vulnerability_events(osv_id);
CREATE INDEX idx_pve_event_type ON project_vulnerability_events(event_type);
CREATE INDEX idx_pve_created_at ON project_vulnerability_events(created_at DESC);
```

**Events tracked:**

- **detected**: When a vulnerability is first found during extraction (automatically logged)
- **resolved**: When a vulnerability is no longer present after a re-scan (dependency upgraded)
- **suppressed**: When a user marks a vulnerability as suppressed
- **unsuppressed**: When a suppression is removed
- **accepted**: When a user marks vulnerability as accepted risk (with reason)
- **kev_added**: When a vulnerability is added to CISA KEV (detected during background monitoring)
- **epss_changed**: When EPSS score changes by >10% (detected during background monitoring)
- **depscore_changed**: When Depscore changes significantly (due to tier change, KEV addition, etc.)

**Frontend display:**

- Timeline shown in the Vulnerability Detail Sidebar (6D) under the "Timeline" section
- Timeline chart on project overview (Phase 10): "Vulnerability trend over time" - line chart showing total active vulns by severity over time

**Metrics:**

- **MTTR (Mean Time To Remediation)**: calculated per project from detected â†’ resolved events
- Available in the Project Security Sidebar and project overview
- Exportable in security reports

### 6L: Smart Version Recommendation Engine

**Goal:** Provide verified, actionable version upgrade recommendations for each vulnerable package. Instead of a vague "safest version," compute specific candidate versions with OSV-verified safety status and release notes.

**How it works:**

For each vulnerable package during extraction:

1. **Collect fix data**: Aggregate `fixed_versions[]` across all CVEs for the package. Example:
  - CVE-A: fixed in >=4.17.21
  - CVE-B: fixed in >=4.17.20
  - CVE-C: fixed in >=5.0.0
2. **Compute candidate versions**:
  - **Same-major safe**: `max(4.17.21, 4.17.20) = 4.17.21` (highest fix version within current major). Fixes CVE-A and CVE-B but NOT CVE-C.
  - **Fully safe**: `5.0.0` (lowest version that fixes ALL CVEs). May be a major bump.
  - **Latest**: From registry metadata we already fetch during extraction.
3. **Verify candidates against OSV**: One batch API call per package:

```
POST https://api.osv.dev/v1/querybatch
{
  "queries": [
    { "package": { "ecosystem": "npm", "name": "lodash" }, "version": "4.17.21" },
    { "package": { "ecosystem": "npm", "name": "lodash" }, "version": "5.0.0" },
    { "package": { "ecosystem": "npm", "name": "lodash" }, "version": "5.2.1" }
  ]
}
```

Response tells us how many known CVEs exist for each candidate version. Store the count and IDs.

1. **Fetch release notes**: For packages with a linked GitHub repo (available in registry metadata):
  - Query GitHub Releases API: `GET /repos/{owner}/{repo}/releases/tags/v{version}`
  - Store the release notes markdown (truncated to ~2000 chars)
  - If no GitHub release exists, store a link to the package registry page for that version

**Storage:**

```sql
CREATE TABLE project_version_candidates (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  package_name TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  current_version TEXT NOT NULL,
  candidate_type TEXT NOT NULL, -- 'same_major_safe', 'fully_safe', 'latest'
  candidate_version TEXT NOT NULL,
  fixes_cve_count INTEGER NOT NULL, -- how many current CVEs this version fixes
  total_current_cves INTEGER NOT NULL, -- total CVEs for this package in the project
  fixes_cve_ids TEXT[], -- which specific CVEs are fixed
  known_new_cves INTEGER DEFAULT 0, -- CVEs in the candidate version (from OSV verification)
  known_new_cve_ids TEXT[], -- specific new CVE IDs
  is_major_bump BOOLEAN DEFAULT false,
  release_notes TEXT, -- GitHub release notes markdown (truncated)
  release_notes_url TEXT, -- link to full release notes
  published_at TIMESTAMPTZ, -- when this version was published
  verified_at TIMESTAMPTZ, -- when OSV verification was performed
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(project_id, package_name, ecosystem, candidate_type)
);

CREATE INDEX idx_pvc_project_package ON project_version_candidates(project_id, package_name, ecosystem);
```

**Pipeline addition** ([pipeline.ts](backend/extraction-worker/src/pipeline.ts)):

After vulnerability parsing, add a new step:

```typescript
// For each package with vulnerabilities:
// 1. Aggregate fixed_versions across all CVEs
// 2. Compute same_major_safe, fully_safe candidates
// 3. Batch-query OSV for candidate versions
// 4. Fetch release notes from GitHub (if repo URL available)
// 5. Upsert into project_version_candidates
```

**Banned version exclusion:** Before finalizing candidates, query `banned_versions` (org-level) and `team_banned_versions` (for the project's owner team). Any candidate version that appears in the banned list is excluded from recommendations. If the only safe version is banned, store the candidate with an `is_org_banned = true` flag so the UI can show "Safe version exists but is banned by your organization."

**Supply chain tab alignment:** The `project_version_candidates` table becomes the **single source of truth** for version recommendations across both the Security tab and the Supply Chain tab. The supply chain tab's existing version sidebar (`latest-safe-version.ts`) should pull recommended versions from this table instead of computing on-the-fly. This ensures consistent recommendations: the same "same-major safe" and "fully safe" versions shown in the Security tab sidebars also appear in the Supply Chain version sidebar. `latest-safe-version.ts` still handles the computation logic but writes results to `project_version_candidates` during extraction rather than computing per-request.

**Cost:** One OSV API call per vulnerable package (free, fast). One GitHub API call per candidate version with release notes (rate-limited at 5000/hr with auth token, plenty for our use case). Adds ~10-30 seconds to extraction.

### 6J: Design Reference (Stitch AI Prompts)

**IMPORTANT: Stitch AI reference images are saved in the project assets folder. Use these as structural inspiration but adapt to Deptex's design system below.**

Reference mockups (NOT final style -- adapt colors and typography):

- Vulnerability sidebar: `assets/c__Users_hruck_..._image-e46a451f-...png`
- Project sidebar: `assets/c__Users_hruck_..._image-ce79d1e9-...png`
- Dependency sidebar: `assets/c__Users_hruck_..._image-81fe9dfc-...png`
- Aegis panel: `assets/c__Users_hruck_..._image-e1d4b8c4-...png`

**Deptex Design System (use for ALL prompts):**

- Background: `#09090b` (zinc-950)
- Card background: `#18181b` (zinc-900)
- Card header / elevated: `bg-background-card-header` (slightly lighter than card)
- Borders: `#27272a` (zinc-800), 1px solid
- Primary text: `#fafafa`
- Secondary text: `#a1a1aa` (zinc-400)
- Muted text: `#71717a` (zinc-500)
- Primary accent: `#22c55e` (green-500) -- buttons, links, positive indicators
- Destructive: `#ef4444` (red-500) -- critical severity, errors, alerts
- Warning: `#f59e0b` (amber-500) -- high severity, caution
- Border radius: 8px (cards), 6px (badges, buttons), 4px (small elements)
- Font: Inter 14px body, 13px secondary, 12px badges/labels. JetBrains Mono for CVE IDs, file paths, code, versions.
- No gradients, no shadows except very subtle `shadow-sm` on hover. No saturated card backgrounds.
- Style: ultra-minimal, Linear/Vercel-inspired. Dense but breathable. Every pixel deliberate.
- Existing sidebar pattern: slides in from right with `translate-x` transition, width `w-[26rem]` (~416px), full height, close X button in header. Reference: `CreateRoleSidebar.tsx`, `PolicyExceptionSidebar.tsx`.

**Prompt for Vulnerability Detail Sidebar:**

> Design a slide-in security vulnerability detail sidebar for Deptex (dark theme: bg #09090b, cards #18181b, borders #27272a 1px, text #fafafa, secondary #a1a1aa, accent green #22c55e). Width ~416px, full viewport height, slides from right. Font: Inter body, JetBrains Mono for IDs/code. 8px border-radius. No gradients, no shadows. Ultra-minimal Linear/Vercel style.
>
> **Header**: Left: small shield icon + GHSA/CVE ID in JetBrains Mono 15px semibold (clickable, subtle underline on hover). Right: X close button (ghost, zinc-400 hover zinc-100).
>
> **Risk Badges Row** (below header, horizontal wrap, 8px gap): Three pill badges -- (1) "DEPSCORE: 84" with red dot + red border for 75-100, orange for 40-74, gray for 0-39. (2) "SEVERITY: CRITICAL" with matching color text/border (red=critical, orange=high, amber=medium, zinc-500=low). (3) "EPSS: 3.2%" in zinc-500 border. All badges: 12px JetBrains Mono, uppercase, px-2.5 py-1, rounded-md, border 1px, transparent bg.
>
> **CISA KEV Banner** (conditional, full width): If active: rounded-lg card with red-500/10 bg, red-500/30 border. Left: warning triangle icon (red-500). Text: "CISA Known Exploited Vulnerability" bold + "Active exploitation confirmed in the wild. Immediate remediation required." secondary. Right edge: large faded warning triangle watermark at 0.1 opacity.
>
> **RISK CONTEXT section** (label: 12px uppercase zinc-500 tracking-wider): Two rows, each a flex row with icon + text. (1) Green filled shield icon + "Confirmed reachable" bold + "Data-flow analysis successfully traced input to sink." secondary. (2) Purple diamond icon + "Asset Tier: Crown Jewels" bold + "Risk multiplier: 1.5x applied due to asset sensitivity." secondary. Both rows on zinc-900 bg rounded-lg cards with zinc-800 border, py-3 px-4, 8px gap between rows.
>
> **ADVISORY section**: Label "ADVISORY" 12px uppercase zinc-500 left, "Explain with Aegis" text button right (green-500, sparkle icon, 13px). Body: advisory paragraph text in 14px zinc-200, `leading-relaxed`. Inline code snippets (function names like `defaultsDeep`) in JetBrains Mono with zinc-800 bg, px-1.5 py-0.5, rounded, 13px.
>
> **VULNERABLE PATH section** (the code impact view): Label "VULNERABLE PATH". Card with zinc-900 bg, zinc-800 border. Top bar: file path in JetBrains Mono 12px zinc-400 left, "Vulnerable Sink" badge right (red-500/15 bg, red-500 text, 11px, rounded-md). Below: code block with slightly darker bg (#111113), line numbers in zinc-600, code in JetBrains Mono 13px. The vulnerable line (line 42) has a red-500/20 bg highlight spanning full width with a 2px red-500 left border. Syntax highlighting: strings in green-400, keywords in purple-400, functions in blue-400, params in amber-400 (same as code editors).
>
> **REMEDIATION section**: Card with zinc-900 bg. Row: "Upgrade lodash" text bold left + "SAME-MAJOR FIX" badge right (green-500/15 bg, green-500 text, 11px uppercase). Expandable to show target version, fix impact preview ("also resolves CVE-B, CVE-C"), and release notes snippet.
>
> **Sticky Footer** (fixed at bottom, zinc-900 bg, border-t zinc-800, px-4 py-3): Left side: "Suppress" ghost button (zinc-400 text, Eye icon) + "Accept Risk" ghost button (zinc-400 text, Shield icon). Right side / full width below: "Fix with AI" primary button (green-500 bg, white text, sparkle icon, full width, 40px height, rounded-lg, hover green-600).

**Prompt for Dependency Detail Sidebar:**

> Design a slide-in dependency security sidebar for Deptex (same dark theme tokens as above). Width ~416px, full height, slides from right.
>
> **Header**: Left-aligned: "Back to Dashboard" small link (zinc-400, arrow-left icon, 12px) at very top. Below: package name "lodash" in 20px semibold + version "v4.17.21" in JetBrains Mono 14px zinc-400. Below: row of small pill badges -- "MIT License" (green-500/15 bg, green-500 text, lock icon), "Direct Dependency" (zinc-700 bg, zinc-300 text, link icon). Right side: "Last checked: 2h ago" in zinc-500 12px. Far right: X close button.
>
> **Score Row**: Two side-by-side cards on zinc-900 bg. Left card (wider): "Security Score" label 12px zinc-500, large "98" number in 28px semibold green-500, with a thin green-500 progress bar below. Right card: "Anomaly Score" label, large "12" number in green-500, "Normal Activity" badge with green dot below.
>
> **VERSION MATRIX section** (12px uppercase zinc-500 label): Three rows on zinc-900 card. Each row: label left (zinc-400 13px) + version right (JetBrains Mono 14px). (1) "Installed" + "v4.17.21" with orange "Current" badge. (2) "Safest" + "v4.17.21" as green link. (3) "Latest" + "v4.17.21" with "Changelog" link (zinc-400). Rows separated by zinc-800 borders.
>
> **VULNERABILITIES section**: Label + "2 Resolved" count badge right (zinc-500). List of vulnerability rows on zinc-900 cards. Each row: CVE ID in JetBrains Mono 13px bold + "HIGH" severity badge (orange) right side. Description text below in zinc-400 14px. "Patched" badge with green checkmark right (green-500/15 bg). Cards have zinc-800 border, 8px gap between them.
>
> **CODE USAGE section**: Label + "(12 files)" count in zinc-500. File path list with small icons (arrow for imports, circle for components, arrow for API routes). Each path in JetBrains Mono 13px zinc-300. "Show all occurrences" link at bottom (zinc-400, arrow-right).
>
> **Footer** (sticky): Two buttons side by side. "Bump Version" primary (green-500 bg, white text, full width left). "View Full Detail" secondary (zinc-800 bg, zinc-200 text, external-link icon, right). Both rounded-lg, 40px height.

**Prompt for Project Security Sidebar:**

> Design a slide-in project security overview sidebar for Deptex (same dark theme tokens). Width ~416px, full height, slides from right.
>
> **Header**: Project name "Aegis-Core-API" in 18px semibold. Right of name: "High Risk" status badge (red-500/15 bg, red-500 text, red dot, rounded-full, 12px). Right edge: X close button. Below: "Last scan: 12 min ago" in zinc-500 13px.
>
> **Stats Row**: Two side-by-side summary blocks. Left: "VULNERABILITIES" 11px uppercase zinc-500, "23 Total" in 13px zinc-200. Below: thin horizontal multi-color bar (segments: red for critical, orange for high, amber for medium, zinc-600 for low, proportional widths). Below bar: "3 Crit  8 High  7 Mod  5 Low" in 11px with colored dots. Right block: "DEP HEALTH" label, "62 Total". Below: similar bar (red=urgent, orange=moderate, green=healthy). "2 Urgent  15 Mod  45 Healthy" below.
>
> **TOP PRIORITIES section** (12px uppercase zinc-500): Numbered action items as clickable cards (zinc-900 bg, zinc-800 border, hover bg-table-hover). Each card: left-aligned number badge ("01", "02", "03" in zinc-600 JetBrains Mono), title in 14px semibold (e.g., "Update lodash to 4.17.21"), subtitle in 13px zinc-400 (e.g., "Patches CVE-2023-2598"), right: chevron-right icon zinc-600. Cards stacked with 6px gap.
>
> **CODE ISSUES section**: Label "CODE ISSUES" left + "Semgrep" tool badge right (zinc-700 bg, zinc-400 text, 11px). Finding cards on zinc-900 bg: each has a category badge left (red dot + "Injection" in red-400 11px uppercase or "XSS" in amber-400), file path right in JetBrains Mono 12px zinc-500. Description below in 14px zinc-200. "View all 14 issues â†’" link below (zinc-400 13px).
>
> **SECRETS DETECTED section**: Label + "TruffleHog" tool badge. Finding cards: detector type bold ("AWS Access Key ID"), file path in JetBrains Mono 12px zinc-400 below. Verified badge: green checkmark circle (green-500).
>
> **Footer** (sticky): "Re-scan Project" primary button (green-500, left, ~60% width). "Export Report" secondary button (zinc-800 bg, right, ~35% width). Below both: centered "Ask Aegis AI" text link (zinc-400, sparkle icon).

**Prompt for Aegis Copilot Panel:**

> Design a collapsible AI chat panel for Deptex's "Aegis AI" security copilot (same dark theme tokens). The panel lives on the right edge of the Security tab. This should look and feel like the existing PolicyAIAssistant component: same bg-background-card, same border-border, same chat bubble styling.
>
> **Collapsed state**: A small vertical tab fixed to the right viewport edge, 40px wide, ~120px tall, rounded-l-lg (rounded on left, flush on right). Tab has: Aegis lightning bolt icon + "Aegis AI" text rotated 90 degrees. zinc-800 bg, zinc-600 border-l, hover zinc-700. Click to expand.
>
> **Expanded state**: ~350px width, full viewport height, border-l border-border. bg-background-card.
>
> **Header bar** (px-4 py-2.5, border-b border-border): Left: sparkle icon (green-500) + "Aegis AI" in 14px semibold. Center: context dropdown pill (zinc-800 bg, zinc-800 border, 12px text): "Context: CVE-2024-30941 â–¾" -- clicking opens a dropdown to switch context. Right: minimize (â€”) and close (X) ghost buttons.
>
> **Chat area** (flex-1, overflow-y-auto, px-4 py-3): Date separator: "Today, 10:42 AM" centered in zinc-500 12px. User messages: right-aligned, zinc-800 bg rounded-xl (rounded-tr-sm for speech bubble effect), px-3 py-2, 14px text, max-width 85%. Timestamp below: "You â€¢ 10:42 AM" zinc-500 11px right-aligned. Assistant messages: left-aligned, no bg (or very subtle zinc-900/50), border-l-2 green-500/30 pl-3, 14px text. Inline "CRITICAL" badge in red within text. Markdown rendering: bold, bullet lists, code blocks (zinc-900 bg with zinc-800 border, JetBrains Mono 13px, rounded-lg, px-3 py-2). Timestamp: "Aegis â€¢ 10:42 AM" zinc-500 11px.
>
> **Action cards** (inline in chat): Special message type rendered as a card (zinc-900 bg, zinc-800 border, rounded-lg, p-3). Left: green checkmark circle icon. Title: "Patch Proposal Generated" 14px semibold. Subtitle: "Modified package.json to downgrade xz-utils to v4.6." zinc-400 13px. Below: two small buttons side by side -- "Apply Fix" (green-500 bg, white text, 12px, rounded-md) + "Review Diff" (zinc-700 bg, zinc-200 text, 12px, rounded-md).
>
> **Quick actions row** (px-4 py-2, border-t border-border): Row of small pill buttons (zinc-800 bg, zinc-400 text, 12px, rounded-full, px-3 py-1.5, hover zinc-700). Context-specific: "Fix vulnerability", "Explain CVE", "Scan project". Each with a small icon left of text.
>
> **Input area** (px-4 py-3, border-t border-border): Textarea with zinc-800 bg, zinc-700 border, rounded-xl, placeholder "Ask Aegis about your project's security..." in zinc-500 13px. Right side of textarea: green-500 send button (arrow-up icon, circular, 28px). Below textarea: "Aegis can make mistakes. Verify critical actions." in zinc-600 11px centered.
>
> **Streaming behavior**: Unlike the PolicyAIAssistant (which shows "Thinking..." until done), Aegis streams content live. Use `react-markdown` + `remarkGfm` for incremental rendering. Add a streaming fence guard: if accumulated text ends with an unclosed code block (opening 

```without closing), strip from the last

``` onward in the rendered output until the block closes. Same for unclosed bold markers. This prevents raw markdown artifacts during streaming while keeping the live-typing feel. Cursor blink animation at the end of the last line while streaming.

### 6K: Phase 6 Test Suite

#### Backend Tests (`backend/src/__tests__/security-api.test.ts`)

Tests 1-5 (Semgrep/TruffleHog Parsing):

1. Parse valid Semgrep JSON output into `project_semgrep_findings` rows
2. Parse valid TruffleHog JSONL output into `project_secret_findings` rows with redacted values
3. Handle empty/missing Semgrep output gracefully (0 findings, no error)
4. Handle malformed TruffleHog output (skip invalid lines, log warning)
5. Re-extraction replaces old findings (delete + insert pattern)

Tests 6-10 (Vulnerability Detail API):
6. `GET /api/projects/:id/vulnerabilities/:osvId/detail` returns full detail with affected deps and files
7. Returns 404 for non-existent vulnerability
8. Suppress vulnerability sets `suppressed = true`
9. Accept risk sets `risk_accepted`, `risk_accepted_by`, `risk_accepted_at`
10. Suppressed vulnerabilities excluded from default queries (included with `?include_suppressed=true`)

Tests 11-15 (BYOK):
11. Add AI provider with encrypted key, verify key is not returned in GET
12. Test connection endpoint returns success for valid key
13. Test connection endpoint returns error for invalid key
14. Delete provider removes key and cascades
15. Only `manage_integrations` permission can add/modify/delete providers

Tests 16-18 (Background Monitoring):
16. vuln-check job type enqueues and runs correctly
17. New vulnerability detected triggers `project_vulnerability_events` insert with `detected` type
18. EPSS score change >10% triggers `epss_changed` event

#### Frontend Tests (`frontend/src/__tests__/security-tab.test.ts`)

Tests 19-24 (Node Enrichment):
19. Vulnerability node renders Depscore badge, EPSS, KEV indicator, reachability icon, fix available
20. Dependency node renders severity count breakdown and worst depscore
21. Center node renders security issue counts (vulns + code issues + secrets)
22. All three node types show pointer cursor and respond to clicks
23. Clicking a vulnerability node opens `VulnerabilityDetailSidebar`
24. Clicking a dependency node opens `DependencySecuritySidebar`

Tests 25-30 (Filtering):
25. Severity filter hides/dims nodes that don't match
26. Depscore threshold filter works correctly
27. CISA KEV toggle shows only KEV-listed vulnerabilities
28. Multiple simultaneous filters combine correctly (AND logic)
29. Filter state persists in URL search params
30. "Clear all" resets all filters

Tests 31-36 (Sidebars):
31. Vulnerability detail sidebar renders all sections with correct data
32. "Explain with Aegis" button sends context to Aegis panel
33. Dependency sidebar shows vulnerability list sorted by Depscore
34. Project security sidebar shows Semgrep findings and TruffleHog findings
35. Only one sidebar is open at a time (switching node types closes current)
36. Suppress/Accept Risk actions update UI immediately

Tests 37-42 (Aegis Panel):
37. Aegis panel renders collapsed by default (small tab on right edge)
38. Expanding shows chat interface with input field
39. Context switches when user clicks different node types
40. Quick action buttons change based on context type
41. ALL AI features hidden for users without `interact_with_aegis` permission (Aegis panel, "Fix with AI", "Explain with Aegis", "Analyze with AI", policy assistant)
42. Chat messages persist in thread across panel collapse/expand

Tests 43-46 (BYOK UI):
43. AI Configuration section renders provider cards in org settings
44. Connect flow: modal with API key input, model selector, test button
45. Successful test shows "Connected" badge
46. Non-admin users cannot see AI Configuration section

Tests 47-52 (Depscore-based Coloring):
47. Vulnerability node border color matches Depscore bracket (75-100=red, 40-74=orange, 0-39=gray)
48. Dependency node border reflects worst Depscore of child vulns
49. Project center node glow reflects worst Depscore across all child deps
50. Edge colors match target vulnerability Depscore bracket
51. When Depscore data is unavailable, coloring falls back to severity-based
52. Team node (org graph) reflects worst Depscore across child projects

Tests 53-56 (Banned Version Integration):
53. Recommended version in Vuln Detail Sidebar (6D) skips banned versions
54. If only safe version is banned, sidebar shows "banned by your organization" explanation
55. "Fix with AI" button never auto-selects a banned target version
56. Dependency Detail Sidebar (6E) shows red "Banned" badge on banned recommended versions

Tests 57-60 (No-BYOK State):
57. Aegis panel shows setup prompt card when org has no BYOK key configured
58. "Fix with AI" button disabled with tooltip when no BYOK key
59. Tier 1 features ("Analyze with AI") work independently of BYOK status
60. Setup prompt links to correct AI Configuration section in Org Settings

Tests 61-66 (AI Rate Limits & Logging):
61. "Analyze usage with AI" blocked after 5 calls per package per day (shows limit message)
62. Policy AI assistant blocked after 20 messages per conversation
63. Aegis BYOK monthly cost cap blocks new calls when exceeded
64. All AI calls (both tiers) create `ai_usage_logs` rows with correct feature, tier, tokens
65. AI Usage Dashboard renders monthly summary with correct aggregated data
66. AI Usage Dashboard only visible to `manage_integrations` users

Tests 67-70 (Org & Team Security Pages):
67. Org Security page uses Depscore-based coloring on all nodes
68. Ungrouped projects connect directly to org node (no "No team" intermediary)
69. Team Security page shows aggregated security counts (vulns + code issues + secrets)
70. Org Security page filter bar includes "Has active fix" and "PR created" status filters

Tests 71-74 (Safety Cutoffs):
71. Fix attempt blocked after 3 failures for the same target in 24h (shows "manual intervention required")
72. Security Sprint pauses after >50% consecutive failures (asks user confirmation)
73. Extraction worker machine self-destructs after 4h regardless of state
74. Secret findings with `is_current = false` disable "remediate_secret" button (show "Rotate credential" guidance instead)

### 6M: Org & Team Security Pages Overhaul

Both the Organization Vulnerabilities page ([OrganizationVulnerabilitiesPage.tsx](frontend/src/app/pages/OrganizationVulnerabilitiesPage.tsx)) and Team Vulnerabilities page ([TeamAlertsPage.tsx](frontend/src/app/pages/TeamAlertsPage.tsx)) need the Phase 6 treatment. These pages were built before the Security tab overhaul and are missing most of the new features.

**Rename:**

- Organization: "Vulnerabilities" â†’ "Security" in sidebar navigation and breadcrumbs
- Team: "Vulnerabilities" â†’ "Security" in team tabs
- Route updates: `/organizations/:orgId/security` (redirect from old `/vulnerabilities`), team equivalent

**Graph coloring -- Depscore-based:**

Apply the same Depscore coloring from 6A:

- Team nodes: colored by worst Depscore across child projects (75-100=red, 40-74=orange, 0-39=gray, none=green)
- Project nodes: colored by worst Depscore across child deps
- Replace `getWorstSeverity()` calls in `useOrganizationVulnerabilitiesGraphLayout.ts` and `useTeamVulnerabilitiesGraphLayout.ts` with `getWorstDepscore()`

**"No Team" bug fix:**

Current behavior: projects without a team are placed under a synthetic "No team" node (`UNGROUPED_TEAM_ID = 'org-ungrouped'`), AND get an extra direct edge from the org center to the project. This creates visual clutter and a confusing intermediary.

Fix in [useOrganizationVulnerabilitiesGraphLayout.ts](frontend/src/components/vulnerabilities-graph/useOrganizationVulnerabilitiesGraphLayout.ts):

- Remove the `UNGROUPED_TEAM_ID` team node entirely
- Place ungrouped projects directly on the org ring at the same level as team nodes
- Edge: org â†’ project (direct, no intermediary "No team" node)
- Ungrouped projects use the same `VulnProjectNode` component (not `isTeamNode: true`)
- In [OrganizationVulnerabilitiesPage.tsx](frontend/src/app/pages/OrganizationVulnerabilitiesPage.tsx): remove the synthetic team list entry for `UNGROUPED_TEAM_ID`. Instead, pass ungrouped projects as a separate flat list to the layout hook.

**Enriched center nodes:**

- **Org center node**: show aggregated counts below org name: "X vulns | Y code issues | Z secrets" (summed across all projects)
- **Team center node**: same aggregated counts for team's projects
- Both clickable: clicking opens a summary sidebar with security posture breakdown

**Advanced filter bar:**

Add the same filter bar from 6C (severity, Depscore range, EPSS threshold, KEV, fix available, reachable only) to both org and team Security pages. Additional org/team-specific filters:

- **Fix status**: "Has active fix job" / "Fix PR created" / "Risk accepted" / "Suppressed"
- **Sprint status**: "Sprint in progress" / "Sprint completed"
- **Project status**: filter by project's compliance status (from policy engine)
- **Asset tier**: filter by project tier (Crown Jewels, External, Internal, Non-Production)

These filters apply to which PROJECT NODES are shown/dimmed. When a project is dimmed, its child dep/vuln nodes are also dimmed.

**Clickable project nodes:**

- Clicking a project node in the org/team graph navigates to that project's Security tab
- Or (for quick glance): opens an inline mini-sidebar showing the project's security summary (vuln counts by severity, worst Depscore, active fix count, compliance status). "Open Security Tab â†’" link at the bottom.

**Clickable team nodes (org graph only):**

- Clicking a team node navigates to that team's Security page

**Aegis panel:**

- Available on org Security page with org-wide context: "What are the biggest risks across my organization?"
- Available on team Security page with team-wide context: "What should this team fix first?"
- Quick actions adapt: "Prioritize org risks", "Run org sprint", "Generate org security report"

**Sprint launch:**

- "Run Security Sprint" button accessible from both org and team Security pages
- Org-level sprint targets all projects (or filtered subset) -- connects to 7B cross-project sprint
- Team-level sprint targets team's projects only

### 6N: Safety Cutoffs & Runaway Prevention

Comprehensive safety mechanisms to prevent infinite loops, runaway costs, and stuck processes across all AI and VM operations.

#### Fix Attempt Limits

Before starting any AI fix job (Phase 7), check `project_security_fixes` for the same target:

```typescript
const recentFailures = await supabase
  .from('project_security_fixes')
  .select('id')
  .eq('project_id', projectId)
  .eq('osv_id', osvId) // or semgrep_finding_id / secret_finding_id
  .eq('status', 'failed')
  .gte('created_at', new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString());

if (recentFailures.data && recentFailures.data.length >= 3) {
  return { error: 'MAX_ATTEMPTS_REACHED',
    message: 'This issue has had 3 failed fix attempts in the last 24 hours. Manual intervention is required.',
    pastAttempts: recentFailures.data.length };
}
```

The Aegis failure analysis (smart fix failure flow in 7D) must be aware of past attempts:

- After 1 failure: suggest alternative strategy normally
- After 2 failures: suggest with warning "This is the third approach. If it fails, I'll recommend manual intervention."
- After 3 failures: stop suggesting retries. Show: "All automatic approaches have been exhausted for this issue. Here's what I recommend doing manually: [specific guidance based on the three failure modes]."

#### Sprint Circuit Breaker

In the sprint orchestrator (7B-A), track consecutive failures:

```typescript
let consecutiveFailures = 0;
for (const fixRequest of sprintPlan) {
  const result = await executeFixJob(fixRequest);
  if (result.success) {
    consecutiveFailures = 0;
  } else {
    consecutiveFailures++;
    totalFailed++;
    // Circuit breaker: if >50% failed AND at least 3 failures, pause
    if (totalFailed > totalAttempted * 0.5 && totalFailed >= 3) {
      await updateSprintStatus(sprintId, 'paused');
      await notifyUser('Sprint paused: ' + totalFailed + '/' + totalAttempted +
        ' fixes failed. Review failures before continuing.');
      // Wait for user confirmation to resume or cancel
      break;
    }
  }
  totalAttempted++;
}
```

User can: "Resume sprint (skip failed types)" / "Resume sprint (retry all)" / "Cancel sprint"

#### Machine-Level Watchdogs

Every Fly.io machine has a self-destruct timer enforced at the machine level (independent of the application process):

- **Extraction worker**: 4-hour max lifetime (covers 3h dep-scan research timeout + cdxgen + Semgrep + TruffleHog + parsing + buffer). Enforced via Fly Machines API `auto_destroy` and a shell-level `timeout` wrapper.
- **Aider worker**: 10-minute max lifetime (already specified in 7E, this is the same). Enforced via Fly Machines API and Aider's `--timeout` flag.
- Both: if the Node.js process itself hangs (not the child tool), the machine-level timer kills the entire machine. Supabase job status is updated to `failed` with `error_message = 'Machine timeout exceeded'` by a cleanup cron that checks for machines that stopped without reporting completion.

#### Aegis Conversation Limits

Per-thread token budget (200K tokens max) tracked via running total on `aegis_chat_threads`:

```sql
ALTER TABLE aegis_chat_threads
  ADD COLUMN total_tokens_used INTEGER DEFAULT 0;
```

Before each Aegis message: check `total_tokens_used`. If approaching limit (>180K): show warning "This conversation is getting long. Consider starting a new thread for better results." At 200K: block new messages in this thread with "Token limit reached for this thread. Start a new conversation."

#### Secret Finding Safety

`project_secret_findings.is_current` distinguishes secrets found in the current HEAD from secrets found only in git history:

- `**is_current = true**`: Secret exists in the current codebase. "Remediate with AI" button available (Aider replaces hardcoded value with env var reference).
- `**is_current = false**`: Secret was found in git history but no longer in HEAD. Show guidance: "This credential was exposed in a previous commit. Rotate this credential immediately, even though it's been removed from the code. Git history still contains it." No "Remediate with AI" button (nothing to fix in current code). Show "Mark as rotated" button to dismiss.

TruffleHog parsing in pipeline.ts determines `is_current` by checking if the finding's file_path and line still contain the secret in the HEAD checkout. If TruffleHog reports `SourceMetadata.Data.Git` (git history scan) vs `SourceMetadata.Data.Filesystem` (current files), use the source type to set the flag.

#### Re-extraction Safety

When a user triggers a re-extraction while fix jobs are active:

- Check `project_security_fixes` for `status IN ('queued', 'running')` for this project
- If any exist: show warning dialog: "X fix jobs are in progress for this project. Re-extraction will refresh vulnerability data but won't affect running fixes (they use context captured at job start). The Security tab may show temporary inconsistencies until fixes complete. Continue?"
- Running fix jobs are NOT cancelled -- they already have their context. But their results may reference outdated data once extraction completes.

### Competitor Features Matched

- **Snyk Priority Score** â†’ Our Depscore (CVSS + EPSS + CISA KEV + reachability + asset tier). More granular than Snyk's score because it incorporates org-specific asset tiers and customizable environmental multipliers.
- **Snyk Reachability Analysis** â†’ Our dep-scan research profile + atom engine (Phase 6B) provides source-to-sink data-flow reachability: traces user input from framework entry points through call chains to vulnerable library functions, with exact file, line, and method at each step. Comparable to Snyk's function-level reachability but using open-source tooling we control.
- **Snyk DeepCode AI Fix** â†’ Our Aegis + Aider integration (Phase 7). Contextual AI that explains vulnerabilities and can trigger automated fixes. Aegis also handles Semgrep code issues and TruffleHog secret findings (not just dependency vulns).
- **Aikido AutoFix** â†’ Our Aider-based fix engine (Phase 7) for SCA (dependency vulns), SAST (Semgrep code issues via Aegis-driven fixes), and secret remediation (TruffleHog findings).
- **Aikido Exploitability Validation** â†’ Our combination of atom data-flow reachability + CISA KEV + EPSS + Watchtower forensics. With 6B, we can show the exact call path from user code to vulnerable function.
- **Aikido Infinite (Continuous Pentesting)** â†’ Our background vulnerability monitoring (6H) with periodic re-checks against OSV, CISA KEV, and EPSS.
- **Socket Precomputed Reachability** â†’ Our atom usages slices provide detailed usage analysis (HOW and WHERE libraries are used) without Socket's per-contributor pricing.
- **Endor Labs Function-level Reachability** â†’ Our atom reachable flows provide source-to-sink data-flow tracing with call paths and code snippets (Phase 6B). Endor's pre-computed approach is more precise for known CVE-to-function mappings; our approach works automatically for all CVEs without curation. Future enhancement: add CVE-to-function mapping database for Endor-level precision.

**Our unique differentiators:**

- **Aegis Autonomous Security Engineer (Phase 7B)**: No competitor has a full agentic AI that can autonomously manage security operations. Aegis runs a ReAct loop with 50+ tools, creates multi-step plans, executes background tasks over hours, remembers organizational context, proactively monitors for threats, and reaches users via Slack bot, email, and PR comments. This is "Cursor for security engineering" -- not a chatbot with canned responses.
- **Aegis AI Security Copilot with BYOK**: Contextual AI embedded in the security workflow (not a separate tool). Context-switches based on selected node. Handles vuln explanation, Semgrep fix suggestions, secret remediation guidance, and prioritized fix recommendations -- all with the user's own AI keys.
- **Natural language platform control**: "Block all versions of event-stream across the org," "Fix all critical reachable vulns in payments," "Prepare our SOC 2 audit package" -- Aegis can do anything a user can do in the UI, through conversation.
- **Scheduled security operations**: No competitor offers cron-based AI-powered automations. Daily briefings, weekly digests, monthly compliance reports, event-driven zero-day response -- all running automatically.
- **Full interactive Slack bot**: @Aegis in Slack for security queries, approval workflows via Slack buttons, proactive alerts delivered where your team already works.
- **PR security review with AI**: Every PR gets a deep security analysis -- new dependency risk assessment, vulnerability impact, license changes, code security patterns -- posted as a structured review comment.
- **Compliance autopilot**: Automated VEX generation with reachability-based justifications, one-command audit package export (SBOMs + VEX + licenses + reports), audit readiness scoring against SOC 2 / ISO 27001.
- **Proactive intelligence**: Package reputation scoring, cross-project blast radius analysis, EPSS trajectory prediction, zero-day rapid response that assesses and starts fixing across all org projects within minutes.
- **Security debt tracking**: Burndown charts, velocity estimation ("clearing critical debt will take ~3 weeks"), proactive alerts when debt grows faster than it's resolved.
- **Source-to-sink reachability via open-source tooling**: No vendor lock-in, no per-seat reachability pricing. dep-scan + atom gives us data-flow analysis comparable to commercial tools, with CodeImpactView showing the exact code path.
- **Watchtower forensics integration**: Anomaly detection signals feed into vulnerability risk assessment -- a layer competitors don't have.
- **Custom Asset Tiers affecting Depscore**: Organizations define their own criticality model with customizable environmental multipliers.
- **Unified security view**: Dependency vulns + Semgrep code issues + TruffleHog secrets in one tab, all with code-level detail and AI fix capabilities.
- **Depscore**: Context-aware vulnerability scoring that combines CVSS + EPSS + CISA KEV + data-flow reachability + asset tier -- more signals than any single competitor.

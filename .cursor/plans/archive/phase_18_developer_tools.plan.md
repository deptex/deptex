---
name: Phase 18 - Developer Touchpoints
overview: VS Code extension, CLI tool, GitHub Action, and git hooks that bring Deptex security intelligence directly into developer workflows.
todos:
  - id: phase-18-dev-tools
    content: "Phase 18: Developer Touchpoints - VS Code extension with inline vulnerability warnings on import statements, gutter icons for affected packages, quick-fix suggestions linking to Aegis, dependency hover cards showing Depscore/vuln count/license; CLI tool (npx deptex) with check/scan/fix/status commands for local and CI use; GitHub Action and GitLab CI component for pipeline security checks (blocks PRs with critical vulns, generates comment summaries); git pre-commit hook integration; all tools authenticate via org API key, respect RBAC and plan tier limits, 32-test suite"
    status: pending
isProject: false
---
## Phase 18: Developer Touchpoints (IDE, CLI, CI)

**Goal:** Bring Deptex security intelligence directly into the places developers already work -- their IDE, their terminal, and their CI pipeline. Instead of requiring developers to open the Deptex web app, surface vulnerability warnings, dependency scores, and fix suggestions inline in their daily workflow. This drives bottoms-up adoption (developers discover and recommend Deptex to their security team) and creates daily engagement touchpoints that make Deptex harder to remove.

**Prerequisites:** Phase 6 (Security data APIs), Phase 7 (fix engine), Phase 8 (PR webhooks for CI), Phase 13 (API key generation + plan tier limits).

**Timeline:** ~4-6 weeks. Three independent workstreams (IDE, CLI, CI) that can be built in parallel.

### 18A: Authentication & API

All developer tools authenticate via an **Organization API Key** (not user tokens -- these tools run in shared CI environments and shouldn't be tied to individual users):

```sql
CREATE TABLE organization_api_keys (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,                    -- e.g., "CI Pipeline Key", "VS Code Key"
  key_hash TEXT NOT NULL,                -- bcrypt hash of the API key (never store plaintext)
  key_prefix TEXT NOT NULL,              -- first 8 chars for display: "dptx_abc1..."
  permissions TEXT[] DEFAULT '{}',       -- scoped permissions: 'read', 'write', 'fix'
  last_used_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,               -- optional expiration
  created_by UUID NOT NULL REFERENCES auth.users(id),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  revoked_at TIMESTAMPTZ                -- null = active, set = revoked
);
```

**API key management** in Org Settings > Integrations (or new "API Keys" section):

- "Create API Key" button: name input, permission scope selector (Read Only / Read + Write / Full Access), optional expiration date
- Key shown ONCE on creation (modal with copy button, "This key won't be shown again")
- Key list: name, prefix (`dptx_abc1...`), permissions badge, last used, created by, revoke button
- Rate limiting: 1000 requests/hour per key (adjustable per plan tier)

**Backend middleware:**

```typescript
// New auth middleware for API key authentication
// Header: Authorization: Bearer dptx_xxxxxxxxxxxxxxxxxxxx
async function apiKeyAuth(req, res, next) {
  const key = req.headers.authorization?.replace('Bearer ', '');
  if (!key?.startsWith('dptx_')) return res.status(401).json({ error: 'Invalid API key' });
  
  const keyRecord = await lookupApiKey(key); // bcrypt compare against key_hash
  if (!keyRecord || keyRecord.revoked_at) return res.status(401).json({ error: 'Invalid or revoked key' });
  if (keyRecord.expires_at && new Date() > keyRecord.expires_at) return res.status(401).json({ error: 'Expired key' });
  
  // Update last_used_at
  await touchApiKey(keyRecord.id);
  
  // Attach org context to request
  req.orgId = keyRecord.organization_id;
  req.apiKeyPermissions = keyRecord.permissions;
  next();
}
```

**Public API endpoints** (new, separate from internal APIs, prefixed `/api/v1/`):

- `GET /api/v1/projects` -- list projects (for CLI project selection)
- `GET /api/v1/projects/:id/vulnerabilities` -- vulnerability summary
- `GET /api/v1/projects/:id/dependencies` -- dependency list with scores
- `GET /api/v1/projects/:id/security-posture` -- overall security status
- `GET /api/v1/packages/:ecosystem/:name/info` -- package info (Depscore, vulns, license)
- `POST /api/v1/check` -- submit a manifest file for ad-hoc security check (without creating a project)

### 18B: VS Code Extension

Published as `deptex.deptex-security` on the VS Code Marketplace. Built with the VS Code Extension API.

**Setup:**

1. Install extension from marketplace
2. Command palette: "Deptex: Configure API Key" -- prompts for API key + org selection
3. Extension stores key in VS Code's SecretStorage (encrypted)
4. Extension auto-detects projects by matching the workspace's git remote URL against Deptex projects

**Features:**

**1. Import Warnings (inline diagnostics):**

When a file imports a package that has known vulnerabilities in the user's Deptex project:

```typescript
import merge from 'lodash/merge';
//     ~~~~~ Warning: lodash@4.17.15 has 3 vulnerabilities (1 critical)
//           Depscore: 84 (Critical). Fix available: upgrade to 4.17.21
```

Implementation:
- Extension fetches project vulnerability data on workspace open (cached, refreshed every 5 minutes)
- `DiagnosticCollection` with severity mapped from Depscore: critical = Error, high = Warning, medium = Information
- Diagnostics appear in the Problems panel and as squiggly underlines on import statements
- Parse import statements for JS/TS (regex or tree-sitter-wasm), Python (`import`/`from`), Go, Java

**2. Gutter Icons:**

Small icons in the editor gutter next to import lines:
- Red shield: critical vulnerability in imported package
- Amber shield: high vulnerability
- Green shield: package is clean
- Click the gutter icon: opens a hover card with package details

**3. Hover Cards:**

Hovering over a package name in an import statement shows a rich hover card:

```
lodash@4.17.15
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Depscore: 84 (Critical)  |  License: MIT
Vulnerabilities: 3 (1 crit, 1 high, 1 med)
Reachable: Yes (confirmed data-flow)

Top Issue: CVE-2024-XXXX - Prototype Pollution
Fix: Upgrade to 4.17.21 (same-major, no breaking changes)

[Open in Deptex]  [Fix with Aegis]
```

"Open in Deptex" opens the dependency page in the browser. "Fix with Aegis" triggers the Aider fix engine via API (if the API key has `fix` permission).

**4. CodeLens:**

Above functions that call vulnerable package methods (using atom usage slice data):

```typescript
// Aegis: This call reaches lodash.merge() which has CVE-2024-XXXX (prototype pollution)
const result = _.merge({}, userInput);
```

**5. Status Bar:**

Small status bar item showing: "Deptex: 3 vulns (1 crit)" in the bottom bar. Click opens the Problems panel filtered to Deptex diagnostics.

**6. Commands:**

- `Deptex: Check Current File` -- re-scan current file's imports
- `Deptex: Check Workspace` -- re-scan entire workspace
- `Deptex: Open Dashboard` -- opens Deptex web app for this project
- `Deptex: Fix Vulnerability` -- opens quick pick to select a vuln, then triggers AI fix
- `Deptex: Configure API Key` -- setup/change API key

**Extension tech stack:**

- TypeScript + VS Code Extension API
- Tree-sitter WASM for reliable import parsing (JS/TS/Python/Go)
- Webview panel for rich hover cards (or use built-in Hover provider with MarkdownString)
- Caching: LRU cache with 5-minute TTL for API responses
- Debounced file watching: re-check imports when files are saved

### 18C: CLI Tool

Published as `@deptex/cli` on npm. Installable via `npm install -g @deptex/cli` or usable via `npx @deptex/cli`.

**Commands:**

```bash
# Configure (one-time setup, stores key in ~/.deptex/config.json)
deptex auth --key dptx_xxxxxxxxxxxx

# Check current project's security posture
deptex check
# Output:
# Deptex Security Check - payments-api
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Vulnerabilities:  23 total (3 critical, 8 high, 7 medium, 5 low)
# Reachable:        5 confirmed, 3 data-flow
# SLA Breaches:     0
# Compliance:       Passing
# Security Debt:    342 (down 12% this week)
#
# Critical Issues:
#   CVE-2024-XXXX  lodash@4.17.15     Depscore: 94  SLA: 36h left
#   CVE-2024-YYYY  express@4.17.1     Depscore: 87  SLA: 5d left
#   CVE-2024-ZZZZ  jsonwebtoken@8.5.1 Depscore: 82  SLA: 12d left
#
# Run `deptex fix` to start AI-powered fixing.

# Check a specific package before adding it
deptex check-package lodash@4.17.21
# Output:
# lodash@4.17.21
# ━━━━━━━━━━━━━━
# Depscore: 12 (Low)
# Vulnerabilities: 0 known CVEs
# License: MIT (compliant with your org policies)
# Reputation: 92/100
# Safe to add.

# Scan a manifest file (without a Deptex project)
deptex scan ./package.json
# Parses manifest, queries Deptex API, shows vulnerability summary

# Trigger AI fix for a specific vulnerability
deptex fix CVE-2024-XXXX --project payments-api --strategy bump_version
# Queues an AI fix job, shows progress

# Show fix status
deptex status --fixes
# Lists running/queued/completed fix jobs

# Generate security report
deptex report --format markdown --output security-report.md
```

**Exit codes (for CI):**

- `0`: No critical/high vulnerabilities, all SLAs met, compliance passing
- `1`: Critical vulnerabilities found
- `2`: High vulnerabilities found
- `3`: SLA breaches detected
- `10`: Authentication error
- `11`: Project not found

**CI-friendly features:**

- `--json` flag: outputs structured JSON instead of formatted text (for parsing in CI scripts)
- `--fail-on` flag: `--fail-on critical` (default), `--fail-on high`, `--fail-on medium`, `--fail-on none`
- `--sarif` flag: outputs SARIF format for GitHub Code Scanning integration
- `DEPTEX_API_KEY` environment variable (alternative to config file, preferred for CI)
- `--project` flag: explicit project ID (for monorepos where git remote matching is ambiguous)

### 18D: GitHub Action

Published as `deptex/security-check` on the GitHub Actions Marketplace.

```yaml
# .github/workflows/deptex.yml
name: Deptex Security Check
on: [pull_request]

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: deptex/security-check@v1
        with:
          api-key: ${{ secrets.DEPTEX_API_KEY }}
          fail-on: critical      # 'critical', 'high', 'medium', 'none'
          comment: true           # post results as PR comment
          sarif: true             # upload SARIF to GitHub Code Scanning
```

**What the action does:**

1. Reads the repo's manifest files (package.json, requirements.txt, go.mod, etc.)
2. Calls `POST /api/v1/check` with the manifest data
3. Receives vulnerability analysis from Deptex
4. Posts a structured PR comment with findings (if `comment: true`)
5. Uploads SARIF file to GitHub Code Scanning (if `sarif: true`)
6. Sets exit code based on `fail-on` threshold

**PR comment format:**

```markdown
## Deptex Security Check

| Severity | Count | Reachable |
|----------|-------|-----------|
| Critical | 1     | 1         |
| High     | 3     | 1         |
| Medium   | 5     | 0         |
| Low      | 2     | 0         |

### Critical Issues
- **CVE-2024-XXXX** in `lodash@4.17.15` - Prototype Pollution (Depscore: 94, reachable)
  - Fix: Upgrade to 4.17.21

<details>
<summary>High Issues (3)</summary>
...
</details>

---
*Powered by [Deptex](https://deptex.dev) | [View full report](https://app.deptex.dev/...)*
```

**GitLab CI equivalent:**

```yaml
# .gitlab-ci.yml
deptex-check:
  image: node:20
  script:
    - npx @deptex/cli check --json --fail-on critical
  variables:
    DEPTEX_API_KEY: $DEPTEX_API_KEY
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

### 18E: Git Hooks Integration

Optional pre-commit hook that checks for vulnerabilities before allowing commits:

```bash
# Install via CLI
deptex hooks install
# Creates .git/hooks/pre-commit that runs `deptex check --fail-on critical`
```

**Behavior:**

- Only runs when `package.json`, `requirements.txt`, `go.mod`, or other manifest files are in the staged changes
- If no manifest files changed: hook passes immediately (no API call, no delay)
- If manifest changed: runs `deptex check-package` for any newly added dependencies
- Blocks commit if new dependency has critical vulnerabilities
- `--no-verify` flag bypasses the hook (standard git behavior)
- Optional: husky/lint-staged integration for JS/TS projects

**Performance:** The hook caches the last check result in `.git/deptex-cache.json` (gitignored). If the manifest hash hasn't changed since the last check, the hook passes without an API call. Typical execution: <500ms for cached, 2-3s for API call.

### 18F: Phase 18 Test Suite

#### VS Code Extension Tests (`extensions/vscode/src/__tests__/`)

Tests 1-8 (Extension Core):
1. API key stored securely in VS Code SecretStorage
2. Project auto-detected from workspace git remote URL
3. Vulnerability data fetched and cached on workspace open
4. Cache refreshes every 5 minutes (not on every file open)
5. Import statement parsing: JS/TS `import` and `require` correctly identified
6. Import statement parsing: Python `import` and `from` correctly identified
7. Diagnostic severity maps correctly: critical=Error, high=Warning, medium=Information
8. Status bar shows correct vulnerability count

Tests 9-14 (UI Features):
9. Hover card renders package info with Depscore, vulns, license
10. Gutter icon color matches vulnerability severity
11. "Open in Deptex" command opens correct URL in browser
12. "Fix with Aegis" triggers API call with correct parameters
13. CodeLens shows on functions calling vulnerable package methods
14. "Check Workspace" command re-scans all files and updates diagnostics

#### CLI Tests (`packages/cli/src/__tests__/`)

Tests 15-22 (CLI Commands):
15. `deptex auth` stores API key in config file with correct permissions
16. `deptex check` returns correct vulnerability summary for a project
17. `deptex check-package` returns correct info for a specific package
18. `deptex scan` parses package.json and returns vulnerability results
19. `deptex fix` triggers fix job and shows progress
20. Exit code 0 when no critical vulns, exit code 1 when critical vulns present
21. `--json` flag outputs valid JSON structure
22. `--sarif` flag outputs valid SARIF 2.1.0 format

Tests 23-26 (CI Integration):
23. `DEPTEX_API_KEY` environment variable used when config file missing
24. `--fail-on high` returns exit code 2 for high vulns (not just critical)
25. `--project` flag overrides auto-detection for monorepos
26. Rate limiting: CLI handles 429 response with retry and clear error message

#### GitHub Action Tests (`actions/security-check/src/__tests__/`)

Tests 27-32 (Action):
27. Action reads manifest files from checked-out repo
28. Action posts PR comment with correct vulnerability table
29. Action uploads valid SARIF file to GitHub Code Scanning
30. Action respects `fail-on` threshold and sets correct exit code
31. Action handles missing API key with clear error message
32. Action edits existing Deptex comment instead of posting duplicate (smart comment dedup)

# Adding a New Ecosystem

Deptex uses [cdxgen](https://github.com/CycloneDX/cdxgen) for SBOM generation and [depscan](https://github.com/owasp-dep-scan/dep-scan) for vulnerability scanning — both already support dozens of ecosystems. Adding a new one to Deptex is just registering it in three places.

---

## Quick start — add an ecosystem in 3 files

Once the foundation is in place (see [Architecture](#architecture) below), adding a new ecosystem is **three one-line additions**.

### 1. Register the manifest file

**File:** `backend/src/lib/ecosystems.ts`

```typescript
// Each entry maps a manifest filename → ecosystem id.
// The ecosystem id is also the PURL type and the depscan -t flag.
export const MANIFEST_FILES: Record<string, string> = {
  'package.json':      'npm',
  'requirements.txt':  'pypi',
  'pom.xml':           'maven',
  // ...

  'your-manifest.xyz': 'your-ecosystem',   // ← add your line here
};
```

This is the **single source of truth**. It controls:
- Which files are detected when scanning a repository
- Which ecosystem id flows through the pipeline (`-t` flag to depscan, PURL matching, DB storage)

The key is the **exact filename** found in the repository root (or subdirectory). The value is the ecosystem identifier string — this must match the [PURL type](https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst) and the [depscan `-t` flag](https://github.com/owasp-dep-scan/dep-scan#supported-languages-and-package-formats).

> **Multiple manifests per ecosystem** are fine. For example, Python has `requirements.txt`, `Pipfile`, `pyproject.toml`, and `setup.py` — all mapping to `pypi`.

### 2. Add framework detection rules

**File:** `backend/src/lib/ecosystems.ts`

```typescript
// Each ecosystem has an array of framework detection rules.
// Rules are checked in order; first match wins.
// The `match` string is tested against the raw manifest file content.
export const FRAMEWORK_RULES: Record<string, Array<{ match: string; framework: string }>> = {
  npm: [
    { match: '"next"',            framework: 'nextjs' },
    { match: '"react-scripts"',   framework: 'create-react-app' },
    { match: '"react"',           framework: 'react' },
    // ...
  ],
  pypi: [
    { match: 'django',   framework: 'django' },
    { match: 'fastapi',  framework: 'fastapi' },
    { match: 'flask',    framework: 'flask' },
  ],
  // ...

  'your-ecosystem': [                                // ← add your block here
    { match: 'some-framework', framework: 'some-fw' },
  ],
};

// Fallback icon/label when no framework rule matches.
// This is what shows up in the UI for a generic project of that ecosystem.
export const ECOSYSTEM_DEFAULTS: Record<string, string> = {
  npm:       'node',
  pypi:      'python',
  maven:     'java',
  nuget:     'dotnet',
  golang:    'go',
  cargo:     'rust',
  gem:       'ruby',
  composer:  'php',
  pub:       'dart',
  hex:       'elixir',
  swift:     'swift',

  'your-ecosystem': 'your-icon-id',                  // ← add your line here
};
```

If you don't know which frameworks to detect, just add the `ECOSYSTEM_DEFAULTS` entry. Framework rules are optional — the fallback covers it.

### 3. Add the icon

**File:** `frontend/src/components/framework-icon.tsx`

```typescript
import { SiPython, SiDjango /* ... */ } from '@icons-pack/react-simple-icons';

const icons: Record<string, React.ComponentType<{ size?: number; className?: string }>> = {
  // ...existing entries...

  'your-icon-id': SiYourIcon,   // ← add your line here
};
```

Icons come from [`react-simple-icons`](https://simpleicons.org/) — search for your language/framework there. If none exists, use a custom SVG or omit it (the Deptex logo shows as fallback).

### That's it

Commit, open a PR. The rest of the pipeline (cdxgen SBOM generation, depscan vulnerability scanning, PURL parsing, database storage) is ecosystem-agnostic and handles everything automatically.

---

## Currently supported ecosystems

All of the following ecosystems are fully wired up end-to-end: manifest detection, cdxgen SBOM generation, depscan vulnerability scanning, PURL parsing, database storage, and frontend icons.

| Ecosystem | Manifest files | Ecosystem id | Frameworks detected | Icon |
|---|---|---|---|---|
| **Node.js** (npm/yarn/pnpm) | `package.json` | `npm` | nextjs, react, vue, nuxt, svelte, angular, express | SiNodedotjs |
| **Python** (pip/poetry) | `requirements.txt`, `Pipfile`, `pyproject.toml`, `setup.py` | `pypi` | django, fastapi, flask, scrapy | SiPython |
| **Java** (Maven/Gradle) | `pom.xml`, `build.gradle`, `build.gradle.kts` | `maven` | spring-boot, quarkus, android | SiOpenjdk |
| **C# / .NET** | `*.csproj`, `*.fsproj`, `*.vbproj` | `nuget` | aspnet | SiDotnet |
| **Go** | `go.mod` | `golang` | gin, echo, fiber | SiGo |
| **Rust** | `Cargo.toml` | `cargo` | actix, axum, rocket | SiRust |
| **Ruby** | `Gemfile` | `gem` | rails, sinatra | SiRuby |
| **PHP** | `composer.json` | `composer` | laravel, symfony, wordpress | SiPhp |
| **Dart / Flutter** | `pubspec.yaml` | `pub` | — | SiDart |
| **Elixir** | `mix.exs` | `hex` | — | SiElixir |
| **Swift / iOS** | `Package.swift` | `swift` | — | SiSwift |

> **.NET note:** .NET project files have variable names (e.g. `MyApp.csproj`), so detection uses extension-based matching via `MANIFEST_EXTENSIONS` in `ecosystems.ts` rather than exact filename matching.

### Icon reference

Available icons from `@icons-pack/react-simple-icons`:

| Framework id | Import |
|---|---|
| `python` | `SiPython` |
| `django` | `SiDjango` |
| `fastapi` | `SiFastapi` |
| `flask` | `SiFlask` |
| `java` | `SiOpenjdk` |
| `spring-boot` | `SiSpringboot` |
| `go` | `SiGo` |
| `rust` | `SiRust` |
| `ruby` | `SiRuby` |
| `rails` | `SiRubyonrails` |
| `dotnet` | `SiDotnet` |
| `php` | `SiPhp` |
| `laravel` | `SiLaravel` |
| `swift` | `SiSwift` |
| `dart` | `SiDart` |
| `flutter` | `SiFlutter` |
| `elixir` | `SiElixir` |

---

## Architecture

How the ecosystem plumbing works end-to-end, for contributors who want to understand (or modify) the internals.

### Pipeline overview

```
Repository scan          Extraction pipeline (worker)
─────────────────        ──────────────────────────────────────────────
1. Scan repo tree   →    2. Clone repo
   find manifest         3. cdxgen generates SBOM (ecosystem-agnostic)
   detect ecosystem      4. Parse SBOM, extract deps via PURL
   detect framework      5. depscan -t <ecosystem> finds vulns
                         6. Map vulns to deps via PURL
                         7. Enrich (EPSS, CISA KEV, depscore)
                         8. Store in DB
```

### Key files

| File | Role |
|---|---|
| `backend/src/lib/ecosystems.ts` | **Single source of truth** — `MANIFEST_FILES`, `FRAMEWORK_RULES`, `ECOSYSTEM_DEFAULTS` |
| `backend/src/lib/detect-monorepo.ts` | Scans GitHub repo tree for manifest files, returns detected projects with ecosystem |
| `backend/src/routes/projects.ts` | API endpoints — repo listing with framework detection, connect endpoint |
| `backend/src/lib/redis.ts` | Queues extraction job (includes `ecosystem` field) |
| `backend/extraction-worker/src/index.ts` | Worker entry — reads jobs from Redis queue |
| `backend/extraction-worker/src/pipeline.ts` | Full extraction pipeline — cdxgen, depscan, vuln parsing |
| `backend/extraction-worker/src/sbom.ts` | CycloneDX SBOM parser — generic PURL parsing |
| `frontend/src/components/framework-icon.tsx` | Icon component — maps framework id → SVG icon |
| `frontend/src/utils/detect-framework.ts` | Client-side framework detection (optional, backend is primary) |

### How manifest detection works

`detect-monorepo.ts` scans the repository tree via GitHub API and matches filenames against `MANIFEST_FILES`. Each match produces a `PotentialProject`:

```typescript
interface PotentialProject {
  name: string;       // From manifest (e.g. package.json "name") or directory name
  path: string;       // Directory path relative to repo root ('' = root)
  ecosystem: string;  // From MANIFEST_FILES lookup
  manifestFile: string;
}
```

For npm projects, it also checks `pnpm-workspace.yaml` and `package.json` workspaces for monorepo detection. Other ecosystems use the simpler approach of scanning the full tree for their manifest files.

### How PURL parsing works

All ecosystems use the same [Package URL](https://github.com/package-url/purl-spec) format:

```
pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>
```

The generic parser in `sbom.ts` handles any PURL type:

```typescript
// pkg:npm/express@4.18.0          → { type: 'npm',   name: 'express',                      version: '4.18.0' }
// pkg:pypi/django@4.2             → { type: 'pypi',  name: 'django',                       version: '4.2' }
// pkg:maven/org.springframework/spring-core@6.0.0
//                                 → { type: 'maven', name: 'org.springframework/spring-core', version: '6.0.0' }
```

No per-ecosystem PURL logic is needed. If cdxgen generates it, the parser handles it.

### How depscan ecosystem selection works

The extraction worker passes the `ecosystem` field from the job payload as the `-t` flag to depscan:

```typescript
const depScanArgs = [
  '--bom', bomPath,
  '--reports-dir', reportsDir,
  '-t', job.ecosystem || 'npm',
  '--no-banner',
  '--vulnerability-analyzer', 'VDRAnalyzer',
];
```

The ecosystem id **is** the depscan type string (they follow the same PURL type convention). No mapping needed.

### How framework detection works

When listing repositories in the UI, the backend fetches the manifest file content and runs it through `FRAMEWORK_RULES`:

```typescript
function detectFramework(ecosystem: string, manifestContent: string): string {
  const rules = FRAMEWORK_RULES[ecosystem] || [];
  for (const rule of rules) {
    if (manifestContent.includes(rule.match)) return rule.framework;
  }
  return ECOSYSTEM_DEFAULTS[ecosystem] || 'unknown';
}
```

Simple string matching on the raw file content. No AST parsing, no special handling per ecosystem.

### Database schema

The `ecosystem` is stored in `project_repositories`:

```sql
ALTER TABLE project_repositories ADD COLUMN ecosystem TEXT NOT NULL DEFAULT 'npm';
```

Dependencies in `project_dependencies` are ecosystem-agnostic — they store `name`, `version`, `is_direct`, and `source`. The `source` field uses:
- `'dependencies'` / `'devDependencies'` for npm (preserving npm semantics)
- `'direct'` / `'transitive'` for all other ecosystems

### Data flow for `ecosystem`

```
Frontend (scan result)
  → API: POST /repositories/connect { ecosystem: 'pypi', ... }
    → project_repositories.ecosystem = 'pypi'
    → Redis job: { ecosystem: 'pypi', ... }
      → Worker: depscan -t pypi
      → Worker: PURL parser (generic, handles pkg:pypi/...)
        → project_dependencies rows
        → project_dependency_vulnerabilities rows
```

---

## Foundation work (one-time setup)

These changes only need to happen once to make the system ecosystem-agnostic. They are **not** repeated per ecosystem. If these are already done, skip to [Quick start](#quick-start--add-an-ecosystem-in-3-files).

### Checklist

- [ ] Create `backend/src/lib/ecosystems.ts` with `MANIFEST_FILES`, `FRAMEWORK_RULES`, and `ECOSYSTEM_DEFAULTS`
- [ ] Update `detect-monorepo.ts` to scan for all manifest types (not just `package.json`)
- [ ] Update `PotentialProject` interface to include `ecosystem` and `manifestFile`
- [ ] Refactor `detectFramework()` in `projects.ts` to use `FRAMEWORK_RULES` from `ecosystems.ts`
- [ ] Replace npm-specific PURL parser in `sbom.ts` with generic `parsePurl()`
- [ ] Replace `parseNpmPurl()` in `pipeline.ts` with generic PURL parser
- [ ] Change hardcoded `-t npm` in `pipeline.ts` to `-t ${job.ecosystem || 'npm'}`
- [ ] Add `ecosystem` field to extraction job interface (`redis.ts`, `index.ts`)
- [ ] Add `ecosystem` column to `project_repositories` table (DB migration)
- [ ] Update connect endpoint in `projects.ts` to accept and store `ecosystem`
- [ ] Update frontend `api.connectProjectRepository()` to pass `ecosystem`
- [ ] Update `ProjectsPage.tsx` error messages (replace "No package.json found" with generic text)

### Detailed file changes

Each item references the exact file and current line numbers.

<details>
<summary><strong>ecosystems.ts</strong> — new file, single source of truth</summary>

Create `backend/src/lib/ecosystems.ts`. This is the one file contributors edit when adding an ecosystem. All other code imports from here.

```typescript
/** Manifest filename → ecosystem id (also the PURL type and depscan -t value). */
export const MANIFEST_FILES: Record<string, string> = {
  'package.json':      'npm',
  'requirements.txt':  'pypi',
  'Pipfile':           'pypi',
  'pyproject.toml':    'pypi',
  'setup.py':          'pypi',
  'pom.xml':           'maven',
  'build.gradle':      'maven',
  'build.gradle.kts':  'maven',
  'go.mod':            'golang',
  'Cargo.toml':        'cargo',
  'Gemfile':           'gem',
  'composer.json':     'composer',
  'pubspec.yaml':      'pub',
  'mix.exs':           'hex',
  'Package.swift':     'swift',
};

/** Framework detection rules per ecosystem. First match wins. */
export const FRAMEWORK_RULES: Record<string, Array<{ match: string; framework: string }>> = {
  npm: [
    { match: '"next"',            framework: 'nextjs' },
    { match: '"react-scripts"',   framework: 'create-react-app' },
    { match: '"react"',           framework: 'react' },
    { match: '"vue"',             framework: 'vue' },
    { match: '"nuxt"',            framework: 'nuxt' },
    { match: '"svelte"',          framework: 'svelte' },
    { match: '"@angular/core"',   framework: 'angular' },
    { match: '"express"',         framework: 'express' },
  ],
  pypi: [
    { match: 'django',    framework: 'django' },
    { match: 'fastapi',   framework: 'fastapi' },
    { match: 'flask',     framework: 'flask' },
    { match: 'scrapy',    framework: 'scrapy' },
  ],
  maven: [
    { match: 'spring-boot',  framework: 'spring-boot' },
    { match: 'quarkus',      framework: 'quarkus' },
    { match: 'android',      framework: 'android' },
  ],
  golang: [
    { match: 'gin-gonic',      framework: 'gin' },
    { match: 'labstack/echo',  framework: 'echo' },
    { match: 'gofiber',        framework: 'fiber' },
  ],
  cargo: [
    { match: 'actix',   framework: 'actix' },
    { match: 'axum',    framework: 'axum' },
    { match: 'rocket',  framework: 'rocket' },
  ],
  gem: [
    { match: 'rails',    framework: 'rails' },
    { match: 'sinatra',  framework: 'sinatra' },
  ],
  nuget: [
    { match: 'Microsoft.AspNetCore',  framework: 'aspnet' },
  ],
  composer: [
    { match: 'laravel',    framework: 'laravel' },
    { match: 'symfony',    framework: 'symfony' },
    { match: 'wordpress',  framework: 'wordpress' },
  ],
};

/** Fallback framework id when no rule matches (used for icon + label). */
export const ECOSYSTEM_DEFAULTS: Record<string, string> = {
  npm:       'node',
  pypi:      'python',
  maven:     'java',
  nuget:     'dotnet',
  golang:    'go',
  cargo:     'rust',
  gem:       'ruby',
  composer:  'php',
  pub:       'dart',
  hex:       'elixir',
  swift:     'swift',
};

/** Directories to skip when scanning repository trees for manifests. */
export const IGNORED_DIRS = ['node_modules', 'vendor', '.venv', '__pycache__', 'target', 'build', 'dist'];

/** Detect framework from manifest content using the rule tables above. */
export function detectFrameworkForEcosystem(ecosystem: string, manifestContent: string): string {
  const rules = FRAMEWORK_RULES[ecosystem] || [];
  for (const rule of rules) {
    if (manifestContent.includes(rule.match)) return rule.framework;
  }
  return ECOSYSTEM_DEFAULTS[ecosystem] || 'unknown';
}
```
</details>

<details>
<summary><strong>detect-monorepo.ts</strong> — scan for all manifest types</summary>

**Current:** `getPackageJsonDirsFromTree()` (line 40-49) only matches `package.json`.

Add a new function that uses `MANIFEST_FILES`:

```typescript
import { MANIFEST_FILES, IGNORED_DIRS } from './ecosystems';

function getManifestDirsFromTree(
  tree: Array<{ path: string; type: string }>
): Array<{ dirPath: string; filePath: string; ecosystem: string }> {
  const dirs: Array<{ dirPath: string; filePath: string; ecosystem: string }> = [];
  const seen = new Set<string>();

  for (const node of tree) {
    if (node.type !== 'blob') continue;
    if (IGNORED_DIRS.some(d => node.path.includes(d + '/'))) continue;

    const fileName = node.path.split('/').pop() || '';
    const ecosystem = MANIFEST_FILES[fileName];
    if (!ecosystem) continue;

    const dirPath = node.path === fileName ? '' : node.path.slice(0, -(fileName.length + 1));
    const key = `${dirPath}::${ecosystem}`;
    if (seen.has(key)) continue;
    seen.add(key);

    dirs.push({ dirPath, filePath: node.path, ecosystem });
  }
  return dirs;
}
```

Update `PotentialProject`:

```typescript
export interface PotentialProject {
  name: string;
  path: string;
  ecosystem: string;
  manifestFile: string;
}
```

Keep the existing `package.json` workspace detection for npm monorepos — just add `ecosystem: 'npm'` to the returned objects. The fallback tree scan should use `getManifestDirsFromTree()`.
</details>

<details>
<summary><strong>sbom.ts</strong> — generic PURL parser</summary>

**Current:** `nameFromPurl()` (line 44) regex is hardcoded to `pkg:npm`.

Replace with:

```typescript
function parsePurl(purl: string): { type: string; name: string; version: string | null } | null {
  const match = purl.match(/^pkg:([^/]+)\/(.+?)(?:@([^?#]+))?(?:\?|#|$)/);
  if (!match) return null;
  const [, type, fullName, version] = match;
  return {
    type,
    name: decodeURIComponent(fullName),
    version: version ? decodeURIComponent(version) : null,
  };
}

function nameFromPurl(purl: string): string {
  return parsePurl(purl)?.name ?? purl.split('/').pop() ?? '';
}

function versionFromPurl(purl: string): string | null {
  return parsePurl(purl)?.version ?? null;
}
```
</details>

<details>
<summary><strong>pipeline.ts</strong> — dynamic depscan flag + generic vuln PURL</summary>

**Line 400:** Replace `'npm'` with `job.ecosystem || 'npm'`.

**Lines 563-577:** Replace `parseNpmPurl` with:

```typescript
const parsePurl = (ref: string): { name: string; version: string } | null => {
  if (!ref || typeof ref !== 'string') return null;
  const match = ref.match(/^pkg:[^/]+\/(.+?)@([^?#]+)/);
  if (!match) return null;
  return { name: decodeURIComponent(match[1]), version: decodeURIComponent(match[2]) };
};
```
</details>

<details>
<summary><strong>redis.ts + index.ts</strong> — add ecosystem to job payload</summary>

Add `ecosystem?: string` to the extraction job interface in both files.

`redis.ts` (line 125-130): add to `repoRecord` parameter.

`index.ts` (line 21-28): add to `ExtractionJob` interface.
</details>

<details>
<summary><strong>projects.ts</strong> — connect endpoint + repo listing</summary>

**Connect endpoint (line 3192):** Destructure `ecosystem` from `req.body`, store in `project_repositories`, pass to `queueExtractionJob()`.

**Repo listing endpoints (lines 848-878 and 3063-3091):** Use `detectFrameworkForEcosystem()` from `ecosystems.ts` instead of the inline `detectFramework()`.
</details>

<details>
<summary><strong>framework-icon.tsx</strong> — add icons</summary>

Import new icons from `@icons-pack/react-simple-icons` and add entries to the `icons` map. See [Icon reference](#icon-reference) for the full list.
</details>

<details>
<summary><strong>ProjectsPage.tsx</strong> — update strings</summary>

- Replace `'No package.json found'` with `'No manifest file found'`
- Replace `'Repository has no detectable package.json.'` with `'No supported manifest file found in this repository.'`
</details>

<details>
<summary><strong>Database migration</strong></summary>

Create `backend/database/add_ecosystem_to_project_repositories.sql`:

```sql
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'project_repositories'
      AND column_name = 'ecosystem'
  ) THEN
    ALTER TABLE project_repositories
      ADD COLUMN ecosystem TEXT NOT NULL DEFAULT 'npm';
  END IF;
END $$;
```
</details>

---

## Testing a new ecosystem

1. Find a public GitHub repo that uses the ecosystem (e.g. `django/django` for Python, `spring-projects/spring-boot` for Maven)
2. Install the Deptex GitHub App on a fork (or your own test repo with that ecosystem)
3. Create a new project and connect the repo
4. Verify:
   - [ ] Manifest file detected in repo scan
   - [ ] Correct ecosystem stored in `project_repositories`
   - [ ] cdxgen generates valid SBOM (check Supabase storage bucket)
   - [ ] depscan runs with correct `-t` flag (check worker logs for `dep-scan command`)
   - [ ] Vulnerabilities parsed and stored in `project_dependency_vulnerabilities`
   - [ ] Dependencies visible in the Dependencies tab
   - [ ] Correct icon on the project card

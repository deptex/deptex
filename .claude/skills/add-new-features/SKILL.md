---
name: add-new-features
description: Where to add new code in the Deptex codebase — backend routes, shared libs, DB migrations, worker jobs, frontend pages/components. Read this before adding a feature so it lands in the right place and follows existing conventions.
---

# Add New Features — "Where does X go?"

A practical map of where each kind of new code lives in Deptex, with real files to copy from. Paths are relative to the repo root (`C:\Coding\Deptex`). See `CLAUDE.md` for the architecture overview, `DEVELOPERS.md` for setup.

Backend: `cd backend && npm run dev` (Express, port 3001). Frontend: `cd frontend && npm run dev` (Vite, port 3000). Use git bash, not PowerShell.

---

## 1. Backend API route

Two steps: create the router file, then mount it.

**Create** `backend/src/routes/<name>.ts`. Every route file follows the same shape (copy `backend/src/routes/reachability-settings.ts` as the canonical small example):

```ts
import express from 'express';
import { authenticateUser, type AuthRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';

const router = express.Router();

router.get('/:id/thing', authenticateUser, async (req: AuthRequest, res) => {
  const userId = req.user!.id;   // set by authenticateUser
  const orgId = req.params.id;
  // ... permission check + supabase query
  res.json(data);
});

export default router;   // default-export the router
```

- `authenticateUser` (`backend/src/middleware/auth.ts:126`) requires a valid JWT/API-token and populates `req.user = { id, email }`. Use `optionalAuth` (`auth.ts:196`) for routes that work signed-out but personalize when signed-in. The request type is `AuthRequest` (`auth.ts:6`).
- Router files catch their own errors and `res.status(500).json({ error })` — they do **not** rethrow. The global handler in `index.ts:272` is only a last-resort net (and deliberately strips body bytes from logs).

**Mount** it in `backend/src/index.ts`: add an `import fooRouter from './routes/foo'` alongside the others (`index.ts:14-73`) and an `app.use('/api/...', fooRouter)` in the mount block (`index.ts:183-250`). Note the mount-prefix conventions already in use:
- Org-scoped resources mount under `/api/organizations` and match `/:id/...` inside the router (the `:id` is the org id). Many routers share this prefix — e.g. `organizations`, `teams`, `projects`, `scanner-findings`.
- Internal/worker/cron endpoints mount under `/api/internal/...` and are protected by the internal key, not `authenticateUser` (see §4).
- Webhook receivers verify a signature over the raw body instead of a JWT (`gitlab-webhooks`, `bitbucket-webhooks`, and the GitHub handler `app.post('/api/webhook/github', ...)` at `index.ts:248`).

### RBAC — check a permission KEY, never a role name

Roles are permission bundles, not a ladder. Authorize by looking up the caller's role row and checking the relevant key in its `permissions` JSONB; `owner` always passes. **Never** gate on `role === 'admin'` — there is no built-in `admin` role, and role names are org-customizable.

The inline pattern is in `reachability-settings.ts:35-53` (`hasPermission(userId, orgId, permissionKey)` → read `organization_members.role`, `owner` short-circuits true, else read `organization_roles.permissions[key]`). Shared helpers live in `backend/src/lib/rbac.ts` — `checkOrgManageIntegrations` (`rbac.ts:14`) and `checkOrgAccess` (`rbac.ts:41`, any-member read gate). Reuse or mirror these; don't invent a new membership query shape.

Permission keys are enumerated in `CLAUDE.md` under "RBAC & Permissions" (org keys in `organization_roles.permissions`, team keys in `team_roles.permissions`). Note the memory rule: some CLAUDE.md keys can lag reality — grep an existing route for the exact key before relying on it.

---

## 2. Shared backend lib

Reusable, non-HTTP logic goes in `backend/src/lib/`. Two layouts coexist:
- **Sub-directory** per subsystem when it's more than one file: `ai/`, `aegis/`, `aegis-v3/`, `billing/`, `findings/`, `flows/`, `flow-code/`, `job-queue/`, `learning/`, `malicious/`, `observability/`, `taint-engine/`.
- **Single file** at `lib/` root for a focused concern: `policy-engine.ts`, `github.ts`, `health-score.ts`, `permissions.ts`, `rbac.ts`, `email.ts`, `ghsa.ts`, etc.

Rule of thumb: start as `lib/<name>.ts`; promote to `lib/<name>/` (with an `index.ts` barrel) once it grows past a couple of files. Import shared infra from here — `supabase` from `lib/supabase`, job dispatch from `lib/qstash`, caching from `lib/cache`.

---

## 3. Database migration

Add `backend/database/phaseNN_<description>.sql` (plain SQL — `CREATE TABLE` / `ALTER` / `CREATE FUNCTION`, RPCs included). The `phaseNN_` prefix is historical and stable but carries no load-bearing ordering beyond what the filenames imply; a fresh install runs the ~340 files in filename-sorted order. Some tables predate the prefix scheme and use bare names (`teams_schema.sql`).

**Mandatory follow-up (same PR):** after adding or modifying any migration, refresh the generated schema:

```bash
cd depscanner && npm run schema:dump
```

This regenerates `backend/database/schema.sql`, the single source of truth for PGLite local-mode (depscanner CLI + CI smoke tests). CI enforces it: `.github/workflows/schema-check.yml` fails any PR that touches `backend/database/*.sql` without also updating `schema.sql`. Caveat from prior work: `schema:dump` pulls live-prod drift, so if it drags in unrelated changes, hand-edit `schema.sql` to add only your migration's new identifiers.

---

## 4. Worker job / QStash step

Two Fly.io workers, dispatched off `scan_jobs.type`:
- **`depscanner/`** — extraction and DAST. A single Fly app claims jobs via the atomic `claim_scan_job(machine_id, [types])` RPC (`depscanner/src/job-db.ts:59`, `FOR UPDATE SKIP LOCKED`) and branches on `job.type` (`depscanner/src/index.ts:115,132,181,183` — `extraction` vs `dast`/`dast_zap`/`dast_nuclei`). To add a new scan kind, add its type string to the claim's supported-types list and add a `job.type === '...'` branch in the dispatch.
- **`fix-worker/`** — the Aegis Fix Agent (plan-then-execute coding agent). Separate app; `fix-worker/src/index.ts`, `executor.ts`, `edit-tool.ts`.

**Async backend jobs** (not the scan workers) go through QStash via the `lib/qstash.ts` helpers — e.g. `queueExtractionJob` (`backend/src/lib/extraction-jobs.ts:44`), `queueDependencyAnalysis` / `queuePopulateDependencyBatch` / `queueBackfillDependencyTrees` (`lib/qstash.ts:62,124,188`). These route through the pluggable `JobQueue` abstraction (`backend/src/lib/job-queue/index.ts:22` — QStash in cloud, BullMQ/noop for self-host), so add new job kinds as functions there rather than calling QStash directly.

The endpoint a QStash step calls back into is an internal route under `/api/internal/...`, authenticated by `INTERNAL_API_KEY` (constant-time compare in `backend/src/middleware/internal-key.ts`) and/or the QStash signature (`verifyJobRequest` in `lib/qstash.ts`) — **not** `authenticateUser`. Copy an existing internal router such as `backend/src/routes/internal-billing.ts` or `cron-dispatcher.ts`.

---

## 5. Frontend page

Two steps: create the page component, then register the route.

**Create** `frontend/src/app/pages/<Name>Page.tsx` (default-export a React component). Nested feature areas get a sub-folder — `pages/admin/`, `pages/orgs/`, `pages/docs/`, `pages/legal/`.

**Register** in `frontend/src/app/routes.tsx` (React Router v6 `createBrowserRouter`, `routes.tsx:97`): add an `import` (`routes.tsx:8-44`) and a route object. Wrap in a guard component:
- `<ProtectedRoute>` — redirects unauthenticated users to `/` (`components/ProtectedRoute.tsx`).
- `<PublicRoute>` — redirects authenticated users to `/organizations` (marketing/login pages).

Most in-app pages are children of the `/organizations/:id` route so they render inside `OrganizationLayout` and inherit the org sidebar (`routes.tsx:129-225`). Add a child `{ path: "your-tab", element: <YourPage /> }` there rather than a new top-level route unless it's genuinely outside an org.

Auth on the frontend: the session/JWT comes from `contexts/AuthContext.tsx` (Supabase Auth, Google/GitHub OAuth); API calls send `Authorization: Bearer <jwt>`.

---

## 6. UI component

Shared components live in `frontend/src/components/`. Low-level primitives (shadcn pattern: Radix + Tailwind + `class-variance-authority`) live in `frontend/src/components/ui/` — `button.tsx`, `dialog.tsx`, `select.tsx`, `badge.tsx`, `sheet.tsx`, etc.

Add a new primitive with the shadcn CLI (config is `frontend/components.json`, the `cn` helper is `frontend/src/lib/utils.ts`):

```bash
cd frontend && npx shadcn@latest add <component>
```

Compose feature components from those primitives at `components/<Name>.tsx` (or a sub-folder for a cluster, e.g. `components/NavBar/`). Follow the house UI standards in `.claude/skills/frontend-design/SKILL.md` and `.claude/skills/ui-principles/SKILL.md` — Radix Tooltip (never native `title=`), color restraint, the green/white/outline button convention.

---

## Auth flow reminder

1. Frontend does Google/GitHub OAuth via Supabase Auth → JWT.
2. API calls send `Authorization: Bearer <jwt>`.
3. Backend `authenticateUser` verifies the token (locally against `SUPABASE_JWT_SECRET` when set, else via the Supabase auth server) and sets `req.user = { id, email }`. `dptx_`-prefixed API tokens are also accepted and set `req.apiToken`.
4. Internal/worker endpoints skip JWT auth entirely — they use `INTERNAL_API_KEY` and/or a QStash/webhook signature over the raw request body.

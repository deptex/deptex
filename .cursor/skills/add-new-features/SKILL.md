---
name: deptex-add-new-features
description: When adding new features to Deptex, use this skill to decide whether the feature belongs in the open-source core (CE) or the commercial layer (ee/) and how to implement it correctly.
---

# Adding New Features to Deptex

Deptex uses an **open-core model**: open-source core (CE) and a commercial layer in `ee/`. When adding a new feature, you must decide where it belongs and implement it accordingly.

---

## Step 1: Decide CE vs EE

| If the feature... | Put it in |
|-------------------|-----------|
| Is dependency/vulnerability logic, SBOM parsing, ecosystem detection, or pure analysis | **CE** — `backend/src/lib/`, `backend/extraction-worker/` |
| Involves organizations, teams, invitations, roles, or billing | **EE** — `ee/backend/routes/`, `ee/backend/lib/` |
| Involves GitHub App, GitLab, Bitbucket OAuth, or installation tokens | **EE** — `ee/backend/lib/` |
| Involves QStash, Redis queues, email, or Aegis (AI agent) | **EE** — `ee/backend/lib/` |
| Is a new API route for org-scoped resources | **EE** — `ee/backend/routes/` |
| Is a minimal shared route (e.g. user profile) | **CE** — `backend/src/routes/` |

---

## Step 2: Where to Add the Code

### CE Feature (Open Source)

- **Routes**: `backend/src/routes/`
- **Libraries**: `backend/src/lib/`
- **Worker logic**: `backend/extraction-worker/src/`

**Rules:**

- Do not import from `ee/` — CE must work when `DEPTEX_EDITION=ce`
- If CE needs a provider interface, define a minimal interface in CE (e.g. `MonorepoGitProvider` in `detect-monorepo.ts`) so EE can implement it
- For types shared with EE, put them in CE and have EE import from backend

### EE Feature (Commercial)

- **Routes**: `ee/backend/routes/`
- **Libraries**: `ee/backend/lib/`

**Rules:**

- EE can import from `backend/` via `../../../backend/src/lib/xyz` or `../../../backend/src/middleware/auth`
- EE routes are loaded only when `DEPTEX_EDITION=ee` (or unset); see `backend/src/index.ts`
- When adding a new EE route, register it in the `if (isEeEdition()) { ... }` block in `backend/src/index.ts`

---

## Step 3: Feature Flag (EE Only)

EE features are gated by `DEPTEX_EDITION`:

- `DEPTEX_EDITION=ce` — EE routes and libs are not loaded
- `DEPTEX_EDITION=ee` or unset — Full SaaS behavior

EE route registration is in `backend/src/index.ts`:

```typescript
if (isEeEdition()) {
  app.use('/api/organizations', require('../../ee/backend/routes/organizations').default);
  // ... add your route here
}
```

---

## Step 4: Database Migrations

- **CE tables** (projects, dependencies, vulnerabilities, etc.): Add SQL to `backend/database/`
- **EE tables** (organizations, teams, integrations, aegis_*, etc.): Add SQL to `backend/database/` (migrations live there; document in `ee/database/README.md` which are EE-only)

---

## Step 5: Frontend

- **CE-only UI**: Can live in `frontend/` and render when `isEeEdition()` is false (Phase 5 of open-core strategy, currently deferred)
- **EE UI** (org/team/projects): Stays in `frontend/`; it calls EE routes and only works when backend runs in EE mode

---

## Quick Reference

| Component | CE Location | EE Location |
|-----------|-------------|-------------|
| Routes | `backend/src/routes/` | `ee/backend/routes/` |
| Libs | `backend/src/lib/` | `ee/backend/lib/` |
| Middleware | `backend/src/middleware/` | shared |
| DB migrations | `backend/database/` | same dir, document in `ee/database/README.md` |

---

## See Also

- [ee/database/README.md](../../ee/database/README.md) — EE migrations

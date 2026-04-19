---
name: deptex-add-new-features
description: When adding new features to Deptex, use this skill for where to put routes and libs in the backend.
---

# Adding New Features to Deptex

The app uses a **single backend** in `backend/`. All API routes live in **`backend/src/routes/`** and are registered in **`backend/src/index.ts`**. Shared logic lives in **`backend/src/lib/`**.

---

## Where to put the feature

| If the feature... | Put it in |
|-------------------|-----------|
| Is a new HTTP API surface | **`backend/src/routes/`** — add router + register in **`backend/src/index.ts`** |
| Is shared logic (policy engine, AI, GitHub, Redis, etc.) | **`backend/src/lib/`** |
| Is extraction / SBOM / vuln pipeline worker logic | **`backend/extraction-worker/`** (and related workers under `backend/`) |
| Is org/team/project/integrations/Aegis | **`backend/src/routes/`** + **`backend/src/lib/`** |

---

## Routes and registration

- **Routes:** `backend/src/routes/<name>.ts` — export a router, mount with `app.use('/api/...', router)` in `backend/src/index.ts`.
- **Pattern:** Follow existing routers (`organizations.ts`, `integrations.ts`, `aegis.ts`, etc.) for `authenticateUser`, org membership checks, and error handling.

---

## Libraries

- **Libs:** `backend/src/lib/` — AI (`lib/ai/`), Aegis (`lib/aegis/`), GitHub (`lib/github.ts`), notification dispatchers, policy engine, etc.
- **Imports:** Use relative imports within `backend/src/`.

---

## Database migrations

- **All tables:** migrations in **`backend/database/`**.

---

## Frontend

- **Frontend** in **`frontend/`** — calls `/api/...` as usual.

---

## Quick reference

| Component | Location |
|-----------|----------|
| API routes | `backend/src/routes/` |
| Shared libs | `backend/src/lib/` |
| Middleware | `backend/src/middleware/` |
| Express entry + mounts | `backend/src/index.ts` |
| DB migrations | `backend/database/` |

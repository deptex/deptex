# Developing Deptex

This guide helps you set up a local development environment for Deptex.

---

## Prerequisites

- **Node.js** 18+ (check [backend/package.json](./backend/package.json) and [frontend/package.json](./frontend/package.json))
- **Git**
- **Supabase** account (or self-hosted Postgres with Supabase Auth) for auth and database
- **npm** or **pnpm**

---

## Quick Start

### 1. Clone the repo

```bash
git clone https://github.com/deptex/deptex.git
cd deptex
```

### 2. Backend setup

```bash
cd backend
npm install
cp .env.example .env   # or create .env with required vars
```

**Required env vars** (see `.env.example`):

- `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_ANON_KEY`
- For full stack: `UPSTASH_REDIS_URL`, `UPSTASH_REDIS_TOKEN`, `QSTASH_*`, GitHub App credentials, etc.
- `AI_ENCRYPTION_KEY` (32-byte hex) — AES-256-GCM key for `organization_registry_credentials.encrypted_credentials` (IaC v2 registry auth). BYOK AI was retired in `phase29_drop_byok`; the same encryption helper is reused for registry creds. Optional `AI_ENCRYPTION_KEY_PREV` + `AI_ENCRYPTION_KEY_VERSION=N` for key rotation.
- `DAST_CREDENTIAL_KEY` (32-byte hex, **depscanner Fly env only — NOT backend API**) — encrypts per-target DAST credentials (`project_dast_credentials.encrypted_payload`). Required to scan authenticated apps; routes refuse credential PUT with `503 dast_encryption_not_configured` until set. Optional `DAST_CREDENTIAL_KEY_PREV` + `DAST_CREDENTIAL_KEY_VERSION=N` for rotation. Decryption is worker-side only — the API never decrypts.

### 3. Run the backend

```bash
cd backend
npm run dev
```

Backend runs at `http://localhost:3001`.

### 4. Frontend setup

```bash
cd frontend
npm install
```

Create `.env` with:

```
VITE_API_URL=http://localhost:3001
VITE_SUPABASE_URL=<your-supabase-url>
VITE_SUPABASE_ANON_KEY=<your-supabase-anon-key>
```

### 5. Run the frontend

```bash
cd frontend
npm run dev
```

Frontend runs at `http://localhost:3000` (or the port Vite assigns).

### 6. Extraction worker (optional)

For dependency extraction (clone, SBOM, dep-scan):

```bash
cd depscanner
npm install
# Set SUPABASE_* and optionally REDIS in .env
npm run dev
```

The extraction pipeline now includes a `malicious_scan` step (after vuln scan, before Semgrep) that does feed lookup against `known_malicious_packages` plus a GuardDog source-code scan. GuardDog is installed into an isolated venv at `/opt/guarddog-venv/` inside the Docker image so its bundled Semgrep doesn't conflict with the global pin; the worker invokes `/opt/guarddog-venv/bin/guarddog` explicitly. Outside the container the step soft-fails with an install hint — feed lookup still runs.

---

## Project Structure

| Directory                    | Purpose                                               |
| ---------------------------- | ----------------------------------------------------- |
| `backend/`                   | Express API; routes in `backend/src/routes/`, libs in `backend/src/lib/` |
| `depscanner/` | Clone, cdxgen, SBOM, dep-scan pipeline                |
| `frontend/`                  | React dashboard                                       |
| `backend/database/`          | SQL migrations                                        |

---

## Running Tests

```bash
cd backend && npm run test
cd frontend && npm run test:run
```

Tests use mocks for external services (Supabase, GitHub, etc.).

---

## Database

- Migrations live in `backend/database/`
- Tables include `projects`, `organizations`, `teams`, `organization_integrations`, `aegis_*`, dependencies/vulnerabilities, etc.

---

## Common Tasks

- **Add an API route:** `backend/src/routes/` + register in `backend/src/index.ts`
- **Add a lib:** `backend/src/lib/`

---

## Create a Pull Request

1. Fork the repo
2. Create a branch
3. Make changes, run tests
4. Open a PR — see [CONTRIBUTING.md](./CONTRIBUTING.md)

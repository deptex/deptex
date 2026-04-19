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

### 6. Workers (optional)

Deptex ships three workers. For local development, running the extraction worker is usually enough; the others are driven by the backend in production.

```bash
# Extraction worker — clone repo, cdxgen SBOM, dep-scan, AST, Semgrep, TruffleHog
cd backend/extraction-worker
npm install
# Copy .env from backend/.env or set SUPABASE_* manually
npm run dev

# Watchtower worker — supply-chain forensic analysis (job-based, no HTTP)
cd backend/watchtower-worker
npm install && npm run dev

# Aider worker — AI-powered fix worker (Python; requires Python 3 + pip)
cd backend/aider-worker
pip install -r requirements.txt
python src/server.py
```

See [fly.md](./fly.md) for how each worker is deployed on Fly.io.

---

## Project Structure

| Directory                      | Purpose                                                                 |
| ------------------------------ | ----------------------------------------------------------------------- |
| `backend/`                     | Express API; routes in `backend/src/routes/`, libs in `backend/src/lib/` |
| `backend/extraction-worker/`   | Clone, cdxgen, dep-scan, AST, Semgrep, TruffleHog (Fly.io scale-to-zero) |
| `backend/watchtower-worker/`   | Supply-chain forensic analysis (Fly.io scale-to-zero)                   |
| `backend/aider-worker/`        | AI-powered fix worker, Python/Aider (Fly.io)                            |
| `frontend/`                    | React dashboard (Vite + Tailwind + Radix)                               |
| `backend/database/`            | SQL migrations (~140 files)                                             |
| `.cursor/plans/`               | Current roadmap (archived phase plans live in `archive/`)               |
| `docs/`                        | Topic docs (depscore, polling, adding ecosystems / integrations)         |

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

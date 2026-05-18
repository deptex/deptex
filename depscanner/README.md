# Deptex Extraction Worker

Two modes share the same pipeline code:

1. **Local CLI** (`./bin/deptex-scan`) — scan any local directory, Docker-only, no Supabase/Redis/GitHub required.
2. **Fly.io worker** (`npm start`) — consumes jobs from Redis, writes results to Supabase. See [Fly.io worker mode](#flyio-worker-mode) below.

---

## Local CLI (deptex-scan)

Scans a codebase for dependency vulnerabilities, SBOM, reachability (Atom), SAST (Semgrep), and secrets (TruffleHog), then prints a Trivy-style findings table.

### Prerequisites

**Docker Desktop** (or a running Docker daemon on Linux). That's it.

All heavy tooling (cdxgen, dep-scan, Semgrep, TruffleHog, Atom, Python, Go, Maven, JDK 21) ships inside the image.

### Build

```bash
cd depscanner
npm run docker:build
```

First build is slow (~10-15 min) because the image installs language runtimes and security tools. Subsequent builds are fast (cached layers).

### Scan

```bash
# Unix / macOS / WSL / Git Bash
./bin/deptex-scan run <path-to-project>

# Windows PowerShell
.\bin\deptex-scan.ps1 run <path-to-project>
```

Example:

```bash
./bin/deptex-scan run ./fixtures/test-npm --verbose
```

Findings are written to `./extraction-results/summary.json` plus per-finding JSON files. Exit code: `0` (clean), `1` (findings above `--fail-on`), `2` (pipeline error).

### Common options

| Flag | Purpose |
|---|---|
| `--output=<dir>` | Output directory (default `./extraction-results`) |
| `--severity=<list>` | Filter, e.g. `--severity=high,critical` |
| `--fail-on=<sev>` | Non-zero exit if any finding ≥ threshold |
| `--format=<table\|json>` | Output format (auto: table in TTY, json otherwise) |
| `--verbose` | Show info-level step chatter |
| `--quiet` | Suppress success lines |

Full help: `./bin/deptex-scan --help`.

### Development

- Edit TypeScript under `src/`
- Rebuild with `npm run docker:build`
- Scan with `./bin/deptex-scan run ./fixtures/test-npm`

Storage & snapshot tests run natively (no Docker):

```bash
npm run test:storage    # PGLite integration tests
npm run test:fixtures   # deterministic output snapshot tests
```

Framework detector unit tests run via Jest:

```bash
NODE_OPTIONS=--experimental-vm-modules npx jest src/framework-rules/__tests__/
```

---

## Reachability extractor

The worker runs a tree-sitter-based usage extractor that maps first-party source files to SBOM dependencies, then emits per-file imports, call-sites, and framework entry points (HTTP routes, serverless handlers, etc.) into the DB. These power EPD contextual scoring and, ultimately, the `depscore`.

Supported languages: JavaScript/TypeScript, Python, Java, Go, Ruby, PHP, Rust, C# (8 MVP languages). 34 framework detectors across those languages — Express, NestJS, Spring, Gin, Rails, Laravel, Actix, ASP.NET Core, and more.

Adding a new framework or debugging why a detector doesn't fire:

- **[Framework rule-pack guide](docs/framework-rule-pack-guide.md)** — how to add a new detector, lifecycle, testing.
- **[Language query guide](docs/language-query-guide.md)** — AST shapes, node types, and known grammar quirks per language.

---

## Fly.io worker mode

Worker that processes extraction jobs from Redis: clone repo, run cdxgen (SBOM), dep-scan, Semgrep, TruffleHog, and update Supabase.

## Prerequisites

- UPSTASH_REDIS_URL, UPSTASH_REDIS_TOKEN
- SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
- GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY (or GITHUB_APP_PRIVATE_KEY_PATH)
- BACKEND_URL or API_BASE_URL (for queue-populate)
- EXTRACTION_WORKER_SECRET (optional, for queue-populate auth)

## Local Development

```bash
npm install
npm run dev
```

**Optional (for full scanning):** dep-scan (reachable vulnerabilities), Semgrep, TruffleHog. The worker skips steps gracefully if these tools are not installed.

- **dep-scan:** `pip install owasp-depscan`
- **Semgrep:** `pip install semgrep`
- **TruffleHog:** https://trufflesecurity.com/docs/trufflehog/installation

## Build

```bash
npm run build
npm start
```

## Docker (easiest – no Python/pip on your machine)

Everything (Node, cdxgen, dep-scan, Semgrep, TruffleHog) runs inside the container.

From `depscanner`:

```bash
docker compose up --build
```

Uses your existing `.env` and mounts `github-app-private-key.pem`. If your backend runs on the host (e.g. `npm run dev` in another terminal), set in `.env`:

```bash
BACKEND_URL=http://host.docker.internal:3001
```

So the worker in Docker can reach your local backend for queue-populate.

**Plain docker (no compose):**

```bash
docker build -t deptex-extraction-worker .
docker run --env-file .env -e BACKEND_URL=http://host.docker.internal:3001 -v "$(pwd)/github-app-private-key.pem:/app/github-app-private-key.pem:ro" deptex-extraction-worker
```

## Queue

Polls `extraction-jobs` (prod) or `extraction-jobs-local` (dev). Jobs are pushed by the backend when a user connects a repository.

### Import says "Extracting" but worker shows nothing

1. **Check the backend terminal** (where you run the main API, not this worker) when you click Import. You should see:
   - `[EXTRACT] POST connect received: org=... project=... repo=...`
   - Either `Queued extraction job for project ... (queue: extraction-jobs-local, length: 1)` or `[EXTRACT] Redis not configured - extraction job NOT queued.`
   - If you see "Redis not configured", the **backend** is missing `UPSTASH_REDIS_URL` and `UPSTASH_REDIS_TOKEN` in **backend/.env** (not this folder).

2. **Same Redis and queue name:** The backend uses **backend/.env**; this worker uses **depscanner/.env**. Both need the same `UPSTASH_REDIS_URL` and `UPSTASH_REDIS_TOKEN`. Queue name is `extraction-jobs-local` when `NODE_ENV` is not `production`, and `extraction-jobs` when it is. If the backend runs with `NODE_ENV=production` and the worker without it (or vice versa), they use different queues and jobs never meet. Fix: set `NODE_ENV` the same for both, or set `EXTRACTION_QUEUE_NAME=extraction-jobs-local` in both .env files.

3. **Verify worker startup:** When you run `npm start` here you should see `[EXTRACT] NODE_ENV=... → queue: extraction-jobs-local` and the Redis URL prefix. Compare with the backend’s "Backend Redis URL" log; they should match.

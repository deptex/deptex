# Deptex Depscanner

The unified scanner worker (`deptex-depscanner`). One Fly app, type-aware dispatch on `scan_jobs.type`: **extraction** (SCA/SBOM/reachability/SAST/secrets) and **DAST** (ZAP / Nuclei). Two modes share the same pipeline code:

1. **Local CLI** (`./bin/deptex-scan`) — scan any local directory, Docker-only, no Supabase/Redis/GitHub required.
2. **Fly.io worker** (`npm start`) — claims jobs from the Supabase `scan_jobs` table, writes results to Supabase. See [Fly.io worker mode](#flyio-worker-mode) below.

---

## Local CLI (deptex-scan)

Scans a codebase for dependency vulnerabilities, SBOM, reachability (tree-sitter usage extraction + dep-scan + the cross-file taint engine), SAST (Semgrep), and secrets (TruffleHog), then prints a Trivy-style findings table.

### Prerequisites

**Docker Desktop** (or a running Docker daemon on Linux). That's it.

All heavy tooling (cdxgen, dep-scan, Semgrep, TruffleHog, Python, Go, Maven, JDK 21) ships inside the image.

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

Framework specs (sources/sinks/sanitizers) are validated against fixtures by the taint-engine preflight harness:

```bash
npm run taint-engine:validate -- all   # validate every framework-models/*.yaml spec
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

Worker that claims scan jobs from the Supabase `scan_jobs` table and dispatches on `scan_jobs.type`:

- **`extraction`** — clone repo, run cdxgen (SBOM), dep-scan, tree-sitter usage extraction, the cross-file taint engine, Semgrep, TruffleHog, and update Supabase.
- **`dast`** (and `dast_zap` / `dast_nuclei` variants) — dynamic scan of a running target via ZAP / Nuclei (added Phase 23+).

Jobs are claimed atomically via the `claim_scan_job(p_machine_id, p_supported_types, p_max_per_org)` Postgres RPC (`FOR UPDATE SKIP LOCKED`), not from a Redis queue — Redis is used only for caching.

## Prerequisites

- SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
- GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY (or GITHUB_APP_PRIVATE_KEY_PATH)
- BACKEND_URL or API_BASE_URL (for queue-populate)
- UPSTASH_REDIS_URL, UPSTASH_REDIS_TOKEN (optional — caching only, not the job queue)

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
docker build -t deptex-depscanner .
docker run --env-file .env -e BACKEND_URL=http://host.docker.internal:3001 -v "$(pwd)/github-app-private-key.pem:/app/github-app-private-key.pem:ro" deptex-depscanner
```

## Job intake

When a user connects a repository the backend inserts a row into the Supabase `scan_jobs` table (`type='extraction'`) and boots a Fly depscanner machine. The worker loops, claiming jobs atomically via the `claim_scan_job` RPC (`FOR UPDATE SKIP LOCKED`); after 60s with no claimable job it exits (scale-to-zero).

### Import says "Extracting" but worker shows nothing

1. **Same Supabase project:** The backend (**backend/.env**) and this worker (**depscanner/.env**) must point at the same `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY` — otherwise the worker claims from a different `scan_jobs` table than the backend writes to.

2. **Check the row was inserted:** look for a pending row in `scan_jobs` for your project. If none was created, the issue is on the backend side (it never queued the job).

3. **Verify the worker is claiming:** when a job is picked up you'll see `[ext-<id>] Claimed for project <id> ...`; an idle worker logs `[depscanner] No jobs for 60s, shutting down` and exits.

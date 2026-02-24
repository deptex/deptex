# Deptex Extraction Worker

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

From `backend/extraction-worker`:

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

2. **Same Redis and queue name:** The backend uses **backend/.env**; this worker uses **backend/extraction-worker/.env**. Both need the same `UPSTASH_REDIS_URL` and `UPSTASH_REDIS_TOKEN`. Queue name is `extraction-jobs-local` when `NODE_ENV` is not `production`, and `extraction-jobs` when it is. If the backend runs with `NODE_ENV=production` and the worker without it (or vice versa), they use different queues and jobs never meet. Fix: set `NODE_ENV` the same for both, or set `EXTRACTION_QUEUE_NAME=extraction-jobs-local` in both .env files.

3. **Verify worker startup:** When you run `npm start` here you should see `[EXTRACT] NODE_ENV=... → queue: extraction-jobs-local` and the Redis URL prefix. Compare with the backend’s "Backend Redis URL" log; they should match.

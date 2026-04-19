# Self-Hosting Deptex

> **Status:** Placeholder. A full self-hosting guide is tracked as a dedicated phase of the repo cleanup work and is not yet complete. This page exists so you know what's coming and what the rough shape of a self-hosted deployment looks like.

Deptex is built on managed services (Supabase, Fly.io, Upstash, QStash) by default. Self-hosting replaces each of those with an equivalent piece of infrastructure you operate.

## What a self-hosted stack needs

| Managed service (default) | Self-hosted equivalent                                                       |
| ------------------------- | ---------------------------------------------------------------------------- |
| Supabase (Postgres)       | PostgreSQL 15+ with the `pgvector` extension                                 |
| Supabase Auth            | Self-hosted Supabase Auth (gotrue) or any OIDC provider you wire to the API  |
| Supabase Realtime        | Self-hosted Supabase Realtime, or Postgres `LISTEN/NOTIFY` wired to the API  |
| Supabase Storage         | Any S3-compatible store (MinIO, Cloudflare R2, AWS S3)                       |
| Upstash Redis            | Redis 6+ (self-hosted or any provider)                                       |
| Upstash QStash           | Any task queue with HTTP delivery + cron — e.g. BullMQ + a cron runner       |
| Fly.io workers           | Any container host that can start/stop workloads on demand (Kubernetes Jobs, Nomad, ECS) — or simply long-running containers if scale-to-zero isn't needed |

## What still needs to be built before this guide is useful

These items are open work in the repo-cleanup project:

1. **Env-var inventory** — a single authoritative list of every env var, what it does, which services need it, and which are optional vs required.
2. **Docker Compose** — a local `docker-compose.yml` that brings up Postgres (with pgvector), Redis, MinIO, the backend, and the workers with sane defaults.
3. **Migration runner** — a script that applies the ~140 SQL files in `backend/database/` in the correct order. Today migrations are applied manually via Supabase; self-hosters need a runnable `npm run migrate` or similar.
4. **QStash replacement** — the backend currently assumes QStash for async dispatch + cron. Self-hosting needs either (a) a shim that routes QStash-style HTTP calls to a local queue or (b) a feature flag that swaps in an in-process job runner.
5. **First-run setup guide** — creating the first organization, wiring OAuth, seeding default roles/policies.
6. **License clarification** — `backend/package.json` declares MIT today. The top-level `README.md` hints at an open-core model with separate licensing for the platform pieces. This needs to be resolved before a self-host guide can promise anything.

## Until this is done

If you want to run Deptex on your own infrastructure today, the realistic path is:

1. Stand up your own Supabase project (or a self-hosted Supabase instance) and point `SUPABASE_URL` / `SUPABASE_SERVICE_ROLE_KEY` at it.
2. Run the SQL files in `backend/database/` in filename-sorted order against that database.
3. Point `UPSTASH_REDIS_URL` / `UPSTASH_REDIS_TOKEN` and `QSTASH_*` at Upstash (free tier works) — fully replacing Upstash is not yet a supported configuration.
4. Follow [`fly.md`](../fly.md) to deploy the workers to Fly.io, or adapt the Dockerfiles to your own container platform.
5. Deploy `backend/` to any Node host and `frontend/dist/` to any static host.

Open a GitHub issue if you hit gaps not covered above; they help prioritise the missing pieces.

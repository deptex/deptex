# Feature Brief — Observability Arc: Sentry

**Status:** brainstorm locked, pre-plan (2026-05-29)
**Arc:** observability (Sentry first; `billing_events` admin screen is the fast-follow, separate arc)
**Branch:** new worktree off `main` (`ebdd68d`) — `worktree-observability` (one branch for the whole arc)
**Predecessor:** billing prepaid rewrite, merged `ebdd68d` (PR #56)

---

## Why

Today every error on every surface goes to a bare `console.*` → Fly.io's **ephemeral** log stream: no grouping, no search beyond a short window, **no alerting**. The billing audit added dozens of `console.error('[billing] …')` lines on money-critical paths that *silently* swallow failures (auto-recharge wedge, webhook credit-loss, alert-send failures). If auto-recharge fails at 3am, nobody is paged. Sentry closes that gap before real money flows.

## Locked decisions

| # | Decision | Choice |
|---|----------|--------|
| 1 | Plan / alert routing | **Sentry free tier, email alerts** to Henry. 5k events/mo. Slack = later dashboard toggle (Team plan $29/mo), no code change. |
| 2 | Capture scope | **Errors only.** `tracesSampleRate: 0`, no session replay. Stays in free quota; minimal PII surface for a billing/security app. |
| 3 | Manual billing capture | **All 16 money-path sites** get explicit `captureException` (table below). |
| D1 | PII/secret scrubbing | **One shared `beforeSend` redactor module**, reused by all 4 surfaces. `sendDefaultPii: false` (the SDK default). Defense-in-depth, not a question. |
| D2 | SDK version | Pin **`@sentry/node` / `@sentry/react` ≥ 10.27.0** — avoids **CVE-2025-65944** (header leak in 10.11.0–10.26.0 when `sendDefaultPii:true`). |
| D3 | When Sentry runs | Init **only when `SENTRY_DSN` is set** → no dev/local noise unless a local DSN is provided. `environment` = `prod`/`dev`. |
| D4 | Release tagging | `release` = git commit SHA (injected at build/deploy). Lets us tie a regression to a deploy. |

## Scope

**In:** error capture + grouping + email alerting across **backend API + depscanner worker + fix-worker + frontend**; shared secret-scrubber; manual captures on the 16 billing money-paths + per-job context on both workers; Vite source-map upload; `unhandledRejection`/`uncaughtException` + `Sentry.close()` on SIGINT/SIGTERM for both workers; a real e2e harness.

**Out (this arc):** performance tracing, session replay, Datadog/APM (deferred until traffic), the `billing_events` admin screen (= deferred audit finding P1-19, the fast-follow arc), replacing all 96 frontend `console.error` call-sites (the `CaptureConsole`/breadcrumb integration covers them passively; explicit per-site rewrites are out).

---

## Per-surface wiring (anchors from the understand pass)

### Backend (`backend/`)
- **`instrument.ts`** (new) — `Sentry.init(...)` with the shared `beforeSend`. **Imported FIRST** in `index.ts` (line 1, before dotenv/express) or auto-instrumentation of HTTP/DB breaks.
- `Sentry.setupExpressErrorHandler(app)` (v10 API — replaces the old `Handlers.*` trio) **after all routes, before** the existing global handler at `index.ts:249`.
- **Outside the Express lifecycle → need explicit `captureException`:**
  - QStash adapter `lib/job-queue/qstash-adapter.ts:103,109`
  - BullMQ adapter `lib/job-queue/bullmq-adapter.ts:104` (worker `failed` event)
  - `lib/self-host-cron.ts:52-55` (tag `{component:'self-host-cron', tick}`)
  - Stripe webhook handler `routes/billing-stripe-webhooks.ts:83` — capture **before** `releaseWebhookEvent` so retries are visible; **must not** suppress the existing `console.error` (Stripe retry visibility depends on it).
- No `unhandledRejection` handler in `index.ts` today — the SDK's default integration will catch floating rejections once initialized.

### depscanner worker (`depscanner/src/index.ts`)
- `Sentry.init` at process start (before `runWorker()` at ~line 239).
- Wrap `processJob` (~98-167): set tags `job_id / job_type / project_id / organization_id` so every error in the job carries identity.
- Capture in the job catch (~138-148) and DAST abort path (`dast/pipeline.ts:1494-1520`).
- Add `process.on('unhandledRejection'|'uncaughtException')` (none exist today; heartbeat `setInterval` + memory watcher run outside the loop try/catch).
- SIGINT/SIGTERM handlers → `await Sentry.close(2000)` before `process.exit` (Fly sends **SIGINT**, 5-min grace).

### fix-worker (`fix-worker/src/index.ts`)
- Same pattern: init at top; set `fix_id / organization_id / project_id / run_id` context after `loadFullRow` (~line 42); capture in `processJob` catch (~138-156) and the outer loop catch (~185-188).
- Add the two process-level handlers; `Sentry.close()` in SIGINT/SIGTERM (~192-199).

### Frontend (`frontend/`)
- `@sentry/react` init in a `src/instrument.ts` imported first in `main.tsx`.
- `Sentry.ErrorBoundary` at `RootLayout` (`app/routes.tsx:66-72`) — **no error boundary exists today**; React render crashes currently white-screen.
- `reactRouterV6BrowserTracingIntegration` wired to `createBrowserRouter` (instrumentation only; tracing sample 0).
- Capture API failures in the single fetch wrapper `lib/api.ts:312-348` before it throws (tag url+status).
- **Source maps:** `vite.config.ts` has none today. Add `build.sourcemap:'hidden'` + `@sentry/vite-plugin` **last** in `plugins[]`, `filesToDeleteAfterUpload:['./**/*.map']`, auth via `SENTRY_AUTH_TOKEN` (gitignored / CI only).

---

## Secret-scrubbing (`beforeSend`) — shared module

`sendDefaultPii:false` + a redactor reused on all surfaces. Most flagged sites are low-risk DB error strings; the **genuinely sensitive** ones the redactor must neutralize:
- GitHub App **private-key path** — `lib/github.ts:36,39`
- Encryption/decryption error details — `routes/registry-credentials.ts:290,550,583`, `lib/ai/encryption.ts:128`
- **JWTs / auth errors** — `middleware/auth.ts:170,191`
- Stripe init / secret presence — `lib/billing/stripe-billing.ts:10`
- Strip `Authorization`/`Cookie` headers + request bodies from events & breadcrumbs; drop `user.email`; redact values whose keys match `token|key|secret|password|authorization|cookie`.

## The 16 billing money-path captures

All are *caught-and-swallowed* or *caught-and-returned-success* today → invisible without Sentry.

| File | Line | Failure mode |
|------|------|--------------|
| `lib/billing/auto-recharge.ts` | 107-108 | cap-reached email send fails (fire-and-forget) |
| `lib/billing/auto-recharge.ts` | 185-186 | auto-recharge-failed email fails after off-session PI failure (org wedged, unnotified) |
| `lib/billing/auto-recharge.ts` | 197-198 | email fails inside catch after `createTopUpInvoice` throws (double silent failure) |
| `lib/billing/alerts.ts` | 303-305 | zero-balance alert email fails silently |
| `lib/billing/alerts.ts` | 314-315 | low-balance alert email fails silently |
| `lib/billing/stripe-billing.ts` | 328-329 | invoice metadata update fails pre-payment (correlation_id lost) |
| `lib/billing/stripe-billing.ts` | 340-341 | PI metadata update fails pre-payment (org_id lost) |
| `lib/billing/stripe-billing.ts` | 367-371 | off-session charge fails AND invoice refetch fails (charge state unknown) |
| `lib/billing/stripe-billing.ts` | 699-700 | default-PM DB update fails after Stripe attach (config desync) |
| `lib/billing/stripe-billing.ts` | 478-479 | default-PM DB clear fails after detach (next recharge uses dead card) |
| `routes/billing-stripe-webhooks.ts` | 198-205 | `credit_balance` RPC fails (non-23505) → credit loss (handled via throw+release; capture for audit trail) |
| `routes/billing-stripe-webhooks.ts` | 233-234 | post-credit alert reset fails (threshold flags stuck) |
| `routes/billing-stripe-webhooks.ts` | 261-262 | auto-recharge-failed email fails in `payment_intent.payment_failed` |
| `routes/billing-stripe-webhooks.ts` | 323-324 | auto-recharge-failed email fails in `invoice.payment_failed` |
| `lib/billing/ledger.ts` | 176-182 | `setImmediate` post-deduction side-effects (recharge+alerts) fail silently |
| `routes/internal-billing.ts` | 189-191 | `recordMeterEvent` throws after attribution verified (revenue not recorded / double on retry) |

---

## Env / config

- `SENTRY_DSN` (backend + both workers) — Fly secrets on `deptex-backend`, `deptex-depscanner`, `deptex-fix`.
- `VITE_SENTRY_DSN` (frontend, public DSN — build-time).
- `SENTRY_AUTH_TOKEN` + `SENTRY_ORG` + `SENTRY_PROJECT` (frontend build/CI only, for source-map upload — gitignored).
- `release` SHA injected at build/deploy.

## Milestones

- **M1 — Shared scrubber + backend.** `instrument.ts`, shared `beforeSend` redactor (its own unit-tested module), `setupExpressErrorHandler`, explicit captures on the out-of-Express paths (QStash/BullMQ/cron/webhooks). Unit tests for the redactor (asserts secrets stripped).
- **M2 — Workers.** depscanner + fix-worker init, per-job context, catch-block captures, process-level handlers, `Sentry.close()` on signals.
- **M3 — Billing money-paths.** All 16 explicit `captureException` with org/correlation context, reusing the scrubber.
- **M4 — Frontend.** `@sentry/react` init, `ErrorBoundary` at RootLayout, router integration, fetch-wrapper capture, Vite source-map upload.
- **M5 — E2E + docs.** Committed `npm run e2e:sentry` harness that forces a real error on each surface and asserts an event reaches Sentry with secrets scrubbed (use a test DSN / Sentry's `getCurrentScope` transport spy). Update `CLAUDE.md` env table + add a short observability section; remove the stale "Pino/Datadog forwarders" comment at `index.ts`.

## Risks / notes
- **Don't swallow the Stripe webhook `console.error`** — its retry semantics rely on operator-visible logs; capture *in addition to*, never *instead of*.
- Free-tier 5k events/mo drops silently when exceeded — `tracesSampleRate:0` + errors-only keeps us well under pre-launch.
- Worker `Sentry.close()` timeout must be short (2s) so it doesn't fight Fly's shutdown.
- Per `feedback_always_e2e`: the arc isn't done until `npm run e2e:sentry` runs against a real Sentry transport, not a mock.

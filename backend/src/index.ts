import dotenv from 'dotenv';
import path from 'path';

// Load .env file from the backend root directory (one level up from src/)
dotenv.config({ path: path.resolve(__dirname, '../.env') });

import express from 'express';
import cors from 'cors';
import userProfileRouter from './routes/userProfile';
import docsAssistantRouter from './routes/docs-assistant';
import recoveryRouter from './routes/recovery';
import fixRecoveryRouter from './routes/fix-recovery';
import vulnCheckRouter from './routes/vuln-check';
import scheduledExtractionRouter from './routes/scheduled-extraction';
import watchtowerDailyPollRouter from './routes/watchtower-daily-poll';
import notificationUnsubscribeRouter from './routes/notification-unsubscribe';
import userNotificationsRouter from './routes/user-notifications';
import aegisTaskStepRouter from './routes/aegis-task-step';
import billingRouter from './routes/billing';
import internalBillingRouter from './routes/internal-billing';
import billingStripeWebhooksRouter from './routes/billing-stripe-webhooks';
import billingDriftCronRouter from './routes/billing-drift-cron';
import syncCounterResetRouter from './routes/sync-counter-reset';
import scannerCacheReaperRouter from './routes/scanner-cache-reaper';
import ssoRouter from './routes/sso';
import userSessionsRouter from './routes/user-sessions';
import userApiTokensRouter from './routes/user-api-tokens';
import scimRouter from './routes/scim';
import learningCronRouter from './routes/learning-cron';
import incidentCronRouter from './routes/incident-cron';
import cronDispatcherRouter from './routes/cron-dispatcher';
import dispatchRouter from './routes/dispatch';
import { startSelfHostCrons } from './lib/self-host-cron';
import feedbackRouter from './routes/feedback';
import demoRequestRouter from './routes/demo-request';
import enterpriseContactRouter from './routes/enterprise-contact';
import taintEngineRouter from './routes/taint-engine';
import organizationsRouter from './routes/organizations';
import teamsRouter from './routes/teams';
import projectsRouter from './routes/projects';
import dastRouter from './routes/dast';
import scannerFindingsRouter from './routes/scanner-findings';
import baseImageRecommendationsRouter from './routes/base-image-recommendations';
import organizationCanvasRouter from './routes/organization-canvas';
import activitiesRouter from './routes/activities';
import integrationsRouter, { githubWebhookHandler } from './routes/integrations';
import invitationsRouter from './routes/invitations';
import aegisRouter from './routes/aegis';
import aegisV3Router from './routes/aegis-v3';
import aegisFixRouter from './routes/aegis-fix';
import workersRouter from './routes/workers';
import internalRouter from './routes/internal';
import adminRouter from './routes/admin';
import learningRouter from './routes/learning';
import incidentsRouter from './routes/incidents';
import gitlabWebhooksRouter from './routes/gitlab-webhooks';
import bitbucketWebhooksRouter from './routes/bitbucket-webhooks';
import flowsRouter from './routes/flows';
import maliciousRouter, { maliciousInternalRouter } from './routes/malicious';
import maliciousAllowlistRouter from './routes/malicious-allowlist';
import capabilitiesRouter from './routes/capabilities';
import maliciousRetentionRouter from './routes/malicious-retention';
import reachabilitySettingsRouter from './routes/reachability-settings';
import generatedRulesRouter from './routes/generated-rules';
import registryCredentialsRouter from './routes/registry-credentials';
import configuredImagesRouter from './routes/configured-images';

const app = express();
app.set('trust proxy', true);
const PORT = process.env.PORT || 3001;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// Middleware
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // Allow the frontend URL
    if (origin === FRONTEND_URL || origin === 'http://localhost:3000') {
      return callback(null, true);
    }
    
    // For development, allow localhost on any port
    if (process.env.NODE_ENV === 'development' && origin.startsWith('http://localhost:')) {
      return callback(null, true);
    }
    
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['Authorization', 'X-Thread-Id'],
}));

// Log all incoming requests for debugging
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    console.log(`${req.method} ${req.path}`, {
      authorization: req.headers.authorization ? 'present' : 'missing',
      origin: req.headers.origin,
      allHeaders: Object.keys(req.headers),
    });
  }
  next();
});

// Parse JSON and capture raw body for signature verification (QStash, GitHub webhook).
// Explicit limit so a future refactor can't silently uncap the body-parser
// default; 100kb is plenty for any current route (registry creds top out at
// ~10kb after per-field caps).
//
// Phase 36 (v1.1) — DAST replay needs a larger body cap. Two routes are
// path-gated to skip the global 100kb parser and mount their own:
//   1. POST /replay/preview — 1.5MB (raw HAR JSON)
//   2. PUT /credentials — 1.5MB (assembled replay payload up to the documented
//      HAR_MAX_SERIALIZED_PLAINTEXT_BYTES=1MB cap, with headroom)
// Without gating PUT /credentials, a legitimate 150KB replay payload (5
// captured requests × 30KB bodies, all under per-entry caps) would be
// rejected by the 100kb parser with PayloadTooLargeError → surfaces as
// generic 500 via the global error handler. The documented
// `replay_payload_too_large` error code would be unreachable.
//
// The path-gated form is the only one that works — Express middleware fires
// in mount order, so a router-internal `express.json` would no-op once the
// global parser has populated req._body=true.
const REPLAY_PREVIEW_PATH = /^\/api\/projects\/[^/]+\/dast\/targets\/[^/]+\/replay\/preview\/?$/;
const DAST_CREDENTIALS_PUT_PATH = /^\/api\/projects\/[^/]+\/dast\/targets\/[^/]+\/credentials\/?$/;
const globalJsonParser = express.json({
  limit: '100kb',
  verify: (req: any, res, buf) => {
    // rawBody (string) is what QStash/GitHub/GitLab/Bitbucket signature verifiers expect.
    // rawBodyBuffer preserves byte-fidelity for Stripe webhooks — Stripe signs the raw
    // request bytes, and a UTF-8 round-trip through a string can drift on non-UTF-8
    // sequences. Webhook handlers that care about exact bytes should read this field.
    req.rawBody = buf.toString();
    req.rawBodyBuffer = buf;
  },
});
app.use((req, res, next) => {
  if (REPLAY_PREVIEW_PATH.test(req.path)) {
    // The dast router installs its own 1.5mb parser for this exact route.
    return next();
  }
  // PUT /credentials only — the regex matches GET/DELETE too because the path
  // is the same, but those carry no body. method gate avoids unbounding
  // DELETE-with-body or future method introductions.
  if (req.method === 'PUT' && DAST_CREDENTIALS_PUT_PATH.test(req.path)) {
    return next();
  }
  return globalJsonParser(req, res, next);
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// API Routes - CE (always mounted)
app.use('/api/user-profile', userProfileRouter);
app.use('/api/docs-assistant', docsAssistantRouter);
app.use('/api/internal/recovery', recoveryRouter);
app.use('/api/internal/recovery', fixRecoveryRouter);
app.use('/api/internal/vuln-check', vulnCheckRouter);
app.use('/api/workers', scheduledExtractionRouter);
app.use('/api/workers', watchtowerDailyPollRouter);
app.use('/api/notifications', notificationUnsubscribeRouter);
app.use('/api/user-notifications', userNotificationsRouter);
app.use('/api/internal/aegis', aegisTaskStepRouter);
app.use('/api/stripe/webhooks', billingStripeWebhooksRouter);
app.use('/api/internal/billing', internalBillingRouter);
app.use('/api/internal/billing', billingDriftCronRouter);
app.use('/api/workers', syncCounterResetRouter);
app.use('/api/workers', scannerCacheReaperRouter);
app.use('/api/sso', ssoRouter);
app.use('/api/user/sessions', userSessionsRouter);
app.use('/api/user/api-tokens', userApiTokensRouter);
app.use('/api/scim/v2', scimRouter);
app.use('/api/internal/learning', learningCronRouter);
app.use('/api/internal/incidents', incidentCronRouter);
app.use('/api/internal/cron', cronDispatcherRouter);
app.use('/api/internal/dispatch', dispatchRouter);
app.use('/api/feedback', feedbackRouter);
app.use('/api/demo-request', demoRequestRouter);
app.use('/api/enterprise-contact', enterpriseContactRouter);
// API Routes (former EE - now merged)
app.use('/api/organizations', billingRouter);
app.use('/api/organizations', organizationsRouter);
app.use('/api/organizations', taintEngineRouter);
app.use('/api/organizations', teamsRouter);
app.use('/api/organizations', projectsRouter);

// Drain mode middleware lives in middleware/dast-drain.ts so tests can
// import it without pulling in this file's load-time side effects.
import { dastDrainMiddleware } from './middleware/dast-drain';

app.use('/api/projects', dastDrainMiddleware);
app.use('/api/projects', dastRouter);
app.use('/api/organizations', scannerFindingsRouter);
app.use('/api/organizations', baseImageRecommendationsRouter);
app.use('/api/organizations', maliciousRouter);
app.use('/api/organizations', maliciousAllowlistRouter);
app.use('/api/organizations', capabilitiesRouter);
app.use('/api/internal/malicious', maliciousInternalRouter);
app.use('/api/internal/malicious', maliciousRetentionRouter);
app.use('/api/organizations', organizationCanvasRouter);
app.use('/api/organizations', activitiesRouter);
app.use('/api/organizations', reachabilitySettingsRouter);
app.use('/api/organizations', generatedRulesRouter);
app.use('/api/organizations', registryCredentialsRouter);
app.use('/api/organizations', configuredImagesRouter);
app.use('/api/integrations', integrationsRouter);
app.use('/api/invitations', invitationsRouter);
app.use('/api/aegis', aegisRouter);
app.use('/api/aegis/v3', aegisV3Router);
app.use('/api/aegis/fix', aegisFixRouter);
app.use('/api/workers', workersRouter);
app.use('/api/internal', internalRouter);
app.use('/api/admin', adminRouter);
app.use('/api/organizations', learningRouter);
app.use('/api/organizations', incidentsRouter);
app.use('/api/flows', flowsRouter);
app.post('/api/webhook/github', githubWebhookHandler);
app.use('/api/integrations', gitlabWebhooksRouter);
app.use('/api/integrations', bitbucketWebhooksRouter);

// Error handling middleware.
//
// Phase 36 (v1.1) — body-parser-thrown errors carry the failed body bytes on
// `err.body` (and sometimes `err.bodyRaw`). Logging the raw err object would
// echo those bytes to stdout, which leaks HAR contents on a parse failure
// (POST /replay/preview with malformed JSON would otherwise emit the entire
// failed body to Pino / Datadog forwarders bypassing console). Strip those
// fields off the cloned shape we hand to the logger. Route-scoped error
// handlers in the dast router strip them too for defense-in-depth — this
// global handler is the last gate.
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  const safe = {
    name: err.name,
    message: err.message,
    stack: err.stack,
    // Body-parser specific fields that we intentionally omit:
    // body, bodyRaw, rawBody, statusCode, expose, type.
  };
  console.error('Error:', safe);
  res.status(500).json({ error: 'Internal server error' });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    if (!process.env.AI_ENCRYPTION_KEY) {
      console.warn('[AI] WARNING: AI_ENCRYPTION_KEY is not set. IaC v2 registry credential storage will be unavailable.');
    }
    startSelfHostCrons();
  });
}

export default app;


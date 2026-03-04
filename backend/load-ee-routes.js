/**
 * Loads EE routes at runtime. Plain JS so tsc does not compile ee/ (which lacks backend deps).
 * Called from src/index.ts when DEPTEX_EDITION=ee.
 * No-ops when ee/ is missing (e.g. temporarily removed for CE-only deployment).
 */
const path = require('path');
const fs = require('fs');

module.exports = function mountEeRoutes(app) {
  const eeDir = path.join(__dirname, '../ee');
  if (!fs.existsSync(eeDir)) {
    console.warn('[load-ee-routes] ee/ directory not found; running without EE routes.');
    return;
  }
  // Use compiled EE when present (Vercel/production); otherwise source for tsx dev
  const eeDistRoutes = path.join(__dirname, '../ee/backend/dist/routes');
  const eeSrcRoutes = path.join(__dirname, '../ee/backend/routes');
  const eeRoutes = fs.existsSync(eeDistRoutes) ? eeDistRoutes : eeSrcRoutes;
  if (!fs.existsSync(eeRoutes)) {
    console.warn('[load-ee-routes] ee/backend/routes not found; running without EE routes.');
    return;
  }
  app.use('/api/organizations', require(path.join(eeRoutes, 'organizations')).default);
  app.use('/api/organizations', require(path.join(eeRoutes, 'teams')).default);
  app.use('/api/organizations', require(path.join(eeRoutes, 'projects')).default);
  app.use('/api/organizations', require(path.join(eeRoutes, 'activities')).default);
  app.use('/api/integrations', require(path.join(eeRoutes, 'integrations')).default);
  app.use('/api/invitations', require(path.join(eeRoutes, 'invitations')).default);
  app.use('/api/aegis', require(path.join(eeRoutes, 'aegis')).default);
  app.use('/api/workers', require(path.join(eeRoutes, 'workers')).default);
  app.use('/api/watchtower', require(path.join(eeRoutes, 'watchtower')).default);
  app.use('/api/internal', require(path.join(eeRoutes, 'internal')).default);
  app.use('/api/organizations', require(path.join(eeRoutes, 'learning')).default);
  app.use('/api/organizations', require(path.join(eeRoutes, 'incidents')).default);

  const integrations = require(path.join(eeRoutes, 'integrations'));
  app.post('/api/webhook/github', integrations.githubWebhookHandler);

  // Phase 8: GitLab and Bitbucket webhook handlers
  app.use('/api/integrations', require(path.join(eeRoutes, 'gitlab-webhooks')).default);
  app.use('/api/integrations', require(path.join(eeRoutes, 'bitbucket-webhooks')).default);
};

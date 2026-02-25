/**
 * Loads EE routes at runtime. Plain JS so tsc does not compile ee/ (which lacks backend deps).
 * Called from src/index.ts when DEPTEX_EDITION=ee.
 */
const path = require('path');

module.exports = function mountEeRoutes(app) {
  const eeRoutes = path.join(__dirname, '../ee/backend/routes');
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

  const integrations = require(path.join(eeRoutes, 'integrations'));
  app.post('/api/webhook/github', integrations.githubWebhookHandler);
};

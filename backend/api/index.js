/**
 * Vercel serverless handler: use the pre-built Express app from dist/.
 * This file is plain JS so Vercel does not run TypeScript compilation here.
 */
const app = require('../dist/index.js').default;
module.exports = app;
 
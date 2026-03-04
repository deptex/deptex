import dotenv from 'dotenv';
import path from 'path';

// Load .env file from the backend root directory (one level up from src/)
dotenv.config({ path: path.resolve(__dirname, '../.env') });

// EE routes loaded via load-ee-routes.js (plain JS) so tsc never compiles ee/
import express from 'express';
import cors from 'cors';
import { isEeEdition } from './lib/features';
import userProfileRouter from './routes/userProfile';
import docsAssistantRouter from './routes/docs-assistant';
import recoveryRouter from './routes/recovery';
import fixRecoveryRouter from './routes/fix-recovery';
import vulnCheckRouter from './routes/vuln-check';
import scheduledExtractionRouter from './routes/scheduled-extraction';
import watchtowerDailyPollRouter from './routes/watchtower-daily-poll';
import notificationUnsubscribeRouter from './routes/notification-unsubscribe';
import userNotificationsRouter from './routes/user-notifications';
import watchtowerRecoveryRouter from './routes/watchtower-recovery';
import watchtowerEventRouter from './routes/watchtower-event';
import aegisTaskStepRouter from './routes/aegis-task-step';
import stripeWebhooksRouter from './routes/stripe-webhooks';
import syncCounterResetRouter from './routes/sync-counter-reset';
import ssoRouter from './routes/sso';
import userSessionsRouter from './routes/user-sessions';
import userApiTokensRouter from './routes/user-api-tokens';
import scimRouter from './routes/scim';
import learningCronRouter from './routes/learning-cron';
import incidentCronRouter from './routes/incident-cron';
import cronDispatcherRouter from './routes/cron-dispatcher';
import feedbackRouter from './routes/feedback';
import demoRequestRouter from './routes/demo-request';
import enterpriseContactRouter from './routes/enterprise-contact';

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
  exposedHeaders: ['Authorization'],
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

// Parse JSON and capture raw body for signature verification (QStash, GitHub webhook)
app.use(express.json({
  verify: (req: any, res, buf) => {
    req.rawBody = buf.toString();
  }
}));

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
app.use('/api/internal/recovery', watchtowerRecoveryRouter);
app.use('/api/internal/watchtower-event', watchtowerEventRouter);
app.use('/api/internal/aegis', aegisTaskStepRouter);
app.use('/api/stripe/webhooks', stripeWebhooksRouter);
app.use('/api/workers', syncCounterResetRouter);
app.use('/api/sso', ssoRouter);
app.use('/api/user/sessions', userSessionsRouter);
app.use('/api/user/api-tokens', userApiTokensRouter);
app.use('/api/scim/v2', scimRouter);
app.use('/api/internal/learning', learningCronRouter);
app.use('/api/internal/incidents', incidentCronRouter);
app.use('/api/internal/cron', cronDispatcherRouter);
app.use('/api/feedback', feedbackRouter);
app.use('/api/demo-request', demoRequestRouter);
app.use('/api/enterprise-contact', enterpriseContactRouter);

// API Routes - EE (mounted only when DEPTEX_EDITION=ee, loaded from ee/backend/routes/)
if (isEeEdition()) {
  require('../load-ee-routes')(app);
}

// Error handling middleware
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    if (!process.env.AI_ENCRYPTION_KEY) {
      console.warn('[AI] WARNING: AI_ENCRYPTION_KEY is not set. BYOK AI provider features will be unavailable.');
    }
  });
}

export default app;


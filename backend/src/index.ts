import dotenv from 'dotenv';
import path from 'path';

// Load .env file from the backend root directory (one level up from src/)
dotenv.config({ path: path.resolve(__dirname, '../.env') });

import express from 'express';
import cors from 'cors';
import { isEeEdition } from './lib/features';
import userProfileRouter from './routes/userProfile';

const app = express();
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

// API Routes - EE (mounted only when DEPTEX_EDITION=ee, loaded from ee/backend/routes/)
if (isEeEdition()) {
  app.use('/api/organizations', require('../../ee/backend/routes/organizations').default);
  app.use('/api/organizations', require('../../ee/backend/routes/teams').default);
  app.use('/api/organizations', require('../../ee/backend/routes/projects').default);
  app.use('/api/organizations', require('../../ee/backend/routes/activities').default);
  app.use('/api/integrations', require('../../ee/backend/routes/integrations').default);
  app.use('/api/invitations', require('../../ee/backend/routes/invitations').default);
  app.use('/api/aegis', require('../../ee/backend/routes/aegis').default);
  app.use('/api/workers', require('../../ee/backend/routes/workers').default);
  app.use('/api/watchtower', require('../../ee/backend/routes/watchtower').default);
  app.use('/api/internal', require('../../ee/backend/routes/internal').default);

  // Webhook routes (must be before error handling). GitHub sends to this URL; handler uses req.rawBody for signature verification.
  const { githubWebhookHandler } = require('../../ee/backend/routes/integrations');
  app.post('/api/webhook/github', githubWebhookHandler);
}

// Error handling middleware
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

export default app;


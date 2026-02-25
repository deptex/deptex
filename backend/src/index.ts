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
// Dynamic require so tsc doesn't compile ee/ (which lacks backend deps). Loaded at runtime.
if (isEeEdition()) {
  const eeRoutes = path.join(__dirname, '../../ee/backend/routes');
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


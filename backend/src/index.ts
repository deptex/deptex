import dotenv from 'dotenv';
import path from 'path';

// Load .env file from the backend root directory (one level up from src/)
dotenv.config({ path: path.resolve(__dirname, '../.env') });

import express from 'express';
import cors from 'cors';
import organizationsRouter from './routes/organizations';
import integrationsRouter from './routes/integrations';
import invitationsRouter from './routes/invitations';
import teamsRouter from './routes/teams';
import projectsRouter from './routes/projects';
import userProfileRouter from './routes/userProfile';
import activitiesRouter from './routes/activities';
import aegisRouter from './routes/aegis';
import workersRouter from './routes/workers';
import watchtowerRouter from './routes/watchtower';
import internalRouter from './routes/internal';
import authRouter from './routes/auth';

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

// API Routes
app.use('/api/organizations', organizationsRouter);
app.use('/api/organizations', teamsRouter);
app.use('/api/organizations', projectsRouter);
app.use('/api/organizations', activitiesRouter);
app.use('/api/integrations', integrationsRouter);
app.use('/api/invitations', invitationsRouter);
app.use('/api/user-profile', userProfileRouter);
app.use('/api/aegis', aegisRouter);
app.use('/api/workers', workersRouter);
app.use('/api/watchtower', watchtowerRouter);
app.use('/api/internal', internalRouter);
app.use('/api/auth', authRouter);

// Webhook routes (must be before error handling). GitHub sends to this URL; handler uses req.rawBody for signature verification.
import { githubWebhookHandler } from './routes/integrations';
app.post('/api/webhook/github', githubWebhookHandler);

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


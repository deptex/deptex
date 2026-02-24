# Deptex Backend

Core backend API for Deptex - dependency tracking and security platform.

## Overview

This backend repository contains the core business logic for Deptex. It's designed to be partially open source, with the understanding that additional repositories may contain specialized logic in the future.

## Tech Stack

- **Runtime**: Node.js
- **Framework**: Express.js
- **Language**: TypeScript
- **Database & Auth**: Supabase
- **Package Manager**: npm

## Setup

### Prerequisites

- Node.js 18+ and npm
- Supabase account and project

### Installation

1. Install dependencies:
```bash
npm install
```

2. Create a `.env` file in the root directory:
```env
SUPABASE_URL=your_supabase_project_url
SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key
SUPABASE_ANON_KEY=your_supabase_anon_key
PORT=3001
NODE_ENV=development
FRONTEND_URL=http://localhost:3000
```

3. Set up the database schema in Supabase (see `database/schema.sql`)

4. Configure OAuth providers in Supabase Dashboard:
   - Go to Authentication > Providers
   - Enable Google OAuth
   - Enable GitHub OAuth
   - Configure redirect URLs

### Running the Server

Development mode (with hot reload):
```bash
npm run dev
```

Production build:
```bash
npm run build
npm start
```

## API Endpoints

All endpoints require authentication via Bearer token in the Authorization header unless noted.

### Organizations

- `GET /api/organizations` - List user's organizations
- `POST /api/organizations` - Create new organization
- `GET /api/organizations/:id` - Get organization details

### Watchtower (security & upstream monitoring)

Watchtower provides extra safety checks for packages your organization adds to its watchlist: **registry integrity** (tarball vs git source), **install scripts** analysis (dangerous capabilities), and **entropy analysis** (obfuscated or hidden payloads). Users can add packages to Watchtower from a dependency’s Watchtower tab; that enables analysis and surfaces commits, contributors, anomaly scores, and per-version check results.

- `GET /api/watchtower/:packageName` - Full analysis for a watched package (requires org membership with package on watchlist).
- `GET /api/watchtower/:packageName/summary` - Summary (status, security check results, quarantine, counts). Query: `project_dependency_id`, `refresh=true`.
- `GET /api/watchtower/:packageName/commits` - Recent commits. Query: `limit`, `offset`, `organization_id`, `project_dependency_id`, `filter=touches_imported`, `sort=anomaly`.
- `GET /api/watchtower/:packageName/contributors` - Contributor profiles for the package.
- `GET /api/watchtower/:packageName/anomalies` - Anomalies sorted by score. Query: `min_score`.
- `POST /api/watchtower/analyze-commit` - Body: `packageName`, `commitSha`, `repoFullName`. Aegis AI analysis of a commit diff.

**Enable / disable Watchtower (org-level)** – via projects router:

- `PATCH /api/organizations/:id/projects/:projectId/dependencies/:dependencyId/watching` - Body: `{ "is_watching": true | false }`. Enable adds the package to the org watchlist and queues analysis; disable removes it. Requires org manage teams & projects or team manage projects (owner team).

## Project Structure

```
backend/
├── src/
│   ├── index.ts              # Main server entry point
│   ├── lib/
│   │   └── supabase.ts       # Supabase client configuration
│   ├── middleware/
│   │   └── auth.ts           # Authentication middleware
│   └── routes/
│       └── organizations.ts  # Organization API routes
├── database/
│   └── schema.sql            # Database schema
├── package.json
├── tsconfig.json
└── README.md
```

## Environment Variables

- `SUPABASE_URL` - Your Supabase project URL
- `SUPABASE_SERVICE_ROLE_KEY` - Supabase service role key (for backend operations)
- `SUPABASE_ANON_KEY` - Supabase anonymous key
- `PORT` - Server port (default: 3001)
- `NODE_ENV` - Environment (development/production)
- `FRONTEND_URL` - Frontend URL for CORS and OAuth redirects (e.g. `http://localhost:3000` or `https://your-app.vercel.app`)
- `BACKEND_URL` - Backend API base URL for OAuth callback URLs (e.g. `http://localhost:3001` or `https://api.yourdomain.com`). Use **no trailing slash**.

### Production: CI/CD integrations (GitHub, GitLab, Bitbucket)

When hosting the app online, set in your backend environment:

- **`BACKEND_URL`** = your deployed backend API root (e.g. `https://api.yourdomain.com`) — **no trailing slash**
- **`FRONTEND_URL`** = your deployed frontend app root (e.g. `https://deptex.vercel.app`) — **no trailing slash**

Then register these **exact** callback URLs in each provider:

| Provider   | Where to set it | Callback URL to register |
|-----------|------------------|---------------------------|
| **GitHub**  | GitHub App → General → "Callback URL" / "Setup URL" | `{BACKEND_URL}/api/integrations/github/callback` |
| **GitLab**  | GitLab → Settings → Applications → Redirect URI | `{BACKEND_URL}/api/integrations/gitlab/org-callback` |
| **Bitbucket** | Bitbucket → Settings → OAuth consumers → Callback URL | `{BACKEND_URL}/api/integrations/bitbucket/org-callback` |

In your **frontend** env (e.g. `frontend/.env` or Vercel env vars), set:

- **`VITE_API_BASE_URL`** = same as `BACKEND_URL` (e.g. `https://api.yourdomain.com`) so login and API calls use the deployed backend.

### Login with GitHub (no Supabase URL on GitHub’s page)

To have GitHub show “Redirect to **yourapp.com**” instead of “Redirect to **xxx.supabase.co**”, the app uses a custom GitHub OAuth flow for **login** (separate from the GitHub App used for repo access):

1. **Create a separate GitHub OAuth App** (e.g. “Deptex Login”): GitHub → Settings → Developer settings → OAuth Apps → New OAuth App.
2. Set **Authorization callback URL** to your **frontend** URL so GitHub shows your app domain (e.g. “Redirect to **deptex.dev**”), not your backend: `{FRONTEND_URL}/auth/callback` (e.g. `https://deptex.dev/auth/callback`).
3. In the backend, set:
   - **`GITHUB_OAUTH_CLIENT_ID`** = Client ID of that OAuth App
   - **`GITHUB_OAUTH_CLIENT_SECRET`** = Client secret of that OAuth App

Then “Sign in with GitHub” will go: your app → GitHub (shows your domain as redirect) → your backend → Supabase session → back to your app. Keep your existing Supabase Auth GitHub provider/callback for Google or other providers if you use them.

## Development

The project uses TypeScript for type safety. Run type checking:
```bash
npm run type-check
```

## License

MIT

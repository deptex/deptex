# AST Parser Worker Deployment Guide

## Prerequisites

1. **Upstash Redis Account**
   - Sign up at https://upstash.com
   - Create a Redis database
   - Note the `UPSTASH_REDIS_URL` and `UPSTASH_REDIS_TOKEN`

2. **Fly.io Account**
   - Sign up at https://fly.io
   - Install flyctl: `curl -L https://fly.io/install.sh | sh`

3. **Database Migration**
   - Run the migration: `backend/database/add_import_analysis_to_project_dependencies.sql`
   - This adds the `files_importing_count` column and `project_dependency_functions` table

## Local Testing

1. **Set up environment variables** (create `.env` file):
```bash
UPSTASH_REDIS_URL=your_redis_url
UPSTASH_REDIS_TOKEN=your_redis_token
SUPABASE_URL=your_supabase_url
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
GITHUB_APP_ID=your_github_app_id
GITHUB_APP_PRIVATE_KEY_PATH=./github-app-private-key.pem
```

2. **Install dependencies**:
```bash
cd backend/parser-worker
npm install
```

3. **Build and run**:
```bash
npm run build
npm start
```

## Fly.io Deployment

1. **Initialize Fly.io app** (first time only):
```bash
cd backend/parser-worker
flyctl launch
```
   - When prompted, say "no" to copying config from existing app
   - Choose a region (e.g., `iad` for US East)
   - Say "no" to deploying now

2. **Set secrets**:
```bash
flyctl secrets set \
  UPSTASH_REDIS_URL="your_redis_url" \
  UPSTASH_REDIS_TOKEN="your_redis_token" \
  SUPABASE_URL="your_supabase_url" \
  SUPABASE_SERVICE_ROLE_KEY="your_service_role_key" \
  GITHUB_APP_ID="your_github_app_id" \
  GITHUB_APP_PRIVATE_KEY_PATH="./github-app-private-key.pem"
```

   **Note:** For the private key, you have two options:
   - Set `GITHUB_APP_PRIVATE_KEY` directly with the key content (newlines as `\n`)
   - Or upload the key file and reference it with `GITHUB_APP_PRIVATE_KEY_PATH`

3. **Deploy**:
```bash
flyctl deploy
```

4. **Check status**:
```bash
flyctl status
flyctl logs
```

## Monitoring

- View logs: `flyctl logs`
- Scale: `flyctl scale count 2` (for multiple workers)
- Restart: `flyctl restart`

## Troubleshooting

- **Worker not processing jobs**: Check Redis connection and queue name
- **Clone failures**: Verify GitHub App permissions and installation token
- **Parse errors**: Check that oxc-parser is correctly installed
- **Database errors**: Verify migration has been run and RLS policies allow service role access

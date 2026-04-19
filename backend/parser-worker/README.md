# Deptex AST Parser Worker

Background worker service that analyzes GitHub repositories using AST parsing to extract:
- Which functions are imported from each package
- How many files import each package

## Architecture

This worker runs as a Docker container on Fly.io and processes jobs from an Upstash Redis queue.

## Setup

### Environment Variables

Required environment variables:

- `UPSTASH_REDIS_URL` - Upstash Redis connection URL
- `UPSTASH_REDIS_TOKEN` - Upstash Redis authentication token
- `SUPABASE_URL` - Supabase project URL
- `SUPABASE_SERVICE_ROLE_KEY` - Supabase service role key (for database access)
- `GITHUB_APP_ID` - GitHub App ID
- `GITHUB_APP_PRIVATE_KEY` or `GITHUB_APP_PRIVATE_KEY_PATH` - GitHub App private key

### Local Development

```bash
npm install
npm run dev
```

**Note:** `oxc-parser` will automatically install the correct platform-specific native binding (Windows, Linux, macOS) as an optional dependency. If you encounter module not found errors, you may need to install the binding manually:
- Windows: `npm install @oxc-parser/binding-win32-x64-msvc`
- Linux: `npm install @oxc-parser/binding-linux-x64-gnu`
- macOS: `npm install @oxc-parser/binding-darwin-x64` or `@oxc-parser/binding-darwin-arm64`

### Building

```bash
npm run build
npm start
```

### Docker Build

```bash
docker build -t deptex-parser-worker .
docker run --env-file .env deptex-parser-worker
```

### Fly.io Deployment

```bash
flyctl launch
flyctl secrets set UPSTASH_REDIS_URL=... UPSTASH_REDIS_TOKEN=... SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... GITHUB_APP_ID=... GITHUB_APP_PRIVATE_KEY_PATH=...
flyctl deploy
```

## How It Works

1. Worker polls Redis queue (`ast-parsing-jobs`) for jobs
2. When a job is received, it clones the GitHub repository
3. Parses all JavaScript/TypeScript files using oxc parser
4. Extracts import statements and function names
5. Stores results in database:
   - Updates `files_importing_count` in `project_dependencies`
   - Inserts function names into `project_dependency_functions`
6. Cleans up cloned repository

## Queue Integration

Jobs are queued from the main backend API when a repository is connected via the `/api/organizations/:id/projects/:projectId/repositories/connect` endpoint.

# Debug: "Project still extracting" when extraction is done

## What to check in the database

The Overview tab shows "Project still extracting" when `project_repositories.status` is not exactly `'ready'`. The frontend and Realtime both read from this table.

### 1. Find your project and repo row

In **Supabase** (or your Postgres client), run:

```sql
SELECT
  pr.project_id,
  p.name AS project_name,
  pr.status,
  pr.extraction_step,
  pr.extraction_error,
  pr.updated_at
FROM project_repositories pr
JOIN projects p ON p.id = pr.project_id
WHERE p.name = 'YOUR_PROJECT_NAME';
```

Replace `'YOUR_PROJECT_NAME'` with the project that stays on "extracting". Or use the project ID:

```sql
SELECT project_id, status, extraction_step, extraction_error, updated_at
FROM project_repositories
WHERE project_id = 'YOUR_PROJECT_UUID';
```

### 2. How to interpret the result

| status        | Meaning |
|---------------|--------|
| `pending`     | Repo connected, extraction not started |
| `initializing` | Job queued |
| `extracting`  | Worker is running |
| `analyzing`   | Pipeline done, populate-dependencies in progress |
| `finalizing`  | AST parsing / final steps |
| **`ready`**   | **Done – UI should show the graph** |
| `error`       | Extraction failed (see `extraction_error`) |

- If you see **`status = 'ready'`** and **`extraction_step = 'completed'`** but the UI still says "Project still extracting" → the bug is on the **frontend** (Realtime or refetch not updating the UI). The new periodic refetch should fix this.
- If you see **`status`** still **`extracting`**, **`analyzing`**, or **`finalizing`** → the **backend/worker** never wrote `ready` (worker crashed, callback failed, or populate-dependencies never ran). Check extraction logs and `extraction_error` for that project.

### 3. Optional: check extraction_jobs (if using Supabase job queue)

```sql
SELECT id, project_id, status, error, created_at, updated_at
FROM extraction_jobs
WHERE project_id = 'YOUR_PROJECT_UUID'
ORDER BY created_at DESC
LIMIT 5;
```

`status` should be `completed` when extraction is done; if it’s stuck as `processing` or `queued`, the worker or recovery flow may not be updating it.

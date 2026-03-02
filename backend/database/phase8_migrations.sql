-- Phase 8: PR Management & Webhooks - ALTER TABLE migrations
-- Covers: 8B (sync_frequency), 8I/8J (webhook management), 8K (webhook health), 8N (scheduled extraction)

-- 8B: Sync frequency for push event intelligence
ALTER TABLE project_repositories
  ADD COLUMN IF NOT EXISTS sync_frequency TEXT NOT NULL DEFAULT 'on_commit';
-- Valid values: 'manual', 'on_commit', 'daily', 'weekly'

-- 8I/8J: Webhook management for GitLab/Bitbucket
ALTER TABLE project_repositories ADD COLUMN IF NOT EXISTS webhook_id TEXT;
ALTER TABLE project_repositories ADD COLUMN IF NOT EXISTS webhook_secret TEXT;

-- 8K: Webhook health tracking
ALTER TABLE project_repositories ADD COLUMN IF NOT EXISTS last_webhook_at TIMESTAMPTZ;
ALTER TABLE project_repositories ADD COLUMN IF NOT EXISTS last_webhook_event TEXT;
ALTER TABLE project_repositories ADD COLUMN IF NOT EXISTS webhook_status TEXT DEFAULT 'unknown';
-- webhook_status: 'active', 'inactive', 'unknown', 'error'

-- 8N: Scheduled extraction tracking
ALTER TABLE project_repositories ADD COLUMN IF NOT EXISTS last_extracted_at TIMESTAMPTZ;

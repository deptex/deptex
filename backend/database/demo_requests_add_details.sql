-- Add details field to demo_requests; make dev_count and company_name optional for new flow.

ALTER TABLE demo_requests
  ADD COLUMN IF NOT EXISTS details text,
  ALTER COLUMN dev_count DROP NOT NULL,
  ALTER COLUMN company_name DROP NOT NULL;

COMMENT ON COLUMN demo_requests.details IS 'Optional free-text from the demo form (e.g. what they are interested in).';

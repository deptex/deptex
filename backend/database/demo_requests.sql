-- Demo request leads from the public Get Demo page (CE).
-- No auth required; used by marketing/sales to follow up.

CREATE TABLE IF NOT EXISTS demo_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  first_name text NOT NULL,
  last_name text NOT NULL,
  email text NOT NULL,
  company_name text NOT NULL,
  dev_count text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_demo_requests_created_at ON demo_requests (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_demo_requests_email ON demo_requests (email);

COMMENT ON TABLE demo_requests IS 'Demo request leads from the public Get Demo page; CE.';

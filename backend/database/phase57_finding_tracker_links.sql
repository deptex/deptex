-- phase57: finding -> external tracker links (Jira / Linear / GitHub issues)
--
-- A tracker link is a REFERENCE, not a status driver: closing the linked ticket
-- does NOT resolve the finding (and vice-versa in v1). The link is keyed by the
-- stable (project_id, finding_type, finding_key) handle from phase55, so it
-- survives rescans the same way the finding does.
--
-- One link per (finding, provider): re-filing to the same provider is blocked
-- until the existing link is removed, but a finding can carry a Jira AND a
-- GitHub link simultaneously.

BEGIN;

CREATE TABLE IF NOT EXISTS public.finding_tracker_links (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  project_id uuid NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  finding_type text NOT NULL,
  finding_key text NOT NULL,
  provider text NOT NULL,          -- 'jira' | 'linear' | 'github'
  external_id text NOT NULL,       -- provider-internal id (jira issue id, linear issue id, github issue number)
  external_key text,               -- human-facing ref (JIRA-123, ENG-45, #42)
  external_url text,               -- browse URL
  title text,                      -- ticket title at creation time
  created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT finding_tracker_links_provider_chk
    CHECK (provider = ANY (ARRAY['jira'::text, 'linear'::text, 'github'::text])),
  CONSTRAINT finding_tracker_links_type_chk
    CHECK (finding_type = ANY (ARRAY[
      'vulnerability'::text, 'secret'::text, 'semgrep'::text, 'iac'::text,
      'container'::text, 'dast'::text, 'malicious'::text, 'taint_flow'::text
    ])),
  CONSTRAINT finding_tracker_links_unique
    UNIQUE (project_id, finding_type, finding_key, provider)
);

-- Read path: all links for a finding (the row chip + the detail panel).
CREATE INDEX IF NOT EXISTS idx_finding_tracker_links_finding
  ON public.finding_tracker_links (project_id, finding_type, finding_key);

-- Org-wide listing / cascade hygiene.
CREATE INDEX IF NOT EXISTS idx_finding_tracker_links_org
  ON public.finding_tracker_links (organization_id);

COMMIT;

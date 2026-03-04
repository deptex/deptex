-- Phase 13: Drop organizations.plan — use organization_plans as single source of truth
-- Run after: phase13_billing.sql (backfill must have run so organization_plans has all orgs)

ALTER TABLE organizations DROP COLUMN IF EXISTS plan;

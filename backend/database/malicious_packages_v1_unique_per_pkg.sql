-- Widen the dedup key on known_malicious_packages.
--
-- The original UNIQUE (source, source_id) was too narrow: a single GHSA
-- advisory can flag multiple packages (e.g. a typosquat campaign with
-- 10 names sharing one GHSA-XXXX), so the per-page upsert hit the
-- "ON CONFLICT DO UPDATE command cannot affect row a second time" error
-- and zero rows landed.
--
-- Fix: dedup on the full natural key — (source, source_id, package_name,
-- version, ecosystem). NULLS NOT DISTINCT lets `version=null` (= "all
-- versions") still dedup against another `version=null` row of the same
-- (source, source_id, package_name, ecosystem).
--
-- Replaces the constraint added in malicious_packages_v1.sql.

ALTER TABLE public.known_malicious_packages
  DROP CONSTRAINT IF EXISTS known_malicious_packages_source_id_key;

ALTER TABLE public.known_malicious_packages
  ADD CONSTRAINT known_malicious_packages_natural_key UNIQUE NULLS NOT DISTINCT
  (source, source_id, package_name, version, ecosystem);

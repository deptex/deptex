-- phase50_reset_project_importance.sql
--
-- The project-"importance" feature (a per-project [0.5, 2.0] multiplier into every
-- finding's depscore) has been parked: its UI entry points (project settings card,
-- create-project flow, org-overview graph-tile subtext) were removed. With no way to
-- edit it, any project still carrying a non-default value would keep silently
-- multiplying its depscores on every future scan. Reset them all to the neutral
-- default so the feature does nothing until/unless it's deliberately revived.
--
-- The column, its DEFAULT 1.0, the chk_importance_range CHECK constraint, and the whole
-- depscore pipeline are intentionally LEFT IN PLACE (importance = 1.0 is an exact no-op
-- multiplier) so reviving the feature later needs no schema/scoring changes.
-- See .cursor/plans/feature-parking-garage.md.

UPDATE public.projects
SET importance = 1.0
WHERE importance IS DISTINCT FROM 1.0;

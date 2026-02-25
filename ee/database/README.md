# EE Database Migrations

This directory documents **Deptex Cloud (EE)** tables. Actual migration SQL files live in `backend/database/` (same repo). This README explains which migrations apply when.

## Schema Release (Open Source)

Like Supabase, Deptex publishes its schema. The **core schema** (projects, dependencies, vulnerabilities, project_repositories, etc.) in `backend/database/` is open source. EE-specific tables (organizations, teams, integrations, aegis_*, etc.) are documented here; their migrations are in `backend/database/` as well, but they are only needed when running EE.

## When to Run EE Migrations

- **CE-only deployment** (`DEPTEX_EDITION=ce`): Run only core migrations from `backend/database/` — skip EE-related ones.
- **Full/SaaS deployment** (`DEPTEX_EDITION=ee` or unset): Run all migrations in `backend/database/` in order.

## EE-Related Tables

EE migrations (in `backend/database/`) typically cover:

- `organizations`, `organization_members`, `organization_roles`
- `teams`, `team_roles`, `project_teams`, `team_members`
- `invitations`, `invitation_teams`
- `organization_integrations`, `integrations`
- `activities`
- `aegis_*` (chat, config, automations, etc.)
- `organization_watchlist`, `organization_watchlist_cleared_commits`
- `banned_versions`, `team_banned_versions`
- Policy tables used by org/team scoping

Core tables (projects, dependencies, vulnerabilities, etc.) remain in `backend/database/` and are part of the open-source release.

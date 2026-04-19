---
name: Phase 14 Enterprise Security
overview: "Complete overhaul of Phase 14: Enterprise Security. Adds MFA (Supabase TOTP with OAuth), SSO/SAML (free via @node-saml, not Supabase's $599/mo SAML), session management, IP allowlisting, API tokens, security audit logging, and SCIM provisioning. All at $0 additional infrastructure cost."
todos:
  - id: 14-migration
    content: "Database migration: single phase14_enterprise_security.sql with all tables (security_audit_logs, organization_mfa_exemptions, organization_sso_providers, organization_sso_bypass_tokens, organization_ip_allowlist, api_tokens, user_sessions, organization_scim_configs, scim_user_mappings) + ALTER TABLE additions + permission fix"
    status: in_progress
  - id: 14-trust-proxy
    content: Add app.set('trust proxy', true) to backend/src/index.ts
    status: in_progress
  - id: 14a-audit-log
    content: "14A: Security Audit Log - logSecurityEvent helper, GET/export endpoints, frontend timeline"
    status: in_progress
  - id: 14b-mfa
    content: "14B: MFA - MFAGate interceptor, TOTP enrollment, org enforcement, AAL checking middleware"
    status: pending
  - id: 14c-sessions
    content: "14C: Session Management - sessions list, revoke, force logout, session policy"
    status: pending
  - id: 14f-api-tokens
    content: "14F: API Tokens - token CRUD, extend auth middleware for dptx_ tokens, scope enforcement"
    status: pending
  - id: 14d-sso
    content: "14D: SSO/SAML - node-saml, CE routes, domain verification, SSO wizard, LoginPage changes"
    status: pending
  - id: 14e-ip-allowlist
    content: "14E: IP Allowlisting - middleware with Redis caching, CRUD endpoints, frontend UI"
    status: pending
  - id: 14g-scim
    content: "14G: SCIM Provisioning - SCIM 2.0 CE routes, token auth, user provisioning/deprovisioning"
    status: pending
  - id: 14-plan-gating
    content: "Plan tier gating: getFeatureAccess() helper + frontend gating"
    status: pending
  - id: 14-update-rules
    content: "Update CLAUDE.md and deptex.mdc with Phase 14 documentation"
    status: pending
isProject: false
---

# Phase 14: Enterprise Security (Complete Overhaul)

See `c:\Users\hruck\.cursor\plans\phase_14_enterprise_security_d5ee598b.plan.md` for the full detailed plan with architecture diagrams, code snippets, and test suite.

Key sub-phases: 14A Security Audit Log, 14B MFA, 14C Session Management, 14D SSO/SAML, 14E IP Allowlisting, 14F API Tokens, 14G SCIM Provisioning.

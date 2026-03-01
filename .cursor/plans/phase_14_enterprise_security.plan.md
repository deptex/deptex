---
name: Phase 14 - Enterprise Security
overview: MFA via Supabase Auth TOTP, SSO via SAML, session management.
todos:
  - id: phase-14-security
    content: "Phase 14: Enterprise Security - MFA via Supabase Auth TOTP (org-wide enforcement toggle), SSO via SAML (Supabase Auth Pro, Team+ tier), session management"
    status: pending
isProject: false
---
## Phase 14: Enterprise Security (MFA & SSO)

**Goal:** Add multi-factor authentication and single sign-on capabilities for enterprise customers. MFA available on Team+ tier with org-wide enforcement. SSO via SAML available on Team+ tier.

**Timeline:** ~2-3 weeks. Supabase Auth handles the heavy lifting for both MFA and SAML.

**Prerequisite:** Supabase Pro plan (for SAML support).

### 14A: Multi-Factor Authentication (MFA)

**Supabase Auth TOTP support:**

Supabase Auth has built-in TOTP MFA. We need to:

1. **User-level MFA setup** (user profile/account settings):
  - "Enable Two-Factor Authentication" button
  - Flow: generate TOTP secret â†’ show QR code â†’ user scans with authenticator app â†’ verify with 6-digit code â†’ MFA enabled
  - Show recovery codes (one-time backup codes) after setup
  - "Disable MFA" option (requires current TOTP code to disable)
  - Supabase handles: secret generation, QR code URI, code verification, session management
2. **Org-wide MFA enforcement** (Org Settings > Security, Team+ only):
  - Toggle: "Require MFA for all organization members"
  - When enabled: members without MFA are prompted to set it up on next login. Grace period: 7 days to enable MFA before being locked out.
  - Admin override: org admins can temporarily exempt specific users (e.g., service accounts)
  - Enforcement check: on every authenticated API request, verify MFA status if org enforcement is enabled

**Database:**

```sql
ALTER TABLE organizations ADD COLUMN mfa_enforced BOOLEAN DEFAULT false;
ALTER TABLE organizations ADD COLUMN mfa_grace_period_days INTEGER DEFAULT 7;
```

MFA status per user is managed by Supabase Auth (stored in `auth.mfa_factors` table).

**Frontend changes:**

- New "Security" section in user account settings (separate from org settings)
- MFA setup wizard with QR code display and code verification
- Recovery code display (shown once, user must save them)
- Org Settings > Security: MFA enforcement toggle (Team+ gated via plan limits from Phase 13)
- Login flow: if MFA enabled, show TOTP input after password

### 14B: Single Sign-On (SSO via SAML)

**Supabase Auth SAML support** (requires Supabase Pro plan):

Supabase Auth supports SAML 2.0 for enterprise SSO. We need to:

1. **SSO Configuration UI** (Org Settings > Security > SSO, Team+ only):
  - "Configure SSO" button opens a setup wizard
  - Step 1: Choose provider (Okta, Azure AD, Google Workspace, OneLogin, custom SAML)
  - Step 2: Enter SAML metadata URL or upload metadata XML
  - Step 3: Configure attribute mapping (email, name, groups â†’ Deptex roles)
  - Step 4: Test SSO connection
  - Step 5: Enable SSO (optionally: "Require SSO for all members" -- disables password login)
2. **Backend SSO management:**
  - Use Supabase Admin API to create/manage SSO providers: `supabase.auth.admin.createSSOProvider()`
  - Map SAML groups to Deptex org roles (configurable mapping table)
  - Auto-provision users on first SSO login (create Deptex user + add to org)
  - JIT (Just-In-Time) provisioning with configurable default role

**Database:**

```sql
CREATE TABLE organization_sso_providers (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider_type TEXT NOT NULL, -- 'okta', 'azure_ad', 'google_workspace', 'onelogin', 'custom_saml'
  supabase_sso_provider_id TEXT NOT NULL, -- Supabase's internal SSO provider ID
  metadata_url TEXT,
  domain TEXT, -- e.g., 'company.com' -- for domain-based SSO routing
  enforce_sso BOOLEAN DEFAULT false, -- if true, password login disabled for this org
  default_role_id UUID REFERENCES organization_roles(id), -- role for JIT-provisioned users
  group_role_mapping JSONB, -- { "Engineering": "role-id-1", "Security": "role-id-2" }
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(organization_id)
);
```

1. **Login flow changes:**
  - Login page: add "Sign in with SSO" button below the email/password form
  - SSO button: prompts for email or org domain â†’ routes to correct SAML IdP
  - Domain-based routing: if user's email domain matches an org's SSO domain, auto-redirect to SSO
  - Post-SSO: user lands in their org dashboard, auto-provisioned if first login

### 14C: Session Management

While implementing MFA/SSO, add basic session management:

- **Active sessions list** (user account settings): show all active sessions with device, IP, last active time
- **Revoke session** button per session
- **Org admin: force logout** for any member (Org Settings > Members > member dropdown > "Force Logout")
- Supabase Auth provides session management APIs for this

### 14D: Phase 14 Test Suite

Tests 1-5 (MFA):

1. MFA setup generates valid TOTP secret and QR code
2. MFA verification accepts correct 6-digit code
3. MFA enforcement: non-MFA user prompted to set up after login
4. MFA enforcement respects grace period (user not locked out during grace days)
5. Recovery codes work for one-time login when authenticator unavailable

Tests 6-10 (SSO):
6. SSO provider creation stores correct metadata in Supabase
7. SSO login redirects to correct IdP based on email domain
8. JIT provisioning creates user with correct default role
9. Group-role mapping assigns correct Deptex role from SAML groups
10. "Enforce SSO" disables password login for org members

Tests 11-12 (Session Management):
11. Active sessions list shows correct device and timestamp info
12. Revoking a session invalidates the token immediately

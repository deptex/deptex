const apiBase = "https://api.deptex.io"; // Replace with your API base in production

export default function EnterpriseSecurityContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          <strong className="text-foreground">Enterprise Security</strong> adds MFA (multi-factor authentication),
          SSO (SAML 2.0), session management, IP allowlisting, API tokens, a security audit log, and optional SCIM provisioning.
          These features are available on Team+ or Enterprise plans. Configuration is under{" "}
          <strong className="text-foreground">Organization Settings → Security</strong> and user-level options under{" "}
          <strong className="text-foreground">Settings → Security</strong>.
        </p>
        <p className="text-foreground-secondary leading-relaxed">
          Before using SSO or MFA in production, run the Phase 14 database migration and install backend packages.
          See <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">docs/phase14-deployment.md</code> for the full checklist.
        </p>
      </div>

      {/* MFA */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Multi-Factor Authentication (MFA)</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground-secondary leading-relaxed">
            Users can enable TOTP-based 2FA from <strong className="text-foreground">Settings → Security → Two-Factor Authentication</strong>.
            After signing in with Google or GitHub, they enroll a factor (QR code or secret) and verify with a 6-digit code.
          </p>
          <p className="text-foreground-secondary leading-relaxed">
            Organization admins can <strong className="text-foreground">require MFA for all members</strong> from{" "}
            <strong className="text-foreground">Organization Settings → Security → Multi-Factor Authentication</strong>.
            You can set a grace period (e.g. 7 days) and create temporary exemptions for specific users. Once enforced,
            the API returns <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">403 MFA_REQUIRED</code> for
            org-scoped requests if the session is not at AAL2.
          </p>
        </div>
      </div>

      {/* SSO */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Single Sign-On (SSO / SAML 2.0)</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground-secondary leading-relaxed">
            Admins configure an identity provider (Okta, Azure AD, Google Workspace, etc.) under{" "}
            <strong className="text-foreground">Organization Settings → Security → Single Sign-On</strong>.
            You provide IdP metadata (URL or XML), set a <strong className="text-foreground">domain</strong> (e.g.{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">company.com</code>),
            and verify ownership via a DNS TXT record. After verification, users with that email domain can use{" "}
            <strong className="text-foreground">Sign in with SSO</strong> on the login page.
          </p>
          <p className="text-foreground-secondary leading-relaxed">
            JIT (just-in-time) provisioning creates new users when they first sign in via SSO; you can map SAML groups to
            Deptex roles. Emergency bypass tokens (24-hour, single-use) allow sign-in when the IdP is unavailable.
          </p>
        </div>
      </div>

      {/* Session management */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Session Management</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground-secondary leading-relaxed">
            Users see <strong className="text-foreground">Active Sessions</strong> under{" "}
            <strong className="text-foreground">Settings → Security</strong> and can revoke individual sessions or sign out all other devices.
          </p>
          <p className="text-foreground-secondary leading-relaxed">
            Admins configure <strong className="text-foreground">Session Policy</strong> under Organization Settings → Security:
            max session duration (e.g. 7 days), require re-authentication for sensitive actions, and force logout all members.
          </p>
        </div>
      </div>

      {/* IP allowlist */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">IP Allowlist</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground-secondary leading-relaxed">
            When enabled, only requests from allowed IPv4/IPv6 CIDR ranges can access organization-scoped APIs.
            Configure under <strong className="text-foreground">Organization Settings → Security → IP Allowlist</strong>.
            Add at least one range before enabling to avoid locking yourself out.
          </p>
        </div>
      </div>

      {/* API tokens */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">API Tokens</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground-secondary leading-relaxed">
            Users create tokens from <strong className="text-foreground">Settings → Security → API Tokens</strong> (name, organization, scopes: read/write/admin, optional expiry).
            The full token is shown once; use <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">Authorization: Bearer dptx_&lt;hex&gt;</code>.
            Org admins can view and revoke any token used in their org under Organization Settings → Security → API Tokens.
          </p>
        </div>
      </div>

      {/* Audit log */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Security Audit Log</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground-secondary leading-relaxed">
            All security-relevant actions (MFA enrollment, SSO login, session revoke, IP deny, token create/revoke, etc.)
            are recorded in the audit log. View and export from{" "}
            <strong className="text-foreground">Organization Settings → Security → Audit Logs</strong> (or Audit Logs in the sidebar).
            CSV export is available for compliance evidence.
          </p>
        </div>
      </div>

      {/* SCIM */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">SCIM Provisioning</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground-secondary leading-relaxed">
            Enterprise customers can enable SCIM 2.0 user provisioning under{" "}
            <strong className="text-foreground">Organization Settings → Security → SCIM Provisioning</strong>.
            A bearer token and base URL are provided; your IdP (e.g. Okta) uses the SCIM Users endpoints to provision and
            deprovision users in the organization.
          </p>
        </div>
      </div>

      {/* API Reference */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">API Reference (Enterprise Security)</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          All organization security endpoints require authentication and the{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">manage_security</code> permission
          unless noted. Base URL: <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">{apiBase}/api</code>.
        </p>

        <h3 className="text-base font-semibold text-foreground mb-2 mt-6">Audit Log</h3>
        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">Method</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">Path</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              <tr><td className="px-4 py-2 font-mono">GET</td><td className="px-4 py-2 font-mono">/organizations/:id/security/audit-log</td><td className="px-4 py-2 text-foreground-secondary">Paginated audit log (query: page, limit, action, actor_id, severity, from, to)</td></tr>
              <tr><td className="px-4 py-2 font-mono">GET</td><td className="px-4 py-2 font-mono">/organizations/:id/security/audit-log/export</td><td className="px-4 py-2 text-foreground-secondary">CSV export (query: from, to)</td></tr>
            </tbody>
          </table>
        </div>

        <h3 className="text-base font-semibold text-foreground mb-2 mt-6">MFA</h3>
        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">Method</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">Path</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              <tr><td className="px-4 py-2 font-mono">GET</td><td className="px-4 py-2 font-mono">/organizations/:id/security/mfa-status</td><td className="px-4 py-2 text-foreground-secondary">Enforcement state and member MFA status</td></tr>
              <tr><td className="px-4 py-2 font-mono">PATCH</td><td className="px-4 py-2 font-mono">/organizations/:id/security/mfa-enforcement</td><td className="px-4 py-2 text-foreground-secondary">Body: enabled, grace_period_days</td></tr>
              <tr><td className="px-4 py-2 font-mono">POST</td><td className="px-4 py-2 font-mono">/organizations/:id/security/mfa-exemptions</td><td className="px-4 py-2 text-foreground-secondary">Body: target_user_id, reason, expires_in_days</td></tr>
              <tr><td className="px-4 py-2 font-mono">DELETE</td><td className="px-4 py-2 font-mono">/organizations/:id/security/mfa-exemptions/:userId</td><td className="px-4 py-2 text-foreground-secondary">Remove exemption</td></tr>
            </tbody>
          </table>
        </div>

        <h3 className="text-base font-semibold text-foreground mb-2 mt-6">SSO</h3>
        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">Method</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">Path</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              <tr><td className="px-4 py-2 font-mono">GET</td><td className="px-4 py-2 font-mono">/organizations/:id/security/sso</td><td className="px-4 py-2 text-foreground-secondary">Get SSO config</td></tr>
              <tr><td className="px-4 py-2 font-mono">POST</td><td className="px-4 py-2 font-mono">/organizations/:id/security/sso</td><td className="px-4 py-2 text-foreground-secondary">Create (provider_type, entity_id, sso_url, certificate, domain, …)</td></tr>
              <tr><td className="px-4 py-2 font-mono">PUT</td><td className="px-4 py-2 font-mono">/organizations/:id/security/sso</td><td className="px-4 py-2 text-foreground-secondary">Update config</td></tr>
              <tr><td className="px-4 py-2 font-mono">DELETE</td><td className="px-4 py-2 font-mono">/organizations/:id/security/sso</td><td className="px-4 py-2 text-foreground-secondary">Remove SSO</td></tr>
              <tr><td className="px-4 py-2 font-mono">POST</td><td className="px-4 py-2 font-mono">/organizations/:id/security/sso/verify-domain</td><td className="px-4 py-2 text-foreground-secondary">Verify domain via DNS TXT</td></tr>
              <tr><td className="px-4 py-2 font-mono">POST</td><td className="px-4 py-2 font-mono">/organizations/:id/security/sso/bypass-token</td><td className="px-4 py-2 text-foreground-secondary">Generate emergency bypass token</td></tr>
            </tbody>
          </table>
        </div>
        <p className="text-sm text-foreground-secondary mt-2">
          Public SSO routes (no auth): <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">GET /sso/login?email=</code>,{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">POST /sso/callback</code>,{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">GET /sso/check?email=</code>,{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">POST /sso/bypass</code>.
        </p>

        <h3 className="text-base font-semibold text-foreground mb-2 mt-6">Sessions (user)</h3>
        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">Method</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">Path</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              <tr><td className="px-4 py-2 font-mono">GET</td><td className="px-4 py-2 font-mono">/user/sessions</td><td className="px-4 py-2 text-foreground-secondary">List active sessions</td></tr>
              <tr><td className="px-4 py-2 font-mono">DELETE</td><td className="px-4 py-2 font-mono">/user/sessions/:sessionId</td><td className="px-4 py-2 text-foreground-secondary">Revoke one session</td></tr>
              <tr><td className="px-4 py-2 font-mono">DELETE</td><td className="px-4 py-2 font-mono">/user/sessions</td><td className="px-4 py-2 text-foreground-secondary">Revoke all other sessions</td></tr>
            </tbody>
          </table>
        </div>

        <h3 className="text-base font-semibold text-foreground mb-2 mt-6">API Tokens (user)</h3>
        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">Method</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">Path</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              <tr><td className="px-4 py-2 font-mono">GET</td><td className="px-4 py-2 font-mono">/user/api-tokens</td><td className="px-4 py-2 text-foreground-secondary">List tokens</td></tr>
              <tr><td className="px-4 py-2 font-mono">POST</td><td className="px-4 py-2 font-mono">/user/api-tokens</td><td className="px-4 py-2 text-foreground-secondary">Create (name, organization_id, scopes, expires_in_days); returns token once</td></tr>
              <tr><td className="px-4 py-2 font-mono">DELETE</td><td className="px-4 py-2 font-mono">/user/api-tokens/:id</td><td className="px-4 py-2 text-foreground-secondary">Revoke</td></tr>
              <tr><td className="px-4 py-2 font-mono">POST</td><td className="px-4 py-2 font-mono">/user/api-tokens/:id/rotate</td><td className="px-4 py-2 text-foreground-secondary">Revoke and issue new token</td></tr>
            </tbody>
          </table>
        </div>

        <h3 className="text-base font-semibold text-foreground mb-2 mt-6">IP Allowlist, Session Policy, SCIM</h3>
        <p className="text-foreground-secondary text-sm mb-2">
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">GET/POST/DELETE /organizations/:id/security/ip-allowlist</code>,{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">PATCH .../ip-allowlist-enabled</code>;{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">GET/PATCH .../security/session-policy</code>,{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">POST .../security/force-logout/:userId</code>;{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">GET/POST .../security/scim</code>,{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">GET/DELETE .../security/api-tokens</code> (org admin).
        </p>
        <p className="text-foreground-secondary text-sm">
          SCIM 2.0 base: <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">/scim/v2</code> (ServiceProviderConfig, Schemas, Users CRUD). Auth: <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">Authorization: Bearer &lt;scim_token&gt;</code>.
        </p>
      </div>
    </div>
  );
}

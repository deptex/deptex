export default function EnterpriseSecurityContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <p className="text-foreground/90 leading-relaxed">
          <strong className="text-foreground">Enterprise Security</strong> adds MFA (multi-factor authentication), SSO (SAML 2.0),
          session management, IP allowlisting, API tokens, a security audit log, and optional SCIM provisioning. Available on Team+ or
          Enterprise plans. Configuration: <strong className="text-foreground">Organization Settings → Security</strong> and{" "}
          <strong className="text-foreground">Settings → Security</strong> (user-level).
        </p>
      </div>

      {/* MFA */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Multi-Factor Authentication (MFA)</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground/90 leading-relaxed">
            Users enable TOTP-based 2FA from <strong className="text-foreground">Settings → Security → Two-Factor Authentication</strong>.
            After signing in, they enroll a factor (QR code or secret) and verify with a 6-digit code.
          </p>
          <p className="text-foreground/90 leading-relaxed">
            Admins can <strong className="text-foreground">require MFA for all members</strong> from Organization Settings → Security.
            Set a grace period and create temporary exemptions. Once enforced, API returns 403 for org-scoped requests if the session is not at AAL2.
          </p>
        </div>
      </div>

      {/* SSO */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Single Sign-On (SSO / SAML 2.0)</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground/90 leading-relaxed">
            Configure an identity provider (Okta, Azure AD, Google Workspace, etc.) under Organization Settings → Security → SSO.
            Provide IdP metadata, set a domain, and verify ownership via DNS TXT. Users with that email domain can use{" "}
            <strong className="text-foreground">Sign in with SSO</strong> on the login page.
          </p>
          <p className="text-foreground/90 leading-relaxed">
            JIT provisioning creates new users on first SSO sign-in. Map SAML groups to Deptex roles. Emergency bypass tokens (24-hour, single-use) allow sign-in when the IdP is unavailable.
          </p>
        </div>
      </div>

      {/* Session management */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Session Management</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground/90 leading-relaxed">
            Users see <strong className="text-foreground">Active Sessions</strong> under Settings → Security and can revoke individual sessions or sign out all other devices.
          </p>
        </div>
      </div>

      {/* IP allowlist */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">IP Allowlist</h2>
        </div>
        <div className="p-6">
          <p className="text-foreground/90 leading-relaxed">
            When enabled, only requests from allowed IPv4/IPv6 CIDR ranges can access organization-scoped APIs. Configure under Organization Settings → Security → IP Allowlist. Add at least one range before enabling to avoid locking yourself out.
          </p>
        </div>
      </div>

      {/* API tokens */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">API Tokens</h2>
        </div>
        <div className="p-6">
          <p className="text-foreground/90 leading-relaxed">
            Users create tokens from <strong className="text-foreground">Settings → Security → API Tokens</strong> (name, organization, scopes: read/write/admin, optional expiry).
            The full token is shown once; use <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">Authorization: Bearer dptx_&lt;hex&gt;</code>.
            Org admins can view and revoke tokens used in their org.
          </p>
        </div>
      </div>

      {/* Audit log */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Security Audit Log</h2>
        </div>
        <div className="p-6">
          <p className="text-foreground/90 leading-relaxed">
            All security-relevant actions (MFA enrollment, SSO login, session revoke, IP deny, token create/revoke, etc.) are recorded.
            View and export from Organization Settings → Security → Audit Logs. CSV export available for compliance.
          </p>
        </div>
      </div>

      {/* SCIM */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">SCIM Provisioning</h2>
        </div>
        <div className="p-6">
          <p className="text-foreground/90 leading-relaxed">
            Enterprise customers can enable SCIM 2.0 user provisioning under Organization Settings → Security → SCIM Provisioning.
            A bearer token and base URL are provided; your IdP (e.g. Okta) uses the SCIM Users endpoints to provision and deprovision users.
          </p>
        </div>
      </div>
    </div>
  );
}

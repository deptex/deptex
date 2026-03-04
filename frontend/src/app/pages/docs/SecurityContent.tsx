export default function SecurityContent() {
  return (
    <div className="space-y-12">
      <p className="text-foreground/90 leading-relaxed">
        Security is at the core of Deptex. We help you secure your dependency supply chain and take our own security practices seriously.
      </p>

      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">What We Protect</h2>
        </div>
        <div className="p-6">
          <p className="text-foreground/90 leading-relaxed">
            Deptex safeguards your account data, organization settings, and the dependency and vulnerability information we process.
            We use encryption in transit and at rest, and follow secure development practices.
          </p>
        </div>
      </div>

      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Access Control</h2>
        </div>
        <div className="p-6">
          <p className="text-foreground/90 leading-relaxed">
            Organizations can define roles, permissions, and team-scoped access. SSO and MFA (on Team+ or Enterprise plans) add extra layers for enterprise customers.
          </p>
        </div>
      </div>

      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Compliance & Transparency</h2>
        </div>
        <div className="p-6">
          <p className="text-foreground/90 leading-relaxed">
            We are working toward SOC2 and other compliance certifications. For security questionnaires or specific documentation requests, contact us at{" "}
            <a href="mailto:deptex.app@gmail.com" className="text-foreground underline hover:no-underline">deptex.app@gmail.com</a>.
          </p>
        </div>
      </div>
    </div>
  );
}

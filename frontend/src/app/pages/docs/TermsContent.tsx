export default function TermsContent() {
  return (
    <div className="space-y-12">
      <p className="text-foreground/90 leading-relaxed">
        These Terms of Service govern your use of Deptex. By using our platform, you agree to these terms.
      </p>

      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Acceptance of Terms</h2>
        </div>
        <div className="p-6">
          <p className="text-foreground/90 leading-relaxed">
            By accessing or using Deptex, you agree to be bound by these Terms. If you do not agree, please do not use our services.
          </p>
        </div>
      </div>

      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Use of the Service</h2>
        </div>
        <div className="p-6">
          <p className="text-foreground/90 leading-relaxed">
            Deptex provides dependency tracking, vulnerability monitoring, and compliance tools for software development teams.
            You agree to use the service in compliance with applicable laws and not to misuse or abuse the platform.
          </p>
        </div>
      </div>

      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Contact</h2>
        </div>
        <div className="p-6">
          <p className="text-foreground/90 leading-relaxed">
            Questions about these terms? Reach out at{" "}
            <a href="mailto:deptex.app@gmail.com" className="text-foreground underline hover:no-underline">deptex.app@gmail.com</a>.
          </p>
        </div>
      </div>
    </div>
  );
}

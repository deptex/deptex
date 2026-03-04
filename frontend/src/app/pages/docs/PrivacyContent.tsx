import { Link } from "react-router-dom";

export default function PrivacyContent() {
  return (
    <div className="space-y-12">
      <p className="text-foreground/90 leading-relaxed">
        We take your privacy seriously. This policy describes how Deptex collects, uses, and protects your information.
      </p>

      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Information We Collect</h2>
        </div>
        <div className="p-6">
          <p className="text-foreground/90 leading-relaxed">
            We collect information you provide (e.g., account details, organization data) and usage data necessary to operate the service,
            including repository metadata and dependency information from your connected projects.
          </p>
        </div>
      </div>

      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">How We Use It</h2>
        </div>
        <div className="p-6">
          <p className="text-foreground/90 leading-relaxed">
            Your data is used to deliver Deptex features: dependency scanning, vulnerability alerts, compliance reporting, and integrations you configure.
            We do not sell your personal information.
          </p>
        </div>
      </div>

      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Data Security</h2>
        </div>
        <div className="p-6">
          <p className="text-foreground/90 leading-relaxed">
            We use industry-standard practices to protect your data. For more details, see our{" "}
            <Link to="/docs/security" className="text-foreground underline hover:no-underline">Security</Link> page.
          </p>
        </div>
      </div>

      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Contact</h2>
        </div>
        <div className="p-6">
          <p className="text-foreground/90 leading-relaxed">
            Privacy questions? Email us at{" "}
            <a href="mailto:deptex.app@gmail.com" className="text-foreground underline hover:no-underline">deptex.app@gmail.com</a>.
          </p>
        </div>
      </div>
    </div>
  );
}

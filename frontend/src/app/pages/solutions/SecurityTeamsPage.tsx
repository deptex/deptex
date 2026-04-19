import { Link } from "react-router-dom";
import { Button } from "../../../components/ui/button";
import { CheckCircle2 } from "lucide-react";

export default function SecurityTeamsPage() {
  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="container mx-auto px-4 py-20 lg:py-32">
        <div className="max-w-5xl mx-auto text-center">
          <div className="text-sm text-primary mb-4 font-medium uppercase tracking-wide">
            DEPTEX FOR SECURITY TEAMS
          </div>
          <h1 className="text-5xl md:text-6xl lg:text-7xl font-bold mb-6">
            <span className="text-foreground">Gain deep visibility</span>
            <br />
            <span className="text-primary">into your supply chain</span>
          </h1>
          <p className="text-xl text-foreground-secondary mb-12 max-w-3xl mx-auto leading-relaxed">
            Gain deep visibility into your software supply chain, detect anomalies, enforce policy, and streamline compliance reporting. Get the insights you need to protect your organization.
          </p>
          <Button
            asChild
            size="lg"
            className="bg-primary text-primary-foreground hover:bg-primary/90 text-base px-8 py-6"
          >
            <Link to="/signup">Start your project</Link>
          </Button>
        </div>
      </section>

      {/* Benefits Section */}
      <section className="container mx-auto px-4 py-20">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-semibold text-foreground mb-12 text-center">
            Why security teams choose Deptex
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Supply Chain Visibility</h3>
                <p className="text-foreground-secondary">
                  Map your entire dependency tree with direct and transitive dependencies. Understand what's actually running in production.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Anomaly Detection</h3>
                <p className="text-foreground-secondary">
                  Detect typosquatting, malicious packages, and suspicious commit patterns before they become incidents.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Compliance Reporting</h3>
                <p className="text-foreground-secondary">
                  Generate SBOMs, track license compliance, and produce audit-ready reports on-demand or scheduled.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Policy-as-Code</h3>
                <p className="text-foreground-secondary">
                  Define and enforce security policies across all projects. Automatically block violations at the PR level.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}


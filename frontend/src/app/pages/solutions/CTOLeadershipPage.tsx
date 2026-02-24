import { Link } from "react-router-dom";
import { Button } from "../../../components/ui/button";
import { CheckCircle2 } from "lucide-react";

export default function CTOLeadershipPage() {
  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="container mx-auto px-4 py-20 lg:py-32">
        <div className="max-w-5xl mx-auto text-center">
          <div className="text-sm text-primary mb-4 font-medium uppercase tracking-wide">
            DEPTEX FOR CTOs & ENGINEERING LEADERSHIP
          </div>
          <h1 className="text-5xl md:text-6xl lg:text-7xl font-bold mb-6">
            <span className="text-foreground">Improve security posture</span>
            <br />
            <span className="text-primary">reduce operational risk</span>
          </h1>
          <p className="text-xl text-foreground-secondary mb-12 max-w-3xl mx-auto leading-relaxed">
            Improve security posture, reduce operational risk, automate manual review burdens, and maintain organization-wide standards. Get executive-level visibility into your dependency governance.
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
            Why CTOs and engineering leaders choose Deptex
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Organization-Wide Visibility</h3>
                <p className="text-foreground-secondary">
                  Get a unified view of security posture across all projects. Track compliance and risk metrics at scale.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Risk Reduction</h3>
                <p className="text-foreground-secondary">
                  Proactively identify and remediate security risks before they become incidents. Reduce breach probability.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Automated Compliance</h3>
                <p className="text-foreground-secondary">
                  Maintain regulatory compliance automatically. Generate audit-ready reports and SBOMs on-demand.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Cost Efficiency</h3>
                <p className="text-foreground-secondary">
                  Reduce manual security review time. Automate repetitive tasks and free up engineering resources.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}


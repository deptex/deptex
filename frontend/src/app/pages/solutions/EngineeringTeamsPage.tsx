import { Link } from "react-router-dom";
import { Button } from "../../../components/ui/button";
import { CheckCircle2 } from "lucide-react";

export default function EngineeringTeamsPage() {
  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="container mx-auto px-4 py-20 lg:py-32">
        <div className="max-w-5xl mx-auto text-center">
          <div className="text-sm text-primary mb-4 font-medium uppercase tracking-wide">
            DEPTEX FOR ENGINEERING TEAMS
          </div>
          <h1 className="text-5xl md:text-6xl lg:text-7xl font-bold mb-6">
            <span className="text-foreground">Keep your repositories</span>
            <br />
            <span className="text-primary">secure and compliant</span>
          </h1>
          <p className="text-xl text-foreground-secondary mb-12 max-w-3xl mx-auto leading-relaxed">
            Keep your repositories secure, updated, and compliant with automated dependency monitoring and AI-driven remediation. Focus on building features while Deptex handles the security and maintenance overhead.
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
            Why engineering teams choose Deptex
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Automated Dependency Updates</h3>
                <p className="text-foreground-secondary">
                  Receive automated PRs for safe dependency upgrades. Let AI handle the tedious work of keeping dependencies current.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Real-time Vulnerability Alerts</h3>
                <p className="text-foreground-secondary">
                  Get instant notifications about security issues in your dependencies, prioritized by impact and reachability.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Policy Enforcement</h3>
                <p className="text-foreground-secondary">
                  Enforce license policies and security standards automatically. Block non-compliant dependencies at PR time.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">AI-Powered Remediation</h3>
                <p className="text-foreground-secondary">
                  Let your AI security agent investigate, fix, and explain issues automatically with human-in-the-loop approval.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}


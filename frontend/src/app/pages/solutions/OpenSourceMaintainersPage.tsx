import { Link } from "react-router-dom";
import { Button } from "../../../components/ui/button";
import { CheckCircle2 } from "lucide-react";

export default function OpenSourceMaintainersPage() {
  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="container mx-auto px-4 py-20 lg:py-32">
        <div className="max-w-5xl mx-auto text-center">
          <div className="text-sm text-primary mb-4 font-medium uppercase tracking-wide">
            DEPTEX FOR OPEN SOURCE MAINTAINERS
          </div>
          <h1 className="text-5xl md:text-6xl lg:text-7xl font-bold mb-6">
            <span className="text-foreground">Maintain project health</span>
            <br />
            <span className="text-primary">safeguard your ecosystem</span>
          </h1>
          <p className="text-xl text-foreground-secondary mb-12 max-w-3xl mx-auto leading-relaxed">
            Maintain project health, track dependency drift, receive automated PRs, and safeguard your package ecosystem. Keep your open source projects secure and up-to-date with minimal effort.
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
            Why open source maintainers choose Deptex
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Dependency Drift Tracking</h3>
                <p className="text-foreground-secondary">
                  Monitor how your dependencies change over time. Detect when transitive dependencies introduce vulnerabilities.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Automated PRs</h3>
                <p className="text-foreground-secondary">
                  Receive automated pull requests for safe dependency updates. Review and merge when ready.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Package Health Monitoring</h3>
                <p className="text-foreground-secondary">
                  Track the health of your dependencies. Get alerts when maintainers become inactive or packages show signs of risk.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Ecosystem Protection</h3>
                <p className="text-foreground-secondary">
                  Protect your package ecosystem from typosquatting, malicious packages, and supply chain attacks.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}


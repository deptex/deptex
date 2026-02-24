import { Link } from "react-router-dom";
import { Button } from "../../../components/ui/button";
import { CheckCircle2 } from "lucide-react";

export default function DevOpsTeamsPage() {
  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="container mx-auto px-4 py-20 lg:py-32">
        <div className="max-w-5xl mx-auto text-center">
          <div className="text-sm text-primary mb-4 font-medium uppercase tracking-wide">
            DEPTEX FOR PLATFORM & DEVOPS TEAMS
          </div>
          <h1 className="text-5xl md:text-6xl lg:text-7xl font-bold mb-6">
            <span className="text-foreground">Ensure safe deployments</span>
            <br />
            <span className="text-primary">across your pipeline</span>
          </h1>
          <p className="text-xl text-foreground-secondary mb-12 max-w-3xl mx-auto leading-relaxed">
            Ensure safe deployments, consistent environments, and proactive package health checks across the entire build pipeline. Integrate security into your CI/CD workflows seamlessly.
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
            Why platform & DevOps teams choose Deptex
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">CI/CD Integration</h3>
                <p className="text-foreground-secondary">
                  Block deployments that violate policies. Integrate with GitHub Actions, GitLab CI, Jenkins, and more.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Environment Consistency</h3>
                <p className="text-foreground-secondary">
                  Track dependencies across dev, staging, and production. Detect drift and ensure consistency.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Proactive Health Checks</h3>
                <p className="text-foreground-secondary">
                  Monitor package health, detect stale dependencies, and get upgrade recommendations before issues arise.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Automated Remediation</h3>
                <p className="text-foreground-secondary">
                  Automatically generate PRs for safe upgrades and patches. Reduce manual maintenance overhead.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}


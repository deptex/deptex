import { Link } from "react-router-dom";
import { Button } from "../../../components/ui/button";
import { CheckCircle2 } from "lucide-react";

export default function StartupsScaleupsPage() {
  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="container mx-auto px-4 py-20 lg:py-32">
        <div className="max-w-5xl mx-auto text-center">
          <div className="text-sm text-primary mb-4 font-medium uppercase tracking-wide">
            DEPTEX FOR STARTUPS & SCALEUPS
          </div>
          <h1 className="text-5xl md:text-6xl lg:text-7xl font-bold mb-6">
            <span className="text-foreground">Launch fast</span>
            <br />
            <span className="text-primary">scale effortlessly</span>
          </h1>
          <p className="text-xl text-foreground-secondary mb-12 max-w-3xl mx-auto leading-relaxed">
            Launch fast with built-in security routines and automated maintenance that scales effortlessly as your team grows. Get enterprise-grade dependency governance from day one.
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
            Why startups and scaleups choose Deptex
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Built-in Security</h3>
                <p className="text-foreground-secondary">
                  Start with security best practices from day one. No need to build custom tooling or processes.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Automated Maintenance</h3>
                <p className="text-foreground-secondary">
                  Keep dependencies updated automatically. Focus on building features, not maintaining packages.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Scales with You</h3>
                <p className="text-foreground-secondary">
                  As your team and codebase grow, Deptex scales seamlessly. Add projects and teams without friction.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-primary flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-foreground mb-2">Fast Onboarding</h3>
                <p className="text-foreground-secondary">
                  Get up and running in minutes. Link your repositories and start monitoring immediately.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}


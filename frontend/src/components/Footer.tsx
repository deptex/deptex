import { Link } from "react-router-dom";

const GITHUB_REPO_URL = "https://github.com/deptex/deptex";

export default function Footer() {
  return (
    <footer className="border-t border-border bg-background">
      <div className="container mx-auto px-4 py-12">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8 mb-8">
          {/* Branding */}
          <div className="lg:col-span-1">
            <Link to="/" className="flex items-center gap-2 mb-4">
              <span className="text-2xl font-bold text-foreground">Deptex</span>
            </Link>
            <p className="text-sm text-foreground-secondary mb-4">
              Security you can trust. Dependency governance for modern teams.
            </p>
            <div className="flex gap-4">
              <a
                href={GITHUB_REPO_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="text-foreground-secondary hover:text-foreground transition-colors"
                aria-label="Deptex on GitHub"
              >
                <img src="/images/integrations/github.png" alt="" className="h-5 w-5 rounded-full" aria-hidden />
              </a>
            </div>
          </div>

          {/* Product — same items and labels as NavBar Product dropdown */}
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-4">Product</h3>
            <ul className="space-y-3">
              <li>
                <Link to="/platform-features/ai-security-agent" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  AI Security Agent
                </Link>
              </li>
              <li>
                <Link to="/platform-features/vulnerability-intelligence" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Vulnerability Intelligence
                </Link>
              </li>
              <li>
                <Link to="/platform-features/customizable-compliance" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Customizable Compliance
                </Link>
              </li>
              <li>
                <Link to="/platform-features/customizable-notifications" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Customizable Notifications
                </Link>
              </li>
              <li>
                <Link to="/platform-features/advanced-upstream-insights" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Advanced Upstream Insights
                </Link>
              </li>
            </ul>
          </div>

          {/* Resources — Docs, Open Source, Help, Pricing */}
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-4">Resources</h3>
            <ul className="space-y-3">
              <li>
                <Link to="/docs" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Docs
                </Link>
              </li>
              <li>
                <Link to="/open-source" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Open Source
                </Link>
              </li>
              <li>
                <Link to="/support" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Help
                </Link>
              </li>
              <li>
                <Link to="/pricing" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Pricing
                </Link>
              </li>
            </ul>
          </div>

          {/* Legal — terms, privacy, security */}
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-4">Legal</h3>
            <ul className="space-y-3">
              <li>
                <Link to="/docs/terms" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Terms of Service
                </Link>
              </li>
              <li>
                <Link to="/docs/privacy" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Privacy Policy
                </Link>
              </li>
              <li>
                <Link to="/docs/security" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Security
                </Link>
              </li>
            </ul>
          </div>
        </div>

        {/* Bottom bar — copyright only; legal links are in Legal column above */}
        <div className="border-t border-border pt-8">
          <p className="text-sm text-foreground-secondary">
            © {new Date().getFullYear()} Deptex. All rights reserved.
          </p>
        </div>
      </div>
    </footer>
  );
}

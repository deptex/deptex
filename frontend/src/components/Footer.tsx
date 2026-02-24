import { Link } from "react-router-dom";
import { Github, Twitter } from "lucide-react";

export default function Footer() {
  return (
    <footer className="border-t border-border bg-background">
      <div className="container mx-auto px-4 py-12">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-8 mb-8">
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
                href="https://twitter.com"
                target="_blank"
                rel="noopener noreferrer"
                className="text-foreground-secondary hover:text-foreground transition-colors"
                aria-label="Twitter"
              >
                <Twitter className="h-5 w-5" />
              </a>
              <a
                href="https://github.com"
                target="_blank"
                rel="noopener noreferrer"
                className="text-foreground-secondary hover:text-foreground transition-colors"
                aria-label="GitHub"
              >
                <Github className="h-5 w-5" />
              </a>
            </div>
          </div>

          {/* Product */}
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-4">Product</h3>
            <ul className="space-y-3">
              <li>
                <Link to="/product/tracking" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Dependency Tracking
                </Link>
              </li>
              <li>
                <Link to="/product/policy" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Policy Enforcement
                </Link>
              </li>
              <li>
                <Link to="/product/ai" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  AI Remediation
                </Link>
              </li>
              <li>
                <Link to="/product/sbom" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  SBOM Generation
                </Link>
              </li>
              <li>
                <Link to="/pricing" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Pricing
                </Link>
              </li>
            </ul>
          </div>

          {/* Solutions */}
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-4">Solutions</h3>
            <ul className="space-y-3">
              <li>
                <Link to="/solutions/enterprise" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Enterprise
                </Link>
              </li>
              <li>
                <Link to="/solutions/startups" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Startups
                </Link>
              </li>
              <li>
                <Link to="/solutions/compliance" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Compliance
                </Link>
              </li>
            </ul>
          </div>

          {/* Developers */}
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-4">Developers</h3>
            <ul className="space-y-3">
              <li>
                <Link to="/docs" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Documentation
                </Link>
              </li>
              <li>
                <Link to="/developers/github" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  GitHub Integration
                </Link>
              </li>
              <li>
                <Link to="/developers/cli" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  CLI Tools
                </Link>
              </li>
              <li>
                <Link to="/developers/webhooks" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Webhooks
                </Link>
              </li>
            </ul>
          </div>

          {/* Company */}
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-4">Company</h3>
            <ul className="space-y-3">
              <li>
                <Link to="/about" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  About
                </Link>
              </li>
              <li>
                <Link to="/blog" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Blog
                </Link>
              </li>
              <li>
                <Link to="/careers" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Careers
                </Link>
              </li>
              <li>
                <Link to="/privacy" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Privacy Policy
                </Link>
              </li>
              <li>
                <Link to="/terms" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                  Terms of Service
                </Link>
              </li>
            </ul>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="border-t border-border pt-8 flex flex-col md:flex-row justify-between items-center gap-4">
          <p className="text-sm text-foreground-secondary">
            © {new Date().getFullYear()} Deptex. All rights reserved.
          </p>
          <div className="flex gap-6">
            <Link to="/security" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
              Security
            </Link>
            <Link to="/status" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
              Status
            </Link>
          </div>
        </div>
      </div>
    </footer>
  );
}


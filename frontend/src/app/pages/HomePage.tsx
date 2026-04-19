import { Link } from "react-router-dom";
import { Button } from "../../components/ui/button";
import CompanyBanner from "../../components/CompanyBanner";
import FeaturesSection from "../../components/FeaturesSection";
import FrameworkSupportSection from "../../components/FrameworkSupportSection";
import ProductShowcaseSection from "../../components/ProductShowcaseSection";
import CTASection from "../../components/CTASection";

export default function HomePage() {
  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="container mx-auto px-4 py-20 lg:py-32">
        <div className="max-w-5xl mx-auto text-center">
          <h1 className="text-5xl md:text-6xl lg:text-7xl font-bold mb-6">
            <span className="text-foreground">Security you can trust.</span>
          </h1>
          <p className="text-xl md:text-2xl text-foreground-secondary mb-12 max-w-3xl mx-auto leading-relaxed">
            Start your project with deep dependency tracking, policy enforcement, AI-powered remediation, compliance reporting, and intelligent alerts.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Button
              asChild
              size="lg"
              className="bg-primary text-primary-foreground hover:bg-primary/90 text-base px-8 py-6"
            >
              <Link to="/signup">Start your project</Link>
            </Button>
            <Button
              asChild
              size="lg"
              variant="outline"
              className="text-base px-8 py-6 border-border hover:bg-background-subtle"
            >
              <Link to="/demo">View demo</Link>
            </Button>
          </div>
        </div>
      </section>

      {/* Company Banner */}
      <CompanyBanner />

      {/* Features Section */}
      <FeaturesSection />

      {/* Framework Support Section */}
      <FrameworkSupportSection />

      {/* Product Showcase Section */}
      <ProductShowcaseSection />

      {/* CTA Section */}
      <CTASection />
    </div>
  );
}

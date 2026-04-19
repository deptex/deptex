import { Button } from "../../components/ui/button";
import { Mail } from "lucide-react";

export default function SupportPage() {
  const handleSupportEmail = () => {
    window.location.href = "mailto:deptex.app@gmail.com?subject=Support Request";
  };

  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="container mx-auto px-4 py-20 lg:py-32">
        <div className="max-w-3xl mx-auto text-center">
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6 text-foreground">
            Support
          </h1>
          <p className="text-xl text-foreground-secondary mb-12 leading-relaxed">
            Need help? We're here for you. Reach out to our support team and we'll get back to you as soon as possible.
          </p>
          <Button
            size="lg"
            className="bg-primary text-primary-foreground hover:bg-primary/90 text-base px-8 py-6"
            onClick={handleSupportEmail}
          >
            <Mail className="h-5 w-5 mr-2" />
            Contact Support
          </Button>
        </div>
      </section>
    </div>
  );
}


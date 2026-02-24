import { Link } from "react-router-dom";
import { Button } from "./ui/button";

export default function CTASection() {
  return (
    <section className="container mx-auto px-4 py-20 lg:py-32">
      <div className="max-w-4xl mx-auto text-center">
        <h2 className="text-3xl md:text-4xl lg:text-5xl font-semibold mb-8">
          <span className="text-foreground">Secure your stack in minutes.</span>
        </h2>
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Button
            asChild
            size="lg"
            className="bg-primary text-primary-foreground hover:bg-primary/90 text-base px-8 py-6"
          >
            <Link to="/signup">
              Start your first project for free
            </Link>
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
  );
}


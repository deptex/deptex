/**
 * Big CTA card at the end of the landing page — Try Deptex free (left), See Deptex in action (right).
 */
import { Link } from "react-router-dom";
import { Button } from "./ui/button";
import { ChevronRight } from "lucide-react";

export default function LandingCTACard() {
  return (
    <div
      className="relative w-screen max-w-none left-1/2 -ml-[50vw] flex justify-center pl-4 sm:pl-6 pr-10 sm:pr-14 py-12 sm:py-16"
      aria-label="Get started with Deptex"
    >
      <div
        className="w-full max-w-4xl rounded-xl overflow-hidden border border-border bg-[#121418]"
        style={{ boxShadow: "0 0 0 1px rgba(255,255,255,0.03), 0 4px 24px -4px rgba(0,0,0,0.5)" }}
      >
        <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-border/50">
          {/* Try Deptex for free — left half */}
          <div className="p-8 sm:p-10 flex flex-col justify-center">
            <h3 className="text-xl sm:text-2xl font-semibold text-foreground mb-3">
              Try Deptex for free
            </h3>
            <p className="text-foreground text-sm sm:text-base leading-relaxed mb-6">
              Create your free account to start securing dependencies in minutes. No credit card required.
            </p>
            <Button
              asChild
              className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 font-semibold rounded-lg h-8 px-3.5 w-fit"
            >
              <Link to="/login">Get started</Link>
            </Button>
          </div>

          {/* See Deptex in action — right half */}
          <div className="p-8 sm:p-10 flex flex-col justify-center">
            <h3 className="text-xl sm:text-2xl font-semibold text-foreground mb-3">
              See Deptex in action
            </h3>
            <p className="text-foreground text-sm sm:text-base leading-relaxed mb-6">
              See why teams choose Deptex for dependency security — and what it can do for yours.
            </p>
            <Link
              to="/get-demo"
              className="inline-flex items-center gap-1 text-[#2eb37c] text-sm font-medium w-fit"
            >
              Book a live demo
              <ChevronRight className="h-4 w-4" />
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

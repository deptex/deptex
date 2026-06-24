/**
 * §3.14 Final CTA (landing-page-redesign.plan.md).
 * The safety net: restated promise, two clear actions (try free + book a
 * demo), zero new information. Differentiated by whitespace alone — no top
 * hairline, no fill, no motion, no artwork — confidence through omission.
 */
import { Link } from "react-router-dom";
import { Button } from "../ui/button";

export default function FinalCTA() {
  return (
    <section className="w-full">
      <div className="mx-auto flex max-w-[1200px] flex-col items-center px-6 py-24 text-center md:py-28">
        <h2 className="text-3xl font-semibold leading-[1.1] tracking-[-0.02em] text-foreground md:text-4xl">
          Start securing with Deptex now.
        </h2>
        <p className="mt-5 text-[15px] leading-relaxed text-foreground md:text-base">
          Scan a repo and read the first trace yourself.
        </p>
        <div className="mt-8 flex flex-col items-center gap-3 sm:flex-row">
          <Button variant="green" asChild>
            <Link to="/login">Try for free</Link>
          </Button>
          <Button
            variant="outline"
            asChild
            className="!h-8 !rounded-lg !px-3 text-foreground"
          >
            <Link to="/get-demo">Book a demo</Link>
          </Button>
        </div>
      </div>
    </section>
  );
}

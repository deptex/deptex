/**
 * §3.14 Final CTA (landing-page-redesign.plan.md).
 * The safety net: one action, restated promise, zero new information.
 * Full-width band differentiated by top hairline + whitespace, not fill.
 * No motion, no glow, no artwork — confidence through omission.
 */
import { Link } from "react-router-dom";
import { Button } from "../ui/button";
import { REPO_URL } from "./repoLinks";

export default function FinalCTA() {
  return (
    <section className="w-full border-t border-white/[0.08]">
      <div className="mx-auto flex max-w-[1200px] flex-col items-center px-6 py-28 text-center md:py-36">
        <h2 className="text-4xl font-semibold leading-[1.1] tracking-[-0.02em] text-foreground md:text-[48px]">
          Proof, then fixes.
        </h2>
        <p className="mt-5 text-[15px] leading-relaxed text-foreground-secondary md:text-base">
          Scan a repo and read the first trace yourself.
        </p>
        <div className="mt-8 flex flex-col items-center gap-3 sm:flex-row">
          <Button variant="green" asChild>
            <Link to="/login">Try for free</Link>
          </Button>
          <Button variant="white" asChild>
            <a href={REPO_URL} target="_blank" rel="noopener noreferrer">
              Read the code ↗
            </a>
          </Button>
        </div>
        <p className="mt-3 text-xs text-foreground-secondary">
          Free $5 credit · no credit card
        </p>
        <Link
          to="/get-demo"
          className="mt-7 text-sm text-foreground-secondary transition-colors hover:text-foreground"
        >
          Book a demo →
        </Link>
      </div>
    </section>
  );
}

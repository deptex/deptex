/**
 * §3.7b Mid-page CTA row — the conversion point after the receipts.
 * landing-page-redesign.plan.md: one quiet inline row, verbatim "Scan a repo"
 * green pill + friction line, hairline-separated above and below. No headline,
 * no artwork, no background shift, no motion.
 */
import { Link } from "react-router-dom";
import { Button } from "../ui/button";

export default function InlineCTA() {
  return (
    <section className="w-full border-y border-white/[0.08]">
      <div className="mx-auto flex max-w-[1200px] flex-col items-center justify-center gap-3 px-6 py-10 sm:flex-row sm:gap-5">
        <Button variant="green" asChild>
          <Link to="/login">Try for free</Link>
        </Button>
        <span className="text-sm text-foreground-secondary">
          Free $5 credit · no credit card
        </span>
      </div>
    </section>
  );
}

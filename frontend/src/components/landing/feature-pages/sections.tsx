/**
 * Shared section primitives for the dedicated feature pages (founder
 * 2026-06-22). Extracted from the Dependency scanning template so all four
 * pages share one skeleton: video hero + glow → alternating real-component
 * showcases → capability grid → CTA. Visuals are REAL product components fed
 * heroDemo mock data; no screenshots.
 *
 * The hero video is a PLACEHOLDER (the original finding-journey film, poster
 * fallback) — a real per-feature recording swaps in later.
 */
import { type ReactNode } from "react";
import { Link } from "react-router-dom";
import { type LucideIcon } from "lucide-react";
import { Button } from "../../ui/button";
import { Reveal } from "../primitives";

export function CTAs() {
  return (
    <div className="flex flex-col gap-3 sm:flex-row">
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
  );
}

function FeatureVideo() {
  return (
    <div className="overflow-hidden rounded-xl border border-border bg-[#0a0a0a] shadow-[0_0_0_1px_#262626]">
      <video
        autoPlay
        muted
        loop
        playsInline
        poster="/images/landing/finding-journey-poster.jpg"
        className="block aspect-[8/5] w-full"
      >
        <source src="/videos/landing/finding-journey.webm" type="video/webm" />
      </video>
    </div>
  );
}

export function FeatureVideoHero({
  eyebrow,
  headline,
  sub,
}: {
  eyebrow: string;
  headline: ReactNode;
  sub: ReactNode;
}) {
  return (
    <section className="relative w-full overflow-hidden pb-24 sm:pb-28">
      <div className="mx-auto max-w-[1200px] px-6 pt-28 text-center sm:pt-36">
        <p className="text-sm font-medium text-accent-text">{eyebrow}</p>
        <h1 className="mx-auto mt-4 max-w-3xl text-4xl font-semibold leading-[1.05] tracking-[-0.02em] text-foreground sm:text-5xl lg:text-[64px]">
          {headline}
        </h1>
        <p className="mx-auto mt-6 max-w-2xl text-base leading-relaxed text-foreground sm:text-lg">
          {sub}
        </p>
        <div className="mt-8 flex justify-center">
          <CTAs />
        </div>
      </div>

      <Reveal className="mt-16 sm:mt-20">
        <div className="mx-auto max-w-[1180px] px-6">
          <div className="relative">
            <div
              className="glow-green pointer-events-none absolute -inset-12 opacity-50"
              aria-hidden
            />
            <div className="relative">
              <FeatureVideo />
            </div>
          </div>
        </div>
      </Reveal>
    </section>
  );
}

/** Alternating real-component showcase. `reverse` puts the visual on the left. */
export function Showcase({
  title,
  body,
  reverse,
  children,
}: {
  title: string;
  body: ReactNode;
  reverse?: boolean;
  children: ReactNode;
}) {
  return (
    <section className="w-full border-t border-white/[0.08]">
      <div className="mx-auto max-w-[1200px] px-6 py-20 sm:py-24">
        <div className="grid gap-12 lg:grid-cols-2 lg:items-center">
          <div className={reverse ? "lg:order-2" : ""}>
            <h2 className="text-3xl font-semibold leading-[1.1] tracking-[-0.02em] text-foreground md:text-4xl">
              {title}
            </h2>
            <p className="mt-5 max-w-xl text-base leading-relaxed text-foreground">
              {body}
            </p>
          </div>
          <Reveal className={reverse ? "lg:order-1" : ""}>{children}</Reveal>
        </div>
      </div>
    </section>
  );
}

export type Capability = { Icon: LucideIcon; title: string; body: string };

export function CapabilityGrid({
  title,
  items,
}: {
  title: string;
  items: Capability[];
}) {
  return (
    <section className="w-full border-t border-white/[0.08]">
      <div className="mx-auto max-w-[1200px] px-6 py-20 sm:py-24">
        <h2 className="text-3xl font-semibold leading-[1.1] tracking-[-0.02em] text-foreground md:text-4xl">
          {title}
        </h2>
        <div className="mt-12 grid grid-cols-1 gap-x-10 gap-y-12 sm:grid-cols-2 lg:grid-cols-3">
          {items.map(({ Icon, title: cardTitle, body }) => (
            <div key={cardTitle} className="flex flex-col">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-white/[0.08] bg-white/[0.03]">
                <Icon
                  className="h-[18px] w-[18px] text-foreground-secondary"
                  aria-hidden
                />
              </div>
              <h3 className="mt-4 text-[15px] font-medium text-foreground">
                {cardTitle}
              </h3>
              <p className="mt-2 text-sm leading-relaxed text-foreground-secondary">
                {body}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

export function FeatureFinalCTA({ title, sub }: { title: string; sub: string }) {
  return (
    <section className="w-full border-t border-white/[0.08]">
      <div className="mx-auto flex max-w-[1200px] flex-col items-center px-6 py-24 text-center md:py-28">
        <h2 className="text-3xl font-semibold leading-[1.1] tracking-[-0.02em] text-foreground md:text-4xl">
          {title}
        </h2>
        <p className="mt-5 text-base leading-relaxed text-foreground">{sub}</p>
        <div className="mt-8">
          <CTAs />
        </div>
      </div>
    </section>
  );
}

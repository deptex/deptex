import { useNavigate } from 'react-router-dom';
import { Check } from 'lucide-react';
import { Button } from '../../components/ui/button';
import { PricingUsageGraph } from '../../components/landing/PricingUsageGraph';
import { Reveal } from '../../components/landing/primitives';

const FEATURES: string[] = [
  '$5 in free credit, then cost-plus usage',
  'All Deptex features',
  'Unlimited projects, members & teams',
];

export default function PricingPage() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="mx-auto max-w-6xl px-6 pt-28 pb-24 lg:pt-32">
        {/* Hero — value prop left, animated usage graph right */}
        <header className="grid items-center gap-12 lg:grid-cols-2">
          <div className="text-center lg:text-left">
            <Reveal>
              <p className="text-sm font-medium uppercase tracking-[0.18em] text-accent-text">
                Pricing
              </p>
            </Reveal>
            <Reveal delayMs={60}>
              <h1 className="mt-4 text-4xl font-bold leading-[1.08] tracking-[-0.02em] sm:text-5xl">
                Pay only for what you use.
              </h1>
            </Reveal>
            <Reveal delayMs={120}>
              <p className="mt-5 max-w-xl text-lg leading-relaxed text-foreground lg:mx-0">
                No seats, no tiers. Start with $5 in free credit, then pay cost-plus for
                only the AI and worker time you use.
              </p>
            </Reveal>
          </div>
          <Reveal delayMs={120} className="w-full">
            <PricingUsageGraph />
          </Reveal>
        </header>

        {/* Plan card — one plan, everything included (Railway-style) */}
        <Reveal delayMs={80}>
          <section className="mt-16">
            <div className="rounded-2xl border border-white/[0.08] bg-white/[0.02] p-8 lg:p-10">
              <div className="grid gap-10 lg:grid-cols-2 lg:items-center">
                {/* Price + CTA */}
                <div>
                  <h2 className="text-xl font-bold">Pay as you go</h2>
                  <div className="mt-4">
                    <span className="text-5xl font-bold tracking-tight">$0</span>
                  </div>
                  <div className="mt-7">
                    <Button variant="green" onClick={() => navigate('/login')}>
                      Try for free
                    </Button>
                  </div>
                </div>

                {/* Features */}
                <div>
                  <ul className="space-y-3.5">
                    {FEATURES.map((f) => (
                      <li key={f} className="flex items-start gap-3 text-sm text-foreground">
                        <span className="mt-px flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-white/[0.08] bg-white/[0.04] text-foreground-secondary">
                          <Check className="h-3 w-3" />
                        </span>
                        <span className="leading-snug">{f}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </section>
        </Reveal>

        {/* Enterprise / self-host */}
        <section className="mt-16 text-center text-sm text-foreground-secondary">
          <p>
            Need an enterprise contract or help self-hosting?{' '}
            <button
              type="button"
              onClick={() => navigate('/contact-enterprise')}
              className="text-foreground underline underline-offset-4 transition-colors hover:text-accent-text"
            >
              Get in touch
            </button>
            .
          </p>
        </section>
      </div>
    </div>
  );
}

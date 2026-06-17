import { useNavigate } from 'react-router-dom';
import { Check } from 'lucide-react';
import { Button } from '../../components/ui/button';
import { PricingCalculator } from '../../components/billing/PricingCalculator';

const INCLUDED: string[] = [
  'Continuous dependency + supply-chain scanning',
  'Reachability analysis (8 languages)',
  'Aegis — autonomous security agent',
  'Auto-fix PRs for vulnerabilities',
  'Policy-as-code engine',
  'IaC + container scanning',
  'Malicious package detection',
  'SSO, MFA, IP allowlists, audit logs',
  'Unlimited projects, members, teams',
];

export default function PricingPage() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-background">
      <div className="mx-auto max-w-5xl px-6 py-16 sm:py-24">
        <header className="text-center">
          <p className="text-sm font-medium uppercase tracking-wider text-foreground-secondary">
            Pricing
          </p>
          <h1 className="mt-3 text-4xl font-semibold tracking-tight text-foreground sm:text-5xl">
            $5 free. Then pay as you go.
          </h1>
          <p className="mt-4 text-lg text-foreground-secondary">
            Every feature, every org, no tiers. Prepaid credit covers AI usage and worker time at
            cost-plus pricing.
          </p>
          <div className="mt-8 flex justify-center gap-3">
            <Button variant="green" size="lg" onClick={() => navigate('/login')}>
              Try for free
            </Button>
            <Button variant="outline" size="lg" onClick={() => navigate('/docs')}>
              See the docs
            </Button>
          </div>
        </header>

        <section className="mt-16">
          <h2 className="text-center text-sm font-medium uppercase tracking-wider text-foreground-secondary">
            What's included
          </h2>
          <div className="mt-6 rounded-xl border border-border bg-background-card p-8">
            <ul className="grid gap-3 sm:grid-cols-2">
              {INCLUDED.map((line) => (
                <li key={line} className="flex items-start gap-3 text-sm text-foreground">
                  <Check className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
                  <span>{line}</span>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section className="mt-16">
          <h2 className="text-center text-2xl font-semibold tracking-tight text-foreground">
            Estimate your monthly bill
          </h2>
          <p className="mt-2 text-center text-sm text-foreground-secondary">
            Drag the sliders. Numbers update live.
          </p>
          <div className="mt-8">
            <PricingCalculator />
          </div>
        </section>

        <section className="mt-16 text-center text-sm text-foreground-secondary">
          <p>
            Need an enterprise contract or help self-hosting?{' '}
            <button
              type="button"
              onClick={() => navigate('/contact-enterprise')}
              className="text-foreground underline"
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

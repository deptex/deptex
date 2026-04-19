import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Check, ArrowRight } from 'lucide-react';
import { Button } from '../../components/ui/button';

const tiers = [
  {
    id: 'free',
    name: 'Free',
    description: 'For individual developers and open-source projects.',
    price: { monthly: 0, annual: 0 },
    cta: 'Get Started Free',
    features: [
      '3 projects',
      '5 members',
      '10 syncs / month',
      'Deep reachability analysis',
      'Vulnerability scanning (GHSA, OSV)',
      'Policy-as-code engine',
      'Dependency graph visualization',
      'Platform AI summaries (Gemini)',
      'Community support',
    ],
  },
  {
    id: 'pro',
    name: 'Pro',
    description: 'For growing teams that need full automation and AI.',
    price: { monthly: 25, annual: 250 },
    cta: 'Start Pro',
    popular: true,
    features: [
      '15 projects',
      '20 members',
      '100 syncs / month',
      'Everything in Free',
      'Aegis AI Security Copilot (BYOK)',
      'AI-powered fixes & sprints',
      'Background vulnerability monitoring',
      'Watchtower supply-chain forensics',
      'Configurable sync frequency',
      'All integrations (Slack, Jira, Linear, etc.)',
      '10 teams, 20 notification rules',
      '5 Aegis automations',
    ],
  },
  {
    id: 'team',
    name: 'Team',
    description: 'For organizations with compliance and security needs.',
    price: { monthly: 300, annual: 3000 },
    cta: 'Start Team',
    features: [
      '50 projects',
      'Unlimited members & teams',
      '1,000 syncs / month',
      'Everything in Pro',
      'SSO (SAML)',
      'MFA enforcement',
      'Audit logs',
      'Legal documents (DPA, TIA)',
      'Aegis management console',
      'Unlimited notification rules',
      '50 Aegis automations',
      'Priority support',
    ],
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    description: 'Custom solutions for large organizations.',
    price: { monthly: -1, annual: -1 },
    cta: 'Contact Sales',
    features: [
      'Unlimited everything',
      'Everything in Team',
      'Custom SLA',
      'BYO cloud / self-hosted options',
      'Private Slack channel + CSM',
      'Custom integrations',
      'Advanced incident response',
      'Dedicated support engineer',
    ],
  },
];

export default function PricingPage() {
  const [cycle, setCycle] = useState<'monthly' | 'annual'>('monthly');
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
        {/* Header */}
        <div className="text-center max-w-2xl mx-auto mb-12">
          <h1 className="text-4xl font-bold text-foreground tracking-tight">
            Simple, transparent pricing
          </h1>
          <p className="text-lg text-foreground-secondary mt-4">
            Start free. Upgrade when you need more projects, AI automation, or enterprise compliance.
          </p>
        </div>

        {/* Billing toggle */}
        <div className="flex justify-center mb-10">
          <div className="flex items-center gap-1 rounded-lg border border-border p-1 bg-muted/50">
            <button
              onClick={() => setCycle('monthly')}
              className={`px-4 py-2 text-sm font-medium rounded-md transition-colors ${
                cycle === 'monthly' ? 'bg-background text-foreground shadow-sm' : 'text-foreground-secondary hover:text-foreground'
              }`}
            >
              Monthly
            </button>
            <button
              onClick={() => setCycle('annual')}
              className={`px-4 py-2 text-sm font-medium rounded-md transition-colors ${
                cycle === 'annual' ? 'bg-background text-foreground shadow-sm' : 'text-foreground-secondary hover:text-foreground'
              }`}
            >
              Annual <span className="text-green-500 ml-1 text-xs font-semibold">Save 17%</span>
            </button>
          </div>
        </div>

        {/* Tier Cards */}
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
          {tiers.map((tier) => {
            const isCustom = tier.price.monthly === -1;
            const price = cycle === 'annual' ? tier.price.annual : tier.price.monthly;

            return (
              <div
                key={tier.id}
                className={`relative rounded-xl border p-6 flex flex-col ${
                  tier.popular
                    ? 'border-primary bg-primary/5 ring-1 ring-primary'
                    : 'border-border bg-background-card'
                }`}
              >
                {tier.popular && (
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                    <span className="text-[10px] font-bold uppercase tracking-widest bg-primary text-primary-foreground px-3 py-1 rounded-full">
                      Most Popular
                    </span>
                  </div>
                )}

                <div className="mb-4">
                  <h3 className="text-lg font-semibold text-foreground">{tier.name}</h3>
                  <p className="text-sm text-foreground-secondary mt-1">{tier.description}</p>
                </div>

                <div className="mb-6">
                  {isCustom ? (
                    <span className="text-3xl font-bold text-foreground">Custom</span>
                  ) : price === 0 ? (
                    <span className="text-3xl font-bold text-foreground">$0</span>
                  ) : (
                    <>
                      <span className="text-3xl font-bold text-foreground">
                        ${cycle === 'annual' ? price.toLocaleString() : price}
                      </span>
                      <span className="text-sm text-foreground-secondary ml-1">
                        {cycle === 'annual' ? '/yr' : '/mo'}
                      </span>
                    </>
                  )}
                </div>

                <ul className="space-y-2.5 mb-6 flex-1">
                  {tier.features.map((f) => (
                    <li key={f} className="flex items-start gap-2 text-sm text-foreground-secondary">
                      <Check className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                      {f}
                    </li>
                  ))}
                </ul>

                <Button
                  className="w-full"
                  variant={tier.popular ? 'default' : 'outline'}
                  onClick={() => {
                    if (tier.id === 'enterprise') {
                      window.location.href = 'mailto:sales@deptex.io';
                    } else {
                      navigate('/login');
                    }
                  }}
                >
                  {tier.cta}
                  <ArrowRight className="h-4 w-4 ml-1" />
                </Button>
              </div>
            );
          })}
        </div>

        {/* FAQ Section */}
        <div className="mt-20 max-w-3xl mx-auto">
          <h2 className="text-2xl font-bold text-foreground text-center mb-8">Frequently Asked Questions</h2>
          <div className="space-y-6">
            {[
              {
                q: 'What counts as a sync?',
                a: 'A sync is a full extraction run for one project repository. This includes SBOM generation, vulnerability scanning, reachability analysis, and all post-processing. Both manual and automated (webhook, scheduled) extractions count.',
              },
              {
                q: 'Do I need my own AI API keys?',
                a: 'Platform AI features (summaries, policy assistance, docs Q&A) are free and powered by Google Gemini. For Aegis AI Security Copilot and AI-powered fixes, you need to bring your own API key (OpenAI, Anthropic, or Google).',
              },
              {
                q: 'What happens when I hit a limit?',
                a: "You'll see a warning when approaching limits. Once reached, the specific action is blocked until usage resets (syncs reset each billing period) or you upgrade. Existing data is never deleted.",
              },
              {
                q: 'Can I downgrade my plan?',
                a: "Yes, but you'll need to reduce your usage to fit within the lower tier's limits first (e.g., reduce projects, remove team members). Downgrade takes effect at the end of your current billing period.",
              },
              {
                q: 'Is there a free trial for Pro or Team?',
                a: 'Not currently. The Free plan gives you full access to core features so you can evaluate the platform before upgrading.',
              },
            ].map(({ q, a }) => (
              <div key={q} className="border-b border-border pb-4">
                <h3 className="text-sm font-semibold text-foreground">{q}</h3>
                <p className="text-sm text-foreground-secondary mt-1.5">{a}</p>
              </div>
            ))}
          </div>
        </div>

        {/* CTA */}
        <div className="mt-16 text-center">
          <p className="text-foreground-secondary text-sm mb-4">
            Stripe processes all payments securely. 2.9% + $0.30 per transaction. No hidden fees.
          </p>
        </div>
      </div>
    </div>
  );
}

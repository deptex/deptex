import { useNavigate } from 'react-router-dom';
import { Check } from 'lucide-react';
import { Button } from '../../components/ui/button';

const tiers = [
  {
    id: 'free',
    name: 'Free',
    description: 'For individual developers and open-source projects.',
    price: { monthly: 0, annual: 0 },
    cta: 'Start for free',
    features: [
      '3 projects',
      '5 members',
      '10 syncs / month',
      'Deep reachability analysis',
      'Vulnerability scanning (GHSA, OSV)',
      'Policy-as-code engine',
      'Dependency graph visualization',
      'Platform AI summaries (Gemini)',
      'All integrations',
    ],
  },
  {
    id: 'pro',
    name: 'Pro',
    description: 'For growing teams that need full automation and AI.',
    price: { monthly: 25, annual: 250 },
    cta: 'Upgrade now',
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
    ],
  },
  {
    id: 'team',
    name: 'Team',
    description: 'Compliance and security for growing organizations.',
    price: { monthly: 300, annual: 3000 },
    cta: 'Upgrade now',
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
    ],
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    description: 'Custom solutions for large organizations.',
    price: { monthly: -1, annual: -1 },
    cta: 'Contact us',
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
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 pt-28 pb-20 lg:pt-32 lg:pb-24">
        {/* Header - extra spacing above title */}
        <div className="text-center max-w-2xl mx-auto mb-14">
          <h1 className="text-4xl font-bold text-foreground tracking-tight">
            Simple, transparent pricing
          </h1>
          <p className="text-lg text-foreground-secondary mt-4">
            Start free. Upgrade when you need more projects, AI automation, or enterprise compliance.
          </p>
        </div>

        {/* Tier Cards - Free has no right radius so it connects to Pro; Pro taller; grid overflow-visible so Pro top border isn't clipped */}
        <div className="overflow-visible pt-[1px] -mt-[1px]">
          <div className="grid grid-cols-1 md:grid-cols-[1fr_1.35fr_1fr_1fr] gap-0 md:items-center">
            {tiers.map((tier, index) => {
              const isCustom = tier.price.monthly === -1;
              const price = tier.price.monthly;
              const isPro = tier.popular;
              const isFirst = index === 0;
              const isLast = index === tiers.length - 1;
              const mobileRounded = isFirst
                ? 'rounded-t-2xl md:rounded-l-2xl md:rounded-tr-none md:rounded-br-none'
                : isLast
                  ? 'rounded-b-2xl md:rounded-r-2xl md:rounded-tl-none md:rounded-bl-none'
                  : index === 2
                    ? 'rounded-none border-t-0 md:border-t md:rounded-none'
                    : 'rounded-none border-t-0 md:rounded-2xl';

              return (
                <div
                  key={tier.id}
                  className={`relative flex flex-col min-w-0 border border-border bg-background-card
                    ${mobileRounded}
                    ${index > 0 ? 'md:-ml-px' : ''}
                    ${isPro
                      ? 'md:py-10 md:px-7 md:min-h-[620px] md:z-10 md:ring-2 md:ring-primary'
                      : 'py-6 px-5 md:px-6 md:h-[580px]'
                    }
                  `}
                >
                <div className={isPro ? 'mb-5' : 'mb-4'}>
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className={`font-semibold text-foreground ${isPro ? 'text-xl' : 'text-lg'}`}>{tier.name}</h3>
                    {isPro && (
                      <span className="text-[10px] font-bold uppercase tracking-widest bg-primary text-primary-foreground px-2.5 py-1 rounded-full border border-primary-foreground/20 hover:border-primary-foreground/40 transition-colors">
                        Most Popular
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-foreground-secondary mt-1.5">{tier.description}</p>
                </div>

                <Button
                  className={`w-full mb-5 bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 font-semibold text-sm rounded-lg ${isPro ? 'mt-3' : ''}`}
                  onClick={() => {
                    if (tier.id === 'enterprise') {
                      navigate('/contact-enterprise');
                    } else {
                      navigate('/login');
                    }
                  }}
                >
                  {tier.cta}
                </Button>

                <div className={isPro ? 'mb-6' : 'mb-5'}>
                  {isCustom ? (
                    <span className={`font-bold text-foreground ${isPro ? 'text-3xl' : 'text-2xl'}`}>Custom</span>
                  ) : price === 0 ? (
                    <span className={`font-bold text-foreground ${isPro ? 'text-3xl' : 'text-2xl'}`}>$0</span>
                  ) : (
                    <>
                      <span className={`font-bold text-foreground ${isPro ? 'text-3xl' : 'text-2xl'}`}>
                        ${price.toLocaleString()}
                      </span>
                      <span className="text-sm text-foreground-secondary ml-1">/mo</span>
                    </>
                  )}
                </div>

                <ul className={`space-y-2.5 flex-1 ${isPro ? 'space-y-3' : ''}`}>
                  {tier.features.map((f) => (
                    <li key={f} className="flex items-start gap-2.5 text-sm text-foreground-secondary">
                      <Check className="h-4 w-4 text-primary mt-0.5 flex-shrink-0" />
                      {f}
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
          </div>
        </div>
      </div>
    </div>
  );
}

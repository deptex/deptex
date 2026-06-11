/**
 * §3.12 Works with your stack — one quiet band, three labeled rows.
 * Capability facts wearing logo clothing: logos render white (full
 * opacity, never gray-shrunk), ecosystem names as plain text, hairlines
 * above and below. No motion by design.
 */
import { ReactNode } from "react";

interface StackItem {
  name: string;
  /** Path under public/. Items without a logo render as text names. */
  logo?: string;
}

const GIT_ITEMS: StackItem[] = [
  { name: "GitHub", logo: "/images/integrations/github.png" },
  { name: "GitLab", logo: "/images/integrations/gitlab.png" },
  { name: "Bitbucket", logo: "/images/integrations/bitbucket.png" },
];

const ECOSYSTEMS = [
  "npm",
  "PyPI",
  "Maven",
  "Go",
  "Cargo",
  "RubyGems",
  "Composer",
  "NuGet",
];

const ALERT_ITEMS: StackItem[] = [
  { name: "Slack", logo: "/images/integrations/slack.png" },
  { name: "Discord", logo: "/images/integrations/discord.png" },
  { name: "Jira", logo: "/images/integrations/jira.png" },
  { name: "Linear", logo: "/images/integrations/linear.png" },
  { name: "Asana", logo: "/images/integrations/asana.png" },
  { name: "PagerDuty", logo: "/images/integrations/pagerduty.png" },
  { name: "email" },
  { name: "signed webhooks" },
];

function LogoItem({ item }: { item: StackItem }) {
  return (
    <span className="inline-flex items-center gap-2">
      {item.logo && (
        <img
          src={item.logo}
          alt=""
          aria-hidden
          className="h-5 w-auto brightness-0 invert"
        />
      )}
      <span className="text-sm text-foreground">{item.name}</span>
    </span>
  );
}

function StackRow({
  eyebrow,
  caption,
  children,
}: {
  eyebrow: string;
  caption: string;
  children: ReactNode;
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-[140px_1fr] sm:gap-6">
      <span className="pt-0.5 font-mono text-xs uppercase tracking-wider text-foreground-secondary">
        {eyebrow}
      </span>
      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-3">{children}</div>
        <p className="text-sm leading-relaxed text-foreground-secondary">{caption}</p>
      </div>
    </div>
  );
}

export default function StackBand() {
  return (
    <section className="w-full border-y border-white/[0.08]">
      <div className="mx-auto max-w-[1200px] px-6 py-16">
        <div className="flex flex-col gap-10">
          <StackRow
            eyebrow="GIT"
            caption="PR checks and sticky comments on all three; merge blocking on GitHub and GitLab."
          >
            {GIT_ITEMS.map((item) => (
              <LogoItem key={item.name} item={item} />
            ))}
          </StackRow>

          <StackRow eyebrow="ECOSYSTEMS" caption="dependency scanning — npm to NuGet">
            {ECOSYSTEMS.map((name) => (
              <span key={name} className="text-sm text-foreground">
                {name}
              </span>
            ))}
          </StackRow>

          <StackRow
            eyebrow="ALERTS"
            caption="Routes alerts and creates tickets — Slack to PagerDuty."
          >
            {ALERT_ITEMS.map((item) => (
              <LogoItem key={item.name} item={item} />
            ))}
          </StackRow>
        </div>
      </div>
    </section>
  );
}

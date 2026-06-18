/**
 * §3.8 Breadth wall — breadth as fact, after depth.
 *
 * Reworked 2026-06-16 (founder, Aikido /code-tabs reference): the dry 3×3 text
 * grid became a tabbed feature display. We have ONE platform (not four products
 * like Aikido), so the tabs group the categories by where the vuln lives —
 * Code / Dependencies / Infrastructure.
 *
 * Trimmed 2026-06-16 (founder): dropped Reachability (it owns the Verified
 * section above — featuring it once beats listing it twice) and SBOM & VEX (an
 * export, not a scanner). Engine vendor names removed everywhere — naming the
 * OSS we orchestrate (TruffleHog/Semgrep/…) reads as plumbing, not product.
 */
import { useState } from "react";
import {
  Braces,
  Container,
  KeyRound,
  Layers,
  Package,
  Radar,
  ShieldAlert,
  type LucideIcon,
} from "lucide-react";
import { Reveal } from "./primitives";

interface Feature {
  Icon: LucideIcon;
  name: string;
  sentence: string;
}

const TABS: { id: string; label: string; features: Feature[] }[] = [
  {
    id: "app",
    label: "Code & dependencies",
    features: [
      {
        Icon: Braces,
        name: "SAST",
        sentence:
          "Static analysis across your whole workspace, deduped and CWE-scored, so risks are caught before they merge.",
      },
      {
        Icon: KeyRound,
        name: "Secrets",
        sentence:
          "Leaked keys and tokens, caught and live-verified — a working credential outscores a dormant one.",
      },
      {
        Icon: Package,
        name: "Dependency scanning",
        sentence:
          "A full SBOM every scan, matched against known vulnerabilities so no ecosystem goes blind.",
      },
      {
        Icon: ShieldAlert,
        name: "Malicious packages",
        sentence:
          "Malicious-package feeds, behavioral heuristics, and a capability fingerprint for every package you pull in.",
      },
    ],
  },
  {
    id: "infrastructure",
    label: "Infrastructure",
    features: [
      {
        Icon: Layers,
        name: "Infrastructure as Code",
        sentence:
          "Misconfigurations across Terraform, Kubernetes, Helm, CloudFormation, Dockerfile and more.",
      },
      {
        Icon: Container,
        name: "Containers",
        sentence:
          "Image CVEs, base-image upgrade advice, and a bridge linking OS-package CVEs to the code that loads them.",
      },
      {
        Icon: Radar,
        name: "DAST",
        sentence:
          "Your running app gets actively attacked, guided by an OpenAPI spec synthesized from your detected routes.",
      },
    ],
  },
];

export default function BreadthWall() {
  const [active, setActive] = useState(TABS[0].id);
  const activeTab = TABS.find((t) => t.id === active) ?? TABS[0];

  return (
    <section className="w-full border-t border-white/[0.08]">
      <div className="mx-auto max-w-[1200px] px-6 py-24">
        <Reveal>
          <h2 className="text-[32px] font-semibold leading-[1.1] tracking-[-0.02em] text-foreground sm:text-[40px]">
            One platform, every layer of your stack.
          </h2>
        </Reveal>

        {/* tabs */}
        <Reveal delayMs={60}>
          <div
            role="tablist"
            aria-label="Scanner categories"
            className="mt-10 flex gap-8 border-b border-border"
          >
            {TABS.map((t) => {
              const isActive = t.id === active;
              return (
                <button
                  key={t.id}
                  type="button"
                  role="tab"
                  aria-selected={isActive}
                  onClick={() => setActive(t.id)}
                  className={`-mb-px border-b-2 pb-3 text-[15px] font-medium transition-colors ${
                    isActive
                      ? "border-accent-text text-foreground"
                      : "border-transparent text-foreground-secondary hover:text-foreground"
                  }`}
                >
                  {t.label}
                </button>
              );
            })}
          </div>
        </Reveal>

        {/* active tab's features */}
        <div
          key={activeTab.id}
          className="tab-fade mt-10 grid grid-cols-1 gap-x-10 gap-y-12 sm:grid-cols-2 lg:grid-cols-3"
        >
          {activeTab.features.map(({ Icon, name, sentence }) => (
            <div key={name} className="flex flex-col">
              <Icon className="h-5 w-5 text-foreground-secondary" aria-hidden />
              <h3 className="mt-4 text-[15px] font-medium text-foreground">{name}</h3>
              <p className="mt-2 text-sm leading-relaxed text-foreground-secondary">
                {sentence}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

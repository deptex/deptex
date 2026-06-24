/**
 * §3.8 Breadth wall — breadth as fact, after depth.
 *
 * Reworked 2026-06-19 (founder): the tabbed grid hid half the categories behind
 * a tab. Replaced with an editorial "label on the left, its scanners on the
 * right" layout that shows EVERY category at once, grouped by where the risk
 * lives — Dependencies / Code / Infrastructure (deps lead: the most
 * differentiated layer, reachability-scored).
 *
 * Trimmed earlier (founder): dropped Reachability (it owns the Verified section
 * above — featuring it once beats listing it twice) and SBOM & VEX (an export,
 * not a scanner). Engine vendor names removed everywhere — naming the OSS we
 * orchestrate (TruffleHog/Semgrep/…) reads as plumbing, not product.
 */
import {
  Braces,
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

const GROUPS: { label: string; tagline: string; features: Feature[] }[] = [
  {
    label: "Dependencies",
    tagline: "What you import",
    features: [
      {
        Icon: Package,
        name: "CVE scanning",
        sentence:
          "Dependency CVEs scored by whether they're actually reachable in your codebase — not a generic CVSS rating.",
      },
      {
        Icon: ShieldAlert,
        name: "Malicious packages",
        sentence:
          "Known-malicious feeds plus behavioral and capability fingerprinting on everything you install.",
      },
    ],
  },
  {
    label: "Code",
    tagline: "What you write",
    features: [
      {
        Icon: Braces,
        name: "SAST",
        sentence:
          "Deduped, CWE-scored static analysis across your whole codebase — caught before it merges.",
      },
      {
        Icon: KeyRound,
        name: "Secrets",
        sentence:
          "Hardcoded keys and tokens, live-verified so a working credential outranks a dead one.",
      },
    ],
  },
  {
    label: "Infrastructure",
    tagline: "What you deploy",
    features: [
      {
        Icon: Layers,
        name: "IaC & containers",
        sentence:
          "Misconfigs across Terraform, Kubernetes and Dockerfiles, plus image CVEs and base-image fixes.",
      },
      {
        Icon: Radar,
        name: "DAST",
        sentence:
          "Your running app, actively attacked along an OpenAPI spec synthesized from your routes.",
      },
    ],
  },
];

export default function BreadthWall() {
  return (
    <section className="w-full border-t border-white/[0.08]">
      <div className="mx-auto max-w-[1200px] px-6 py-24">
        <Reveal>
          <h2 className="text-[32px] font-semibold leading-[1.1] tracking-[-0.02em] text-foreground sm:text-[40px]">
            One platform, every layer of your stack.
          </h2>
        </Reveal>

        {/* category groups — label on the left, its scanners on the right */}
        <div className="mt-14">
          {GROUPS.map((group, gi) => (
            <Reveal key={group.label} delayMs={gi * 70}>
              <div
                className={`grid grid-cols-1 gap-x-12 gap-y-8 py-12 lg:grid-cols-[200px_1fr] ${
                  gi > 0 ? "border-t border-white/[0.06]" : ""
                }`}
              >
                <div>
                  <h3 className="text-lg font-semibold tracking-[-0.01em] text-foreground">
                    {group.label}
                  </h3>
                  <p className="mt-1.5 text-sm text-foreground-secondary">
                    {group.tagline}
                  </p>
                </div>

                <div className="grid grid-cols-1 gap-x-10 gap-y-10 sm:grid-cols-2">
                  {group.features.map(({ Icon, name, sentence }) => (
                    <div key={name} className="group flex flex-col">
                      <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-white/[0.08] bg-white/[0.03] transition-colors group-hover:border-white/[0.18]">
                        <Icon
                          className="h-[18px] w-[18px] text-foreground-secondary transition-colors group-hover:text-foreground"
                          aria-hidden
                        />
                      </div>
                      <h4 className="mt-4 text-[15px] font-medium text-foreground">
                        {name}
                      </h4>
                      <p className="mt-2 text-sm leading-relaxed text-foreground-secondary">
                        {sentence}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

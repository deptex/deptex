/**
 * Proof-stat band — the page's logo-wall substitute (2026-06-16).
 *
 * Pre-launch, we have no customer logos to put in the slot every competitor
 * fills directly under the hero. The field's number-forward camp (Endor,
 * Socket, Semgrep) instead asserts its noise-reduction number punchily up top
 * and parks the methodology deep. Layout follows Aikido's trust-bar pattern
 * (founder ref): a single centered stat PILL, then a centered ecosystem logo
 * wall standing in for the customer logos we don't have yet. The marks show
 * the breadth that a bare "8 ecosystems" only states.
 *
 * Cut 2026-06-16 (founder): the engine-internals stat row (languages /
 * detectors / taint models / scanner categories) — inside-baseball, the
 * "hand-authored taint models" caption was factually wrong (we generate
 * source/sink rules with AI, per-CVE), and category breadth is BreadthWall's
 * job. Long supporting paragraph trimmed to the pill.
 *
 * The headline figure is the same 79.6% as the deep benchmark and carries the
 * same caveat: placeholder until the fresh corpus re-run (asset A9). The dashed
 * "placeholder" disclaimer stays in the deep methodology block — the receipts
 * are one scroll away via "See the corpus".
 */
import {
  SiApachemaven,
  SiGo,
  SiNpm,
  SiNuget,
  SiPackagist,
  SiPypi,
  SiRubygems,
  SiRust,
} from "@icons-pack/react-simple-icons";
import { Reveal } from "./primitives";

const ECOSYSTEMS = [
  { name: "npm", Icon: SiNpm },
  { name: "PyPI", Icon: SiPypi },
  { name: "Maven", Icon: SiApachemaven },
  { name: "Go", Icon: SiGo },
  { name: "RubyGems", Icon: SiRubygems },
  { name: "Cargo", Icon: SiRust },
  { name: "Packagist", Icon: SiPackagist },
  { name: "NuGet", Icon: SiNuget },
];

export default function ProofStatBand() {
  return (
    <section className="w-full">
      <div className="mx-auto max-w-[1200px] px-6 py-16 sm:py-20">
        {/* Hero stat — one big line, number + label at the same scale so it
            reads as a single epic statement. Precise 79.6% kept on purpose:
            the decimal is the credibility signal for a "publish the corpus"
            brand. */}
        <Reveal>
          <div className="flex flex-wrap items-baseline justify-center gap-x-4 text-center text-[40px] font-semibold leading-tight tracking-[-0.02em] sm:text-[56px]">
            <span className="font-mono tabular-nums text-accent-text">79.6%</span>
            <span className="text-foreground">noise reduction</span>
          </div>
        </Reveal>

        {/* Ecosystem logo wall — native dependency scanning, shown not stated */}
        <Reveal delayMs={80} className="mt-14">
          <div className="flex flex-wrap items-center justify-center gap-x-12 gap-y-7">
            {ECOSYSTEMS.map(({ name, Icon }) => (
              <div
                key={name}
                className="flex items-center gap-2.5 text-foreground-secondary/70 transition-colors hover:text-foreground"
              >
                <Icon size={26} />
                <span className="text-[15px] font-medium">{name}</span>
              </div>
            ))}
          </div>
        </Reveal>
      </div>
    </section>
  );
}

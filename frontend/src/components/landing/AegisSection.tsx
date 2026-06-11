/**
 * §3.9 Aegis — proof becomes a pull request (landing-page-redesign.plan.md).
 * Left: the A4 recording slot (chat → plan → approval → draft PR, ≈25s,
 * click-to-play `<video preload="none">` + PlanCard poster when the asset
 * lands) inside the page's SECOND and last glow-green frame.
 * Right: the five code-verified guardrails as a left-ruled vertical list.
 * Motion: reveal pattern only — the recording itself is click-to-play, never
 * autoplay. Do NOT claim: autopilot, sprints, PR review, Slack parity, "50+ tools".
 */
import { PlaceholderCanvas, Reveal, SpecimenFrame } from "./primitives";

const GUARDRAILS: { title: string; line: string }[] = [
  {
    title: "Draft PRs, always.",
    line: "A human merges every fix.",
  },
  {
    title: "Hard caps on every run.",
    line: "500 lines, 30 tool calls, 2 repair cycles, 300-second budget.",
  },
  {
    title: "Runs your tests.",
    line: "The repo's own suite, with repair cycles until green — or the run is abandoned and you're told why.",
  },
  {
    title: "Signed approvals.",
    line: "Every approval is an HMAC-signed token — no ambient authority.",
  },
  {
    title: "Honest refusals.",
    line: "No safe fix exists? You get the reason, not a guess.",
  },
];

const SUB_PARAGRAPH =
  "Aegis investigates with 24 tools, shows you every tool call it ran, and plans before it touches code. Once you approve, a sandboxed worker writes the patch, runs your repo's own test suite, and opens the PR. JavaScript, TypeScript, Python and Go today.";

export default function AegisSection() {
  return (
    <section id="aegis" className="w-full">
      <div className="mx-auto max-w-[1200px] px-6 py-28">
        <Reveal>
          <h2 className="text-3xl font-semibold leading-tight tracking-[-0.02em] text-foreground md:text-4xl">
            The fix ships as a draft PR. You merge it.
          </h2>
        </Reveal>

        <div className="mt-12 grid grid-cols-1 items-start gap-10 lg:grid-cols-[3fr_2fr]">
          {/* Recording slot — A4. Click-to-play video replaces the placeholder. */}
          <Reveal>
            <SpecimenFrame glow>
              <PlaceholderCanvas
                assetId="A4"
                description="Aegis recording: chat question → tool calls → plan card → approve → FixStatusCard → real GitHub draft PR. Trimmed to ≈25s with a visible elapsed-time readout; ships click-to-play, poster = the PlanCard frame."
                aspect="16/10"
                className="!rounded-none !border-0"
              />
            </SpecimenFrame>
            <p className="mt-3 font-mono text-xs text-foreground-secondary">
              Real run on our dogfood corpus, trimmed. Elapsed time on screen.
            </p>
          </Reveal>

          {/* Guardrails — vertical list with 2px left rules, not icon cards. */}
          <Reveal delayMs={80}>
            <h3 className="text-sm font-medium text-foreground">Guardrails</h3>
            <ul className="mt-5 flex flex-col gap-5">
              {GUARDRAILS.map((g) => (
                <li key={g.title} className="border-l-2 border-[#262626] pl-4">
                  <p className="text-[15px] font-medium leading-snug text-foreground">
                    {g.title}
                  </p>
                  <p className="mt-1 text-sm leading-relaxed text-foreground-secondary">
                    {g.line}
                  </p>
                </li>
              ))}
            </ul>
          </Reveal>
        </div>

        <Reveal delayMs={120}>
          <p className="mt-12 max-w-3xl text-[15px] leading-relaxed text-foreground-secondary">
            {SUB_PARAGRAPH}
          </p>
        </Reveal>
      </div>
    </section>
  );
}

/**
 * AI Security Agent — dedicated product page. Same template as Dependency
 * scanning (video hero → real-component showcase → capability grid → CTA);
 * the showcase is the real Aegis chat.
 */
import {
  ListChecks,
  MessageSquare,
  ClipboardCheck,
  Calendar,
  GitPullRequest,
  Key,
} from "lucide-react";
import { AegisChatCard } from "../AegisChatCard";
import {
  FeatureVideoHero,
  Showcase,
  CapabilityGrid,
  FeatureFinalCTA,
  type Capability,
} from "./sections";

const CAPS: Capability[] = [
  { Icon: ListChecks, title: "Plan with AI", body: "Multi-step plans you can approve, revise, or reject before anything runs." },
  { Icon: MessageSquare, title: "Chat & command center", body: "Streaming answers and persistent threads for your vulnerability and policy questions." },
  { Icon: ClipboardCheck, title: "Tasks & approvals", body: "Human-in-the-loop for high-impact actions — approve every dangerous step from the console." },
  { Icon: Calendar, title: "Automations & memory", body: "Cron schedules, event triggers, and semantic memory so context persists between runs." },
  { Icon: GitPullRequest, title: "Guardrails", body: "Draft PRs always, hard caps on every run, and honest refusals when no safe fix exists." },
  { Icon: Key, title: "Models & cost control", body: "Pick which models Aegis can use. Usage logging and prepaid spend controls per org." },
];

export default function AiSecurityAgentPage() {
  return (
    <div className="bg-background text-foreground">
      <FeatureVideoHero
        eyebrow="AI Security Agent"
        headline="Your AI security engineer."
        sub="Aegis investigates findings, plans the fix, writes the patch, runs your tests, and opens a pull request — and nothing merges without you."
      />

      <Showcase
        title="Ask about any finding. Get a PR back."
        body="Aegis traces reachability, explains what's exploitable and what isn't, then ships the fix as a draft pull request you review. Chat with it here."
      >
        <AegisChatCard />
      </Showcase>

      <CapabilityGrid title="Everything in the agent." items={CAPS} />

      <FeatureFinalCTA
        title="Put an AI security engineer on every finding."
        sub="Connect a repo and let Aegis open its first fix PR."
      />
    </div>
  );
}

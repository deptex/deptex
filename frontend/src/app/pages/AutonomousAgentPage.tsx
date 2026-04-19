import { useState } from "react";
import { Link } from "react-router-dom";
import { Button } from "../../components/ui/button";
import { BookOpen, ChevronRight } from "lucide-react";

function ImageWithFallback({
  src,
  alt,
  className = "",
  fallbackLabel,
}: {
  src: string;
  alt: string;
  className?: string;
  fallbackLabel?: string;
}) {
  const [failed, setFailed] = useState(false);
  if (failed) {
    return (
      <div
        className={`rounded-lg border border-border/50 bg-background-card overflow-hidden aspect-video flex items-center justify-center ${className}`}
        aria-label={alt}
      >
        <span className="text-sm text-foreground-secondary/60">
          {fallbackLabel || `Add image: ${src.split("/").pop()}`}
        </span>
      </div>
    );
  }
  return (
    <img
      src={src}
      alt={alt}
      className={`rounded-lg border border-border/50 w-full object-cover aspect-video ${className}`}
      onError={() => setFailed(true)}
    />
  );
}

const PROVIDER_LOGOS = [
  { src: "/images/providers/openai.png", name: "OpenAI" },
  { src: "/images/providers/anthropic.png", name: "Anthropic" },
  { src: "/images/providers/google.png", name: "Google" },
];

function SectionText({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-xl border border-border/50 bg-background-card/90 p-6 lg:p-8 aegis-text-glow">
      <h2 className="text-2xl md:text-3xl font-semibold text-primary">
        {title}
      </h2>
      <div className="section-heading-line" />
      <div className="text-foreground-secondary leading-relaxed space-y-4">
        {children}
      </div>
    </div>
  );
}

export default function AutonomousAgentPage() {
  return (
    <div className="min-h-screen bg-background">
      {/* Hero */}
      <section className="container mx-auto px-4 py-20 lg:py-32">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <div>
              <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-4 text-foreground">
                AI Security Agent
              </h1>
              <p className="text-xl text-primary/90 mb-2 leading-relaxed font-medium">
                Your AI security engineer.
              </p>
              <p className="text-lg text-foreground-secondary mb-8 leading-relaxed">
                Chat in natural language, run tasks and automations, and get PR reviews and Slack support—all with your own AI provider and full control.
              </p>
              <div className="flex flex-wrap items-center gap-3">
                <Button
                  asChild
                  className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 font-semibold text-sm px-4 py-2 rounded-lg shadow-lg shadow-primary/20"
                >
                  <Link to="/login">Get started</Link>
                </Button>
                <Button
                  asChild
                  className="bg-primary/10 text-primary hover:bg-primary/20 border border-primary/30 font-semibold text-sm px-4 py-2 rounded-lg"
                >
                  <Link to="/get-demo" className="inline-flex items-center gap-1.5">
                    Book a demo
                    <ChevronRight className="h-4 w-4" />
                  </Link>
                </Button>
                <Button
                  asChild
                  variant="ghost"
                  size="sm"
                  className="text-foreground-secondary hover:text-foreground hover:bg-background-subtle font-normal text-sm px-3 py-2"
                >
                  <Link to="/docs/aegis">
                    <BookOpen className="h-4 w-4 mr-1.5" />
                    Docs
                  </Link>
                </Button>
              </div>
            </div>
            <div>
              <ImageWithFallback
                src="/images/ai-security-agent/hero.png"
                alt="Aegis command center"
                fallbackLabel="Add hero.png"
              />
            </div>
          </div>
        </div>
      </section>

      <div className="border-t border-border/50" />

      {/* Chat and command center – text left, image right */}
      <section className="container mx-auto px-4 py-16 lg:py-24">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 lg:gap-16 items-center">
            <SectionText title="Chat and command center">
              <p>
                Talk to your security posture in plain language. Ask for vulnerability summaries, license violations, or which projects use a given dependency across the org. Aegis streams answers and can call 50+ tools—projects, vulnerabilities, policies, compliance, reporting—in a single conversation.
              </p>
              <p>
                Conversations live in threads so you can switch context and pick up later. Open Aegis from the org sidebar or from the Security tab with project or vulnerability context attached.
              </p>
            </SectionText>
            <div>
              <ImageWithFallback
                src="/images/ai-security-agent/chat.png"
                alt="Aegis chat UI with thread list and streaming response"
                fallbackLabel="Add chat.png"
              />
            </div>
          </div>
        </div>
      </section>

      {/* Tasks and approvals – image left, text right */}
      <section className="container mx-auto px-4 py-16 lg:py-24">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 lg:gap-16 items-center">
            <div className="order-2 lg:order-1">
              <ImageWithFallback
                src="/images/ai-security-agent/tasks.png"
                alt="Aegis task list and approval request UI"
                fallbackLabel="Add tasks.png"
              />
            </div>
            <div className="order-1 lg:order-2">
              <SectionText title="Tasks and approvals">
                <p>
                  For high-impact actions, Aegis creates approval requests. Authorized users approve or reject from the Management Console or in the Aegis UI. Long-running work—like security sprints with multiple fix steps—runs as tasks with steps you can pause, cancel, or approve.
                </p>
                <p>
                  Human-in-the-loop keeps you in control while the agent handles the heavy lifting.
                </p>
              </SectionText>
            </div>
          </div>
        </div>
      </section>

      {/* Automations and memory – text left, image right */}
      <section className="container mx-auto px-4 py-16 lg:py-24">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 lg:gap-16 items-center">
            <SectionText title="Automations and memory">
              <p>
                Schedule automations to run on a cron—daily briefings, weekly digests, monthly compliance reports. Each run uses the same tool set and logs results. Optional event triggers fire on security or policy events.
              </p>
              <p>
                Aegis also stores semantic memory so important decisions and context persist across sessions. Manage entries from the Management Console.
              </p>
            </SectionText>
            <div>
              <ImageWithFallback
                src="/images/ai-security-agent/automations.png"
                alt="Aegis Management Console – Automations and Memory tabs"
                fallbackLabel="Add automations.png"
              />
            </div>
          </div>
        </div>
      </section>

      {/* Slack and PR review – text left, image right (single back-and-forth) */}
      <section className="container mx-auto px-4 py-16 lg:py-24">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 lg:gap-16 items-center">
            <SectionText title="Slack and PR review">
              <p>
                Connect your Slack workspace and @mention Aegis in any channel. The same agent answers there; approval buttons in Slack let you approve or reject actions without leaving chat.
              </p>
              <p>
                Aegis can review pull requests for security risk and policy, then post a structured comment on the PR. Configure auto-review on open or run on demand.
              </p>
            </SectionText>
            <div>
              <ImageWithFallback
                src="/images/ai-security-agent/slack.png"
                alt="Slack thread with Aegis response"
                fallbackLabel="Add slack.png"
              />
            </div>
          </div>
        </div>
      </section>

      {/* BYOK and control – text left, provider logos right (back-and-forth) */}
      <section className="container mx-auto px-4 py-16 lg:py-24">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 lg:gap-16 items-center">
            <SectionText title="BYOK and control">
              <p>
                Aegis uses your organization’s AI provider. API keys are encrypted at rest. Usage is logged for cost and audit; set monthly caps and per-task budgets in the Management Console.
              </p>
              <p>
                The console also lets you tune operating mode, tool permissions, and view active work, automations, memory, usage analytics, and the full audit log.
              </p>
            </SectionText>
            <div className="rounded-xl border border-border/50 bg-background-card/90 p-6 lg:p-8 aegis-text-glow flex flex-col justify-center items-center lg:items-start">
              <p className="text-sm font-medium text-foreground mb-1">Your provider</p>
              <p className="text-xs text-foreground-secondary mb-6">OpenAI, Anthropic, or Google — your keys, encrypted at rest.</p>
              <div className="flex flex-wrap items-center justify-center lg:justify-start gap-8">
                {PROVIDER_LOGOS.map(({ src, name }) => (
                  <ProviderLogo key={name} src={src} name={name} />
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Bottom CTA */}
      <section className="container mx-auto px-4 py-16 lg:py-20">
        <div className="max-w-3xl mx-auto text-center">
          <p className="text-lg text-foreground-secondary mb-6">
            Ready to put an AI security engineer to work?
          </p>
          <div className="flex flex-wrap justify-center gap-3">
            <Button
              asChild
              className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 font-semibold text-sm px-5 py-2.5 rounded-lg shadow-lg shadow-primary/20"
            >
              <Link to="/get-demo" className="inline-flex items-center gap-1.5">
                Book a demo
                <ChevronRight className="h-4 w-4" />
              </Link>
            </Button>
            <Button
              asChild
              variant="outline"
              className="border-border hover:bg-background-subtle text-sm px-5 py-2.5 rounded-lg"
            >
              <Link to="/login">Get started</Link>
            </Button>
          </div>
        </div>
      </section>
    </div>
  );
}

function ProviderLogo({ src, name }: { src: string; name: string }) {
  const [failed, setFailed] = useState(false);
  if (failed) {
    return (
      <span className="text-sm font-medium text-foreground-secondary">{name}</span>
    );
  }
  return (
    <img
      src={src}
      alt={name}
      className="h-8 w-auto object-contain opacity-90 hover:opacity-100 transition-opacity"
      onError={() => setFailed(true)}
    />
  );
}

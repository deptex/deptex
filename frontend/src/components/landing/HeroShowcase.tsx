/**
 * HeroShowcase — the hero's big visual (founder 2026-06-16, Aikido reference).
 *
 * Replaces the product film with a TABBED, INTERACTIVE product showcase: an
 * app-window frame whose contents switch between Overview / Findings / Aegis —
 * the real org-sidebar surfaces (OrgSidebar.tsx) — each a mini, real, scrollable
 * slice of the actual product (not a recording). This shows off the key surfaces
 * as live DOM, kills the dummy-video problem, and needs no asset pipeline.
 * Visuals/data mirror the real app (org graph + multiplayer cursors, the
 * findings table + reachability verdicts, the Aegis chat) on the real
 * dogfood-express scan (lodash CVE-2021-23337 reachable; 141 → 28 after triage).
 */
import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Circle,
  ListChecks,
  Lock,
  MoreVertical,
  PanelRight,
  Plus,
  RotateCw,
} from "lucide-react";
import { Link } from "react-router-dom";
import HeroOverviewGraph from "./HeroOverviewGraph";
import HeroFindingsTable from "./HeroFindingsTable";
import { Button } from "../ui/button";
import { ChatInput } from "../aegis/ChatInput";
import { ModelPicker } from "../aegis/ModelPicker";
import { ToolCallGroup, type ToolCallEntry } from "../aegis/ToolCallCard";
import type { AIModelMetadata } from "../../lib/api";

// Findings leads — it proves the headline ("cut the noise") at first glance.
// (Deviates from the real sidebar order Overview/Findings/Aegis on purpose.)
const TABS: { id: string; label: string }[] = [
  { id: "findings", label: "Findings" },
  { id: "overview", label: "Overview" },
  { id: "aegis", label: "Aegis" },
];

/* ---------------- Aegis: the chat (interactive preview) ----------------
 * Reuses the REAL Aegis chat components fed mock data — NOT a reinvention:
 *   • tool calls  → <ToolCallGroup> (the actual aegis/ToolCallCard component)
 *   • composer    → <ChatInput> + <ModelPicker> (the actual aegis composer; the
 *                   model pill is the real one, Claude Opus 4.8 + Anthropic logo)
 *   • message bubbles → copied verbatim from aegis/MessageBubble markup
 *   • plan sidebar → copied verbatim from aegis/FixPanel's detail body
 *     (awaiting-approval state: title + ModelPicker + Start, then Plan / To-dos /
 *     Verification cards) inside aegis/FixPanelHost's collapsible shell.
 * Typing + send, the sidebar Start button, all funnel to a sign-up gate. */

// Mock model catalog (real AIModelMetadata shape) — feeds the real ModelPicker.
const MODELS: AIModelMetadata[] = [
  { id: "claude-opus-4-8", provider: "anthropic", label: "Claude Opus 4.8", description: "Anthropic's most capable model — best for security reasoning.", contextWindow: 1_000_000, inputPricePer1M: 5, outputPricePer1M: 25, releasedAt: "2026-01-01" },
  { id: "gpt-5.1", provider: "openai", label: "GPT-5.1", description: "OpenAI's flagship reasoning model.", contextWindow: 400_000, inputPricePer1M: 4, outputPricePer1M: 16, releasedAt: "2025-11-01" },
  { id: "gemini-2.5-pro", provider: "google", label: "Gemini 2.5 Pro", description: "Google's long-context reasoning model.", contextWindow: 1_000_000, inputPricePer1M: 2, outputPricePer1M: 10, releasedAt: "2025-09-01" },
];

// Real ToolCallGroup input shape — renders the actual collapsible "N tool calls" pill.
const TOOLS: ToolCallEntry[] = [
  { toolName: "list_project_findings", state: "done" },
  { toolName: "get_finding_detail", state: "done" },
  { toolName: "analyze_reachability", state: "done" },
  { toolName: "request_fix", state: "done" },
];

// Mock plan (matches FixPlan's shape) for the copied FixPanel detail body.
const PLAN = {
  summary: "Fix payments-svc security findings",
  description:
    "Rotate the leaked Stripe key, patch the reachable dependency and the SQL-injection sink, and pin the runtime image — then verify and open a draft PR.",
  todos: [
    { title: "Rotate the exposed Stripe live key and move it into a secret manager", detail: "src/config/credentials.py:24 — replace the hardcoded sk_live_… with an env lookup." },
    { title: "Upgrade cryptography 3.4.7 → 42.0.4", detail: "Closes CVE-2023-50782; the vulnerable cipher path is reachable from the token handler." },
    { title: "Parameterize the user-controlled SQL in the charges handler", detail: "app/routes/charges.py:88 — switch the f-string query to bound parameters." },
    { title: "Pin the Python base image 3.5 → 3.12", detail: "Dockerfile — clears 4 end-of-life runtime CVEs." },
  ],
  verificationSteps: [
    { command: "pytest -q", description: "Full test suite must stay green after the dependency bump." },
    { command: "deptex scan payments-svc", description: "Re-scan confirms the 3 reachable findings are resolved." },
  ],
};

// User bubble — copied verbatim from aegis/MessageBubble.
function UserBubble({ children }: { children: ReactNode }) {
  return (
    <div className="px-4 py-1">
      <div className="mx-auto max-w-3xl flex flex-col items-end">
        <div className="max-w-[72%] rounded-2xl bg-background-card border border-border px-4 py-2.5 text-sm text-foreground/90 whitespace-pre-wrap leading-relaxed">
          {children}
        </div>
      </div>
    </div>
  );
}

// Assistant block — copied verbatim from aegis/MessageBubble (space-y-2 of elements).
function AssistantBlock({ children }: { children: ReactNode }) {
  return (
    <div className="px-4 py-2">
      <div className="mx-auto max-w-3xl">
        <div className="space-y-2">{children}</div>
      </div>
    </div>
  );
}

function GateMessage() {
  return (
    <div className="space-y-3 text-sm leading-relaxed text-foreground/90">
      <p>
        Aegis runs for real once it&apos;s connected to your code. Create a free
        account to point it at your own repos and let it open the fix PR.
      </p>
      <Button variant="green" asChild className="!h-8 !rounded-lg !px-3">
        <Link to="/login">Try Aegis for free</Link>
      </Button>
    </div>
  );
}

// Plan panel — markup copied verbatim from aegis/FixPanel's detail body
// (awaiting-approval state), fed the mock PLAN above.
function HeroPlanPanel({
  modelId,
  onModelSelect,
  onStart,
}: {
  modelId: string;
  onModelSelect: (id: string) => void;
  onStart: () => void;
}) {
  return (
    <div className="h-full flex flex-col bg-background overflow-hidden relative">
      <div className="flex-1 overflow-y-auto custom-scrollbar">
        <div className="px-6 pt-5 pb-6">
          <div className="flex items-center justify-between gap-3">
            <div className="text-lg font-semibold text-foreground leading-snug min-w-0 truncate">
              {PLAN.summary}
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <ModelPicker models={MODELS} selectedModelId={modelId} onSelect={onModelSelect} />
              <Button type="button" variant="solid" onClick={onStart} className="h-8 px-3 shrink-0">
                Start
              </Button>
            </div>
          </div>

          <div className="mt-6 space-y-6">
            <div>
              <div className="text-sm font-semibold text-foreground mb-2">Plan</div>
              <p className="text-sm leading-relaxed text-foreground/80 whitespace-pre-wrap">
                {PLAN.description}
              </p>
            </div>

            <div className="rounded-md border border-border bg-background-subtle/30 px-4 py-3">
              <div className="flex items-center gap-1.5 mb-2 text-xs font-medium text-foreground-secondary">
                <ListChecks className="h-3.5 w-3.5" />
                To-dos
              </div>
              <ul className="space-y-3">
                {PLAN.todos.map((t, i) => (
                  <li key={i} className="flex items-start gap-2.5">
                    <Circle className="h-3 w-3 mt-1 text-foreground-secondary shrink-0" />
                    <div className="min-w-0 flex-1">
                      <div className="text-sm text-foreground leading-snug">{t.title}</div>
                      {t.detail && (
                        <div className="mt-1 text-xs text-foreground-secondary leading-relaxed">
                          {t.detail}
                        </div>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            </div>

            <div className="rounded-md border border-border bg-background-subtle/30 px-4 py-3">
              <div className="flex items-center gap-1.5 mb-2 text-xs font-medium text-foreground-secondary">
                <CheckCircle2 className="h-3.5 w-3.5" />
                Verification
              </div>
              <ul className="space-y-3">
                {PLAN.verificationSteps.map((s, i) => (
                  <li key={i} className="flex items-start gap-2.5">
                    <Circle className="h-3 w-3 mt-1 text-foreground-secondary shrink-0" />
                    <div className="min-w-0 flex-1">
                      <div className="font-mono text-xs text-foreground break-all">{s.command}</div>
                      <div className="mt-1 text-xs text-foreground-secondary leading-relaxed">
                        {s.description}
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function AegisView() {
  const [modelId, setModelId] = useState(MODELS[0].id);
  const [planOpen, setPlanOpen] = useState(true);
  const [extra, setExtra] = useState<{ id: number; role: "user" | "aegis"; text?: string }[]>([]);
  const idRef = useRef(0);
  const scrollRef = useRef<HTMLDivElement>(null);
  const timers = useRef<number[]>([]);

  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [extra]);
  useEffect(() => () => timers.current.forEach((t) => clearTimeout(t)), []);

  // Any send / Start → append the user line, then (briefly later) the sign-up gate.
  const sendGate = (userText?: string) => {
    if (userText !== undefined) {
      setExtra((prev) => [...prev, { id: ++idRef.current, role: "user", text: userText }]);
    }
    const t = window.setTimeout(
      () => setExtra((prev) => [...prev, { id: ++idRef.current, role: "aegis" }]),
      480,
    );
    timers.current.push(t);
  };

  return (
    <div className="flex h-full bg-background">
      {/* chat column — mirrors aegis/ChatPane's active layout */}
      <div className="flex h-full min-w-0 flex-1 flex-col">
        <div ref={scrollRef} className="flex-1 overflow-y-auto custom-scrollbar">
          <div className="py-4">
            <UserBubble>
              Can you fix all of the security vulnerabilities in my payment processing
              project.
            </UserBubble>

            <AssistantBlock>
              <div className="text-sm leading-relaxed text-foreground/90">
                On it — let me see what&apos;s actually exploitable in{" "}
                <span className="font-medium text-foreground">payments-svc</span>.
              </div>
              <ToolCallGroup tools={TOOLS} />
              <div className="text-sm leading-relaxed text-foreground/90">
                8 findings, 3 reachable — including a live Stripe key committed in{" "}
                <code className="text-[13px] bg-background-subtle text-foreground px-1.5 py-0.5 rounded font-mono">
                  credentials.py
                </code>
                . I&apos;ve drafted a plan to fix them — review it in the panel on the
                right. Want me to go ahead and open the PR?
              </div>
            </AssistantBlock>

            {extra.map((m) =>
              m.role === "user" ? (
                <UserBubble key={m.id}>{m.text}</UserBubble>
              ) : (
                <AssistantBlock key={m.id}>
                  <GateMessage />
                </AssistantBlock>
              ),
            )}
          </div>
        </div>

        {/* composer — the REAL ChatInput (textarea + ModelPicker pill + send) */}
        <div className="px-4 pb-4">
          <div className="mx-auto max-w-3xl">
            <div className="rounded-2xl bg-background-card border border-border">
              <ChatInput
                onSubmit={(text) => sendGate(text)}
                placeholder="Ask Aegis anything"
                models={MODELS}
                selectedModelId={modelId}
                onSelectModel={setModelId}
              />
            </div>
          </div>
        </div>
      </div>

      {/* plan sidebar — aegis/FixPanelHost's collapsible shell + FixPanel body */}
      <div
        className="relative flex flex-shrink-0 transition-[width] duration-[220ms] ease-out"
        style={{ width: planOpen ? 400 : 0 }}
        aria-hidden={!planOpen}
      >
        <button
          type="button"
          onClick={() => setPlanOpen((v) => !v)}
          aria-label={planOpen ? "Collapse plan" : "Show plan"}
          className="absolute top-3 -left-8 z-20 inline-flex h-6 w-6 items-center justify-center rounded-md text-foreground-secondary transition-colors hover:bg-background-subtle hover:text-foreground"
        >
          <PanelRight className="h-4 w-4" />
        </button>
        <aside className="flex-1 border-l border-border overflow-hidden">
          <HeroPlanPanel
            modelId={modelId}
            onModelSelect={setModelId}
            onStart={() => sendGate("Go ahead")}
          />
        </aside>
      </div>
    </div>
  );
}

export default function HeroShowcase() {
  // Default to Findings — it proves the headline ("cut the noise") at first
  // glance: CVEs scored by reachability, noise auto-ignored. Overview leads
  // with an org map that reads less obviously as "security".
  const [active, setActive] = useState("findings");

  return (
    <div className="relative">
      <div
        className="glow-green pointer-events-none absolute -inset-x-8 -top-8 bottom-0 opacity-25"
        aria-hidden
      />

      {/* app window — styled as a real (dark) Chrome browser: mac traffic
          lights + Chrome tabs in the title bar, then a toolbar with the address
          bar (founder 2026-06-16). Overview / Findings / Aegis ARE the browser
          tabs; the active tab merges into the toolbar exactly like Chrome. */}
      <div className="relative overflow-hidden rounded-xl border border-[#262626] bg-[#0a0a0a] shadow-[0_30px_80px_rgba(0,0,0,0.6)]">
        {/* title bar — traffic lights + Chrome tabs */}
        <div className="flex h-11 items-end gap-1.5 bg-[#0a0a0a] px-3">
          <div className="flex shrink-0 items-center gap-2 self-center pr-3">
            <span className="h-3 w-3 rounded-full bg-[#ff5f57]" />
            <span className="h-3 w-3 rounded-full bg-[#febc2e]" />
            <span className="h-3 w-3 rounded-full bg-[#28c840]" />
          </div>
          {TABS.map((t) => {
            const isActive = t.id === active;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => setActive(t.id)}
                aria-pressed={isActive}
                className={`flex items-center gap-2 pl-2.5 pr-3.5 pt-1.5 text-[13px] font-medium transition-colors ${
                  isActive
                    ? "chrome-tab-active rounded-t-lg bg-[#141414] pb-3 text-foreground"
                    : "mb-1.5 rounded-lg pb-1.5 text-foreground-secondary hover:bg-white/[0.05] hover:text-foreground"
                }`}
              >
                <img
                  src="/images/website_icon.png"
                  alt=""
                  aria-hidden
                  className="h-4 w-4 shrink-0 rounded-full object-contain"
                />
                {t.label}
              </button>
            );
          })}
          <span className="flex h-6 w-6 items-center justify-center self-center rounded-full text-foreground-secondary/60 hover:bg-white/[0.04]">
            <Plus className="h-4 w-4" aria-hidden />
          </span>
        </div>

        {/* toolbar — nav buttons + address bar (active tab merges into this) */}
        <div className="flex items-center gap-2 bg-[#141414] px-3 py-2">
          <div className="flex items-center gap-1 text-foreground-secondary/50">
            <ChevronLeft className="h-4 w-4" aria-hidden />
            <ChevronRight className="h-4 w-4" aria-hidden />
            <RotateCw className="ml-0.5 h-3.5 w-3.5" aria-hidden />
          </div>
          <div className="ml-1 flex h-7 flex-1 items-center gap-2 rounded-full border border-white/[0.06] bg-[#0a0a0a] px-3">
            <Lock className="h-3 w-3 text-foreground-secondary" aria-hidden />
            <span className="font-mono text-[12px] text-foreground">deptex.dev</span>
          </div>
          <MoreVertical
            className="h-4 w-4 shrink-0 text-foreground-secondary/50"
            aria-hidden
          />
        </div>

        {/* content — fixed height so tab switches don't jump; views scroll */}
        <div key={active} className="tab-fade h-[560px] border-t border-[#1c1c1c]">
          {active === "overview" && <HeroOverviewGraph />}
          {active === "findings" && <HeroFindingsTable />}
          {active === "aegis" && <AegisView />}
        </div>
      </div>
    </div>
  );
}

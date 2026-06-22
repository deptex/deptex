/**
 * AegisChatCard — the real Aegis chat (ChatInput + ModelPicker → Claude logo,
 * ToolCallGroup) fed a mock investigate→fix transcript that funnels to a
 * sign-up gate. Shared so the AI Security Agent feature page can render the
 * same chat the homepage AegisSection shows.
 *
 * NOTE: currently a copy of AegisSection's inline AegisChatCard. When that
 * homepage section is next touched, point it at this file and delete its
 * inline copy (kept separate now to avoid churning the committed homepage).
 *
 * Do NOT claim: autopilot, sprints, PR review, Slack parity, "50+ tools".
 */
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { Button } from "../ui/button";
import { ChatInput } from "../aegis/ChatInput";
import { ToolCallGroup, type ToolCallEntry } from "../aegis/ToolCallCard";
import type { AIModelMetadata } from "../../lib/api";

const MODELS: AIModelMetadata[] = [
  { id: "claude-opus-4-8", provider: "anthropic", label: "Claude Opus 4.8", description: "Anthropic's most capable model — best for security reasoning.", contextWindow: 1_000_000, inputPricePer1M: 5, outputPricePer1M: 25, releasedAt: "2026-01-01" },
  { id: "gpt-5.1", provider: "openai", label: "GPT-5.1", description: "OpenAI's flagship reasoning model.", contextWindow: 400_000, inputPricePer1M: 4, outputPricePer1M: 16, releasedAt: "2025-11-01" },
  { id: "gemini-2.5-pro", provider: "google", label: "Gemini 2.5 Pro", description: "Google's long-context reasoning model.", contextWindow: 1_000_000, inputPricePer1M: 2, outputPricePer1M: 10, releasedAt: "2025-09-01" },
];

const TOOLS_INVESTIGATE: ToolCallEntry[] = [
  { toolName: "list_project_findings", state: "done" },
  { toolName: "get_finding_detail", state: "done" },
  { toolName: "analyze_reachability", state: "done" },
];
const TOOLS_FIX: ToolCallEntry[] = [
  { toolName: "request_fix", state: "done" },
  { toolName: "write_patch", state: "done" },
  { toolName: "run_tests", state: "done" },
  { toolName: "open_pull_request", state: "done" },
];

function UserBubble({ children }: { children: ReactNode }) {
  return (
    <div className="px-4 py-1">
      <div className="mx-auto max-w-3xl flex flex-col items-end">
        <div className="max-w-[80%] rounded-2xl bg-background-card border border-border px-4 py-2.5 text-sm text-foreground/90 whitespace-pre-wrap leading-relaxed">
          {children}
        </div>
      </div>
    </div>
  );
}

function AssistantBlock({ children }: { children: ReactNode }) {
  return (
    <div className="px-4 py-2">
      <div className="mx-auto max-w-3xl">
        <div className="space-y-2">{children}</div>
      </div>
    </div>
  );
}

function Mono({ children }: { children: ReactNode }) {
  return (
    <code className="rounded bg-background-subtle px-1 py-0.5 font-mono text-[12px] text-foreground">
      {children}
    </code>
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

export function AegisChatCard() {
  const [modelId, setModelId] = useState(MODELS[0].id);
  const [extra, setExtra] = useState<
    { id: number; role: "user" | "aegis"; text?: string }[]
  >([]);
  const idRef = useRef(0);
  const scrollRef = useRef<HTMLDivElement>(null);
  const timers = useRef<number[]>([]);

  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [extra]);
  useEffect(() => () => timers.current.forEach((t) => clearTimeout(t)), []);

  const sendGate = (userText?: string) => {
    if (userText !== undefined) {
      setExtra((prev) => [
        ...prev,
        { id: ++idRef.current, role: "user", text: userText },
      ]);
    }
    const t = window.setTimeout(
      () => setExtra((prev) => [...prev, { id: ++idRef.current, role: "aegis" }]),
      480,
    );
    timers.current.push(t);
  };

  return (
    <div className="flex h-[560px] flex-col overflow-hidden rounded-xl border border-border bg-background">
      <div ref={scrollRef} className="flex-1 overflow-y-auto custom-scrollbar py-4">
        <UserBubble>
          lodash is flagged critical — is it actually exploitable here?
        </UserBubble>

        <AssistantBlock>
          <div className="text-sm leading-relaxed text-foreground/90">
            Let me trace it in{" "}
            <span className="font-medium text-foreground">storefront-api</span>.
          </div>
          <ToolCallGroup tools={TOOLS_INVESTIGATE} />
          <div className="text-sm leading-relaxed text-foreground/90">
            Yes —{" "}
            <span className="font-mono text-[13px] text-accent-text">
              CVE-2021-23337
            </span>{" "}
            is reachable. Request body flows into <Mono>_.template()</Mono> in{" "}
            <Mono>routes/render.js</Mono>, so the injection path is live. A patch
            bump to 4.17.21 fixes it — your usage doesn&apos;t touch the changed
            API.
          </div>
        </AssistantBlock>

        <UserBubble>Great — open a PR for it.</UserBubble>

        <AssistantBlock>
          <div className="text-sm leading-relaxed text-foreground/90">On it.</div>
          <ToolCallGroup tools={TOOLS_FIX} />
          <div className="text-sm leading-relaxed text-foreground/90">
            Patched <Mono>lodash</Mono> → 4.17.21, ran your suite (142 passing),
            and opened draft PR{" "}
            <span className="font-mono text-foreground">#1287</span>. Reachability
            re-verified — nothing merges without your review.
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

      <div className="px-3 pb-3">
        <div className="rounded-2xl border border-border bg-background-card">
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
  );
}

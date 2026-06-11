/**
 * §3.10 Policy as code (landing-page-redesign.plan.md).
 * Left: DOM-rendered packagePolicy sample — hand-tinted spans (2–3 muted
 * colors, keywords/strings/comments only) stand in until the shiki codegen
 * script (§8) emits committed pre-highlighted HTML. NO typing animation, ever.
 * Right: facts column — three seeded programs (mono) + sandbox facts.
 * Copy button deliberately skipped (optional in spec).
 * Verify ctx field names against policy-engine.ts before ship.
 */
import { ReactNode } from "react";
import { Reveal } from "./primitives";

/* Hand-tint helpers — keywords (muted indigo), strings (muted green),
   comments (decorative gray). Replaced wholesale by shiki output later. */
function K({ children }: { children: ReactNode }) {
  return <span className="text-[#a5b4fc]">{children}</span>;
}
function S({ children }: { children: ReactNode }) {
  return <span className="text-[#7ec9a3]">{children}</span>;
}
function C({ children }: { children: ReactNode }) {
  return <span className="text-foreground-muted">{children}</span>;
}

const PROGRAMS = ["packagePolicy", "projectStatus", "pullRequestCheck"];

const SUB_PARAGRAPH =
  "Three JavaScript programs govern every org: allow or deny each dependency, assign project compliance status, pass or block pull requests. Sandboxed in a V8 isolate, versioned with one-click revert, evaluated on every scan and every PR.";

export default function PolicySection() {
  const codeLines: ReactNode[] = [
    <C>{"// packagePolicy.js"}</C>,
    <>
      <K>export</K> <K>function</K>
      {" packagePolicy(ctx) {"}
    </>,
    <>
      {"  "}
      <K>if</K>
      {" (ctx.license === "}
      <S>{"'AGPL-3.0'"}</S>
      {")"}
    </>,
    <>
      {"    "}
      <K>return</K>
      {" deny("}
      <S>{"'copyleft'"}</S>
      {");"}
    </>,
    <>
      {"  "}
      <K>if</K>
      {" (ctx.reachability === "}
      <S>{"'confirmed'"}</S>
    </>,
    <>
      {"      && ctx.severity === "}
      <S>{"'critical'"}</S>
      {")"}
    </>,
    <>
      {"    "}
      <K>return</K>
      {" deny("}
      <S>{"'reachable critical'"}</S>
      {");"}
    </>,
    <>
      {"  "}
      <K>return</K>
      {" allow();"}
    </>,
    <>{"}"}</>,
  ];

  return (
    <section id="policy" className="w-full">
      <div className="mx-auto max-w-[1200px] px-6 py-28">
        <Reveal>
          <h2 className="text-3xl font-semibold leading-tight tracking-[-0.02em] text-foreground md:text-4xl">
            Your security policy is a function.
          </h2>
          <p className="mt-5 max-w-3xl text-[15px] leading-relaxed text-foreground-secondary">
            {SUB_PARAGRAPH}
          </p>
        </Reveal>

        <div className="mt-12 grid grid-cols-1 items-start gap-10 lg:grid-cols-[3fr_2fr]">
          {/* Code block — DOM-rendered, real text, mobile h-scroll. */}
          <Reveal>
            <div className="overflow-x-auto rounded-xl border border-border bg-[#050505] p-5">
              <pre className="font-mono text-[13px] leading-6">
                {codeLines.map((line, i) => (
                  <div key={i} className="flex whitespace-pre">
                    <span
                      aria-hidden
                      className="mr-5 w-5 shrink-0 select-none text-right text-foreground-muted"
                    >
                      {i + 1}
                    </span>
                    <span className="text-foreground-secondary">{line}</span>
                  </div>
                ))}
              </pre>
            </div>
            <p className="mt-3 font-mono text-xs text-foreground-secondary">
              sample policy code — ctx field names verified against
              policy-engine.ts before ship; shiki output replaces the
              hand-tinted spans
            </p>
          </Reveal>

          {/* Facts column. */}
          <Reveal delayMs={80}>
            <h3 className="text-[15px] font-medium text-foreground">
              Three programs, seeded on day one
            </h3>
            <ul className="mt-5 flex flex-col gap-3">
              {PROGRAMS.map((name) => (
                <li key={name} className="flex items-baseline gap-3">
                  <span aria-hidden className="select-none text-foreground-muted">
                    &#9472;
                  </span>
                  <span className="font-mono text-sm text-foreground">{name}</span>
                </li>
              ))}
            </ul>
            <p className="mt-6 text-sm leading-relaxed text-foreground-secondary">
              <span className="font-mono text-foreground">V8-isolated</span>,{" "}
              <span className="font-mono text-foreground">30s</span> execution
              cap, versioned, one-click revert.
            </p>
          </Reveal>
        </div>

        <Reveal delayMs={120}>
          <p className="mt-12 text-[15px] leading-relaxed text-foreground">
            Test before save — what passes the editor is what runs in the PR
            gate.
          </p>
        </Reveal>
      </div>
    </section>
  );
}

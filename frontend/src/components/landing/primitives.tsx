/**
 * Shared primitives for the landing rebuild (landing-page-redesign.plan.md §3).
 * Token discipline: surfaces #050505/#0a0a0a/#171717, borders #262626→#404040,
 * text #fafafa/#a1a1a1 (#71717a decorative only), green text = `text-accent-text`,
 * #025230 = surfaces/CTA only. Machine truth renders in font-mono.
 */
import { ReactNode } from "react";
import { useRevealOnScroll } from "./useRevealOnScroll";
import { REPO_PUBLIC, repoFile } from "./repoLinks";

/* ------------------------------------------------------------------ */
/* Reveal — wraps a block in the page-wide scroll-reveal pattern.      */
/* ------------------------------------------------------------------ */
export function Reveal({
  children,
  delayMs = 0,
  className = "",
}: {
  children: ReactNode;
  delayMs?: number;
  className?: string;
}) {
  const ref = useRevealOnScroll<HTMLDivElement>();
  return (
    <div
      ref={ref}
      className={`reveal-up ${className}`}
      style={delayMs ? { transitionDelay: `${delayMs}ms` } : undefined}
    >
      {children}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* TierPill — reachability verdict pill, matches the in-app recipe.    */
/* ------------------------------------------------------------------ */
const TIER_STYLES: Record<string, string> = {
  confirmed: "bg-accent-text/10 border-accent-text/40 text-accent-text",
  data_flow: "bg-emerald-900/30 border-emerald-700/40 text-emerald-400",
  function: "bg-neutral-800/80 border-neutral-600/50 text-neutral-300",
  module: "bg-neutral-800/60 border-neutral-700/50 text-neutral-400",
  unreachable: "bg-neutral-900/60 border-neutral-800 text-neutral-500",
};

export function TierPill({ tier, label }: { tier: keyof typeof TIER_STYLES | string; label?: string }) {
  const style = TIER_STYLES[tier] ?? TIER_STYLES.module;
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-0.5 font-mono text-xs tabular-nums ${style}`}
    >
      {label ?? tier}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* MonoStat — provenance-captioned number tile (proof strip et al).    */
/* ------------------------------------------------------------------ */
export function MonoStat({
  value,
  label,
  caption,
  href,
}: {
  value: string;
  label: string;
  caption: string;
  href?: string;
}) {
  return (
    <div className="flex flex-col gap-1">
      <span className="font-mono text-2xl tabular-nums text-foreground">{value}</span>
      <span className="text-sm text-foreground">{label}</span>
      {href ? (
        <a
          href={href}
          target="_blank"
          rel="noopener noreferrer"
          className="text-xs leading-relaxed text-foreground-secondary hover:text-foreground transition-colors"
        >
          {caption} ↗
        </a>
      ) : (
        <span className="text-xs leading-relaxed text-foreground-secondary">{caption}</span>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* SpecimenFrame — the hairline artifact frame; optional green glow.   */
/* ------------------------------------------------------------------ */
export function SpecimenFrame({
  children,
  glow = false,
  className = "",
}: {
  children: ReactNode;
  glow?: boolean;
  className?: string;
}) {
  return (
    <div className={`relative ${className}`}>
      {glow && (
        <div
          className="glow-green left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 opacity-40"
          aria-hidden
        />
      )}
      <div className="relative rounded-xl border border-border bg-[#0a0a0a] overflow-hidden">
        {children}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* RepoLink — GitHub deep link that degrades to a plain mono path      */
/* when the repo is private (pre-flight blocker #1 fallback).          */
/* ------------------------------------------------------------------ */
export function RepoLink({ path, label }: { path: string; label?: string }) {
  if (!REPO_PUBLIC) {
    return <span className="font-mono text-xs text-foreground-secondary">{label ?? path}</span>;
  }
  return (
    <a
      href={repoFile(path)}
      target="_blank"
      rel="noopener noreferrer"
      className="font-mono text-xs text-foreground-secondary hover:text-foreground transition-colors"
    >
      {label ?? path} ↗
    </a>
  );
}

/* ------------------------------------------------------------------ */
/* PlaceholderCanvas — blank slot standing in for a real capture.      */
/* Used while assets A1–A11 are produced; lists the asset id + what    */
/* will live there so the layout can be judged today.                  */
/* ------------------------------------------------------------------ */
export function PlaceholderCanvas({
  assetId,
  description,
  aspect = "16/10",
  className = "",
}: {
  assetId: string;
  description: string;
  aspect?: string;
  className?: string;
}) {
  return (
    <div
      className={`relative flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-[#404040] bg-[#0a0a0a] ${className}`}
      style={{
        aspectRatio: aspect,
        backgroundImage:
          "repeating-linear-gradient(45deg, transparent, transparent 24px, rgba(255,255,255,0.015) 24px, rgba(255,255,255,0.015) 48px)",
      }}
      role="img"
      aria-label={`Placeholder: ${description}`}
    >
      <span className="font-mono text-xs uppercase tracking-wider text-foreground-secondary">
        {assetId}
      </span>
      <span className="max-w-[80%] text-center text-sm text-foreground-secondary">
        {description}
      </span>
    </div>
  );
}

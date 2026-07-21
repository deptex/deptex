/**
 * §3.13 Changelog + docs band (landing-page-redesign.plan.md).
 * Pre-launch's only honest adoption signal: ship velocity + real docs.
 * Two flat lists, hairline rows, no cards. Entries below are real merges
 * from repo history (PR #73 / #72 / #69) — refresh at build; the Phase 5
 * `changelog.json` + `/changelog` route replace this const when they land.
 */
import { Link } from "react-router-dom";
import { Reveal } from "./primitives";

const CHANGELOG_ENTRIES = [
  {
    date: "Jun 08",
    iso: "2026-06-08",
    text: "Team sidebar rework — projects, members, and role settings",
  },
  {
    date: "Jun 08",
    iso: "2026-06-08",
    text: "Findings table restyle + scanner noise filters",
  },
  {
    date: "Jun 05",
    iso: "2026-06-05",
    text: "Organization overview: projects table with severity breakdown",
  },
];

/**
 * Freshness guard (§3.13): "Shipping weekly." only ships while the head
 * entry is <14 days old; otherwise it degrades to "Recent changes." —
 * a "Shipping weekly" header above a stale entry is anti-proof.
 */
const FOURTEEN_DAYS_MS = 14 * 24 * 60 * 60 * 1000;
const CHANGELOG_HEADER =
  Date.now() - new Date(CHANGELOG_ENTRIES[0].iso).getTime() < FOURTEEN_DAYS_MS
    ? "Shipping weekly."
    : "Recent changes.";

/**
 * Only doc routes that exist in docsConfig.ts ship (§3.13 cut rule).
 * "Reachability semantics" + "Self-hosting guide" have no docs slug yet —
 * cut from the column until those pages exist.
 */
const DOC_LINKS = [
  { label: "Quickstart → first scan", to: "/docs/quick-start" },
];

export default function ChangelogBand() {
  return (
    <section className="w-full">
      <div className="mx-auto max-w-[1200px] px-6 py-20 md:py-24">
        <div className="grid grid-cols-1 gap-14 md:grid-cols-2 lg:gap-24">
          {/* Changelog column */}
          <Reveal>
            <h3 className="text-xl font-semibold tracking-[-0.01em] text-foreground">
              {CHANGELOG_HEADER}
            </h3>
            <ul className="mt-5 divide-y divide-white/[0.08] border-y border-white/[0.08]">
              {CHANGELOG_ENTRIES.map((entry) => (
                <li
                  key={`${entry.iso}-${entry.text}`}
                  className="flex items-baseline gap-4 py-3"
                >
                  <span className="w-14 shrink-0 font-mono text-xs tabular-nums text-foreground-secondary">
                    {entry.date}
                  </span>
                  <span className="text-sm leading-relaxed text-foreground">
                    {entry.text}
                  </span>
                </li>
              ))}
            </ul>
          </Reveal>

          {/* Docs column */}
          <Reveal delayMs={80}>
            <h3 className="text-xl font-semibold tracking-[-0.01em] text-foreground">
              Docs: zero to first scan.
            </h3>
            <ul className="mt-5 divide-y divide-white/[0.08] border-y border-white/[0.08]">
              {DOC_LINKS.map((doc) => (
                <li key={doc.to}>
                  <Link
                    to={doc.to}
                    className="block py-3 text-sm leading-relaxed text-foreground transition-colors hover:text-accent-text"
                  >
                    {doc.label}
                  </Link>
                </li>
              ))}
            </ul>
          </Reveal>
        </div>
      </div>
    </section>
  );
}

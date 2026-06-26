interface LevelRow {
  level: string;
  meaning: string;
  weight: string;
}

const reachabilityLevels: LevelRow[] = [
  {
    level: "Confirmed",
    meaning: "A known exploit path matched a per-CVE reachability rule.",
    weight: "×1.0",
  },
  {
    level: "Data flow",
    meaning: "Tainted input actually reaches the vulnerable sink.",
    weight: "×0.9",
  },
  {
    level: "Function",
    meaning: "The vulnerable function is called somewhere in your code.",
    weight: "×0.7",
  },
  {
    level: "Module",
    meaning: "The package is imported, but no call to the vulnerable code was traced.",
    weight: "×0.5",
  },
  {
    level: "Unreachable",
    meaning: "Present in the dependency tree but never used. Scored to zero and hidden by default.",
    weight: "×0",
  },
];

const factors: { title: string; body: string }[] = [
  {
    title: "Severity (CVSS)",
    body: "The raw impact if the vulnerability is exploited, on the standard 0–10 scale.",
  },
  {
    title: "Exploitability",
    body: "EPSS — the probability the CVE is exploited in the wild — plus a boost when it appears on CISA's Known Exploited Vulnerabilities (KEV) list.",
  },
  {
    title: "Reachability",
    body: "The weight from the table above. This is what separates a vulnerability you can actually hit from one buried in unused code.",
  },
  {
    title: "Dependency context",
    body: "Whether the package is a direct or transitive dependency, dev-only, flagged malicious, and its overall reputation score.",
  },
  {
    title: "Execution path dominance (EPD)",
    body: "Contextual scoring that nudges a finding up when it sits on a path central to how your app actually runs.",
  },
];

interface BandRow {
  band: string;
  score: string;
  dot: string;
}

const bands: BandRow[] = [
  { band: "Critical", score: "90 – 100", dot: "bg-red-500" },
  { band: "High", score: "70 – 89", dot: "bg-orange-500" },
  { band: "Medium", score: "40 – 69", dot: "bg-blue-500" },
  { band: "Low", score: "0 – 39", dot: "bg-emerald-500" },
];

export default function ReachabilityDepscoreContent() {
  return (
    <div className="space-y-12">
      {/* Why reachability */}
      <section>
        <p className="text-foreground/90 leading-relaxed">
          A vulnerability in a dependency only matters if your code can actually reach it. Most CVEs
          in a typical dependency tree are never called — they live in transitive packages you pulled
          in but don&apos;t exercise. Instead of treating every listed CVE as equally urgent, Deptex
          traces the path from your code to the vulnerable code and grades how close that path gets.
          A &ldquo;critical&rdquo; CVE you can&apos;t reach is not treated like one you can.
        </p>
      </section>

      {/* Reachability levels */}
      <section>
        <h2 className="text-lg font-semibold text-foreground mb-4">Reachability levels</h2>
        <div className="overflow-hidden rounded-lg border border-border bg-background-card">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left">
                <th className="px-4 py-3 font-semibold text-foreground">Level</th>
                <th className="px-4 py-3 font-semibold text-foreground">What it means</th>
                <th className="px-4 py-3 font-semibold text-foreground text-right whitespace-nowrap">
                  Weight
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {reachabilityLevels.map((row) => (
                <tr key={row.level}>
                  <td className="px-4 py-3 font-medium text-foreground whitespace-nowrap align-top">
                    {row.level}
                  </td>
                  <td className="px-4 py-3 text-foreground/80 align-top">{row.meaning}</td>
                  <td className="px-4 py-3 text-foreground-secondary text-right tabular-nums align-top">
                    {row.weight}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-sm leading-relaxed text-foreground/70">
          Deptex parses your source with tree-sitter across 8 languages, builds usage and taint
          flows from your entry points, and runs per-CVE reachability rule packs to decide which
          level applies. Unreachable findings drop to a Depscore of zero and are hidden by default,
          so you&apos;re never buried in noise.
        </p>
      </section>

      {/* Depscore */}
      <section>
        <h2 className="text-lg font-semibold text-foreground mb-2">Depscore</h2>
        <p className="text-foreground/90 leading-relaxed mb-5">
          Depscore is a single 0–100 priority number for each finding. It starts from the raw
          severity, then weighs everything Deptex knows about your specific context so the issues
          that are genuinely exploitable in <em>your</em> code rise to the top. These are the signals
          that feed it:
        </p>
        <div className="space-y-5">
          {factors.map((item) => (
            <div key={item.title} className="border-l-2 border-white/[0.08] pl-4">
              <h3 className="font-medium text-foreground">{item.title}</h3>
              <p className="mt-1 text-sm leading-relaxed text-foreground/80">{item.body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Reading the score */}
      <section>
        <h2 className="text-lg font-semibold text-foreground mb-4">Reading the score</h2>
        <div className="overflow-hidden rounded-lg border border-border bg-background-card">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left">
                <th className="px-4 py-3 font-semibold text-foreground">Band</th>
                <th className="px-4 py-3 font-semibold text-foreground text-right whitespace-nowrap">
                  Depscore
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {bands.map((row) => (
                <tr key={row.band}>
                  <td className="px-4 py-3 align-top">
                    <span className="flex items-center gap-2.5 font-medium text-foreground">
                      <span className={`h-2 w-2 rounded-full ${row.dot}`} aria-hidden />
                      {row.band}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-foreground-secondary text-right tabular-nums align-top">
                    {row.score}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-sm leading-relaxed text-foreground/70">
          Findings are sorted by Depscore so you can work top-down. Because the bands are
          reachability-aware, an unreachable &ldquo;Critical&rdquo; CVE correctly lands in a lower
          band instead of demanding attention it doesn&apos;t deserve.
        </p>
      </section>
    </div>
  );
}

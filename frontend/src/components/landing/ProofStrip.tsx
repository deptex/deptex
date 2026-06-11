/**
 * §3.3 Proof strip — provenance facts band (landing-page-redesign.plan.md).
 * Five checkable numbers where competitors put a logo wall. Single
 * hairline-separated row — no boxes, no icons, no green. Each caption deep
 * links to the proving source path; links degrade to plain captions when
 * REPO_PUBLIC is false (pre-flight blocker #1).
 */
import { MonoStat, Reveal } from "./primitives";
import { REPO_PUBLIC, repoDir, repoFile } from "./repoLinks";

const STATS: {
  value: string;
  label: string;
  caption: string;
  href?: string;
}[] = [
  {
    value: "8",
    label: "languages traced",
    caption: "cross-file taint engine: JS/TS, Python, Java, Go, Ruby, PHP, Rust, C#",
    href: REPO_PUBLIC ? repoDir("depscanner/src/taint-engine") : undefined,
  },
  {
    value: "34",
    label: "framework detectors",
    caption: "route handlers and entry points, found in your AST",
    href: REPO_PUBLIC ? repoDir("depscanner/src/framework-rules/detectors") : undefined,
  },
  {
    value: "49",
    label: "taint models",
    caption: "hand-authored source/sink YAML for the libraries you use",
    href: REPO_PUBLIC ? repoDir("depscanner/src/taint-engine/framework-models") : undefined,
  },
  {
    value: "9",
    label: "scanner categories",
    caption:
      "SCA, reachability, SAST, DAST, secrets, IaC, containers, malicious packages, SBOM",
    href: REPO_PUBLIC ? repoFile("depscanner/src/pipeline.ts") : undefined,
  },
  {
    value: "8",
    label: "package ecosystems",
    caption: "dependency scanning, fixture-verified end to end: npm to NuGet",
    href: REPO_PUBLIC ? repoFile("depscanner/test-repos/README.md") : undefined,
  },
];

export default function ProofStrip() {
  return (
    <section className="w-full border-y border-white/[0.08]">
      <div className="mx-auto max-w-[1200px] px-6 py-10">
        <Reveal>
          <div className="grid grid-cols-2 gap-x-6 gap-y-10 lg:grid-cols-5 lg:gap-x-0 lg:gap-y-0">
            {STATS.map((stat, i) => (
              <div
                key={stat.label}
                className={[
                  i === STATS.length - 1 ? "col-span-2 lg:col-span-1" : "",
                  i > 0
                    ? "lg:border-l lg:border-white/[0.08] lg:pl-6"
                    : "lg:pl-0",
                  "lg:pr-6",
                ].join(" ")}
              >
                <MonoStat
                  value={stat.value}
                  label={stat.label}
                  caption={stat.caption}
                  href={stat.href}
                />
              </div>
            ))}
          </div>
        </Reveal>
      </div>
    </section>
  );
}

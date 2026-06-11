/**
 * §3.8 Breadth wall — breadth as fact, after depth.
 * 3×3 shared-hairline grid (gap-px bg-border), no icons, engine names in
 * mono bottom-right. Hover lightens the cell border one step; nothing scales.
 */
import { Reveal, RepoLink } from "./primitives";

interface Category {
  name: string;
  sentence: string;
  engines: string;
}

const CATEGORIES: Category[] = [
  {
    name: "Dependencies",
    sentence:
      "CycloneDX SBOM per scan; dep-scan VDR matching with a direct OSV fallback so no ecosystem goes blind.",
    engines: "cdxgen · dep-scan · OSV",
  },
  {
    name: "Reachability",
    sentence:
      "Cross-file taint analysis in 8 languages; five-tier verdicts weighted into every score.",
    engines: "in-house engine · tree-sitter",
  },
  {
    name: "SAST",
    sentence: "Semgrep registry rules across the workspace, deduped and CWE-scored.",
    engines: "semgrep 1.160.0",
  },
  {
    name: "Secrets",
    sentence:
      "TruffleHog with live credential verification — a verified key outscores an unverified one.",
    engines: "trufflehog v3.83.6",
  },
  {
    name: "IaC",
    sentence:
      "Two engines across 9 frameworks: Terraform, Kubernetes, Helm, CloudFormation, Dockerfile and more.",
    engines: "checkov 3.2.420 · trivy",
  },
  {
    name: "Containers",
    sentence:
      "Image CVEs, base-image advice, and a SONAME bridge that links OS-package CVEs to the code that loads them.",
    engines: "trivy 0.69.3",
  },
  {
    name: "Malicious packages",
    sentence:
      "Known-malicious feeds, GuardDog heuristics, and a 9-signal capability fingerprint per package.",
    engines: "guarddog 2.9.0",
  },
  {
    name: "DAST",
    sentence:
      "Two engines attack the running app, guided by an OpenAPI spec synthesized from your detected routes.",
    engines: "ZAP 2.17.0 · nuclei v3.8.0",
  },
  {
    name: "SBOM & VEX export",
    sentence:
      "CycloneDX SBOM and reachability-aware VEX: unreachable CVEs machine-marked not_affected.",
    engines: "CycloneDX",
  },
];

export default function BreadthWall() {
  return (
    <section className="w-full">
      <div className="mx-auto max-w-[1200px] px-6 py-24">
        <Reveal>
          <h2 className="text-[32px] font-semibold leading-[1.1] tracking-[-0.02em] text-foreground sm:text-[40px]">
            One platform. Nine scanner categories.
          </h2>
        </Reveal>

        <div className="mt-10 grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-border bg-border lg:grid-cols-3">
          {CATEGORIES.map((category, i) => (
            <Reveal
              key={category.name}
              delayMs={i * 40}
              className={i === CATEGORIES.length - 1 ? "col-span-2 lg:col-span-1" : ""}
            >
              <div className="flex h-full flex-col gap-2 bg-[#0a0a0a] p-6 transition-shadow hover:shadow-[inset_0_0_0_1px_#404040]">
                <h3 className="text-[15px] font-medium text-foreground">{category.name}</h3>
                <p className="text-sm leading-relaxed text-foreground-secondary">
                  {category.sentence}
                </p>
                <span className="mt-auto self-end pt-4 font-mono text-xs tabular-nums text-foreground-secondary">
                  {category.engines}
                </span>
              </div>
            </Reveal>
          ))}
        </div>

        <Reveal delayMs={CATEGORIES.length * 40}>
          <p className="mt-6 font-mono text-xs text-foreground-secondary">
            Every engine pinned by version or digest.{" "}
            <RepoLink path="depscanner/Dockerfile" label="Read the Dockerfile" />
          </p>
        </Reveal>
      </div>
    </section>
  );
}

import { useState, useEffect } from "react";
import { Star } from "lucide-react";

const GITHUB_REPO_URL = "https://github.com/deptex/deptex";
const GITHUB_API_REPO = "https://api.github.com/repos/deptex/deptex";

const REPO = {
  name: "deptex",
  repo: "deptex/deptex",
  description:
    "Deptex helps organizations manage open-source risk by tracking dependencies, enforcing security policies, and automatically remediating vulnerabilities with AI",
  contributingUrl: "https://github.com/deptex/deptex/blob/main/CONTRIBUTING.md",
  codeOfConductUrl: "https://github.com/deptex/deptex/blob/main/CODE_OF_CONDUCT.md",
};

function formatStars(count: number): string {
  if (count >= 1000) return `${(count / 1000).toFixed(1)}k`;
  return count.toLocaleString();
}

export default function OpenSourcePage() {
  const [githubStars, setGithubStars] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch(GITHUB_API_REPO)
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error("Failed to fetch"))))
      .then((data) => {
        if (!cancelled && typeof data.stargazers_count === "number") {
          setGithubStars(data.stargazers_count);
        }
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  return (
    <div>
      <section className="container mx-auto px-4 pt-28 lg:pt-32 pb-8 lg:pb-10">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 lg:gap-16 items-center max-w-6xl mx-auto">
          {/* Left: Open Source hero */}
          <div className="text-center lg:text-left">
            <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6 text-foreground">
              Open Source
            </h1>
            <p className="text-xl text-foreground-secondary mb-8 leading-relaxed">
              Deptex’s core platform is open source. We welcome anyone who wants to contribute.
            </p>
            <div className="flex flex-wrap justify-center lg:justify-start gap-6">
              <a
                href={REPO.contributingUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 text-foreground-secondary hover:text-foreground transition-colors"
              >
                <img src="/images/integrations/github.png" alt="" className="h-5 w-5 rounded-full" aria-hidden />
                <span>How to contribute</span>
              </a>
              <a
                href={REPO.codeOfConductUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 text-foreground-secondary hover:text-foreground transition-colors"
              >
                <img src="/images/integrations/github.png" alt="" className="h-5 w-5 rounded-full" aria-hidden />
                <span>Code of Conduct</span>
              </a>
            </div>
          </div>

          {/* Right: GitHub card */}
          <div className="flex justify-center lg:justify-end">
            <a
              href={GITHUB_REPO_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="block w-full max-w-md rounded-2xl border border-border bg-background-card/50 p-6 md:p-8 transition-all duration-200 hover:bg-background-card/70 hover:shadow-[0_0_20px_rgba(255,255,255,0.04)]"
            >
              <div className="flex items-center gap-2">
                <img src="/images/integrations/github.png" alt="" className="h-5 w-5 rounded-full" aria-hidden />
                <h2 className="text-xl font-semibold text-foreground">{REPO.name}</h2>
              </div>
              <p className="mt-3 text-sm text-foreground-secondary leading-relaxed">
                {REPO.description}
              </p>
              <div className="mt-6 flex items-center justify-between text-sm text-foreground-muted">
                <span>{REPO.repo}</span>
                {githubStars !== null ? (
                  <span className="flex items-center gap-1.5 tabular-nums">
                    <Star className="h-4 w-4" aria-hidden />
                    {formatStars(githubStars)}
                  </span>
                ) : (
                  <span className="tabular-nums">—</span>
                )}
              </div>
            </a>
          </div>
        </div>
      </section>
    </div>
  );
}

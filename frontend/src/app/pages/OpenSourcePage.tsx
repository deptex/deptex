const GITHUB_REPO_URL = "https://github.com/deptex/deptex";

const REPO = {
  name: "deptex",
  repo: "deptex/deptex",
  description:
    "AI-powered dependency security — reachability-scored scanning and autonomous fixes, end to end.",
  contributingUrl: "https://github.com/deptex/deptex/blob/main/CONTRIBUTING.md",
  licenseUrl: "https://github.com/deptex/deptex/blob/main/LICENSE",
};

export default function OpenSourcePage() {
  return (
    <div>
      <section className="container mx-auto px-4 pt-28 lg:pt-32 pb-8 lg:pb-10">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 lg:gap-16 items-center max-w-6xl mx-auto">
          {/* Left: Open Source hero */}
          <div className="text-center lg:text-left">
            <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6 text-foreground">
              Open source
            </h1>
            <p className="text-xl text-foreground mb-8 leading-relaxed">
              The whole Deptex platform lives in one repository, licensed under AGPL-3.0 —
              read it, run it locally, and self-host it freely. Contributions welcome.
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
                href={REPO.licenseUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 text-foreground-secondary hover:text-foreground transition-colors"
              >
                <img src="/images/integrations/github.png" alt="" className="h-5 w-5 rounded-full" aria-hidden />
                <span>License (AGPL-3.0)</span>
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
              <p className="mt-3 text-sm text-foreground leading-relaxed">
                {REPO.description}
              </p>
              <div className="mt-6 flex items-center text-sm text-foreground-secondary">
                <span>{REPO.repo}</span>
              </div>
            </a>
          </div>
        </div>
      </section>
    </div>
  );
}

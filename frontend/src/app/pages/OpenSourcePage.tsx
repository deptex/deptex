import { useState } from "react";
import { Github, Star, Users, ExternalLink } from "lucide-react";

const repositories = [
  {
    name: "deptex",
    description: "The core dependency governance platform. Deptex helps organizations manage open source dependencies across projects and teams with deep tracking, policy enforcement, and AI-powered remediation.",
    repo: "deptex/deptex",
    forks: 124,
    stars: 2847,
  },
  {
    name: "deptex-cli",
    description: "Command-line interface for Deptex. Link repositories, run scans, manage watchlists, and interact with the Deptex platform from your terminal.",
    repo: "deptex/deptex-cli",
    forks: 43,
    stars: 892,
  },
  {
    name: "deptex-sdk",
    description: "TypeScript/JavaScript SDK for Deptex. Integrate dependency governance into your applications with a simple, type-safe API.",
    repo: "deptex/deptex-sdk",
    forks: 28,
    stars: 567,
  },
  {
    name: "deptex-scanner",
    description: "Universal dependency scanner supporting npm, pip, Maven, Go modules, and more. Parse lockfiles and build comprehensive dependency graphs.",
    repo: "deptex/deptex-scanner",
    forks: 67,
    stars: 1234,
  },
  {
    name: "deptex-policy-engine",
    description: "Policy-as-code engine for dependency governance. Define and enforce license policies, vulnerability thresholds, and custom rules.",
    repo: "deptex/deptex-policy-engine",
    forks: 35,
    stars: 789,
  },
  {
    name: "deptex-ai-agent",
    description: "AI-powered security agent for automated vulnerability remediation and compliance reporting.",
    repo: "deptex/deptex-ai-agent",
    forks: 52,
    stars: 1456,
  },
];

const tabs = [
  { name: "All", id: "all" },
  { name: "Core", id: "core" },
  { name: "SDKs", id: "sdks" },
  { name: "Tools", id: "tools" },
  { name: "Other", id: "other" },
];

export default function OpenSourcePage() {
  const [activeTab, setActiveTab] = useState("all");

  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="container mx-auto px-4 py-20 lg:py-32">
        <div className="max-w-5xl mx-auto text-center">
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6 text-foreground">
            Open Source Community
          </h1>
          <p className="text-xl text-foreground-secondary mb-12 max-w-3xl mx-auto leading-relaxed">
            Deptex is an open source company, actively fostering collaboration and supporting existing open source tools and communities.
          </p>
          
          {/* Community Links */}
          <div className="flex flex-wrap justify-center gap-6 mb-12">
            <a
              href="https://github.com/deptex/deptex/blob/main/CONTRIBUTING.md"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 text-foreground-secondary hover:text-foreground transition-colors"
            >
              <Github className="h-5 w-5" />
              <span>How to contribute</span>
            </a>
            <a
              href="https://github.com/deptex/deptex/blob/main/CODE_OF_CONDUCT.md"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 text-foreground-secondary hover:text-foreground transition-colors"
            >
              <Github className="h-5 w-5" />
              <span>Code of Conduct</span>
            </a>
            <a
              href="https://github.com/deptex"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 text-foreground-secondary hover:text-foreground transition-colors"
            >
              <Github className="h-5 w-5" />
              <span>GitHub Organization</span>
            </a>
          </div>
        </div>
      </section>

      {/* Tabs */}
      <section className="container mx-auto px-4 pb-8">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-wrap justify-center gap-2 border-b border-border/30 pb-4">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-2 text-sm font-medium transition-colors relative ${
                  activeTab === tab.id
                    ? "text-primary"
                    : "text-foreground-secondary hover:text-foreground"
                }`}
              >
                {tab.name}
                {activeTab === tab.id && (
                  <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-primary -mb-4"></div>
                )}
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* Repositories Grid */}
      <section className="container mx-auto px-4 py-12">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {repositories.map((repo) => (
              <div
                key={repo.name}
                className="rounded-lg border border-border/30 bg-background-card/35 backdrop-blur-lg p-6 hover:border-border hover:bg-background-card/60 transition-all duration-300"
              >
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <Github className="h-5 w-5 text-foreground-secondary" />
                    <a
                      href={`https://github.com/${repo.repo}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-lg font-semibold text-foreground hover:text-primary transition-colors flex items-center gap-2"
                    >
                      {repo.name}
                      <ExternalLink className="h-4 w-4" />
                    </a>
                  </div>
                </div>
                <p className="text-foreground-secondary mb-4 leading-relaxed text-sm">
                  {repo.description}
                </p>
                <div className="flex items-center gap-4 text-sm text-foreground-secondary">
                  <a
                    href={`https://github.com/${repo.repo}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 hover:text-foreground transition-colors"
                  >
                    <Github className="h-4 w-4" />
                    <span>{repo.repo}</span>
                  </a>
                </div>
                <div className="flex items-center gap-4 mt-4 pt-4 border-t border-border/30">
                  <div className="flex items-center gap-1 text-foreground-secondary text-sm">
                    <Users className="h-4 w-4" />
                    <span>{repo.forks}</span>
                  </div>
                  <div className="flex items-center gap-1 text-foreground-secondary text-sm">
                    <Star className="h-4 w-4" />
                    <span>{repo.stars}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}


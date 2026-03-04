import { useState } from "react";
import { Mail, Webhook } from "lucide-react";

const integrations = [
  {
    name: "GitHub",
    iconSrc: "/images/integrations/github.png",
    description: "Connect your repositories for automatic dependency scanning and security monitoring.",
    category: "Source Control",
  },
  {
    name: "GitLab",
    iconSrc: "/images/integrations/gitlab.png",
    description: "Integrate with GitLab repositories and CI/CD pipelines for seamless security workflows.",
    category: "Source Control",
  },
  {
    name: "Bitbucket",
    iconSrc: "/images/integrations/bitbucket.png",
    description: "Connect Bitbucket repositories for dependency scanning and security monitoring.",
    category: "Source Control",
  },
  {
    name: "Slack",
    iconSrc: "/images/integrations/slack.png",
    description: "Get real-time security alerts and vulnerability notifications directly in your Slack channels.",
    category: "Communication",
  },
  {
    name: "Discord",
    iconSrc: "/images/integrations/discord.png",
    description: "Send security alerts and notifications to your Discord channels.",
    category: "Communication",
  },
  {
    name: "Email",
    iconSrc: null,
    description: "Configure email notifications for critical vulnerabilities and compliance violations.",
    category: "Communication",
  },
  {
    name: "Jira",
    iconSrc: "/images/integrations/jira.png",
    description: "Automatically create Jira tickets for security issues and track remediation progress.",
    category: "Project Management",
  },
  {
    name: "Linear",
    iconSrc: "/images/integrations/linear.png",
    description: "Sync security issues with Linear for streamlined issue tracking and team collaboration.",
    category: "Project Management",
  },
  {
    name: "Asana",
    iconSrc: "/images/integrations/asana.png",
    description: "Track security remediation and tasks in Asana.",
    category: "Project Management",
  },
  {
    name: "Webhooks",
    iconSrc: null,
    description: "Build custom integrations with webhooks for any event in your security workflow.",
    category: "Custom",
  },
];

const categories = ["All", "Source Control", "Communication", "Project Management", "Custom"];

function IntegrationIcon({ integration }: { integration: typeof integrations[0] }) {
  if (integration.iconSrc) {
    return (
      <img
        src={integration.iconSrc}
        alt=""
        className="h-8 w-8 rounded-lg object-contain flex-shrink-0"
        aria-hidden
      />
    );
  }
  if (integration.name === "Email") return <Mail className="h-6 w-6 text-foreground-secondary flex-shrink-0" />;
  return <Webhook className="h-6 w-6 text-foreground-secondary flex-shrink-0" />;
}

export default function IntegrationsPage() {
  const [selectedCategory, setSelectedCategory] = useState("All");

  const filteredIntegrations = selectedCategory === "All"
    ? integrations
    : integrations.filter((i) => i.category === selectedCategory);

  return (
    <div className="min-h-screen">
      {/* Hero + Category in one tighter block */}
      <section className="container mx-auto px-4 pt-[84px] pb-6 lg:pt-[100px] lg:pb-8">
        <div className="max-w-5xl mx-auto text-center">
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6 text-foreground">
            Integrations
          </h1>
          <p className="text-xl text-foreground-secondary mb-8 max-w-3xl mx-auto leading-relaxed">
            Connect Deptex with your favorite tools and workflows. Seamlessly integrate security monitoring into your existing development and operations stack.
          </p>

          {/* Category filter – closer to subtitle */}
          <div className="flex flex-wrap justify-center gap-2">
            {categories.map((category) => {
              const isSelected = selectedCategory === category;
              return (
                <button
                  key={category}
                  onClick={() => setSelectedCategory(category)}
                  className={`px-4 py-2 rounded-full text-sm font-medium transition-all duration-200 ${
                    isSelected
                      ? "bg-primary text-primary-foreground border-2 border-primary-foreground/30 hover:border-primary-foreground/50"
                      : "bg-background-card/50 text-foreground-secondary border border-border/50 hover:bg-background-card hover:text-foreground hover:border-border"
                  }`}
                >
                  {category}
                </button>
              );
            })}
          </div>
        </div>
      </section>

      {/* Integrations Grid */}
      <section className="container mx-auto px-4 py-10">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {filteredIntegrations.map((integration) => (
              <div
                key={integration.name}
                className="rounded-xl border border-border/40 bg-background-card/40 backdrop-blur-sm p-5 hover:border-border hover:bg-background-card/70 transition-all duration-200"
              >
                <div className="flex items-start gap-3 mb-3">
                  <div className="flex items-center justify-center w-10 h-10 rounded-lg text-foreground-secondary flex-shrink-0">
                    <IntegrationIcon integration={integration} />
                  </div>
                  <h3 className="text-lg font-semibold text-foreground pt-1">
                    {integration.name}
                  </h3>
                </div>
                <p className="text-sm text-foreground-secondary leading-relaxed">
                  {integration.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}

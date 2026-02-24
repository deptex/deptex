import { useState } from "react";
import { Button } from "../../components/ui/button";
import { 
  Github, 
  Slack, 
  Mail, 
  Zap, 
  GitBranch,
  Webhook,
  Code,
  Shield,
  FileCode,
  Users
} from "lucide-react";

const integrations = [
  {
    name: "GitHub",
    icon: <Github className="h-6 w-6" />,
    description: "Connect your repositories for automatic dependency scanning and security monitoring.",
    category: "Source Control",
  },
  {
    name: "GitLab",
    icon: <GitBranch className="h-6 w-6" />,
    description: "Integrate with GitLab repositories and CI/CD pipelines for seamless security workflows.",
    category: "Source Control",
  },
  {
    name: "Slack",
    icon: <Slack className="h-6 w-6" />,
    description: "Get real-time security alerts and vulnerability notifications directly in your Slack channels.",
    category: "Communication",
  },
  {
    name: "Microsoft Teams",
    icon: <Users className="h-6 w-6" />,
    description: "Receive security updates and compliance reports in your Teams workspace.",
    category: "Communication",
  },
  {
    name: "Email",
    icon: <Mail className="h-6 w-6" />,
    description: "Configure email notifications for critical vulnerabilities and compliance violations.",
    category: "Communication",
  },
  {
    name: "Jira",
    icon: <FileCode className="h-6 w-6" />,
    description: "Automatically create Jira tickets for security issues and track remediation progress.",
    category: "Project Management",
  },
  {
    name: "Linear",
    icon: <Code className="h-6 w-6" />,
    description: "Sync security issues with Linear for streamlined issue tracking and team collaboration.",
    category: "Project Management",
  },
  {
    name: "PagerDuty",
    icon: <Zap className="h-6 w-6" />,
    description: "Escalate critical security incidents to on-call teams via PagerDuty.",
    category: "Incident Management",
  },
  {
    name: "Webhooks",
    icon: <Webhook className="h-6 w-6" />,
    description: "Build custom integrations with webhooks for any event in your security workflow.",
    category: "Custom",
  },
  {
    name: "CI/CD",
    icon: <Shield className="h-6 w-6" />,
    description: "Integrate with GitHub Actions, GitLab CI, Jenkins, and other CI/CD platforms.",
    category: "DevOps",
  },
];

const categories = ["All", "Source Control", "Communication", "Project Management", "Incident Management", "DevOps", "Custom"];

export default function IntegrationsPage() {
  const [selectedCategory, setSelectedCategory] = useState("All");

  const filteredIntegrations = selectedCategory === "All" 
    ? integrations 
    : integrations.filter(integration => integration.category === selectedCategory);

  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="container mx-auto px-4 py-20 lg:py-32">
        <div className="max-w-5xl mx-auto text-center">
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6 text-foreground">
            Integrations
          </h1>
          <p className="text-xl text-foreground-secondary mb-12 max-w-3xl mx-auto leading-relaxed">
            Connect Deptex with your favorite tools and workflows. Seamlessly integrate security monitoring into your existing development and operations stack.
          </p>
        </div>
      </section>

      {/* Category Filter */}
      <section className="container mx-auto px-4 pb-8">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-wrap justify-center gap-3">
            {categories.map((category) => (
              <button
                key={category}
                onClick={() => setSelectedCategory(category)}
                className={`px-4 py-2 rounded-full text-sm font-medium transition-all duration-200 ${
                  selectedCategory === category
                    ? "bg-primary text-primary-foreground"
                    : "bg-background-card/50 text-foreground-secondary hover:bg-background-card hover:text-foreground border border-border/30"
                }`}
              >
                {category}
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* Integrations Grid */}
      <section className="container mx-auto px-4 py-12">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredIntegrations.map((integration) => (
              <div
                key={integration.name}
                className="rounded-lg border border-border/30 bg-background-card/35 backdrop-blur-lg p-6 hover:border-border hover:bg-background-card/60 transition-all duration-300"
              >
                <div className="flex items-center gap-3 mb-4">
                  <div className="text-foreground-secondary">
                    {integration.icon}
                  </div>
                  <h3 className="text-xl font-semibold text-foreground">
                    {integration.name}
                  </h3>
                </div>
                <p className="text-foreground-secondary leading-relaxed mb-4">
                  {integration.description}
                </p>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-foreground-secondary/70 bg-background-subtle px-2 py-1 rounded">
                    {integration.category}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    className="text-xs"
                  >
                    Configure
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}


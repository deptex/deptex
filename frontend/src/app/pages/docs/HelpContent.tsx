import { Link } from "react-router-dom";

interface Faq {
  q: string;
  a: React.ReactNode;
}

const faqs: Faq[] = [
  {
    q: "How do I get started?",
    a: (
      <>
        Connect a repository through the GitHub App, GitLab, or Bitbucket from your organization, and
        Deptex scans it automatically. See{" "}
        <Link to="/docs/projects" className="text-accent-text hover:underline">
          Projects
        </Link>{" "}
        for the details.
      </>
    ),
  },
  {
    q: "Why don't I see any findings?",
    a: (
      <>
        The first scan may still be running — check the project&apos;s scan status. Also note that
        unreachable vulnerabilities are hidden by default, so a noisy dependency tree won&apos;t bury
        the issues that matter. See{" "}
        <Link to="/docs/reachability-depscore" className="text-accent-text hover:underline">
          Reachability &amp; Depscore
        </Link>
        .
      </>
    ),
  },
  {
    q: "A scan is stuck or failed — what should I do?",
    a: "Scans retry automatically after transient failures. You can also trigger a manual rescan from the project at any time. If it keeps failing, get in touch and we'll take a look.",
  },
  {
    q: "How is a finding's priority decided?",
    a: (
      <>
        Every finding gets a reachability-aware{" "}
        <Link to="/docs/reachability-depscore" className="text-accent-text hover:underline">
          Depscore
        </Link>
        , so what&apos;s genuinely exploitable in your code rises to the top — not just whatever has
        the highest raw severity.
      </>
    ),
  },
  {
    q: "Can Aegis fix issues for me?",
    a: (
      <>
        Yes. Hand{" "}
        <Link to="/docs/aegis" className="text-accent-text hover:underline">
          Aegis
        </Link>{" "}
        a finding and it investigates, proposes a plan, and opens a draft pull request you review and
        merge — nothing ships without your approval.
      </>
    ),
  },
  {
    q: "How does billing work?",
    a: (
      <>
        Deptex is prepaid and usage-based — you top up a balance and AI and scan compute draw it down
        as you go. See{" "}
        <Link to="/docs/billing" className="text-accent-text hover:underline">
          Billing &amp; usage
        </Link>
        .
      </>
    ),
  },
  {
    q: "How do I add teammates?",
    a: (
      <>
        Invite members by email and assign them a role. See{" "}
        <Link to="/docs/organizations" className="text-accent-text hover:underline">
          Organizations &amp; roles
        </Link>{" "}
        for how roles and team-scoped access work.
      </>
    ),
  },
];

export default function HelpContent() {
  return (
    <div className="space-y-12">
      <section>
        <p className="text-foreground/90 leading-relaxed">
          Stuck, or have a question? Start with the common questions below — and if you still need a
          hand, we&apos;re an email away.
        </p>
      </section>

      <section>
        <h2 className="text-lg font-semibold text-foreground mb-4">Frequently asked questions</h2>
        <div className="rounded-lg border border-border bg-background-card divide-y divide-border">
          {faqs.map((faq) => (
            <div key={faq.q} className="p-5">
              <h3 className="font-medium text-foreground">{faq.q}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-foreground/80">{faq.a}</p>
            </div>
          ))}
        </div>
      </section>

      <section>
        <h2 className="text-lg font-semibold text-foreground mb-2">Still need help?</h2>
        <p className="text-foreground/90 leading-relaxed">
          Email us at{" "}
          <a
            href="mailto:deptex.app@gmail.com"
            className="text-accent-text hover:underline"
          >
            deptex.app@gmail.com
          </a>{" "}
          and we&apos;ll get back to you. You can also send feedback any time from the profile menu
          inside the app.
        </p>
      </section>
    </div>
  );
}

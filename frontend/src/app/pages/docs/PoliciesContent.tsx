import { Link } from "react-router-dom";

const policyFunctions = [
  { name: "packagePolicy(context)", trigger: "Per-dependency during policy evaluation", returns: "{ allowed, reasons }" },
  { name: "projectStatus(context)", trigger: "After extraction or on-demand", returns: "{ status, violations }" },
  { name: "pullRequestCheck(context)", trigger: "PR / merge request that changes dependencies", returns: "{ status, violations }" },
];

export default function PoliciesContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <div className="space-y-3 text-foreground/90 leading-relaxed">
          <p>
            Deptex <strong className="text-foreground">Policy-as-Code</strong> lets you define organization-wide rules as JavaScript functions.
            Your policy code is evaluated against real dependency and vulnerability data whenever a PR changes dependencies or after each extraction.
          </p>
          <p>
            Define up to three functions: <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">packagePolicy</code> to allow or block
            individual packages, <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">projectStatus</code> to assign a compliance status
            to the project, and <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">pullRequestCheck</code> to gate merges.
            Each receives a rich context object with dependency and vulnerability data.
          </p>
        </div>
      </div>

      {/* Custom Statuses */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Custom Statuses</h2>
        <p className="text-foreground/90 leading-relaxed">
          Organizations define statuses in <strong className="text-foreground">Settings → Statuses</strong>: name, color, rank, and{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">is_passing</code>. Policy functions return one of these status names.
          The <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">is_passing</code> flag determines whether a status counts as passing for PR checks.
        </p>
      </div>

      {/* Policy Functions */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Policy Functions</h2>
        <p className="text-foreground/90 leading-relaxed mb-4">
          Define any of these three functions. Each is optional.
        </p>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Function</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Trigger</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Returns</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {policyFunctions.map((fn) => (
                <tr key={fn.name} className="hover:bg-table-hover transition-colors">
                  <td className="px-4 py-3 font-mono text-xs text-foreground">{fn.name}</td>
                  <td className="px-4 py-3 text-sm text-foreground/90">{fn.trigger}</td>
                  <td className="px-4 py-3 font-mono text-xs text-foreground/90">{fn.returns}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Context */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Context</h2>
        <p className="text-foreground/90 leading-relaxed mb-4">
          Each function receives a <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">context</code> object. Key fields:
        </p>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Function</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Context Fields</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">packagePolicy</td>
                <td className="px-4 py-3 text-foreground/90"><code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">dependency</code> (name, version, license, score, vulnerabilities, supply-chain signals), <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">tier</code></td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">projectStatus</td>
                <td className="px-4 py-3 text-foreground/90"><code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">project</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">dependencies</code> (each with <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">policyResult</code>)</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">pullRequestCheck</td>
                <td className="px-4 py-3 text-foreground/90"><code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">project</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">added</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">updated</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">removed</code> (dependency arrays)</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p className="text-foreground/90 leading-relaxed mt-3 text-sm">
          Dependencies include license, score, vulnerabilities, reachability, and supply-chain signals (registry_integrity_status, install_scripts_status, entropy_analysis_status).
        </p>
      </div>

      {/* Built-in Functions */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Built-in Helpers</h2>
        <p className="text-foreground/90 leading-relaxed mb-3">
          Policy code runs in a sandbox with these helpers:
        </p>
        <ul className="list-disc list-inside space-y-1 text-foreground/90 text-sm">
          <li><code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">isLicenseAllowed(license, allowlist)</code> — Returns true if the license matches the allowlist (SPDX identifiers).</li>
          <li><code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">semverGt(a, b)</code> — Semver comparison: true if a &gt; b.</li>
          <li><code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">daysSince(dateString)</code> — Days elapsed since the given ISO 8601 date.</li>
          <li><code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">fetch(url, options)</code> — Async HTTP requests (proxied; handle errors).</li>
        </ul>
      </div>

      {/* Examples */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Examples</h2>
        <p className="text-foreground/90 leading-relaxed mb-4">
          Copy and adapt in Settings → Policies. See <Link to="/docs/compliance" className="text-foreground underline hover:no-underline">Compliance</Link> for policy changes and exceptions.
        </p>
        <div className="space-y-6">
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-2">License block (packagePolicy)</h3>
            <pre className="rounded-lg border border-border bg-background-card p-4 text-sm text-foreground overflow-x-auto font-mono">
{`const BANNED = ["AGPL-3.0", "GPL-3.0"];
function packagePolicy(context) {
  const lic = context.dependency.license || "UNKNOWN";
  if (BANNED.some(b => lic.includes(b))) {
    return { allowed: false, reasons: ["Banned license: " + lic] };
  }
  return { allowed: true, reasons: [] };
}`}
            </pre>
          </div>
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-2">Depscore threshold (packagePolicy)</h3>
            <pre className="rounded-lg border border-border bg-background-card p-4 text-sm text-foreground overflow-x-auto font-mono">
{`function packagePolicy(context) {
  const dep = context.dependency;
  const vulns = dep.vulnerabilities || [];
  const high = vulns.filter(v => (v.depscore || 0) > 70);
  if (high.length > 0) {
    return { allowed: false, reasons: ["High-risk vulns: " + high.map(v => v.osv_id).join(", ")] };
  }
  return { allowed: true, reasons: [] };
}`}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}

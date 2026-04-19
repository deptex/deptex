import { Link } from "react-router-dom";
import { DocsCodeBlock } from "../../../components/DocsCodeBlock";

const policyFunctions = [
  { name: "packagePolicy(context)", trigger: "Per-dependency during policy evaluation", returns: "{ allowed, reasons }" },
  { name: "projectStatus(context)", trigger: "After extraction or on-demand", returns: "{ status, violations }" },
  { name: "pullRequestCheck(context)", trigger: "PR / merge request that changes dependencies", returns: "{ passed, violations } — passed: true to allow merge, passed: false to block" },
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
        <div className="space-y-3 text-foreground/90 leading-relaxed">
          <p>
            Organizations define statuses in <strong className="text-foreground">Settings → Statuses</strong>: each has a <strong className="text-foreground">name</strong>,{" "}
            <strong className="text-foreground">color</strong>, and <strong className="text-foreground">rank</strong> (for ordering in lists and badges). System statuses ship by default; you can add your own and reorder. Status names are what your policy code returns — there is no separate pass/fail flag on the status itself; you simply return the status string you want the project to show.
          </p>
          <p>
            After extraction (or when policies re-run), Deptex calls your <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">projectStatus(context)</code> function once per project. It must return <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">&#123; status: &quot;…&quot;, violations: [] &#125;</code> where <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">status</code> matches one of your org status names exactly. Merge gating is handled separately by <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">pullRequestCheck</code> (<code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">passed: true/false</code>), not by the project status label.
          </p>
          <p className="text-sm">
            Edit the status code in <strong className="text-foreground">Settings → Statuses → Status Code</strong>; the editor shows only the function body (the engine wraps it in <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">function projectStatus(context) &#123; … &#125;</code>).
          </p>
        </div>
      </div>

      {/* Asset tiers */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Asset tiers</h2>
        <div className="space-y-3 text-foreground/90 leading-relaxed">
          <p>
            <strong className="text-foreground">Asset tiers</strong> live under <strong className="text-foreground">Settings → Statuses → Asset Tiers</strong> (same area as custom statuses). Each project has an asset tier (e.g. Crown Jewels, External, Internal, Non-Production). Tiers define an <strong className="text-foreground">environmental multiplier</strong> used when computing Depscore so higher-criticality projects weight vulnerability risk more heavily.
          </p>
          <p>
            In <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">packagePolicy</code>, every call includes <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">context.tier</code> (name, rank, etc.) for the <strong className="text-foreground">project&apos;s</strong> tier — so you can write stricter rules for Crown Jewels than for Non-Production. The default org <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">packagePolicy</code> uses <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">context.tier.rank</code> to apply different license and score thresholds per tier.
          </p>
          <p className="text-sm">
            Tiers are optional in <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">projectStatus</code> context today (<code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">context.project</code> includes tier name where the engine provides it); the main tie-in is per-dependency evaluation in <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">packagePolicy</code>. See <Link to="/docs/organizations" className="text-foreground underline hover:no-underline">Organizations</Link> for where tiers are managed in Settings.
          </p>
        </div>
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
                <td className="px-4 py-3 text-foreground/90"><code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">dependency</code> (one package per call: name, version, license, dependencyScore, openSsfScore, weeklyDownloads, lastPublishedAt, releasesLast12Months, maliciousIndicator, slsaLevel), <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">tier</code>. No <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">context.dependencies</code> — the engine calls this once per dependency.</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">projectStatus</td>
                <td className="px-4 py-3 text-foreground/90"><code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">project</code> (name, tier when available), <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">dependencies</code> (each with <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">policyResult</code> from <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">packagePolicy</code>), <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">statuses</code> (org status names)</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">pullRequestCheck</td>
                <td className="px-4 py-3 text-foreground/90"><code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">project</code> (name, id, asset_tier), <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">ecosystem</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">changed_files</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">added</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">updated</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">removed</code> (each dep has name, version, license, policyResult, vulnerability_counts, is_direct), <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">statuses</code></td>
              </tr>
            </tbody>
          </table>
        </div>
        <p className="text-foreground/90 leading-relaxed mt-3 text-sm">
          For <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">packagePolicy</code>, you receive a single <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">context.dependency</code> and <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">context.tier</code> each time the engine runs your function. Supply-chain checks (registry integrity, install scripts, entropy) are available on the Watchtower and Supply Chain pages, not in package policy.
        </p>
        <p className="text-foreground/90 leading-relaxed mt-2 text-sm">
          For <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">projectStatus</code>, the engine builds <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">context</code> after running <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">packagePolicy</code> on every dependency. Exact shape: <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">context.project</code> = <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">&#123; name, tier: &#123; name, rank, multiplier &#125;, teamName &#125;</code>; <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">context.dependencies</code> = array of <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">name</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">version</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">license</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">dependencyScore</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">policyResult: &#123; allowed, reasons &#125;</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">isDirect</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">isDevDependency</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">filesImportingCount</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">isOutdated</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">versionsBehind</code>, and <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">vulnerabilities</code> (array of <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">osvId</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">severity</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">depscore</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">isReachable</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">cisaKev</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">fixedVersions</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">summary</code>); <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">context.statuses</code> = array of org status name strings (return <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">status</code> as one of these).
        </p>
        <p className="text-foreground/90 leading-relaxed mt-2 text-sm">
          <strong>Malicious indicator:</strong> The platform may set <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">context.dependency.maliciousIndicator</code> when a package is flagged (e.g. from supply-chain or advisory signals). It is an object with <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">source</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">confidence</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">reason</code>, or null if not flagged. You can block with e.g. <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">if (context.dependency.maliciousIndicator) return &#123; allowed: false, reasons: [&#39;Package flagged as malicious&#39;] &#125;;</code>
        </p>
      </div>

      {/* Built-in Functions */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Built-in Helpers</h2>
        <p className="text-foreground/90 leading-relaxed mb-3">
          Policy code runs in a sandbox with these helpers:
        </p>
        <ul className="list-disc list-inside space-y-1 text-foreground/90 text-sm">
          <li><code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">isLicenseAllowed(license, allowlist)</code> — Returns true if the license matches the allowlist you pass (e.g. <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">isLicenseAllowed(context.dependency.license, [&apos;MIT&apos;, &apos;Apache-2.0&apos;])</code>). The allowlist is defined in your policy code, not an org setting.</li>
          <li><code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">semverGt(a, b)</code> / <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">semverLt(a, b)</code> — Compare version strings (e.g. for minimum version or upgrade checks).</li>
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
        <p className="text-foreground/90 leading-relaxed mb-2 text-sm">
          Allowing only certain licenses is done in <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">packagePolicy</code> by checking <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">context.dependency.license</code> for each dependency (the engine calls your function once per dependency); there is no <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">context.dependencies</code> array in packagePolicy.
        </p>
        <div className="space-y-8">
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">License block (packagePolicy)</h3>
            <DocsCodeBlock
              title="packagePolicy"
              value={`const BANNED = ["AGPL-3.0", "GPL-3.0"];
function packagePolicy(context) {
  const lic = context.dependency.license || "UNKNOWN";
  if (BANNED.some(b => lic.includes(b))) {
    return { allowed: false, reasons: ["Banned license: " + lic] };
  }
  return { allowed: true, reasons: [] };
}`}
            />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">Depscore threshold (packagePolicy)</h3>
            <DocsCodeBlock
              title="packagePolicy"
              value={`function packagePolicy(context) {
  const dep = context.dependency;
  const vulns = dep.vulnerabilities || [];
  const high = vulns.filter(v => (v.depscore || 0) > 70);
  if (high.length > 0) {
    return { allowed: false, reasons: ["High-risk vulns: " + high.map(v => v.osv_id).join(", ")] };
  }
  return { allowed: true, reasons: [] };
}`}
            />
          </div>

          <h3 className="text-sm font-semibold text-foreground mt-6 mb-2">Pull request check (pullRequestCheck)</h3>
          <p className="text-foreground/90 text-sm mb-3">
            Return <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">&#123; passed: true, violations: [] &#125;</code> to allow the merge, or <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">&#123; passed: false, violations: [...] &#125;</code> to block. Use <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">context.added</code> and <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">context.updated</code> (each item has <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">policyResult</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">vulnerability_counts</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">license</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">is_direct</code>).
          </p>
          <div>
            <h4 className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider mb-2">Always pass</h4>
            <DocsCodeBlock
              title="pullRequestCheck"
              value={`function pullRequestCheck(context) {
  return { passed: true, violations: [] };
}`}
            />
          </div>
          <div className="mt-6">
            <h4 className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider mb-2">Block policy violations on new or updated deps</h4>
            <DocsCodeBlock
              title="pullRequestCheck"
              value={`function pullRequestCheck(context) {
  const newViolations = context.added.concat(context.updated).filter(function(d) {
    return d.policyResult && !d.policyResult.allowed;
  });
  if (newViolations.length > 0) {
    const violations = newViolations.map(function(d) {
      return d.name + ': ' + (d.policyResult.reasons || []).join(', ');
    });
    return { passed: false, violations: violations };
  }
  return { passed: true, violations: [] };
}`}
            />
          </div>

          <h3 className="text-sm font-semibold text-foreground mt-8 mb-2">Project status (projectStatus)</h3>
          <p className="text-foreground/90 text-sm mb-3">
            Return <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">&#123; status: &quot;StatusName&quot;, violations: [] &#125;</code>. The <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">status</code> string must match a status you defined under Settings → Statuses. Use <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">context.dependencies</code> (each entry can include <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">policyResult</code> from <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">packagePolicy</code>) to decide which label to apply.
          </p>
          <div>
            <h4 className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider mb-2">Default (org seed): Compliant unless any dependency disallowed</h4>
            <p className="text-foreground/90 text-sm mb-3">
              New organizations get this as the initial Status Code. It aggregates <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">packagePolicy</code> results: if any dependency has <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">policyResult.allowed === false</code>, the project becomes <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">Non-Compliant</code> with reasons; otherwise <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">Compliant</code>.
            </p>
            <DocsCodeBlock
              title="projectStatus"
              value={`function projectStatus(context) {
  var deps = context.dependencies || [];
  var blocked = deps.filter(function(d) {
    return d.policyResult && d.policyResult.allowed === false;
  });
  if (blocked.length > 0) {
    return {
      status: 'Non-Compliant',
      violations: blocked.map(function(d) {
        return d.name + ': ' + (d.policyResult.reasons || []).join(', ');
      })
    };
  }
  return { status: 'Compliant', violations: [] };
}`}
            />
          </div>
          <div className="mt-6">
            <h4 className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider mb-2">Always Compliant (override)</h4>
            <DocsCodeBlock
              title="projectStatus"
              value={`function projectStatus(context) {
  return { status: "Compliant", violations: [] };
}`}
            />
          </div>
          <div className="mt-6">
            <h4 className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider mb-2">Same pattern, different status name</h4>
            <p className="text-foreground/90 text-sm mb-3">
              If you add a status like &quot;Action Required&quot; in Settings → Statuses, you can return that name instead of <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">Non-Compliant</code> when deps are blocked.
            </p>
            <DocsCodeBlock
              title="projectStatus"
              value={`function projectStatus(context) {
  var deps = context.dependencies || [];
  var blocked = deps.filter(function(d) {
    return d.policyResult && d.policyResult.allowed === false;
  });
  if (blocked.length > 0) {
    return {
      status: "Action Required",
      violations: blocked.map(function(d) {
        return d.name + ": " + (d.policyResult.reasons || []).join(", ");
      })
    };
  }
  return { status: "Compliant", violations: [] };
}`}
            />
          </div>
        </div>
      </div>
    </div>
  );
}

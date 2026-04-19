export default function WatchtowerContent() {
  return (
    <div className="space-y-12">
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">What is Watchtower</h2>
        <div className="space-y-3 text-foreground/90 leading-relaxed">
          <p>
            <strong className="text-foreground">Watchtower</strong> is Deptex&apos;s proactive supply chain defense system. Enable it per-project
            to automatically monitor all direct dependencies for registry tampering, malicious install scripts, obfuscated payloads,
            and suspicious contributor activity.
          </p>
          <p>
            When you enable Watchtower, all direct dependencies are added to the watchlist. New dependencies from future extractions
            are automatically included.
          </p>
        </div>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Security Checks</h2>
        <div className="space-y-4 text-foreground/90 leading-relaxed">
          <p>
            <strong className="text-foreground">Registry Integrity</strong> — Compares the published npm tarball against the git source at the
            tagged commit. A failure means the published package contains code not in the repository — a strong indicator of compromise.
          </p>
          <p>
            <strong className="text-foreground">Install Script Analysis</strong> — Scans preinstall, install, and postinstall scripts for network
            access, shell execution, and dangerous operations. Malicious packages exploit these for code execution on{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">npm install</code>.
          </p>
          <p>
            <strong className="text-foreground">Entropy Analysis</strong> — Detects obfuscated or encoded payloads. High-entropy files suggest
            hidden malicious code.
          </p>
          <p>
            <strong className="text-foreground">Commit Anomaly Detection</strong> — Scores each commit against the contributor&apos;s historical
            baseline (files changed, timing, message patterns). Flags unusual activity that may indicate account compromise.
          </p>
        </div>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Quarantine System</h2>
        <p className="text-foreground/90 leading-relaxed">
          Hold new versions for 7 days before allowing upgrades. During quarantine, bump PRs are blocked. Toggle per-package from the
          Watchtower tab. Versions that fail security checks are blocked regardless of quarantine.
        </p>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">PR Guardrails</h2>
        <p className="text-foreground/90 leading-relaxed">
          When Watchtower is enabled, PR guardrails automatically block upgrades to versions that failed security checks or are quarantined.
          PRs that attempt to upgrade to a blocked version receive a detailed failure message.
        </p>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">How to Enable</h2>
        <div className="space-y-3 text-foreground/90 leading-relaxed">
          <p>
            Watchtower is enabled <strong className="text-foreground">per project</strong>. Go to your project&apos;s{" "}
            <strong className="text-foreground">Watchtower</strong> tab and click <strong className="text-foreground">&ldquo;Enable Watchtower&rdquo;</strong>.
            All direct dependencies are added to the watch list; new ones from future extractions are auto-included.
          </p>
          <p>
            The <strong className="text-foreground">organization Watchtower page</strong> (from the org sidebar) shows an overview of all projects
            with Watchtower enabled: aggregated alerts, cross-project package coverage, and per-project activation status.
          </p>
        </div>
      </div>
    </div>
  );
}

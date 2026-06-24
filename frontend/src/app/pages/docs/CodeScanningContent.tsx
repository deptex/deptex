import { Link } from "react-router-dom";
import { FileCode, KeyRound, Waypoints } from "lucide-react";
import type { LucideIcon } from "lucide-react";

interface Area {
  label: string;
  icon: LucideIcon;
  body: React.ReactNode;
}

const areas: Area[] = [
  {
    label: "Static analysis (SAST)",
    icon: FileCode,
    body: "Rule packs flag injection, unsafe APIs, weak cryptography, and other risky patterns directly in the source you write.",
  },
  {
    label: "Secret detection",
    icon: KeyRound,
    body: "Deptex scans your repository for committed credentials and API keys and verifies them against the provider where possible, so you focus on secrets that are actually live rather than chasing false positives.",
  },
  {
    label: "Data-flow analysis",
    icon: Waypoints,
    body: (
      <>
        The taint engine traces untrusted input from where it enters your app to a dangerous sink,
        surfacing real end-to-end exploit paths in your first-party code instead of isolated
        warnings. Each flow is graded by{" "}
        <Link to="/docs/reachability-depscore" className="text-accent-text hover:underline">
          reachability
        </Link>{" "}
        like everything else.
      </>
    ),
  },
];

export default function CodeScanningContent() {
  return (
    <div className="space-y-12">
      <section>
        <p className="text-foreground/90 leading-relaxed">
          Deptex scans the code you write — not just the packages you import — for vulnerabilities,
          dangerous data flows, and leaked secrets. Your source is parsed with tree-sitter across
          eight languages, so the analysis understands your code structurally rather than
          pattern-matching raw text.
        </p>
      </section>

      <section>
        <h2 className="text-lg font-semibold text-foreground mb-4">What Deptex checks</h2>
        <div className="rounded-lg border border-border bg-background-card divide-y divide-border">
          {areas.map((area) => {
            const Icon = area.icon;
            return (
              <div key={area.label} className="flex gap-4 p-5">
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-border bg-background-subtle">
                  <Icon className="h-5 w-5 text-foreground" />
                </span>
                <div>
                  <h3 className="font-medium text-foreground">{area.label}</h3>
                  <p className="mt-1 text-sm leading-relaxed text-foreground/80">{area.body}</p>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}

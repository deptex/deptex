/**
 * Framework band — "Use Deptex with any stack" (founder 2026-06-19, Supabase
 * "any framework" reference). A standalone logos strip proving the polyglot
 * breadth behind "every layer of your stack": real FrameworkIcon glyphs
 * (Simple Icons), monochrome, one wrapping row. Hovering a logo swaps the
 * "any stack" label to that framework's name (the hovered logo brightens).
 *
 * NOT the integration logos we cut earlier — "we post to Slack" is table
 * stakes; going deep across 8 languages, 8 ecosystems and 34 frameworks is a
 * hard capability competitors (great at JS/Python, weak elsewhere) don't have.
 */
import { useState } from "react";
import { FrameworkIcon } from "../framework-icon";
import { Reveal } from "./primitives";

// One representative framework per language + the IaC formats, spanning every
// ecosystem we scan. frameworkId keys must match framework-icon.tsx's map
// (note: Docker is "dockerfile").
const STACK: { id: string; name: string }[] = [
  { id: "react", name: "React" },
  { id: "nextjs", name: "Next.js" },
  { id: "vue", name: "Vue" },
  { id: "express", name: "Express" },
  { id: "django", name: "Django" },
  { id: "fastapi", name: "FastAPI" },
  { id: "spring-boot", name: "Spring Boot" },
  { id: "gin", name: "Gin" },
  { id: "rust", name: "Rust" },
  { id: "dotnet", name: ".NET" },
  { id: "rails", name: "Rails" },
  { id: "laravel", name: "Laravel" },
  { id: "dockerfile", name: "Docker" },
  { id: "kubernetes", name: "Kubernetes" },
  { id: "terraform", name: "Terraform" },
];

export default function FrameworkBand() {
  const [hovered, setHovered] = useState<string | null>(null);

  return (
    <section className="w-full border-t border-white/[0.08]">
      <div className="mx-auto max-w-[1200px] px-6 py-16">
        <Reveal>
          <div className="flex flex-col gap-8 sm:flex-row sm:items-center sm:justify-between sm:gap-12">
            <p className="shrink-0 text-2xl font-semibold leading-tight tracking-[-0.01em]">
              <span className="text-foreground-secondary">Use Deptex with</span>
              <br />
              {/* key tied to the value → remounts + replays the enter anim on
                  every swap: the new word rises up and fades in (Supabase). */}
              <span
                key={hovered ?? "any-stack"}
                className="inline-block text-foreground animate-in fade-in-0 slide-in-from-bottom-2 duration-300 ease-out"
              >
                {hovered ?? "any stack"}
              </span>
            </p>
            <div
              className="flex flex-wrap items-center gap-x-7 gap-y-5"
              onMouseLeave={() => setHovered(null)}
            >
              {STACK.map((s) => (
                <span
                  key={s.id}
                  aria-label={s.name}
                  onMouseEnter={() => setHovered(s.name)}
                  className="inline-flex cursor-default"
                >
                  <FrameworkIcon
                    frameworkId={s.id}
                    size={30}
                    className={`transition-colors ${
                      hovered === s.name
                        ? "text-foreground"
                        : "text-foreground-secondary"
                    }`}
                  />
                </span>
              ))}
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

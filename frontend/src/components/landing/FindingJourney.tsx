/**
 * FindingJourney — the page's flagship argument, as product film.
 * One real screen recording follows ONE finding end to end: the wall of
 * advisories → noise auto-ignored with reasons → the one that matters,
 * scored in your repo's context → Aegis plans the fix.
 *
 * 2026-06-12 (founder): header copy + the 3-column chapter rail were cut in
 * favor of a Railway-style dock straddling the panel's bottom edge — chapter
 * pills with a live progress fill synced to playback. The film now opens the
 * page's argument directly under the hero, no framing copy.
 *
 * Asset: /videos/landing/finding-journey.webm is currently the DUMMY take
 * (uncommitted, local only) — the real take replaces it file-for-file once
 * the Aegis dogfood thread is cleaned up. Poster renders if the file 404s.
 */
import { Fragment, useEffect, useRef, useState } from "react";
import { Filter, GitPullRequest, Plug } from "lucide-react";
import { Reveal } from "./primitives";

/**
 * Chapter marks, in seconds of the current cut. Re-time when the real take
 * lands. Agreed shot list for the real take (2026-06-12):
 *   Connect — create project, pick repo, live extraction logs streaming +
 *             project node landing on the org canvas.
 *   Triage  — findings table fills, wall collapses (141 → 28) as auto-ignore
 *             kills noise with reasons, depscore pills, open the confirmed
 *             finding + reachability trace.
 *   Fix     — send to Aegis, the plan, Approve, the PR diff.
 * (A possible 4th chapter, "Prevent" — PR check blocking a vulnerable dep —
 * is parked until the 3-act cut exists.)
 */
const CHAPTERS = [
  {
    icon: Plug,
    verb: "Connect",
    label: "Point Deptex at a repo — the scan streams live.",
    at: 0,
  },
  {
    icon: Filter,
    verb: "Triage",
    label: "Scores land in your repo's context; noise auto-ignores itself with reasons.",
    at: 7,
  },
  {
    icon: GitPullRequest,
    verb: "Fix",
    label: "Aegis investigates and writes the fix.",
    at: 29,
  },
];

export default function FindingJourney() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const fillRef = useRef<HTMLSpanElement>(null);
  const [active, setActive] = useState(0);

  // Play only while on screen; browsers may block autoplay anyway, so this is
  // also the retry point. Reduced-motion users get the poster + controls.
  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) {
      video.controls = true;
      return;
    }
    const io = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) video.play().catch(() => {});
        else video.pause();
      },
      { threshold: 0.35 }
    );
    io.observe(video);
    return () => io.disconnect();
  }, []);

  // Progress fill on the active pill — rAF writes the transform directly so
  // the bar moves at frame rate without re-rendering React every frame
  // (onTimeUpdate only fires ~4Hz, which reads as a choppy stutter).
  useEffect(() => {
    let raf = 0;
    const tick = () => {
      const video = videoRef.current;
      const fill = fillRef.current;
      if (video && fill) {
        const t = video.currentTime;
        let idx = 0;
        for (let i = 0; i < CHAPTERS.length; i++) if (t >= CHAPTERS[i].at) idx = i;
        const start = CHAPTERS[idx].at;
        const end =
          idx < CHAPTERS.length - 1 ? CHAPTERS[idx + 1].at : video.duration || start + 1;
        const p = Math.min(1, Math.max(0, (t - start) / Math.max(0.1, end - start)));
        fill.style.transform = `scaleX(${p})`;
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);

  const onTimeUpdate = () => {
    const t = videoRef.current?.currentTime ?? 0;
    let idx = 0;
    for (let i = 0; i < CHAPTERS.length; i++) if (t >= CHAPTERS[i].at) idx = i;
    if (idx !== active) setActive(idx);
  };

  const seekTo = (i: number) => {
    const video = videoRef.current;
    if (!video) return;
    video.currentTime = CHAPTERS[i].at;
    video.play().catch(() => {});
  };

  return (
    <section className="w-full bg-[#050505]">
      <div className="mx-auto max-w-[1200px] px-6 pb-24 pt-10 sm:pb-32 sm:pt-14">
        <Reveal>
          {/* Film panel — keyline + faint glow, video bleeds to the frame edge. */}
          <div className="relative">
            <div
              className="glow-green pointer-events-none absolute -inset-16 opacity-40"
              aria-hidden
            />
            <div className="relative overflow-hidden rounded-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),0_0_0_1px_#262626]">
              <video
                ref={videoRef}
                muted
                loop
                playsInline
                preload="none"
                poster="/images/landing/finding-journey-poster.jpg"
                onTimeUpdate={onTimeUpdate}
                className="block aspect-[8/5] w-full bg-[#0a0a0a]"
              >
                <source src="/videos/landing/finding-journey.webm" type="video/webm" />
              </video>
            </div>

            {/* Chapter dock — straddles the panel's bottom edge (Railway
                pattern). Active pill carries the live progress fill. */}
            <div className="absolute inset-x-0 -bottom-5 z-10 flex justify-center">
              <div className="flex items-center gap-1 rounded-full border border-[#262626] bg-[#0b0b0b]/95 p-1.5 shadow-[0_8px_24px_rgba(0,0,0,0.55)] backdrop-blur">
                {CHAPTERS.map((c, i) => {
                  const Icon = c.icon;
                  return (
                    <Fragment key={c.verb}>
                      {i > 0 && (
                        <span className="h-4 w-px shrink-0 bg-[#262626]" aria-hidden />
                      )}
                      <button
                        type="button"
                        onClick={() => seekTo(i)}
                        aria-label={`Jump to chapter: ${c.label}`}
                        className={`relative flex items-center gap-2 overflow-hidden rounded-full px-3 py-1.5 text-[13px] font-medium transition-colors sm:px-4 ${
                          i === active
                            ? "bg-[#34d08a]/[0.06] text-accent-text shadow-[inset_0_0_0_1px_rgba(52,208,138,0.35)]"
                            : "text-foreground-secondary hover:bg-white/[0.04] hover:text-foreground"
                        }`}
                      >
                        {i === active && (
                          <span
                            ref={fillRef}
                            className="absolute inset-0 origin-left scale-x-0 bg-[#34d08a]/[0.10]"
                            aria-hidden
                          />
                        )}
                        <Icon className="relative h-3.5 w-3.5" aria-hidden />
                        <span className="relative">{c.verb}</span>
                      </button>
                    </Fragment>
                  );
                })}
              </div>
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

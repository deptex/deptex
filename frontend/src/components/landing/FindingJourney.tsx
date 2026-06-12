/**
 * FindingJourney — the page's flagship argument, as product film.
 * One real screen recording follows ONE finding end to end: the wall of
 * advisories → noise auto-ignored with reasons → the one that matters,
 * scored in your repo's context → Aegis plans the fix.
 *
 * The timeline/cards treatment was cut 2026-06-11 (founder: "AI generated");
 * research verdict: at the Vercel/Linear tier, sequence sections are one
 * full-width native artifact, never spine+steps+mini-cards.
 *
 * Asset: /videos/landing/finding-journey.webm is currently the DUMMY take
 * (uncommitted, local only) — the real take replaces it file-for-file once
 * the Aegis dogfood thread is cleaned up. Poster renders if the file 404s.
 */
import { useEffect, useRef, useState } from "react";
import { Reveal } from "./primitives";

/** Chapter marks, in seconds of the current cut. Re-time when the real take lands. */
const CHAPTERS = [
  { n: "01", verb: "reported", label: "An advisory lands. Every scanner pages you.", at: 0 },
  { n: "02", verb: "scored", label: "Your repo's context sets the real score.", at: 7 },
  { n: "03", verb: "fixed", label: "Aegis investigates and writes the fix.", at: 29 },
];

export default function FindingJourney() {
  const videoRef = useRef<HTMLVideoElement>(null);
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
      {/* Tight top padding + compact header: this section is the page's first
          visual, so it sits close under the hero and its h2 stays a clear step
          below the H1 instead of competing with it. */}
      <div className="mx-auto max-w-[1200px] px-6 pb-24 pt-10 sm:pb-32 sm:pt-14">
        <Reveal>
          <h2 className="text-2xl font-semibold leading-[1.15] tracking-[-0.02em] text-foreground sm:text-[30px]">
            Follow a finding from alert to fix.
          </h2>
          <p className="mt-3 max-w-[60ch] text-[15px] leading-relaxed text-foreground">
            One finding, end to end, in the real product. Noise dies with
            reasons. The one that matters gets traced, scored, and fixed.
          </p>
        </Reveal>

        <Reveal className="mt-8 sm:mt-10">
          {/* Film panel — keyline + faint glow, video bleeds to the frame edge */}
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
          </div>

          {/* Chapter rail — highlights in sync with playback; click to seek */}
          <div className="mt-6 grid gap-x-8 gap-y-3 sm:grid-cols-3">
            {CHAPTERS.map((c, i) => (
              <button
                key={c.n}
                type="button"
                onClick={() => seekTo(i)}
                aria-label={`Jump to chapter ${c.n}: ${c.verb}`}
                className="group flex flex-col gap-1.5 text-left"
              >
                <span
                  className={`h-px w-full transition-colors duration-300 ${
                    i === active ? "bg-accent-text/70" : "bg-border group-hover:bg-[#404040]"
                  }`}
                  aria-hidden
                />
                <span className="font-mono text-[13px]">
                  <span
                    className={
                      i === active ? "text-foreground" : "text-foreground-secondary"
                    }
                  >
                    {c.n}
                  </span>{" "}
                  <span aria-hidden>▸</span>{" "}
                  <span
                    className={
                      i === active
                        ? "text-accent-text"
                        : "text-foreground-secondary group-hover:text-foreground"
                    }
                  >
                    {c.verb}
                  </span>
                </span>
                <span
                  className={`text-[13px] leading-snug transition-colors duration-300 ${
                    i === active ? "text-foreground" : "text-foreground-muted"
                  }`}
                >
                  {c.label}
                </span>
              </button>
            ))}
          </div>
        </Reveal>
      </div>
    </section>
  );
}

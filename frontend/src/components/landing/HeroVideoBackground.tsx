/**
 * HeroVideoBackground — ambient looping video atmosphere.
 *
 * Expects an AI-generated (or rendered) abstract loop at:
 *   frontend/public/videos/hero-loop.webm   (≤3MB, 8-12s, seamless loop)
 *   frontend/public/videos/hero-loop.jpg    (poster: first/representative frame)
 *
 * Rules of the slot:
 * - muted + autoplay + loop + playsinline (mobile-safe ambient video)
 * - dark overlay gradient on top: keeps headline contrast AND masks the
 *   texture artifacts AI video tends to have at the edges
 * - prefers-reduced-motion → poster only, video never mounts
 * - video failing to load → slot renders nothing (page ground shows)
 */
import { useEffect, useState } from "react";

export default function HeroVideoBackground() {
  const [reducedMotion, setReducedMotion] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReducedMotion(mq.matches);
    const onChange = (e: MediaQueryListEvent) => setReducedMotion(e.matches);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  if (failed) return null;

  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none" aria-hidden>
      {reducedMotion ? (
        <img
          src="/videos/hero-loop.jpg"
          alt=""
          className="h-full w-full object-cover opacity-60"
          onError={() => setFailed(true)}
        />
      ) : (
        <video
          className="h-full w-full object-cover opacity-60"
          src="/videos/hero-loop.webm"
          poster="/videos/hero-loop.jpg"
          autoPlay
          muted
          loop
          playsInline
          preload="auto"
          onError={() => setFailed(true)}
        />
      )}
      {/* Contrast + edge-artifact mask: darkest where the text lives,
          fades the video out toward the trace panel below. */}
      <div
        className="absolute inset-0"
        style={{
          background:
            "linear-gradient(180deg, rgba(5,5,5,0.55) 0%, rgba(5,5,5,0.35) 35%, rgba(5,5,5,0.75) 75%, #050505 100%)",
        }}
      />
    </div>
  );
}

import { useEffect, useRef } from "react";

/**
 * The page-wide reveal pattern (landing-page-redesign.plan.md §6): adds
 * `is-revealed` to a `.reveal-up` element once it crosses ~20% visibility.
 * Runs once; reduced-motion is handled in CSS (elements render final-state).
 */
export function useRevealOnScroll<T extends HTMLElement = HTMLDivElement>() {
  const ref = useRef<T | null>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          el.classList.add("is-revealed");
          observer.disconnect();
        }
      },
      { threshold: 0.2 }
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  return ref;
}

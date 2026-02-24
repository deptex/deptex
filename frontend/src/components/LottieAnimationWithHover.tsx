import { DotLottieReact } from "@lottiefiles/dotlottie-react";
import { useEffect, useRef, useState } from "react";

export default function LottieAnimationWithHover() {
  const [isHovered, setIsHovered] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const lottieRef = useRef<any>(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    // Find the parent card with group class
    const card = container.closest(".group");
    if (!card) return;

    const handleMouseEnter = () => {
      setIsHovered(true);
      // Try to play if ref is available
      if (lottieRef.current?.play) {
        lottieRef.current.play();
      }
    };
    
    const handleMouseLeave = () => {
      setIsHovered(false);
      // Try to pause if ref is available
      if (lottieRef.current?.pause) {
        lottieRef.current.pause();
      }
    };

    card.addEventListener("mouseenter", handleMouseEnter);
    card.addEventListener("mouseleave", handleMouseLeave);

    return () => {
      card.removeEventListener("mouseenter", handleMouseEnter);
      card.removeEventListener("mouseleave", handleMouseLeave);
    };
  }, []);

  return (
    <div ref={containerRef} className="w-full h-full flex items-center justify-center">
      <DotLottieReact
        ref={lottieRef}
        src="https://lottie.host/3c30bfcd-a7ab-44f6-8cc3-975f18a24f2d/5MWtSCnrwU.lottie"
        loop
        autoplay={isHovered}
        key={isHovered ? "playing" : "paused"}
      />
    </div>
  );
}


import { DotLottieReact } from "@lottiefiles/dotlottie-react";

interface LottieAnimationProps {
  autoplay?: boolean;
}

export default function LottieAnimation({ autoplay = false }: LottieAnimationProps) {
  return (
    <div className="w-full h-full flex items-center justify-center">
      <DotLottieReact
        src="https://lottie.host/3c30bfcd-a7ab-44f6-8cc3-975f18a24f2d/5MWtSCnrwU.lottie"
        loop
        autoplay={autoplay}
      />
    </div>
  );
}


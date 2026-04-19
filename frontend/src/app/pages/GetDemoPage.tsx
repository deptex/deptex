import { useState, useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import ReCAPTCHA from "react-google-recaptcha";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { Label } from "../../components/ui/label";
import { ScanSearch, Scale, Bell, Telescope } from "lucide-react";

const RECAPTCHA_SITE_KEY = import.meta.env.VITE_RECAPTCHA_SITE_KEY as string | undefined;

const API_BASE = import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || "http://localhost:3001";

const TYPE_MS = 60;
const BACKSPACE_MS = 40;
const HOLD_AFTER_TYPED_MS = 2200;

/* Same icons as Product dropdown in NavBar */
const AegisIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round" className="h-5 w-5 shrink-0" aria-hidden>
    <path d="M12 2L4 6v5c0 5 4 8 8 10 4-2 8-5 8-10V6l-8-4z" />
    <path d="M12 9l1 2 2 1-1 2-2 1-1-2-2-1 1-2 2-1z" fill="currentColor" stroke="none" />
  </svg>
);

const CYCLING_ITEMS: { phrase: string; icon: React.ReactNode }[] = [
  { phrase: "Try our custom policy as code", icon: <Scale className="h-5 w-5 shrink-0" /> },
  { phrase: "Check out our integrations — connect anything you want", icon: <Bell className="h-5 w-5 shrink-0" /> },
  { phrase: "Aegis AI that investigates, fixes, and reports", icon: <AegisIcon /> },
  { phrase: "Supply chain forensics and Watchtower", icon: <Telescope className="h-5 w-5 shrink-0" /> },
  { phrase: "Dependency intelligence with reachability", icon: <ScanSearch className="h-5 w-5 shrink-0" /> },
  { phrase: "SBOM and compliance made simple", icon: <Scale className="h-5 w-5 shrink-0" /> },
];

function DemoPageTypewriterBlock() {
  const [index, setIndex] = useState(0);
  const [visibleLength, setVisibleLength] = useState(0);
  const [phase, setPhase] = useState<"typing" | "hold" | "backspacing">("typing");
  const { phrase, icon } = CYCLING_ITEMS[index];

  useEffect(() => {
    if (phase !== "hold") return;
    const t = setTimeout(() => setPhase("backspacing"), HOLD_AFTER_TYPED_MS);
    return () => clearTimeout(t);
  }, [phase]);

  useEffect(() => {
    if (phase === "typing") {
      if (visibleLength >= phrase.length) {
        setPhase("hold");
        return;
      }
      const t = setTimeout(() => setVisibleLength((n) => n + 1), TYPE_MS);
      return () => clearTimeout(t);
    }
    if (phase === "backspacing") {
      if (visibleLength <= 0) {
        setIndex((i) => (i + 1) % CYCLING_ITEMS.length);
        setPhase("typing");
        return;
      }
      const t = setTimeout(() => setVisibleLength((n) => n - 1), BACKSPACE_MS);
      return () => clearTimeout(t);
    }
  }, [phase, visibleLength, phrase.length]);

  return (
    <div className="flex items-center gap-3 w-full max-w-md">
      <span className="flex-shrink-0 text-foreground-secondary">
        {icon}
      </span>
      <p className="min-h-[1.5rem] text-base text-foreground">
        {phrase.slice(0, visibleLength)}
        <span className="animate-pulse">|</span>
      </p>
    </div>
  );
}

export default function GetDemoPage() {
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const recaptchaRef = useRef<ReCAPTCHA>(null);

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);
    const form = e.currentTarget;
    const formData = new FormData(form);
    const firstName = (formData.get("firstName") as string)?.trim();
    const lastName = (formData.get("lastName") as string)?.trim();
    const email = (formData.get("email") as string)?.trim();
    const details = (formData.get("details") as string)?.trim();
    if (!firstName || !lastName || !email) {
      setError("Please fill in first name, last name, and email.");
      return;
    }
    const recaptchaToken = RECAPTCHA_SITE_KEY ? recaptchaRef.current?.getValue() ?? "" : "";
    if (RECAPTCHA_SITE_KEY && !recaptchaToken) {
      setError("Please complete the captcha.");
      return;
    }
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/demo-request`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          firstName,
          lastName,
          email,
          details: details || undefined,
          website: (formData.get("website") as string) || "",
          recaptchaToken: recaptchaToken || undefined,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error || "Something went wrong. Please try again.");
        return;
      }
      setSubmitted(true);
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-background">
      <div className="grid grid-cols-1 lg:grid-cols-2 items-start gap-8">
        {/* Left: Headline + subtext, then typewriter block */}
        <div className="flex flex-col px-6 lg:pl-16 lg:pr-12 pt-24 lg:pt-28 pb-8">
          <div className="flex-shrink-0">
            <h1 className="text-4xl md:text-5xl font-bold text-foreground leading-tight mb-4">
              Talk to our Sales team
            </h1>
            <p className="text-base text-foreground-secondary max-w-md">
              Book a demo and set up a trial Enterprise account to see how Deptex features work and can help manage your organization's security.
            </p>
          </div>
          <div className="mt-8 lg:mt-12">
            <DemoPageTypewriterBlock />
          </div>
        </div>

        {/* Right: Form card */}
        <div className="flex flex-col px-6 pt-24 lg:pt-28 pb-8 lg:pr-16 lg:pl-12">
          <div className="rounded-xl border border-border bg-background-card/80 backdrop-blur-sm p-6 max-w-lg w-full mx-auto lg:mx-0 lg:self-start">
            <h2 className="text-xl font-semibold text-foreground mb-5">
              Schedule a Demo
            </h2>

            {submitted ? (
              <div className="py-6 text-center">
                <p className="text-foreground font-medium mb-2">Request received</p>
                <p className="text-sm text-foreground-secondary">
                  We'll be in touch soon to schedule your demo.
                </p>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-4">
                {/* Honeypot: hidden from users; bots that fill it get rejected */}
                <div className="absolute -left-[9999px] opacity-0" aria-hidden>
                  <label htmlFor="demo-website">Website</label>
                  <input id="demo-website" name="website" type="text" tabIndex={-1} autoComplete="off" />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <Label htmlFor="firstName" className="demo-page-label text-sm">
                      First name
                    </Label>
                    <Input
                      id="firstName"
                      name="firstName"
                      required
                      placeholder="First name"
                      className="demo-page-input h-9"
                      disabled={loading}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="lastName" className="demo-page-label text-sm">
                      Last name
                    </Label>
                    <Input
                      id="lastName"
                      name="lastName"
                      required
                      placeholder="Last name"
                      className="demo-page-input h-9"
                      disabled={loading}
                    />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="email" className="demo-page-label text-sm">
                    Business email
                  </Label>
                  <Input
                    id="email"
                    name="email"
                    type="email"
                    required
                    placeholder="you@company.com"
                    className="demo-page-input h-9"
                    disabled={loading}
                  />
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="details" className="demo-page-label text-sm">
                    Details
                  </Label>
                  <textarea
                    id="details"
                    name="details"
                    placeholder="Tell us what you're interested in or anything else we should know."
                    rows={4}
                    className="demo-page-input w-full resize-y rounded-md px-3 py-2.5 text-sm text-foreground shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50 focus-visible:border-primary disabled:cursor-not-allowed disabled:opacity-50 min-h-[100px]"
                    disabled={loading}
                  />
                </div>

                {RECAPTCHA_SITE_KEY && (
                  <div className="flex justify-center">
                    <ReCAPTCHA
                      ref={recaptchaRef}
                      sitekey={RECAPTCHA_SITE_KEY}
                      theme="dark"
                      size="normal"
                    />
                  </div>
                )}

                {error && (
                  <p className="text-sm text-destructive">{error}</p>
                )}

                <Button
                  type="submit"
                  size="lg"
                  disabled={loading}
                  className="w-full bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-10 text-base font-medium"
                >
                  {loading ? "Sending…" : "Request a demo"}
                </Button>

                <p className="text-sm text-foreground-secondary text-center pt-3">
                  By submitting this form, you confirm that you have read and understood our{" "}
                  <Link to="/docs/privacy" className="text-foreground hover:underline">
                    Privacy Policy
                  </Link>
                  . This site is protected by reCAPTCHA and the Google{" "}
                  <a href="https://policies.google.com/privacy" target="_blank" rel="noopener noreferrer" className="text-foreground hover:underline">Privacy Policy</a>
                  {" "}and{" "}
                  <a href="https://policies.google.com/terms" target="_blank" rel="noopener noreferrer" className="text-foreground hover:underline">Terms of Service</a> apply.
                </p>
              </form>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

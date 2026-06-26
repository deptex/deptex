import { useEffect } from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import NavBar from "../components/NavBar/NavBar";
import Footer from "../components/Footer";
import { Toaster } from "../components/ui/toaster";
import { useAuth } from "../contexts/AuthContext";
import "./Main.css";

export default function App() {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, loading } = useAuth();
  const isIndexRoute = location.pathname === "/";
  // "/" is pure routing (no page of its own); the landing homepage lives at
  // "/landing" and is the only full-bleed marketing route.
  const isLandingLayout = location.pathname === "/landing";

  // "/" just decides where to send you: your dashboard if signed in, otherwise
  // the landing page. Wait for auth to resolve (loading) so a returning user
  // isn't bounced to /landing before their cached session loads. Doing this here
  // (not via <Navigate>) keeps the spinner on screen until the transition lands.
  useEffect(() => {
    if (isIndexRoute && !loading) {
      navigate(user ? "/organizations" : "/landing", { replace: true });
    }
  }, [isIndexRoute, loading, user, navigate]);

  useEffect(() => {
    document.documentElement.classList.add("dark");

    if (location.hash) {
      const id = location.hash.replace("#", "");
      const element = document.getElementById(id);
      if (element) {
        element.scrollIntoView();
      }
    } else {
      window.scrollTo(0, 0);
    }
  }, [location]);

  // "/" never renders a page — hold a spinner while the effect above redirects.
  // Prevents the NavBar from painting for one frame before the navigate fires.
  if (isIndexRoute) {
    return (
      <>
        <div className="bg-background text-foreground min-h-screen flex items-center justify-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" aria-hidden />
        </div>
        <Toaster position="bottom-right" />
      </>
    );
  }

  return (
    <>
      <div className="bg-background text-foreground min-h-screen flex flex-col">
        <NavBar />
        {/* Landing page is full-bleed (sections own their max-w containers);
            other marketing routes keep the centered shell. */}
        {isLandingLayout ? (
          <div className="flex-1 pt-14">
            <Outlet />
          </div>
        ) : (
          <div className="mx-auto max-w-screen-2xl flex-1">
            <Outlet />
          </div>
        )}
        <Footer />
      </div>
      <Toaster position="bottom-right" />
    </>
  );
}


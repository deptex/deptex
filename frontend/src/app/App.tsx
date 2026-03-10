import { useEffect } from "react";
import { Outlet, useLocation } from "react-router-dom";
import NavBar from "../components/NavBar/NavBar";
import Footer from "../components/Footer";
import { Toaster } from "../components/ui/toaster";
import { useAuth } from "../contexts/AuthContext";
import "./Main.css";

/**
 * When we're on the exact index path "/" and auth is still loading, we show
 * a single full-screen loader instead of the marketing layout (NavBar + Outlet).
 * This prevents logged-in users from briefly seeing the "onboarding" / marketing
 * header before PublicRoute redirects them to /organizations.
 */
export default function App() {
  const location = useLocation();
  const { loading } = useAuth();
  const isIndexRoute = location.pathname === "/";

  useEffect(() => {
    // Ensure dark mode is always enabled
    document.documentElement.classList.add("dark");
    
    if (location.hash) {
      const id = location.hash.replace("#", "");
      const element = document.getElementById(id);
      if (element) {
        element.scrollIntoView();
      }
    } else {
      // Scroll to top on route change (unless there's a hash)
      window.scrollTo(0, 0);
    }
  }, [location]);

  if (isIndexRoute && loading) {
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
        <div className="mx-auto max-w-screen-2xl flex-1">
          <Outlet />
        </div>
        <Footer />
      </div>
      <Toaster position="bottom-right" />
    </>
  );
}


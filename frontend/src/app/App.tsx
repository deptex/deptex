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
  const { user } = useAuth();
  const isIndexRoute = location.pathname === "/";

  // Redirect authenticated users away from marketing pages without a visible flash.
  // <Navigate> fires one render too late (its navigate() runs in useEffect); doing it
  // here keeps the spinner on screen until the router transition completes.
  useEffect(() => {
    if (isIndexRoute && user) {
      navigate("/organizations", { replace: true });
    }
  }, [isIndexRoute, user, navigate]);

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

  // Hold the spinner on "/" only while we're about to redirect an authenticated
  // user. Prevents the NavBar from painting for one frame before the navigate fires.
  if (isIndexRoute && user) {
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


import { useEffect } from "react";
import { Outlet, useLocation } from "react-router-dom";
import NavBar from "../components/NavBar/NavBar";
import Footer from "../components/Footer";
import { Toaster } from "../components/ui/toaster";
import "./Main.css";

export default function App() {
  const location = useLocation();

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


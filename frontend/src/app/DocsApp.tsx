import { useEffect } from "react";
import { Outlet } from "react-router-dom";
import DocsHeader from "../components/DocsHeader";
import { Toaster } from "../components/ui/toaster";
import "./Main.css";

export default function DocsApp() {
  useEffect(() => {
    const prev = document.title;
    document.title = "Deptex Docs";
    return () => {
      document.title = prev;
    };
  }, []);

  return (
    <>
      <div className="bg-background text-foreground min-h-screen flex flex-col">
        <DocsHeader />
        <Outlet />
      </div>
      <Toaster position="bottom-right" />
    </>
  );
}

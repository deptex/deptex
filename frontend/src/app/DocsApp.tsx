import { useEffect } from "react";
import { Outlet, useLocation } from "react-router-dom";
import DocsHeader from "../components/DocsHeader";
import DocsAIAssistant from "./pages/docs/DocsAIAssistant";
import { Toaster } from "../components/ui/toaster";
import "./Main.css";

export default function DocsApp() {
  const location = useLocation();
  const section = location.pathname.split("/")[2] || "introduction";

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
      <DocsAIAssistant currentPage={section} />
      <Toaster position="bottom-right" />
    </>
  );
}

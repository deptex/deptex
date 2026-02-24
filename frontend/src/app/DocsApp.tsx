import { Outlet } from "react-router-dom";
import DocsHeader from "../components/DocsHeader";
import { Toaster } from "../components/ui/toaster";
import "./Main.css";

export default function DocsApp() {
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

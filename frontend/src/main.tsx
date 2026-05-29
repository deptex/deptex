// Sentry must initialize before the app renders. No-ops without VITE_SENTRY_DSN.
import "./instrument";
import React from "react";
import ReactDOM from "react-dom/client";
import * as Sentry from "@sentry/react";
import { RouterProvider } from "react-router-dom";
import { router } from "./app/routes";
import { TooltipProvider } from "./components/ui/tooltip";
import "./app/Main.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <Sentry.ErrorBoundary fallback={<div style={{ padding: 24 }}>Something went wrong.</div>}>
      <TooltipProvider>
        <RouterProvider router={router} />
      </TooltipProvider>
    </Sentry.ErrorBoundary>
  </React.StrictMode>
);


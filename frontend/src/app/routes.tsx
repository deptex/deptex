import { createBrowserRouter, Navigate, useParams, useLocation, Outlet, useRouteError, isRouteErrorResponse } from "react-router-dom";
import { useEffect } from "react";
import * as Sentry from "@sentry/react";
import { AuthProvider } from "../contexts/AuthContext";
import App from "./App";
import DocsApp from "./DocsApp";
import DocsLayout from "./pages/DocsLayout";
import HelpCenterPage from "./pages/docs/HelpCenterPage";
import HomePage from "./pages/HomePage";
import LoginPage from "./pages/LoginPage";
import SSOCallbackPage from "./pages/SSOCallbackPage";
import OrganizationsLanding from "./pages/OrganizationsLanding";
import OrganizationLayout from "./pages/OrganizationLayout";
import OrganizationSettingsPage from "./pages/OrganizationSettingsPage";
import TaintEngineSettingsPage from "./pages/orgs/taint-engine/TaintEngineSettingsPage";

import PoliciesPage from "./pages/PoliciesPage";
import CompliancePage from "./pages/CompliancePage";
import OrganizationOverviewPage from "./pages/OrganizationOverviewPage";

import InvitePage from "./pages/InvitePage";
import JoinPage from "./pages/JoinPage";
import AccountSettingsPage from "./pages/AccountSettingsPage";
import PlatformFeaturesPage from "./pages/PlatformFeaturesPage";
import ProjectHealthPage from "./pages/ProjectHealthPage";
import IntegrationsPage from "./pages/IntegrationsPage";
import GetDemoPage from "./pages/GetDemoPage";
import OpenSourcePage from "./pages/OpenSourcePage";
import PricingPage from "./pages/PricingPage";
import ContactEnterprisePage from "./pages/ContactEnterprisePage";
import DataProcessingAgreementPage from "./pages/legal/DataProcessingAgreementPage";
import TransferImpactAssessmentPage from "./pages/legal/TransferImpactAssessmentPage";
import CookiePolicyPage from "./pages/legal/CookiePolicyPage";
import ProtectedRoute from "../components/ProtectedRoute";
import PublicRoute from "../components/PublicRoute";
import NotFoundRedirect from "../components/NotFoundRedirect";
import OrganizationFindingsPage from "./pages/OrganizationFindingsPage";
import NewProjectPage from "./pages/NewProjectPage";
import AegisPage from "./pages/AegisPage";
import OrganizationFlowsPage from "./pages/OrganizationFlowsPage";
import FlowEditorPage from "./pages/FlowEditorPage";
import AdminLayout from "./pages/admin/AdminLayout";
import AdminOverviewPage from "./pages/admin/AdminOverviewPage";
import ExtractionFailuresPage from "./pages/admin/ExtractionFailuresPage";

// Forward the legacy /settings entry point to the user's account page within
// their default organization. Falls back to /organizations when no default
// is set (the landing page handles initial selection). Preserves search
// params so OAuth callbacks survive the redirect.
function SettingsRedirect() {
  const { search } = useLocation();
  const defaultOrg = typeof window !== 'undefined'
    ? localStorage.getItem('deptex_default_org')
    : null;
  const target = defaultOrg
    ? `/organizations/${defaultOrg}/account/general${search}`
    : `/organizations${search}`;
  return <Navigate to={target} replace />;
}

/** All project URLs redirect to org overview (project UI lives in org overview sidebar). */
function RedirectToOrgOverview() {
  const { orgId } = useParams<{ orgId: string }>();
  if (!orgId) return <Navigate to="/organizations" replace />;
  return <Navigate to={`/organizations/${orgId}/overview`} replace />;
}

/** Root layout that provides AuthProvider so useAuth is available in all route elements */
function RootLayout() {
  return (
    <AuthProvider>
      <Outlet />
    </AuthProvider>
  );
}

/**
 * Root error boundary for the data router — catches errors thrown during route
 * render/loaders and reports them to Sentry (no-op without a DSN). Expected
 * route responses (e.g. 404s thrown via the router) are NOT reported.
 */
function RootErrorBoundary() {
  const error = useRouteError();
  useEffect(() => {
    if (!isRouteErrorResponse(error)) {
      Sentry.captureException(error);
    }
  }, [error]);
  return (
    <div style={{ padding: 24, textAlign: "center" }}>
      <p>Something went wrong loading this page.</p>
      <button onClick={() => window.location.reload()}>Reload</button>
    </div>
  );
}

export const router = createBrowserRouter([
  {
    element: <RootLayout />,
    errorElement: <RootErrorBoundary />,
    children: [
  // ============================================
  // AUTHENTICATED ROUTES
  // These require login - unauthenticated users are redirected to /
  // ============================================
  {
    path: "/organizations",
    element: (
      <ProtectedRoute>
        <OrganizationsLanding />
      </ProtectedRoute>
    ),
  },
  {
    path: "/admin",
    element: (
      <ProtectedRoute>
        <AdminLayout />
      </ProtectedRoute>
    ),
    children: [
      { index: true, element: <AdminOverviewPage /> },
      { path: "extraction-failures", element: <ExtractionFailuresPage /> },
    ],
  },
  {
    path: "/organizations/:id",
    element: (
      <ProtectedRoute>
        <OrganizationLayout />
      </ProtectedRoute>
    ),
    children: [
      {
        index: true,
        element: <OrganizationOverviewPage />,
      },
      {
        path: "overview",
        element: <OrganizationOverviewPage />,
      },
      {
        path: "teams",
        element: <Navigate to="overview" replace />,
      },
      {
        path: "findings",
        element: <OrganizationFindingsPage />,
      },
      {
        path: "vulnerabilities",
        element: <Navigate to="../findings" replace />,
      },
      {
        path: "projects",
        element: <Navigate to="overview" replace />,
      },
      {
        path: "new-project",
        element: <NewProjectPage />,
      },
      {
        path: "settings",
        element: <OrganizationSettingsPage />,
      },
      {
        path: "settings/:section",
        element: <OrganizationSettingsPage />,
      },
      {
        path: "settings/taint-engine",
        element: <TaintEngineSettingsPage />,
      },
      {
        path: "policies",
        element: <PoliciesPage />,
      },
      {
        path: "compliance",
        element: <CompliancePage />,
      },
      {
        path: "compliance/:section",
        element: <CompliancePage />,
      },
      {
        path: "aegis",
        element: <AegisPage />,
      },
      {
        path: "aegis/routines",
        element: <AegisPage />,
      },
      {
        path: "aegis/:threadId",
        element: <AegisPage />,
      },
      {
        path: "flows",
        element: <OrganizationFlowsPage />,
      },
      {
        path: "flows/:flowId",
        element: <FlowEditorPage />,
      },
      {
        path: "account",
        element: <Navigate to="general" replace />,
      },
      {
        path: "account/general",
        element: <AccountSettingsPage />,
      },
      {
        path: "account/connected-accounts",
        element: <AccountSettingsPage />,
      },
      {
        path: ":tab",
        element: <Navigate to=".." replace />,
      },
    ],
  },
  {
    path: "/organizations/:orgId/projects/:projectId/*",
    element: (
      <ProtectedRoute>
        <RedirectToOrgOverview />
      </ProtectedRoute>
    ),
  },
  {
    path: "/organizations/:orgId/teams/:teamId/*",
    element: (
      <ProtectedRoute>
        <RedirectToOrgOverview />
      </ProtectedRoute>
    ),
  },
  {
    path: "/invite/:invitationId",
    element: (
      <ProtectedRoute>
        <InvitePage />
      </ProtectedRoute>
    ),
  },
  {
    path: "/join/:organizationId",
    element: (
      <ProtectedRoute>
        <JoinPage />
      </ProtectedRoute>
    ),
  },
  {
    path: "/settings",
    element: (
      <ProtectedRoute>
        <SettingsRedirect />
      </ProtectedRoute>
    ),
  },
  {
    path: "/settings/*",
    element: (
      <ProtectedRoute>
        <SettingsRedirect />
      </ProtectedRoute>
    ),
  },

  // ============================================
  // PUBLIC ROUTES
  // These are for unauthenticated users - authenticated users are redirected to /organizations
  // ============================================
  {
    path: "/login",
    element: (
      <PublicRoute>
        <LoginPage />
      </PublicRoute>
    ),
  },
  {
    path: "/sso-callback",
    element: <SSOCallbackPage />,
  },
  {
    path: "/",
    element: <App />,
    children: [
      {
        index: true,
        element: (
          <PublicRoute>
            <HomePage />
          </PublicRoute>
        ),
      },
      {
        path: "platform-features",
        element: (
          <PublicRoute>
            <PlatformFeaturesPage />
          </PublicRoute>
        ),
      },
      {
        path: "platform-features/:featureSlug",
        element: (
          <PublicRoute>
            <PlatformFeaturesPage />
          </PublicRoute>
        ),
      },
      {
        path: "ai-security-agent",
        element: <Navigate to="/platform-features/ai-security-agent" replace />,
      },
      {
        path: "autonomous-agent",
        element: <Navigate to="/platform-features/ai-security-agent" replace />,
      },
      {
        path: "vulnerability-intelligence",
        element: <Navigate to="/platform-features/vulnerability-intelligence" replace />,
      },
      {
        path: "sbom-compliance",
        element: <Navigate to="/platform-features/customizable-compliance" replace />,
      },
      {
        path: "anomaly-detection",
        element: <Navigate to="/platform-features/advanced-upstream-insights" replace />,
      },
      {
        path: "repository-tracking",
        element: <Navigate to="/docs/quick-start" replace />,
      },
      {
        path: "project-health",
        element: (
          <PublicRoute>
            <ProjectHealthPage />
          </PublicRoute>
        ),
      },
      {
        path: "integrations",
        element: (
          <PublicRoute>
            <IntegrationsPage />
          </PublicRoute>
        ),
      },
      {
        path: "get-demo",
        element: (
          <PublicRoute>
            <GetDemoPage />
          </PublicRoute>
        ),
      },
      {
        path: "support",
        element: <Navigate to="/docs/help" replace />,
      },
      {
        path: "terms",
        element: <Navigate to="/docs/terms" replace />,
      },
      {
        path: "privacy",
        element: <Navigate to="/docs/privacy" replace />,
      },
      {
        path: "security",
        element: <Navigate to="/docs/security" replace />,
      },
      {
        path: "pricing",
        element: <PricingPage />,
      },
      {
        path: "contact-enterprise",
        element: <ContactEnterprisePage />,
      },
      {
        path: "legal/dpa",
        element: <DataProcessingAgreementPage />,
      },
      {
        path: "legal/tia",
        element: <TransferImpactAssessmentPage />,
      },
      {
        path: "legal/cookies",
        element: <CookiePolicyPage />,
      },
      {
        path: "open-source",
        element: (
          <PublicRoute>
            <OpenSourcePage />
          </PublicRoute>
        ),
      },
      {
        path: "solutions/*",
        element: <Navigate to="/" replace />,
      },
    ],
  },

  // ============================================
  // DOCS ROUTES
  // Accessible to all users, no auth guard
  // ============================================
  {
    path: "/docs",
    element: <DocsApp />,
    children: [
      {
        index: true,
        element: <Navigate to="/docs/introduction" replace />,
      },
      {
        path: "help",
        element: <HelpCenterPage />,
      },
      {
        path: ":section",
        element: <DocsLayout />,
      },
    ],
  },

  // ============================================
  // CATCH-ALL 404 ROUTE
  // Redirects based on auth state
  // ============================================
  {
    path: "*",
    element: <NotFoundRedirect />,
  },
  ],
  },
]);

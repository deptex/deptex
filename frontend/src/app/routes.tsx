import { createBrowserRouter, Navigate, useParams, useLocation, Outlet } from "react-router-dom";
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

import PoliciesPage from "./pages/PoliciesPage";
import CompliancePage from "./pages/CompliancePage";
import OrganizationVulnerabilitiesPage from "./pages/OrganizationVulnerabilitiesPage";

import InvitePage from "./pages/InvitePage";
import JoinPage from "./pages/JoinPage";
import SettingsPage from "./pages/SettingsPage";
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
import OrganizationVulnerabilitiesTabPage from "./pages/OrganizationVulnerabilitiesTabPage";
import AegisPage from "./pages/AegisPage";
// Redirect /settings to /settings/general while preserving search params (for OAuth callbacks)
function SettingsRedirect() {
  const { search } = useLocation();
  return <Navigate to={`/settings/general${search}`} replace />;
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

export const router = createBrowserRouter([
  {
    element: <RootLayout />,
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
    path: "/organizations/:id",
    element: (
      <ProtectedRoute>
        <OrganizationLayout />
      </ProtectedRoute>
    ),
    children: [
      {
        index: true,
        element: <OrganizationVulnerabilitiesPage />,
      },
      {
        path: "overview",
        element: <OrganizationVulnerabilitiesPage />,
      },
      {
        path: "teams",
        element: <Navigate to="overview" replace />,
      },
      {
        path: "security",
        element: <Navigate to=".." replace />,
      },
      {
        path: "vulnerabilities",
        element: <OrganizationVulnerabilitiesTabPage />,
      },
      {
        path: "projects",
        element: <Navigate to="overview" replace />,
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
        path: "aegis/:threadId",
        element: <AegisPage />,
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
    path: "/settings/general",
    element: (
      <ProtectedRoute>
        <SettingsPage />
      </ProtectedRoute>
    ),
  },
  {
    path: "/settings/general/connected-accounts",
    element: (
      <ProtectedRoute>
        <SettingsPage />
      </ProtectedRoute>
    ),
  },
  {
    path: "/settings/notifications",
    element: <Navigate to="/settings/general" replace />,
  },
  {
    path: "/settings/security",
    element: <Navigate to="/settings/general" replace />,
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

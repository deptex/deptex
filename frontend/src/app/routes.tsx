import { createBrowserRouter, Navigate, useParams } from "react-router-dom";
import App from "./App";
import DocsApp from "./DocsApp";
import DocsLayout from "./pages/DocsLayout";
import HomePage from "./pages/HomePage";
import LoginPage from "./pages/LoginPage";
import OrganizationsPage from "./pages/OrganizationsPage";
import OrganizationLayout from "./pages/OrganizationLayout";
import OrganizationDetailPage from "./pages/OrganizationDetailPage";
import OrganizationSettingsPage from "./pages/OrganizationSettingsPage";

import TeamsPage from "./pages/TeamsPage";
import ProjectsPage from "./pages/ProjectsPage";
import PoliciesPage from "./pages/PoliciesPage";
import CompliancePage from "./pages/CompliancePage";
import OrganizationVulnerabilitiesPage from "./pages/OrganizationVulnerabilitiesPage";

import InvitePage from "./pages/InvitePage";
import JoinPage from "./pages/JoinPage";
import SettingsPage from "./pages/SettingsPage";
import AutonomousAgentPage from "./pages/AutonomousAgentPage";
import RepositoryTrackingPage from "./pages/RepositoryTrackingPage";
import AnomalyDetectionPage from "./pages/AnomalyDetectionPage";
import VulnerabilityIntelligencePage from "./pages/VulnerabilityIntelligencePage";
import SBOMCompliancePage from "./pages/SBOMCompliancePage";
import ProjectHealthPage from "./pages/ProjectHealthPage";
import IntegrationsPage from "./pages/IntegrationsPage";
import SupportPage from "./pages/SupportPage";
import OpenSourcePage from "./pages/OpenSourcePage";
import EngineeringTeamsPage from "./pages/solutions/EngineeringTeamsPage";
import SecurityTeamsPage from "./pages/solutions/SecurityTeamsPage";
import DevOpsTeamsPage from "./pages/solutions/DevOpsTeamsPage";
import OpenSourceMaintainersPage from "./pages/solutions/OpenSourceMaintainersPage";
import CTOLeadershipPage from "./pages/solutions/CTOLeadershipPage";
import StartupsScaleupsPage from "./pages/solutions/StartupsScaleupsPage";
import ProtectedRoute from "../components/ProtectedRoute";
import PublicRoute from "../components/PublicRoute";
import NotFoundRedirect from "../components/NotFoundRedirect";
// Project-level imports
import ProjectLayout from "./pages/ProjectLayout";
import ProjectOverviewPage from "./pages/ProjectOverviewPage";
import ProjectDependenciesPage from "./pages/ProjectDependenciesPage";
import ProjectVulnerabilitiesPage from "./pages/ProjectVulnerabilitiesPage";
import ProjectCompliancePage from "./pages/ProjectCompliancePage";

import ProjectSettingsPage from "./pages/ProjectSettingsPage";
// Team-level imports
import TeamLayout from "./pages/TeamLayout";
import TeamOverviewPage from "./pages/TeamOverviewPage";
import TeamProjectsPage from "./pages/TeamProjectsPage";
import TeamMembersPage from "./pages/TeamMembersPage";
import TeamAlertsPage from "./pages/TeamAlertsPage";
import TeamSettingsPage from "./pages/TeamSettingsPage";
// Redirect old dependency detail URL (no tab) to project dependencies with overview tab
function RedirectDependencyToOverview() {
  const { orgId, projectId, dependencyId } = useParams<{ orgId: string; projectId: string; dependencyId: string }>();
  const to = orgId && projectId && dependencyId
    ? `/organizations/${orgId}/projects/${projectId}/dependencies/${dependencyId}/overview`
    : "/organizations";
  return <Navigate to={to} replace />;
}

export const router = createBrowserRouter([
  // ============================================
  // AUTHENTICATED ROUTES
  // These require login - unauthenticated users are redirected to /
  // ============================================
  {
    path: "/organizations",
    element: (
      <ProtectedRoute>
        <OrganizationsPage />
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
        element: <OrganizationDetailPage />,
      },

      {
        path: "teams",
        element: <TeamsPage />,
      },
      {
        path: "vulnerabilities",
        element: <OrganizationVulnerabilitiesPage />,
      },
      {
        path: "projects",
        element: <ProjectsPage />,
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
        path: ":tab",
        element: <OrganizationDetailPage />,
      },
    ],
  },
  {
    path: "/organizations/:orgId/projects/:projectId",
    element: (
      <ProtectedRoute>
        <ProjectLayout />
      </ProtectedRoute>
    ),
    children: [
      {
        index: true,
        element: <ProjectOverviewPage />,
      },
      {
        path: "overview",
        element: <ProjectOverviewPage />,
      },
      {
        path: "vulnerabilities",
        element: <ProjectVulnerabilitiesPage />,
      },
      {
        path: "dependencies",
        element: <ProjectDependenciesPage />,
      },
      {
        path: "dependencies/:dependencyId",
        element: <RedirectDependencyToOverview />,
      },
      {
        path: "dependencies/:dependencyId/overview",
        element: <ProjectDependenciesPage />,
      },
      {
        path: "dependencies/:dependencyId/watchtower",
        element: <ProjectDependenciesPage />,
      },
      {
        path: "dependencies/:dependencyId/supply-chain",
        element: <ProjectDependenciesPage />,
      },

      {
        path: "compliance",
        element: <ProjectCompliancePage />,
      },
      {
        path: "compliance/:section",
        element: <ProjectCompliancePage />,
      },
      {
        path: "settings",
        element: <ProjectSettingsPage />,
      },
      {
        path: ":tab",
        element: <ProjectOverviewPage />,
      },
    ],
  },
  {
    path: "/organizations/:orgId/projects/:projectId/dependencies/:dependencyId",
    element: (
      <ProtectedRoute>
        <RedirectDependencyToOverview />
      </ProtectedRoute>
    ),
  },
  {
    path: "/organizations/:orgId/teams/:teamId",
    element: (
      <ProtectedRoute>
        <TeamLayout />
      </ProtectedRoute>
    ),
    children: [
      {
        index: true,
        element: <TeamOverviewPage />,
      },
      {
        path: "overview",
        element: <TeamOverviewPage />,
      },
      {
        path: "projects",
        element: <TeamProjectsPage />,
      },
      {
        path: "members",
        element: <TeamMembersPage />,
      },
      {
        path: "alerts",
        element: <TeamAlertsPage />,
      },
      {
        path: "settings",
        element: <TeamSettingsPage />,
      },
      {
        path: ":tab",
        element: <TeamOverviewPage />,
      },
    ],
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
        <SettingsPage />
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
        path: "autonomous-agent",
        element: (
          <PublicRoute>
            <AutonomousAgentPage />
          </PublicRoute>
        ),
      },
      {
        path: "repository-tracking",
        element: (
          <PublicRoute>
            <RepositoryTrackingPage />
          </PublicRoute>
        ),
      },
      {
        path: "anomaly-detection",
        element: (
          <PublicRoute>
            <AnomalyDetectionPage />
          </PublicRoute>
        ),
      },
      {
        path: "vulnerability-intelligence",
        element: (
          <PublicRoute>
            <VulnerabilityIntelligencePage />
          </PublicRoute>
        ),
      },
      {
        path: "sbom-compliance",
        element: (
          <PublicRoute>
            <SBOMCompliancePage />
          </PublicRoute>
        ),
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
        path: "support",
        element: (
          <PublicRoute>
            <SupportPage />
          </PublicRoute>
        ),
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
        path: "solutions/engineering-teams",
        element: (
          <PublicRoute>
            <EngineeringTeamsPage />
          </PublicRoute>
        ),
      },
      {
        path: "solutions/security-teams",
        element: (
          <PublicRoute>
            <SecurityTeamsPage />
          </PublicRoute>
        ),
      },
      {
        path: "solutions/devops-teams",
        element: (
          <PublicRoute>
            <DevOpsTeamsPage />
          </PublicRoute>
        ),
      },
      {
        path: "solutions/open-source-maintainers",
        element: (
          <PublicRoute>
            <OpenSourceMaintainersPage />
          </PublicRoute>
        ),
      },
      {
        path: "solutions/cto-leadership",
        element: (
          <PublicRoute>
            <CTOLeadershipPage />
          </PublicRoute>
        ),
      },
      {
        path: "solutions/startups-scaleups",
        element: (
          <PublicRoute>
            <StartupsScaleupsPage />
          </PublicRoute>
        ),
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
]);

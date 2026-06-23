/**
 * Platform features — pure dispatcher. Every Product slug now has its own
 * dedicated full page (components/landing/feature-pages/); this routes
 * /platform-features/:slug to the right one and redirects unknown or bare
 * paths to the first feature.
 */
import { useParams, Navigate } from "react-router-dom";
import AiSecurityAgentPage from "../../components/landing/feature-pages/AiSecurityAgentPage";
import DependencyScanningPage from "../../components/landing/feature-pages/DependencyScanningPage";
import CodeScanningPage from "../../components/landing/feature-pages/CodeScanningPage";
import InfrastructureDastPage from "../../components/landing/feature-pages/InfrastructureDastPage";

export default function PlatformFeaturesPage() {
  const { featureSlug } = useParams<{ featureSlug?: string }>();
  switch (featureSlug) {
    case "ai-security-agent":
      return <AiSecurityAgentPage />;
    case "dependency-scanning":
      return <DependencyScanningPage />;
    case "code-scanning":
      return <CodeScanningPage />;
    case "infrastructure-dast":
      return <InfrastructureDastPage />;
    default:
      return <Navigate to="/platform-features/ai-security-agent" replace />;
  }
}

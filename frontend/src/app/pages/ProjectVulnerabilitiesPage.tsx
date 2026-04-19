import { Navigate } from 'react-router-dom';

/**
 * Security tab has been merged into Overview. Redirect old /security and /vulnerabilities URLs to overview.
 */
export default function ProjectVulnerabilitiesPage() {
  return <Navigate to="../overview" replace />;
}

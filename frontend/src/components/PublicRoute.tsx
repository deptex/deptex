import { ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

interface PublicRouteProps {
  children: ReactNode;
}

/**
 * Route wrapper for public/unauthenticated routes.
 * Redirects authenticated users to /organizations.
 * Allows unauthenticated users to view the content.
 */
export default function PublicRoute({ children }: PublicRouteProps) {
  const { user, loading } = useAuth();

  // If user is logged in, redirect to organizations
  if (user) {
    return <Navigate to="/organizations" replace />;
  }

  // If no user and still loading, show loading state
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  // If not logged in, show the content
  return <>{children}</>;
}

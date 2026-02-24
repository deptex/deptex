import { Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

/**
 * Handles 404 (not found) routes by redirecting based on auth state.
 * - Authenticated users → /organizations
 * - Unauthenticated users → / (homepage)
 */
export default function NotFoundRedirect() {
  const { user, loading } = useAuth();

  // Show loading state while checking auth
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  // Redirect based on auth state
  if (user) {
    return <Navigate to="/organizations" replace />;
  }

  return <Navigate to="/" replace />;
}

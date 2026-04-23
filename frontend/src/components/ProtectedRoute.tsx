import { ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

interface ProtectedRouteProps {
  children: ReactNode;
}

export default function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { user, loading } = useAuth();

  if (user) return <>{children}</>;

  // No cached session — wait for INITIAL_SESSION before deciding to redirect.
  // Returns null (blank) rather than a spinner; this state is very brief.
  if (loading) return null;

  return <Navigate to="/" replace />;
}

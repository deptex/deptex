import { useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';

export default function InvitePage() {
  const { invitationId } = useParams<{ invitationId: string }>();
  const { user, loading: authLoading } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    // Wait for auth to finish loading
    if (authLoading) return;

    // If logged in, redirect to organizations page
    if (user) {
      navigate('/organizations', { replace: true });
      return;
    }

    // If logged out, redirect to login page with redirect parameter
    navigate(`/login?redirect=/invite/${invitationId}`, { replace: true });
  }, [user, authLoading, navigate, invitationId]);

  // Show loading state while checking auth
  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <div className="text-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
        <p className="text-foreground-secondary">Loading...</p>
      </div>
    </div>
  );
}


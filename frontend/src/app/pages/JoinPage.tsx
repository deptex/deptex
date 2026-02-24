import { useEffect, useState, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { api } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { Toaster } from '../../components/ui/toaster';

export default function JoinPage() {
  const { organizationId } = useParams<{ organizationId: string }>();
  const { user, loading: authLoading } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [joining, setJoining] = useState(false);
  const hasJoinedRef = useRef(false);

  // Get team_id from URL query params
  const searchParams = new URLSearchParams(window.location.search);
  const teamId = searchParams.get('team');

  useEffect(() => {
    // Wait for auth to finish loading
    if (authLoading) return;

    if (!organizationId) {
      navigate('/organizations', { replace: true });
      return;
    }

    // If logged out, redirect to login page with redirect parameter (including team if present)
    if (!user) {
      const redirectPath = teamId ? `/join/${organizationId}?team=${teamId}` : `/join/${organizationId}`;
      navigate(`/login?redirect=${encodeURIComponent(redirectPath)}`, { replace: true });
      return;
    }

    // If already joined, don't join again
    if (hasJoinedRef.current) return;

    // If logged in, auto-join the organization
    const handleJoin = async () => {
      if (joining) return;
      hasJoinedRef.current = true;

      try {
        setJoining(true);
        const result = await api.joinOrganization(organizationId, teamId || undefined);
        
        if (result.message === 'Already a member') {
          // Already a member, just redirect to the org
          navigate(`/organizations/${organizationId}`, { replace: true });
          return;
        }

        // Successfully joined
        toast({
          title: 'Success',
          description: 'You have joined the organization!',
        });
        
        navigate(`/organizations/${organizationId}`, { replace: true });
      } catch (error: any) {
        console.error('Failed to join organization:', error);
        toast({
          title: 'Error',
          description: error.message || 'Failed to join organization',
          variant: 'destructive',
        });
        // Redirect to organizations page on error
        navigate('/organizations', { replace: true });
      } finally {
        setJoining(false);
      }
    };

    handleJoin();
  }, [user, authLoading, navigate, organizationId, toast]);

  // Show loading state while checking auth or joining
  return (
    <>
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-foreground-secondary">
          </p>
        </div>
      </div>
      <Toaster position="bottom-right" />
    </>
  );
}


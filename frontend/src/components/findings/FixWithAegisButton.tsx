import { useCallback, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Loader2, Sparkles } from 'lucide-react';
import { api, type FindingType } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { Button } from '../ui/button';

interface FixWithAegisButtonProps {
  organizationId: string;
  projectId: string;
  findingType: FindingType;
  findingId: string;
  className?: string;
}

export function FixWithAegisButton({
  organizationId,
  projectId,
  findingType,
  findingId,
  className,
}: FixWithAegisButtonProps) {
  const [busy, setBusy] = useState(false);
  const navigate = useNavigate();
  const { toast } = useToast();

  const handleClick = useCallback(async (e: React.MouseEvent) => {
    e.stopPropagation();
    if (busy) return;
    setBusy(true);
    try {
      const res = await api.requestFix({
        organizationId,
        projectId,
        findingType,
        findingId,
      });
      navigate(`/organizations/${organizationId}/aegis?fix=${encodeURIComponent(res.fixId)}`);
      if (res.status === 'failed' && res.plan?.refusal) {
        toast({
          title: "Aegis can't fix this",
          description: res.plan.refusal.reason,
        });
      }
    } catch (err: any) {
      toast({
        title: 'Fix request failed',
        description: err?.message ?? 'Could not generate a fix plan.',
        variant: 'destructive',
      });
    } finally {
      setBusy(false);
    }
  }, [busy, organizationId, projectId, findingType, findingId, navigate, toast]);

  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      className={`h-7 text-xs gap-1.5 ${className ?? ''}`}
      onClick={handleClick}
      disabled={busy}
    >
      {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5" />}
      Fix with Aegis
    </Button>
  );
}

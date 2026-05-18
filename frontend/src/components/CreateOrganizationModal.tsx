import { useState } from 'react';
import { AlertCircle, Loader2 } from 'lucide-react';
import { Button } from './ui/button';
import { api, Organization } from '../lib/api';
import { Dialog, DialogContent, DialogDescription, DialogTitle } from './ui/dialog';

interface CreateOrganizationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (org?: Organization) => void;
}

export default function CreateOrganizationModal({
  isOpen,
  onClose,
  onSuccess,
}: CreateOrganizationModalProps) {
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e?: React.FormEvent) => {
    if (e) {
      e.preventDefault();
    }
    if (!name.trim() || loading) return;

    setError(null);
    setLoading(true);

    try {
      const org = await api.createOrganization(name);
      setName('');
      onSuccess(org);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to create organization');
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    if (!loading) {
      setName('');
      setError(null);
      onClose();
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={(open) => { if (!open) handleClose(); }}>
      <DialogContent hideClose className="sm:max-w-[520px] bg-background-card-header p-0 gap-0 overflow-hidden max-h-[90vh] flex flex-col">
        <div className="px-6 pt-6 pb-4 flex-shrink-0">
          <DialogTitle>Create a new organization</DialogTitle>
          <DialogDescription className="mt-1">
            Organizations help you group and manage your projects. Configure team members and billing settings for each organization.
          </DialogDescription>
        </div>

        <form onSubmit={handleSubmit} className="px-6 py-4 grid gap-4 overflow-y-auto max-h-[60vh] min-h-0">
          {error && (
            <div className="bg-destructive/10 border border-destructive/20 rounded-md p-3 flex items-start gap-2">
              <AlertCircle className="h-5 w-5 text-destructive flex-shrink-0 mt-0.5" />
              <p className="text-sm text-destructive">{error}</p>
            </div>
          )}

          <div>
            <label htmlFor="org-name" className="block text-sm font-medium text-foreground mb-2">
              Organization Name
            </label>
            <input
              id="org-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={32}
              className="w-full px-3 py-2.5 bg-black/20 border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-1 focus:ring-ring focus:border-ring transition-colors"
              autoFocus
              required
            />
          </div>
        </form>

        <div className="px-6 py-4 bg-background border-t border-border flex items-center justify-between">
          <Button
            variant="outline"
            onClick={handleClose}
            disabled={loading}
            className="!h-8 !px-3 !rounded-lg"
          >
            Cancel
          </Button>
          <Button
            variant="green"
            onClick={handleSubmit}
            disabled={loading || !name.trim()}
          >
            {loading ? (
              <>
                <span className="invisible">Create</span>
                <span className="absolute inset-0 flex items-center justify-center">
                  <Loader2 className="h-4 w-4 animate-spin" />
                </span>
              </>
            ) : (
              'Create'
            )}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}


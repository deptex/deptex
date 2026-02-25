import { useState } from 'react';
import { AlertCircle, Plus } from 'lucide-react';
import { Button } from './ui/button';
import { api } from '../lib/api';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from './ui/dialog';

interface CreateOrganizationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
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
      await api.createOrganization(name);
      setName('');
      onSuccess();
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
      <DialogContent hideClose className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-hidden max-h-[90vh] flex flex-col">
        <div className="px-6 pt-6 pb-4 border-b border-border flex-shrink-0">
          <DialogTitle>Create a new organization</DialogTitle>
          <DialogDescription className="mt-1">
            Organizations help you group and manage your projects. Configure team members and billing settings for each organization.
          </DialogDescription>
        </div>

        <form onSubmit={handleSubmit} className="px-6 py-4 grid gap-4 bg-background overflow-y-auto max-h-[60vh] min-h-0">
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
              placeholder="My Organization"
              className="w-full px-3 py-2 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
              autoFocus
              required
            />
          </div>
        </form>

        <DialogFooter className="px-6 py-4 bg-background">
          <Button variant="outline" onClick={handleClose} disabled={loading}>
            Cancel
          </Button>
          <Button
            onClick={handleSubmit}
            className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
            disabled={loading || !name.trim()}
          >
            {loading ? (
              <div className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-primary-foreground border-t-transparent flex-shrink-0" />
            ) : (
              <Plus className="h-4 w-4 mr-2 flex-shrink-0" />
            )}
            Create
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}


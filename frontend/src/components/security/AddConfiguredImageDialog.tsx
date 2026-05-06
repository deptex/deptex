import { useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '../ui/dialog';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Button } from '../ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../ui/select';
import { api, type ConfiguredImage, type RegistryCredential } from '../../lib/api';

const PUBLIC_IMAGE_VALUE = '__public__';

// Mirrors IMAGE_REF_REGEX in backend/src/routes/configured-images.ts. Client-side
// guard so a typo lights up before submitting; the backend re-validates.
const IMAGE_REF_REGEX = /^[a-z0-9._\-/:]+(@sha256:[a-f0-9]{64})?$/;

interface Props {
  open: boolean;
  organizationId: string;
  projectId: string;
  onClose: () => void;
  onCreated: (image: ConfiguredImage) => void;
}

export default function AddConfiguredImageDialog({
  open,
  organizationId,
  projectId,
  onClose,
  onCreated,
}: Props) {
  const [imageRef, setImageRef] = useState('');
  const [credentialsId, setCredentialsId] = useState<string>(PUBLIC_IMAGE_VALUE);
  const [creds, setCreds] = useState<RegistryCredential[] | null>(null);
  const [credsError, setCredsError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Lazy-fetch creds the first time the dialog opens. ConfiguredImagesSection
  // doesn't need cred metadata for its own list (the API attaches
  // credentials_display per row), so we keep the fetch local here.
  useEffect(() => {
    if (!open) return;
    if (creds !== null) return;
    api
      .listRegistryCredentials(organizationId)
      .then(setCreds)
      .catch((e: any) => setCredsError(e?.message ?? 'Failed to load credentials'));
  }, [open, organizationId, creds]);

  const handleSubmit = async () => {
    setError(null);
    if (!imageRef.trim()) {
      setError('Image reference is required');
      return;
    }
    if (!IMAGE_REF_REGEX.test(imageRef.trim())) {
      setError('Image reference must be lower-case docker-pullable shape (e.g. nginx:1.27 or repo@sha256:…)');
      return;
    }
    setSubmitting(true);
    try {
      const created = await api.createConfiguredImage(organizationId, projectId, {
        image_reference: imageRef.trim(),
        credentials_id: credentialsId === PUBLIC_IMAGE_VALUE ? null : credentialsId,
        enabled: true,
      });
      onCreated(created);
      handleClose();
    } catch (e: any) {
      setError(e?.message ?? 'Failed to add image');
    } finally {
      setSubmitting(false);
    }
  };

  const handleClose = () => {
    if (submitting) return;
    setImageRef('');
    setCredentialsId(PUBLIC_IMAGE_VALUE);
    setError(null);
    onClose();
  };

  return (
    <Dialog open={open} onOpenChange={(o) => !o && handleClose()}>
      <DialogContent className="max-w-lg p-0 gap-0 overflow-hidden bg-background-card-header">
        <div className="p-6 space-y-4">
          <DialogHeader>
            <DialogTitle>Add configured image</DialogTitle>
            <DialogDescription>
              Tell the scanner to pull and inspect this specific image on every extraction. Up
              to 20 images can be enabled per project.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-1">
            <Label>Image reference</Label>
            <Input
              value={imageRef}
              onChange={(e) => setImageRef(e.target.value)}
              placeholder="nginx:1.27 or registry/repo@sha256:abc…"
              autoComplete="off"
              spellCheck={false}
            />
            <p className="text-xs text-foreground-muted">
              Lower-case only. Tag refs (<code>repo:tag</code>) and digest pins
              (<code>repo@sha256:&lt;hex&gt;</code>) are both accepted.
            </p>
          </div>

          <div className="space-y-1">
            <Label>Pull credentials</Label>
            <Select value={credentialsId} onValueChange={setCredentialsId}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={PUBLIC_IMAGE_VALUE}>None &mdash; public image</SelectItem>
                {(creds ?? []).map((c) => (
                  <SelectItem key={c.id} value={c.id}>
                    {c.display_name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {credsError && <p className="text-xs text-destructive">{credsError}</p>}
          </div>

          {error && <div className="text-sm text-destructive">{error}</div>}
        </div>

        <div className="flex items-center justify-between px-6 py-4 border-t border-border bg-background">
          <Button variant="outline" onClick={handleClose} disabled={submitting}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={submitting}>
            {submitting ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" />Adding</> : 'Add image'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

import { useState } from 'react';
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
import {
  api,
  type RegistryType,
  type CredentialShape,
  type CredentialPlaintext,
  type RegistryCredential,
  type CreateRegistryCredentialBody,
} from '../../lib/api';

const REGISTRY_TYPES: ReadonlyArray<{ value: RegistryType; label: string }> = [
  { value: 'ghcr', label: 'GitHub Container Registry' },
  { value: 'ecr', label: 'Amazon ECR' },
  { value: 'gcr', label: 'Google Artifact Registry / GCR' },
  { value: 'acr', label: 'Azure Container Registry' },
  { value: 'dockerhub', label: 'Docker Hub' },
  { value: 'quay', label: 'Quay.io' },
  { value: 'harbor', label: 'Harbor (self-hosted)' },
  { value: 'jfrog', label: 'JFrog Artifactory' },
  { value: 'custom', label: 'Custom OCI registry' },
];

// Mirrors VALID_PAIRS in backend/src/routes/registry-credentials.ts. The first
// shape in each list is the form's default when the type is selected.
const SHAPES_BY_TYPE: Record<RegistryType, ReadonlyArray<CredentialShape>> = {
  ghcr: ['token', 'username_password'],
  ecr: ['aws_keys'],
  gcr: ['gcp_service_account_key'],
  acr: ['azure_service_principal', 'username_password'],
  dockerhub: ['username_password', 'token'],
  quay: ['token', 'username_password'],
  harbor: ['username_password'],
  jfrog: ['token', 'username_password'],
  custom: ['username_password', 'token'],
};

const SHAPE_LABELS: Record<CredentialShape, string> = {
  username_password: 'Username + password',
  aws_keys: 'AWS access keys',
  gcp_service_account_key: 'GCP service account JSON',
  azure_service_principal: 'Azure service principal',
  token: 'Bearer token / PAT',
};

const REGISTRY_URL_REQUIRED: ReadonlyArray<RegistryType> = ['harbor', 'jfrog', 'custom'];

interface Props {
  open: boolean;
  organizationId: string;
  onClose: () => void;
  onCreated: (cred: RegistryCredential) => void;
}

export default function AddRegistryCredentialDialog({
  open,
  organizationId,
  onClose,
  onCreated,
}: Props) {
  const [registryType, setRegistryType] = useState<RegistryType>('ghcr');
  const [registryUrl, setRegistryUrl] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [shape, setShape] = useState<CredentialShape>(SHAPES_BY_TYPE.ghcr[0]);
  // Shape-specific fields share state below; only the relevant subset is read
  // when building the submit payload.
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [awsAccessKeyId, setAwsAccessKeyId] = useState('');
  const [awsSecretAccessKey, setAwsSecretAccessKey] = useState('');
  const [awsSessionToken, setAwsSessionToken] = useState('');
  const [awsRegion, setAwsRegion] = useState('');
  const [gcpJson, setGcpJson] = useState('');
  const [azureClientId, setAzureClientId] = useState('');
  const [azureClientSecret, setAzureClientSecret] = useState('');
  const [azureTenantId, setAzureTenantId] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const allowedShapes = SHAPES_BY_TYPE[registryType];
  const urlRequired = REGISTRY_URL_REQUIRED.includes(registryType);

  // Reset all per-shape fields when the user changes registry type. Avoids a
  // GCP JSON blob carrying over into a Docker Hub form.
  const handleRegistryTypeChange = (next: RegistryType) => {
    setRegistryType(next);
    const defaultShape = SHAPES_BY_TYPE[next][0];
    setShape(defaultShape);
    setUsername('');
    setPassword('');
    setToken('');
    setAwsAccessKeyId('');
    setAwsSecretAccessKey('');
    setAwsSessionToken('');
    setAwsRegion('');
    setGcpJson('');
    setAzureClientId('');
    setAzureClientSecret('');
    setAzureTenantId('');
    setRegistryUrl('');
    setError(null);
  };

  const buildPayload = (): CreateRegistryCredentialBody | { error: string } => {
    if (!displayName.trim()) return { error: 'Display name is required' };
    if (urlRequired && !registryUrl.trim()) return { error: 'Registry URL is required for this registry type' };

    let credentials: CredentialPlaintext;
    switch (shape) {
      case 'username_password':
        if (!username || !password) return { error: 'Username and password are required' };
        credentials = { shape: 'username_password', username, password };
        break;
      case 'token':
        if (!token) return { error: 'Token is required' };
        credentials = { shape: 'token', token };
        break;
      case 'aws_keys':
        if (!awsAccessKeyId || !awsSecretAccessKey || !awsRegion) {
          return { error: 'Access key, secret key, and region are required' };
        }
        credentials = {
          shape: 'aws_keys',
          access_key_id: awsAccessKeyId,
          secret_access_key: awsSecretAccessKey,
          region: awsRegion,
          ...(awsSessionToken ? { session_token: awsSessionToken } : {}),
        };
        break;
      case 'gcp_service_account_key':
        if (!gcpJson.trim()) return { error: 'Service account JSON is required' };
        credentials = { shape: 'gcp_service_account_key', service_account_json: gcpJson };
        break;
      case 'azure_service_principal':
        if (!azureClientId || !azureClientSecret || !azureTenantId) {
          return { error: 'Client ID, client secret, and tenant ID are required' };
        }
        credentials = {
          shape: 'azure_service_principal',
          client_id: azureClientId,
          client_secret: azureClientSecret,
          tenant_id: azureTenantId,
        };
        break;
    }

    return {
      registry_type: registryType,
      registry_url: registryUrl.trim() || null,
      display_name: displayName.trim(),
      credentials,
    };
  };

  const handleSubmit = async () => {
    setError(null);
    const payload = buildPayload();
    if ('error' in payload) {
      setError(payload.error);
      return;
    }
    setSubmitting(true);
    try {
      const created = await api.createRegistryCredential(organizationId, payload);
      onCreated(created);
      handleClose();
    } catch (e: any) {
      setError(e?.message ?? 'Failed to create credential');
    } finally {
      setSubmitting(false);
    }
  };

  const handleClose = () => {
    if (submitting) return;
    handleRegistryTypeChange('ghcr');
    setDisplayName('');
    setError(null);
    onClose();
  };

  return (
    <Dialog open={open} onOpenChange={(o) => !o && handleClose()}>
      <DialogContent className="max-w-lg p-0 gap-0 overflow-hidden bg-background-card-header">
        <div className="p-6 space-y-4 max-h-[70vh] overflow-y-auto custom-scrollbar">
          <DialogHeader>
            <DialogTitle>Add registry credential</DialogTitle>
            <DialogDescription>
              Stored encrypted with AES-256-GCM. The plaintext is decrypted only inside
              the scanner worker, never returned to the browser after submit.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-1">
            <Label>Registry type</Label>
            <Select value={registryType} onValueChange={(v) => handleRegistryTypeChange(v as RegistryType)}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {REGISTRY_TYPES.map((rt) => (
                  <SelectItem key={rt.value} value={rt.value}>
                    {rt.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {urlRequired && (
            <div className="space-y-1">
              <Label>Registry URL</Label>
              <Input
                value={registryUrl}
                onChange={(e) => setRegistryUrl(e.target.value)}
                placeholder="harbor.example.com"
                autoComplete="off"
              />
            </div>
          )}

          <div className="space-y-1">
            <Label>Display name</Label>
            <Input
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="prod ghcr"
              autoComplete="off"
            />
          </div>

          {allowedShapes.length > 1 && (
            <div className="space-y-1">
              <Label>Credential type</Label>
              <Select value={shape} onValueChange={(v) => setShape(v as CredentialShape)}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {allowedShapes.map((s) => (
                    <SelectItem key={s} value={s}>
                      {SHAPE_LABELS[s]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}

          {/* Shape-specific fields */}
          {shape === 'username_password' && (
            <div className="space-y-3">
              <div className="space-y-1">
                <Label>Username</Label>
                <Input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" />
              </div>
              <div className="space-y-1">
                <Label>Password</Label>
                <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
              </div>
            </div>
          )}

          {shape === 'token' && (
            <div className="space-y-1">
              <Label>Token</Label>
              <Input
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="ghp_…"
                autoComplete="new-password"
              />
            </div>
          )}

          {shape === 'aws_keys' && (
            <div className="space-y-3">
              <div className="space-y-1">
                <Label>Access key ID</Label>
                <Input value={awsAccessKeyId} onChange={(e) => setAwsAccessKeyId(e.target.value)} autoComplete="off" />
              </div>
              <div className="space-y-1">
                <Label>Secret access key</Label>
                <Input type="password" value={awsSecretAccessKey} onChange={(e) => setAwsSecretAccessKey(e.target.value)} autoComplete="new-password" />
              </div>
              <div className="space-y-1">
                <Label>Region</Label>
                <Input value={awsRegion} onChange={(e) => setAwsRegion(e.target.value)} placeholder="us-east-1" autoComplete="off" />
              </div>
              <div className="space-y-1">
                <Label>Session token <span className="text-foreground-muted">(optional)</span></Label>
                <Input type="password" value={awsSessionToken} onChange={(e) => setAwsSessionToken(e.target.value)} autoComplete="new-password" />
              </div>
            </div>
          )}

          {shape === 'gcp_service_account_key' && (
            <div className="space-y-1">
              <Label>Service account JSON</Label>
              <textarea
                value={gcpJson}
                onChange={(e) => setGcpJson(e.target.value)}
                rows={6}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono text-foreground placeholder:text-foreground-muted focus:outline-none focus:ring-2 focus:ring-ring custom-scrollbar"
                placeholder='{"type":"service_account",...}'
                spellCheck={false}
              />
            </div>
          )}

          {shape === 'azure_service_principal' && (
            <div className="space-y-3">
              <div className="space-y-1">
                <Label>Client ID</Label>
                <Input value={azureClientId} onChange={(e) => setAzureClientId(e.target.value)} autoComplete="off" />
              </div>
              <div className="space-y-1">
                <Label>Client secret</Label>
                <Input type="password" value={azureClientSecret} onChange={(e) => setAzureClientSecret(e.target.value)} autoComplete="new-password" />
              </div>
              <div className="space-y-1">
                <Label>Tenant ID</Label>
                <Input value={azureTenantId} onChange={(e) => setAzureTenantId(e.target.value)} autoComplete="off" />
              </div>
            </div>
          )}

          {error && (
            <div className="text-sm text-destructive">{error}</div>
          )}
        </div>

        <div className="flex items-center justify-between px-6 py-4 border-t border-border bg-background">
          <Button variant="outline" onClick={handleClose} disabled={submitting}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={submitting}>
            {submitting ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" />Saving</> : 'Save credential'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// Worker-only registry credential decryption + per-registry-type auth minting.
//
// rbac-r2-7 invariant: types in this file (DecryptedCredential, the minters'
// plaintext args) carry decrypted credentials and MUST NOT be imported into
// route files. The route layer touches only the encrypted blob.
//
// Minter contract: each takes the relevant CredentialPlaintext shape and
// returns a DockerAuthEntry. ECR / Azure are async (network calls); basic /
// token / GCP are pure. ECR/Azure accept an injection point for tests so the
// unit suite never touches the AWS SDK or the AAD/ACR endpoints.

import { Buffer } from 'buffer';

import { decryptApiKey } from '../lib/encryption';
import type {
  CredentialPlaintext,
  CredentialShape,
  RegistryType,
  RegistryCredential,
} from './types';

export interface DockerAuthEntry {
  /** Base64-encoded "user:password" — the format ~/.docker/config.json expects. */
  auth: string;
}

/** Worker-side bundle: cred metadata + decrypted plaintext. The orchestrator
 *  (M8) builds these in the per-image scope; never produced in route layer. */
export interface DecryptedCredential {
  id: string;
  organization_id: string;
  registry_type: RegistryType;
  registry_url: string | null;
  display_name: string;
  plaintext: CredentialPlaintext;
}

// ---------------------------------------------------------------------------
// Decryption
// ---------------------------------------------------------------------------

/** Decrypts the encrypted_credentials blob written by the route layer and
 *  validates that the resulting JSON parses into one of the five known
 *  CredentialPlaintext shapes. The shape is inside the JSON itself; the
 *  orchestrator separately cross-checks it against the row's credential_shape
 *  column to detect tampering at rest. */
export function decryptCredential(blob: string, version: number): CredentialPlaintext {
  const json = decryptApiKey(blob, version);
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error('decryptCredential: plaintext is not valid JSON');
  }
  return validatePlaintext(parsed);
}

function validatePlaintext(parsed: unknown): CredentialPlaintext {
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('decryptCredential: plaintext is not an object');
  }
  const obj = parsed as Record<string, unknown>;
  if (typeof obj.shape !== 'string') {
    throw new Error('decryptCredential: plaintext missing shape discriminator');
  }
  const shape = obj.shape as CredentialShape;
  switch (shape) {
    case 'username_password':
      requireString(obj, 'username');
      requireString(obj, 'password');
      return { shape, username: obj.username as string, password: obj.password as string };
    case 'aws_keys':
      requireString(obj, 'access_key_id');
      requireString(obj, 'secret_access_key');
      requireString(obj, 'region');
      return {
        shape,
        access_key_id: obj.access_key_id as string,
        secret_access_key: obj.secret_access_key as string,
        session_token: typeof obj.session_token === 'string' ? obj.session_token : undefined,
        region: obj.region as string,
      };
    case 'gcp_service_account_key':
      requireString(obj, 'service_account_json');
      return { shape, service_account_json: obj.service_account_json as string };
    case 'azure_service_principal':
      requireString(obj, 'client_id');
      requireString(obj, 'client_secret');
      requireString(obj, 'tenant_id');
      return {
        shape,
        client_id: obj.client_id as string,
        client_secret: obj.client_secret as string,
        tenant_id: obj.tenant_id as string,
      };
    case 'token':
      requireString(obj, 'token');
      return { shape, token: obj.token as string };
    default:
      throw new Error(`decryptCredential: unknown credential shape "${String(shape)}"`);
  }
}

function requireString(obj: Record<string, unknown>, field: string): void {
  if (typeof obj[field] !== 'string' || (obj[field] as string).length === 0) {
    throw new Error(`decryptCredential: missing or empty field "${field}"`);
  }
}

// ---------------------------------------------------------------------------
// Hostname resolution
// ---------------------------------------------------------------------------

/** Resolves the docker-config.json key (hostname) for a credential row.
 *  Cloud-managed registries with a fixed default (ghcr / dockerhub / quay /
 *  gcr) accept a NULL registry_url and fall back to the convention. ECR /
 *  ACR / harbor / jfrog / custom require an explicit registry_url. */
export function resolveRegistryHostname(
  registry_type: RegistryType,
  registry_url: string | null
): string {
  if (registry_url) {
    return registry_url.replace(/^https?:\/\//, '').replace(/\/$/, '');
  }
  switch (registry_type) {
    case 'ghcr':
      return 'ghcr.io';
    case 'dockerhub':
      return 'index.docker.io';
    case 'quay':
      return 'quay.io';
    case 'gcr':
      return 'gcr.io';
    case 'ecr':
    case 'acr':
    case 'harbor':
    case 'jfrog':
    case 'custom':
      throw new Error(`resolveRegistryHostname: registry_url required for ${registry_type}`);
  }
}

// ---------------------------------------------------------------------------
// Pure minters (no network)
// ---------------------------------------------------------------------------

export function mintBasicAuth(plaintext: { username: string; password: string }): DockerAuthEntry {
  const auth = Buffer.from(`${plaintext.username}:${plaintext.password}`, 'utf8').toString('base64');
  return { auth };
}

/** Most registries (ghcr / Docker Hub PAT / JFrog identity tokens / Quay
 *  robot tokens) accept any literal username with the token in the password
 *  slot. "USERNAME" is the conventional placeholder. */
export function mintTokenAuth(plaintext: { token: string }): DockerAuthEntry {
  const auth = Buffer.from(`USERNAME:${plaintext.token}`, 'utf8').toString('base64');
  return { auth };
}

export function mintGcpAuth(plaintext: { service_account_json: string }): DockerAuthEntry {
  const auth = Buffer.from(
    `_json_key:${plaintext.service_account_json}`,
    'utf8'
  ).toString('base64');
  return { auth };
}

// ---------------------------------------------------------------------------
// ECR — fresh authorization token per scan (12h TTL upstream)
// ---------------------------------------------------------------------------

interface EcrAuthResult {
  authorizationData?: Array<{
    authorizationToken?: string;
    expiresAt?: Date;
    proxyEndpoint?: string;
  }>;
}

interface EcrClientFactoryArgs {
  region: string;
  credentials: {
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken?: string;
  };
}

export type EcrClientFactory = (args: EcrClientFactoryArgs) => Promise<EcrAuthResult>;

/** Lazy-imports @aws-sdk/client-ecr so the IaC-only scan path doesn't pay
 *  the SDK load cost, and so the unit tests below can swap in a mock factory. */
async function defaultEcrClientFactory(args: EcrClientFactoryArgs): Promise<EcrAuthResult> {
  const { ECRClient, GetAuthorizationTokenCommand } = await import('@aws-sdk/client-ecr');
  const client = new ECRClient({
    region: args.region,
    credentials: args.credentials,
  });
  return client.send(new GetAuthorizationTokenCommand({}));
}

export async function mintEcrAuth(
  plaintext: {
    access_key_id: string;
    secret_access_key: string;
    session_token?: string;
    region: string;
  },
  ecrClientFactory: EcrClientFactory = defaultEcrClientFactory
): Promise<DockerAuthEntry> {
  const result = await ecrClientFactory({
    region: plaintext.region,
    credentials: {
      accessKeyId: plaintext.access_key_id,
      secretAccessKey: plaintext.secret_access_key,
      sessionToken: plaintext.session_token,
    },
  });
  const tokens = result.authorizationData ?? [];
  const token = tokens[0]?.authorizationToken;
  if (!token) {
    throw new Error('mintEcrAuth: empty authorizationData from ECR');
  }
  // ECR returns base64('AWS:<password>') already — pass through.
  return { auth: token };
}

// ---------------------------------------------------------------------------
// Azure — exchange SP credentials for ACR refresh token
//
// Two-step flow per ACR docs:
//   1. POST login.microsoftonline.com → AAD access token (client_credentials)
//   2. POST <registry>/oauth2/exchange → ACR refresh token
// The refresh token is then used as the password with the magic GUID
// "00000000-0000-0000-0000-000000000000" as the username.
// ---------------------------------------------------------------------------

export type FetchLike = typeof fetch;

export async function mintAzureAuth(
  plaintext: { client_id: string; client_secret: string; tenant_id: string },
  registry_url: string,
  fetchImpl: FetchLike = fetch
): Promise<DockerAuthEntry> {
  if (!registry_url) {
    throw new Error('mintAzureAuth: registry_url required for ACR');
  }
  const registryHost = registry_url.replace(/^https?:\/\//, '').replace(/\/$/, '');

  const aadResp = await fetchImpl(
    `https://login.microsoftonline.com/${encodeURIComponent(plaintext.tenant_id)}/oauth2/v2.0/token`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: plaintext.client_id,
        client_secret: plaintext.client_secret,
        scope: `https://${registryHost}/.default`,
      }).toString(),
    }
  );
  if (!aadResp.ok) {
    throw new Error(`mintAzureAuth: AAD token exchange failed (${aadResp.status})`);
  }
  const aadJson = (await aadResp.json()) as { access_token?: unknown };
  if (typeof aadJson.access_token !== 'string') {
    throw new Error('mintAzureAuth: AAD response missing access_token');
  }
  const aadAccessToken: string = aadJson.access_token;

  const acrResp = await fetchImpl(`https://${registryHost}/oauth2/exchange`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'access_token',
      service: registryHost,
      tenant: plaintext.tenant_id,
      access_token: aadAccessToken,
    }).toString(),
  });
  if (!acrResp.ok) {
    throw new Error(`mintAzureAuth: ACR exchange failed (${acrResp.status})`);
  }
  const acrJson = (await acrResp.json()) as { refresh_token?: unknown };
  if (typeof acrJson.refresh_token !== 'string') {
    throw new Error('mintAzureAuth: ACR response missing refresh_token');
  }
  const acrRefresh: string = acrJson.refresh_token;

  const auth = Buffer.from(
    `00000000-0000-0000-0000-000000000000:${acrRefresh}`,
    'utf8'
  ).toString('base64');
  return { auth };
}

// ---------------------------------------------------------------------------
// Envelope — JSON suitable for ~/.docker/config.json (M8 will write into a
// per-scan ephemeral DOCKER_CONFIG dir; never log this string).
// ---------------------------------------------------------------------------

export function buildDockerAuthConfig(
  entries: ReadonlyArray<readonly [hostname: string, entry: DockerAuthEntry]>
): string {
  const auths: Record<string, DockerAuthEntry> = {};
  for (const [hostname, entry] of entries) {
    auths[hostname] = entry;
  }
  return JSON.stringify({ auths });
}

// Re-export the row shape so downstream files import the cred-bundle types
// from one place rather than reaching into ./types directly.
export type { RegistryCredential };

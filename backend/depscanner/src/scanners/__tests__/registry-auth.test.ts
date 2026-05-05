import { Buffer } from 'buffer';

import {
  decryptCredential,
  resolveRegistryHostname,
  mintBasicAuth,
  mintTokenAuth,
  mintGcpAuth,
  mintEcrAuth,
  mintAzureAuth,
  buildDockerAuthConfig,
  type EcrClientFactory,
  type FetchLike,
  type DockerAuthEntry,
} from '../registry-auth';
import { encryptApiKey } from '../../lib/encryption';
import type { CredentialPlaintext } from '../types';

const FIXTURE_KEY_HEX = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';

function decodeAuth(entry: DockerAuthEntry): string {
  return Buffer.from(entry.auth, 'base64').toString('utf8');
}

describe('decryptCredential', () => {
  const ORIG_ENV = { ...process.env };

  beforeEach(() => {
    process.env.AI_ENCRYPTION_KEY = FIXTURE_KEY_HEX;
    process.env.AI_ENCRYPTION_KEY_VERSION = '1';
    delete process.env.AI_ENCRYPTION_KEY_PREV;
  });

  afterEach(() => {
    process.env = { ...ORIG_ENV };
  });

  it.each<{ name: string; plaintext: CredentialPlaintext }>([
    {
      name: 'username_password',
      plaintext: { shape: 'username_password', username: 'alice', password: 'pw-1' },
    },
    {
      name: 'aws_keys with session token',
      plaintext: {
        shape: 'aws_keys',
        access_key_id: 'AKIA...',
        secret_access_key: 'secret',
        session_token: 'session',
        region: 'us-west-2',
      },
    },
    {
      name: 'aws_keys without session token',
      plaintext: {
        shape: 'aws_keys',
        access_key_id: 'AKIA...',
        secret_access_key: 'secret',
        region: 'eu-west-1',
      },
    },
    {
      name: 'gcp_service_account_key',
      plaintext: {
        shape: 'gcp_service_account_key',
        service_account_json: '{"type":"service_account","project_id":"x"}',
      },
    },
    {
      name: 'azure_service_principal',
      plaintext: {
        shape: 'azure_service_principal',
        client_id: 'cid',
        client_secret: 'csecret',
        tenant_id: 'tenant-uuid',
      },
    },
    {
      name: 'token',
      plaintext: { shape: 'token', token: 'ghp_abcdef' },
    },
  ])('round-trips $name through encrypt + decryptCredential', ({ plaintext }) => {
    const { encrypted, version } = encryptApiKey(JSON.stringify(plaintext));
    expect(decryptCredential(encrypted, version)).toEqual(plaintext);
  });

  it('throws when plaintext is not valid JSON', () => {
    const { encrypted, version } = encryptApiKey('not json');
    expect(() => decryptCredential(encrypted, version)).toThrow(/not valid JSON/);
  });

  it('throws when shape discriminator is missing', () => {
    const { encrypted, version } = encryptApiKey(JSON.stringify({ username: 'x', password: 'y' }));
    expect(() => decryptCredential(encrypted, version)).toThrow(/missing shape/);
  });

  it('throws on unknown shape', () => {
    const { encrypted, version } = encryptApiKey(JSON.stringify({ shape: 'pgp_key', token: 'x' }));
    expect(() => decryptCredential(encrypted, version)).toThrow(/unknown credential shape/);
  });

  it('throws when a required field is missing', () => {
    const { encrypted, version } = encryptApiKey(JSON.stringify({ shape: 'token' }));
    expect(() => decryptCredential(encrypted, version)).toThrow(/missing or empty field "token"/);
  });
});

describe('resolveRegistryHostname', () => {
  it.each([
    ['ghcr', null, 'ghcr.io'],
    ['dockerhub', null, 'index.docker.io'],
    ['quay', null, 'quay.io'],
    ['gcr', null, 'gcr.io'],
  ] as const)('falls back to default for %s when registry_url is null', (type, url, expected) => {
    expect(resolveRegistryHostname(type, url)).toBe(expected);
  });

  it.each([
    ['ecr', '123.dkr.ecr.us-west-2.amazonaws.com'],
    ['acr', 'myorg.azurecr.io'],
    ['harbor', 'harbor.internal.example.com'],
    ['jfrog', 'company.jfrog.io'],
    ['custom', 'registry.example.com'],
  ] as const)('returns the explicit registry_url for %s, stripping scheme', (type, url) => {
    expect(resolveRegistryHostname(type, `https://${url}/`)).toBe(url);
    expect(resolveRegistryHostname(type, url)).toBe(url);
  });

  it.each(['ecr', 'acr', 'harbor', 'jfrog', 'custom'] as const)(
    'throws when %s is missing registry_url',
    (type) => {
      expect(() => resolveRegistryHostname(type, null)).toThrow(/registry_url required/);
    }
  );
});

describe('pure minters', () => {
  it('mintBasicAuth produces base64("user:pass")', () => {
    const entry = mintBasicAuth({ username: 'alice', password: 's3cret' });
    expect(decodeAuth(entry)).toBe('alice:s3cret');
  });

  it('mintTokenAuth uses the literal "USERNAME" placeholder', () => {
    const entry = mintTokenAuth({ token: 'ghp_xyz' });
    expect(decodeAuth(entry)).toBe('USERNAME:ghp_xyz');
  });

  it('mintGcpAuth uses the "_json_key" username', () => {
    const json = '{"type":"service_account"}';
    const entry = mintGcpAuth({ service_account_json: json });
    expect(decodeAuth(entry)).toBe(`_json_key:${json}`);
  });
});

describe('mintEcrAuth', () => {
  it('returns the authorizationToken from ECR verbatim', async () => {
    const expected = Buffer.from('AWS:supersecret', 'utf8').toString('base64');
    const factory = jest.fn<ReturnType<EcrClientFactory>, Parameters<EcrClientFactory>>().mockResolvedValue({
      authorizationData: [{ authorizationToken: expected, expiresAt: new Date() }],
    });

    const entry = await mintEcrAuth(
      {
        access_key_id: 'AKIAEXAMPLE',
        secret_access_key: 'secret',
        region: 'us-west-2',
      },
      factory
    );

    expect(entry.auth).toBe(expected);
    expect(factory).toHaveBeenCalledWith({
      region: 'us-west-2',
      credentials: {
        accessKeyId: 'AKIAEXAMPLE',
        secretAccessKey: 'secret',
        sessionToken: undefined,
      },
    });
  });

  it('passes session_token when present', async () => {
    const factory = jest.fn<ReturnType<EcrClientFactory>, Parameters<EcrClientFactory>>().mockResolvedValue({
      authorizationData: [{ authorizationToken: Buffer.from('AWS:x', 'utf8').toString('base64') }],
    });

    await mintEcrAuth(
      {
        access_key_id: 'AKIA',
        secret_access_key: 'secret',
        session_token: 'sess-tok',
        region: 'eu-west-1',
      },
      factory
    );

    expect(factory).toHaveBeenCalledWith({
      region: 'eu-west-1',
      credentials: { accessKeyId: 'AKIA', secretAccessKey: 'secret', sessionToken: 'sess-tok' },
    });
  });

  it('throws when ECR returns empty authorizationData', async () => {
    const factory: EcrClientFactory = async () => ({ authorizationData: [] });
    await expect(
      mintEcrAuth({ access_key_id: 'a', secret_access_key: 'b', region: 'us-east-1' }, factory)
    ).rejects.toThrow(/empty authorizationData/);
  });
});

describe('mintAzureAuth', () => {
  function makeFetch(responses: Array<{ status?: number; body: any }>): jest.Mock<ReturnType<FetchLike>, Parameters<FetchLike>> {
    const queue = [...responses];
    return jest.fn().mockImplementation(async () => {
      const next = queue.shift();
      if (!next) throw new Error('mock fetch: no more responses queued');
      return {
        ok: (next.status ?? 200) >= 200 && (next.status ?? 200) < 300,
        status: next.status ?? 200,
        json: async () => next.body,
      } as unknown as Response;
    });
  }

  it('exchanges AAD then ACR and emits base64 of GUID:refresh_token', async () => {
    const fetchMock = makeFetch([
      { body: { access_token: 'aad-access-token' } },
      { body: { refresh_token: 'acr-refresh-token' } },
    ]);

    const entry = await mintAzureAuth(
      { client_id: 'cid', client_secret: 'csec', tenant_id: 'tid' },
      'https://myreg.azurecr.io/',
      fetchMock as unknown as FetchLike
    );

    expect(decodeAuth(entry)).toBe('00000000-0000-0000-0000-000000000000:acr-refresh-token');

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [aadUrl, aadInit] = fetchMock.mock.calls[0];
    expect(aadUrl).toBe('https://login.microsoftonline.com/tid/oauth2/v2.0/token');
    const aadBody = new URLSearchParams((aadInit as any).body);
    expect(aadBody.get('grant_type')).toBe('client_credentials');
    expect(aadBody.get('scope')).toBe('https://myreg.azurecr.io/.default');

    const [acrUrl, acrInit] = fetchMock.mock.calls[1];
    expect(acrUrl).toBe('https://myreg.azurecr.io/oauth2/exchange');
    const acrBody = new URLSearchParams((acrInit as any).body);
    expect(acrBody.get('access_token')).toBe('aad-access-token');
    expect(acrBody.get('service')).toBe('myreg.azurecr.io');
  });

  it('throws when AAD step fails', async () => {
    const fetchMock = makeFetch([{ status: 401, body: { error: 'invalid_client' } }]);
    await expect(
      mintAzureAuth(
        { client_id: 'cid', client_secret: 'wrong', tenant_id: 'tid' },
        'myreg.azurecr.io',
        fetchMock as unknown as FetchLike
      )
    ).rejects.toThrow(/AAD token exchange failed \(401\)/);
  });

  it('throws when ACR step fails', async () => {
    const fetchMock = makeFetch([
      { body: { access_token: 'aad-tok' } },
      { status: 403, body: {} },
    ]);
    await expect(
      mintAzureAuth(
        { client_id: 'cid', client_secret: 'csec', tenant_id: 'tid' },
        'myreg.azurecr.io',
        fetchMock as unknown as FetchLike
      )
    ).rejects.toThrow(/ACR exchange failed \(403\)/);
  });

  it('throws when ACR response is missing refresh_token', async () => {
    const fetchMock = makeFetch([
      { body: { access_token: 'aad-tok' } },
      { body: {} },
    ]);
    await expect(
      mintAzureAuth(
        { client_id: 'cid', client_secret: 'csec', tenant_id: 'tid' },
        'myreg.azurecr.io',
        fetchMock as unknown as FetchLike
      )
    ).rejects.toThrow(/missing refresh_token/);
  });

  it('rejects an empty registry_url', async () => {
    await expect(
      mintAzureAuth({ client_id: 'cid', client_secret: 'csec', tenant_id: 'tid' }, '')
    ).rejects.toThrow(/registry_url required/);
  });
});

describe('buildDockerAuthConfig', () => {
  it('emits a {auths: { host: entry }} envelope', () => {
    const json = buildDockerAuthConfig([
      ['ghcr.io', { auth: 'aGVucnk6cGF0' }],
      ['123.dkr.ecr.us-west-2.amazonaws.com', { auth: 'QVdTOnNlY3JldA==' }],
    ]);
    expect(JSON.parse(json)).toEqual({
      auths: {
        'ghcr.io': { auth: 'aGVucnk6cGF0' },
        '123.dkr.ecr.us-west-2.amazonaws.com': { auth: 'QVdTOnNlY3JldA==' },
      },
    });
  });

  it('handles an empty entry list', () => {
    expect(buildDockerAuthConfig([])).toBe('{"auths":{}}');
  });

  it('the last entry wins on duplicate hostnames', () => {
    const json = buildDockerAuthConfig([
      ['ghcr.io', { auth: 'first' }],
      ['ghcr.io', { auth: 'second' }],
    ]);
    expect(JSON.parse(json)).toEqual({ auths: { 'ghcr.io': { auth: 'second' } } });
  });
});

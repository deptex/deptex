import {
  buildImagePlan,
  listConfiguredImages,
  listCredentialMetadata,
} from '../orchestrator';

// ---------------------------------------------------------------------------
// Mock SupabaseClient with a recording surface so we can assert that the
// orchestrator's tenancy guards (plan §M8 Tenancy Invariants) are in place:
// every read MUST chain .eq('organization_id', orgId) for cred lists and
// .eq('project_id', projectId) for configured-image lists. The depscanner
// uses the service-role key (no RLS); without those filters the reads return
// cross-org data into worker memory.
// ---------------------------------------------------------------------------

interface RecordedCall {
  table: string;
  selectColumns?: string;
  eqs: Array<[string, unknown]>;
}

function makeRecordingSupabase(rows: Record<string, any[]>): {
  client: any;
  calls: RecordedCall[];
} {
  const calls: RecordedCall[] = [];
  const client = {
    from(table: string) {
      const call: RecordedCall = { table, eqs: [] };
      calls.push(call);
      const builder: any = {
        select(cols: string) {
          call.selectColumns = cols;
          return builder;
        },
        eq(col: string, val: unknown) {
          call.eqs.push([col, val]);
          return builder;
        },
        async then(resolve: (v: { data: any[]; error: null }) => void) {
          resolve({ data: rows[table] ?? [], error: null });
        },
      };
      return builder;
    },
  };
  return { client, calls };
}

describe('listCredentialMetadata — tenancy invariant', () => {
  it('always chains .eq("organization_id", orgId) on the cred-list read', async () => {
    const { client, calls } = makeRecordingSupabase({
      organization_registry_credentials: [
        {
          id: 'c1',
          registry_type: 'ecr',
          registry_url: '123.dkr.ecr.us-west-2.amazonaws.com',
          credential_shape: 'aws_keys',
          encryption_key_version: 1,
        },
      ],
    });
    const got = await listCredentialMetadata(client, 'org-uuid-A');
    expect(got).toHaveLength(1);
    expect(got[0].id).toBe('c1');
    expect(calls).toHaveLength(1);
    expect(calls[0].table).toBe('organization_registry_credentials');
    expect(calls[0].eqs).toContainEqual(['organization_id', 'org-uuid-A']);
    // Hard guard — encrypted_credentials MUST NOT be in the metadata SELECT.
    // Only the per-image lazy-decrypt path (fetchAndDecryptCredential) reads it.
    expect(calls[0].selectColumns).not.toMatch(/encrypted_credentials/);
  });
});

describe('listConfiguredImages — tenancy invariant', () => {
  it('always chains .eq("project_id", projectId) AND .eq("enabled", true)', async () => {
    const { client, calls } = makeRecordingSupabase({
      project_configured_images: [
        { id: 'i1', image_reference: 'ghcr.io/foo/bar:1.0', credentials_id: 'c1', enabled: true },
      ],
    });
    const got = await listConfiguredImages(client, 'proj-uuid-X');
    expect(got).toHaveLength(1);
    expect(calls).toHaveLength(1);
    expect(calls[0].table).toBe('project_configured_images');
    expect(calls[0].eqs).toContainEqual(['project_id', 'proj-uuid-X']);
    expect(calls[0].eqs).toContainEqual(['enabled', true]);
  });
});

// ---------------------------------------------------------------------------
// buildImagePlan — pure function, no IO. Covers:
//   - public Dockerfile image → public path, no cred
//   - private Dockerfile image with matching cred → authenticated
//   - ghcr Dockerfile image with NO cred → allowGhcrAppFallback=true (App-token path)
//   - private non-ghcr Dockerfile image with NO cred → no fallback (will skip)
//   - configured image with explicit cred → authenticated, source='configured_image'
//   - configured image with NULL cred + public host → public path
//   - configured image referencing missing cred → null cred, no fallback
// ---------------------------------------------------------------------------

describe('buildImagePlan', () => {
  it('routes public Dockerfile images through the public path with no cred', () => {
    const plan = buildImagePlan({
      dockerfileImageRefs: ['node:20', 'docker.io/library/postgres:15'],
      configuredImages: [],
      creds: [],
    });
    expect(plan).toHaveLength(2);
    expect(plan.every((p) => p.source === 'dockerfile_base')).toBe(true);
    expect(plan.every((p) => p.credId === null)).toBe(true);
    expect(plan.every((p) => p.allowGhcrAppFallback === false)).toBe(true);
  });

  it('matches a Dockerfile image to its registry cred by hostname', () => {
    const plan = buildImagePlan({
      dockerfileImageRefs: ['123.dkr.ecr.us-west-2.amazonaws.com/myrepo:tag'],
      configuredImages: [],
      creds: [
        {
          id: 'cred-ecr',
          registry_type: 'ecr',
          registry_url: '123.dkr.ecr.us-west-2.amazonaws.com',
          credential_shape: 'aws_keys',
          encryption_key_version: 1,
        },
      ],
    });
    expect(plan).toHaveLength(1);
    expect(plan[0].credId).toBe('cred-ecr');
    expect(plan[0].credHostname).toBe('123.dkr.ecr.us-west-2.amazonaws.com');
    expect(plan[0].allowGhcrAppFallback).toBe(false);
  });

  it('flags ghcr Dockerfile images for App-token fallback when no cred matches', () => {
    const plan = buildImagePlan({
      dockerfileImageRefs: ['ghcr.io/anthropic/foo:bar'],
      configuredImages: [],
      creds: [],
    });
    expect(plan).toHaveLength(1);
    expect(plan[0].credId).toBeNull();
    expect(plan[0].allowGhcrAppFallback).toBe(true);
  });

  it('does NOT flag App fallback when an explicit ghcr cred is present', () => {
    const plan = buildImagePlan({
      dockerfileImageRefs: ['ghcr.io/anthropic/foo:bar'],
      configuredImages: [],
      creds: [
        {
          id: 'cred-ghcr',
          registry_type: 'ghcr',
          registry_url: null,
          credential_shape: 'token',
          encryption_key_version: 1,
        },
      ],
    });
    expect(plan).toHaveLength(1);
    expect(plan[0].credId).toBe('cred-ghcr');
    expect(plan[0].allowGhcrAppFallback).toBe(false);
  });

  it('does NOT flag App fallback for non-ghcr private images with no cred', () => {
    const plan = buildImagePlan({
      dockerfileImageRefs: ['quay.io/team/foo:bar'],
      configuredImages: [],
      creds: [],
    });
    expect(plan).toHaveLength(1);
    expect(plan[0].credId).toBeNull();
    expect(plan[0].allowGhcrAppFallback).toBe(false);
  });

  it('attaches the explicit cred to a configured image when credentials_id is set', () => {
    const plan = buildImagePlan({
      dockerfileImageRefs: [],
      configuredImages: [
        {
          id: 'ci-1',
          image_reference: 'myorg.azurecr.io/foo:tag',
          credentials_id: 'cred-acr',
          enabled: true,
        },
      ],
      creds: [
        {
          id: 'cred-acr',
          registry_type: 'acr',
          registry_url: 'myorg.azurecr.io',
          credential_shape: 'azure_service_principal',
          encryption_key_version: 1,
        },
      ],
    });
    expect(plan).toHaveLength(1);
    expect(plan[0].source).toBe('configured_image');
    expect(plan[0].credId).toBe('cred-acr');
    expect(plan[0].credHostname).toBe('myorg.azurecr.io');
  });

  it('treats a configured image with null credentials_id and public host as public', () => {
    const plan = buildImagePlan({
      dockerfileImageRefs: [],
      configuredImages: [
        {
          id: 'ci-2',
          image_reference: 'public.ecr.aws/lambda/python:3.12',
          credentials_id: null,
          enabled: true,
        },
      ],
      creds: [],
    });
    expect(plan).toHaveLength(1);
    expect(plan[0].source).toBe('configured_image');
    expect(plan[0].credId).toBeNull();
    expect(plan[0].allowGhcrAppFallback).toBe(false);
  });

  it('handles a configured image referencing a cred that is not in the cred list (db inconsistency)', () => {
    const plan = buildImagePlan({
      dockerfileImageRefs: [],
      configuredImages: [
        {
          id: 'ci-3',
          image_reference: 'private.example.com/foo:tag',
          credentials_id: 'cred-missing',
          enabled: true,
        },
      ],
      creds: [], // FK violation simulated.
    });
    expect(plan).toHaveLength(1);
    expect(plan[0].source).toBe('configured_image');
    expect(plan[0].credId).toBeNull();
    expect(plan[0].credHostname).toBeNull();
    expect(plan[0].allowGhcrAppFallback).toBe(false);
  });
});

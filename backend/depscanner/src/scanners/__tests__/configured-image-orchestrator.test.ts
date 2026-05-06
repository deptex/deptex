import * as fs from 'fs';
import * as path from 'path';
import {
  fetchAndDecryptCredential,
  listCredentialMetadata,
} from '../orchestrator';
import {
  computeScanResultsHash,
  lookupContainerScanCache,
  truncateFindingsToFit,
  upsertContainerScanCache,
} from '../storage';
import type { ContainerScanCacheKey } from '../storage';
import { CredDecryptError } from '../scanner-errors';
import { encryptApiKey } from '../../lib/encryption';
import type { ContainerFinding, CredentialPlaintext } from '../types';

const FIXTURE_DIR = path.join(__dirname, 'fixtures', 'configured-image-fixture');
const FIXTURE_KEY_HEX =
  '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';

// ---------------------------------------------------------------------------
// Fixture probe — the configured-image fixture is documentation-only (the
// real scan target list lives in project_configured_images), but we still
// guard the fixture's shape so engineers reading the example don't get a
// silently rotten template.
// ---------------------------------------------------------------------------
describe('configured-image fixture', () => {
  it('ships a Dockerfile referencing the well-known sample image', () => {
    const dockerfile = fs.readFileSync(path.join(FIXTURE_DIR, 'Dockerfile'), 'utf8');
    expect(dockerfile).toMatch(/^FROM ghcr\.io\/foo\/sample:1\.2\.3$/m);
  });

  it('ships a configured-images.example.json that parses and matches the table shape', () => {
    const raw = fs.readFileSync(
      path.join(FIXTURE_DIR, '.deptex', 'configured-images.example.json'),
      'utf8',
    );
    const parsed = JSON.parse(raw);
    expect(Array.isArray(parsed.examples)).toBe(true);
    expect(parsed.examples.length).toBeGreaterThanOrEqual(2);
    for (const ex of parsed.examples) {
      expect(typeof ex.image_reference).toBe('string');
      // credentials_id is either a UUID-shaped string OR null OR a
      // documentation placeholder; we only check the runtime contract.
      if (ex.credentials_id !== null) {
        expect(typeof ex.credentials_id).toBe('string');
      }
      expect(typeof ex.enabled).toBe('boolean');
    }
  });
});

// ---------------------------------------------------------------------------
// Recording supabase — supports the 4-eq + maybeSingle path used by
// lookupContainerScanCache and the upsert path used by upsertContainerScanCache.
// Each test wires the in-memory rows it needs, and the recorder captures the
// chained filters so we can assert on them.
// ---------------------------------------------------------------------------
interface CacheCall {
  table: string;
  selectColumns?: string;
  eqs: Array<[string, unknown]>;
  upsertedRow?: Record<string, unknown>;
  upsertOptions?: Record<string, unknown>;
  terminator: 'maybeSingle' | 'single' | 'upsert' | 'none';
}

function makeCacheClient(
  rowsByTable: Record<string, Record<string, unknown>[]>,
): { client: any; calls: CacheCall[] } {
  const calls: CacheCall[] = [];
  const client = {
    from(table: string) {
      const call: CacheCall = { table, eqs: [], terminator: 'none' };
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
        async maybeSingle() {
          call.terminator = 'maybeSingle';
          const matched = (rowsByTable[table] ?? []).filter((r) =>
            call.eqs.every(([col, val]) => r[col] === val),
          );
          return { data: matched[0] ?? null, error: null };
        },
        async single() {
          call.terminator = 'single';
          const matched = (rowsByTable[table] ?? []).filter((r) =>
            call.eqs.every(([col, val]) => r[col] === val),
          );
          if (matched.length === 0) {
            return { data: null, error: { message: 'no row' } };
          }
          return { data: matched[0], error: null };
        },
        async upsert(row: Record<string, unknown>, opts: Record<string, unknown>) {
          call.terminator = 'upsert';
          call.upsertedRow = row;
          call.upsertOptions = opts;
          return { error: null };
        },
        async then(resolve: (v: { data: Record<string, unknown>[]; error: null }) => void) {
          // Plain awaited chain (no maybeSingle / single / upsert) — used by
          // listCredentialMetadata which expects { data, error }.
          const matched = (rowsByTable[table] ?? []).filter((r) =>
            call.eqs.every(([col, val]) => r[col] === val),
          );
          resolve({ data: matched, error: null });
        },
      };
      return builder;
    },
  };
  return { client, calls };
}

// ---------------------------------------------------------------------------
// Cache hit / miss / TTL / integrity
// ---------------------------------------------------------------------------
describe('container scan cache — hit/miss/TTL/integrity', () => {
  const KEY: ContainerScanCacheKey = {
    image_digest: 'a'.repeat(64),
    scanner: 'trivy',
    scanner_version: '0.50.0',
    trivy_db_version_day: '2026-05-04',
  };

  const CACHED_FINDINGS: ContainerFinding[] = [
    {
      id: 'f1',
      project_id: 'proj',
      organization_id: 'org',
      extraction_run_id: 'run',
      scanner_version: '0.50.0',
      image_reference: 'nginx:1.27',
      image_digest: KEY.image_digest,
      image_source: 'configured_image',
      os_package_name: 'libxyz',
      os_package_version: '1.0',
      os_package_ecosystem: 'alpine',
      osv_id: null,
      cve_id: 'CVE-2024-0001',
      vulnerability_id: 'CVE-2024-0001',
      severity: 'HIGH',
      cvss_score: 7.5,
      epss_score: null,
      is_kev: false,
      fix_versions: ['1.0.1'],
      layer_digest: null,
      depscore: 70,
      description: null,
      rule_doc_url: null,
      status: 'open',
      suppressed: false,
      risk_accepted: false,
      risk_accepted_reason: null,
      created_at: new Date().toISOString(),
    } as unknown as ContainerFinding,
  ];

  it('returns null on cache miss when no matching row exists', async () => {
    const { client, calls } = makeCacheClient({ container_image_scan_cache: [] });
    const got = await lookupContainerScanCache(client, KEY);
    expect(got).toBeNull();
    expect(calls).toHaveLength(1);
    // All four key components participate in the lookup filter.
    expect(calls[0].eqs).toEqual(
      expect.arrayContaining([
        ['image_digest', KEY.image_digest],
        ['scanner', KEY.scanner],
        ['scanner_version', KEY.scanner_version],
        ['trivy_db_version_day', KEY.trivy_db_version_day],
      ]),
    );
    expect(calls[0].terminator).toBe('maybeSingle');
  });

  it('returns the stored findings on cache hit when the hash matches', async () => {
    const { client } = makeCacheClient({
      container_image_scan_cache: [
        {
          ...KEY,
          scan_results: CACHED_FINDINGS,
          scan_results_hash: computeScanResultsHash(CACHED_FINDINGS),
          scanned_at: new Date().toISOString(),
        },
      ],
    });
    const got = await lookupContainerScanCache(client, KEY);
    expect(got).not.toBeNull();
    expect(got!.findings).toHaveLength(1);
    expect(got!.scanner_version).toBe(KEY.scanner_version);
  });

  it('returns null when the cached row is older than the 7-day TTL', async () => {
    const stale = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString();
    const { client } = makeCacheClient({
      container_image_scan_cache: [
        {
          ...KEY,
          scan_results: CACHED_FINDINGS,
          scan_results_hash: computeScanResultsHash(CACHED_FINDINGS),
          scanned_at: stale,
        },
      ],
    });
    const got = await lookupContainerScanCache(client, KEY);
    expect(got).toBeNull();
  });

  it('returns null and warns when the stored hash does not match the recomputed hash', async () => {
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    const { client } = makeCacheClient({
      container_image_scan_cache: [
        {
          ...KEY,
          scan_results: CACHED_FINDINGS,
          scan_results_hash: 'deadbeef'.repeat(8),
          scanned_at: new Date().toISOString(),
        },
      ],
    });
    const got = await lookupContainerScanCache(client, KEY);
    expect(got).toBeNull();
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('cache_integrity_mismatch'));
    warnSpy.mockRestore();
  });

  it('upserts a cache row with ON CONFLICT DO NOTHING and the canonical 4-tuple key', async () => {
    const { client, calls } = makeCacheClient({ container_image_scan_cache: [] });
    await upsertContainerScanCache(client, KEY, CACHED_FINDINGS, 'org-A', 'run-99');
    const upsertCall = calls.find((c) => c.terminator === 'upsert');
    expect(upsertCall).toBeDefined();
    expect(upsertCall!.upsertedRow).toMatchObject({
      ...KEY,
      first_scanned_by_org_id: 'org-A',
      first_scanned_run_id: 'run-99',
    });
    expect(upsertCall!.upsertedRow!.scan_results_hash).toBe(
      computeScanResultsHash(CACHED_FINDINGS),
    );
    expect(upsertCall!.upsertOptions).toMatchObject({
      onConflict: 'image_digest,scanner,scanner_version,trivy_db_version_day',
      ignoreDuplicates: true,
    });
  });
});

describe('truncateFindingsToFit', () => {
  it('returns the array unchanged when it already fits the byte budget', () => {
    const small: ContainerFinding[] = [
      {
        id: 'f1',
        severity: 'LOW',
        description: 'short',
      } as unknown as ContainerFinding,
    ];
    const out = truncateFindingsToFit(small);
    expect(out.truncated).toBe(false);
    expect(out.findings).toBe(small);
  });

  it('drops lowest-severity entries first when the budget is exceeded', () => {
    // Build oversized payload — many fat LOW findings + a few CRITICALs.
    // The fat field is a long description string so each row is ~5 KB.
    const fat = (severity: string, id: string): ContainerFinding =>
      ({
        id,
        severity,
        description: 'x'.repeat(5000),
      }) as unknown as ContainerFinding;

    const findings: ContainerFinding[] = [];
    for (let i = 0; i < 5; i++) findings.push(fat('CRITICAL', `c${i}`));
    for (let i = 0; i < 300; i++) findings.push(fat('LOW', `l${i}`));

    const out = truncateFindingsToFit(findings);
    expect(out.truncated).toBe(true);
    // CRITICALs MUST survive truncation.
    expect(out.findings.every((f) => f.severity !== null)).toBe(true);
    expect(out.findings.filter((f) => f.severity === 'CRITICAL').length).toBe(5);
  });
});

// ---------------------------------------------------------------------------
// Cred CRUD via the orchestrator + cross-org isolation regression.
// ---------------------------------------------------------------------------
describe('orchestrator cred resolution — cross-org isolation', () => {
  const ORG_A = 'org-uuid-A';
  const ORG_B = 'org-uuid-B';
  const CRED_A_ID = 'cred-belonging-to-A';

  const ORIG_ENV = { ...process.env };

  beforeEach(() => {
    process.env.AI_ENCRYPTION_KEY = FIXTURE_KEY_HEX;
    process.env.AI_ENCRYPTION_KEY_VERSION = '1';
    delete process.env.AI_ENCRYPTION_KEY_PREV;
  });

  afterEach(() => {
    process.env = { ...ORIG_ENV };
  });

  function seedCipher(plaintext: CredentialPlaintext): {
    encrypted_credentials: string;
    encryption_key_version: number;
  } {
    const result = encryptApiKey(JSON.stringify(plaintext));
    return {
      encrypted_credentials: result.encrypted,
      encryption_key_version: result.version,
    };
  }

  it('decrypts an org-A cred when read by org A', async () => {
    const cipher = seedCipher({
      shape: 'username_password',
      username: 'a-user',
      password: 'a-pass',
    });
    const { client, calls } = makeCacheClient({
      organization_registry_credentials: [
        {
          id: CRED_A_ID,
          organization_id: ORG_A,
          ...cipher,
        },
      ],
    });
    const out = await fetchAndDecryptCredential(client, CRED_A_ID, ORG_A);
    expect(out.shape).toBe('username_password');
    if (out.shape === 'username_password') {
      expect(out.username).toBe('a-user');
      expect(out.password).toBe('a-pass');
    }
    // Must have chained both id AND organization_id — never just id alone.
    expect(calls[0].eqs).toEqual(
      expect.arrayContaining([
        ['id', CRED_A_ID],
        ['organization_id', ORG_A],
      ]),
    );
  });

  it('refuses to decrypt org-A cred when called with org B as the tenant guard', async () => {
    // Same cred row exists, but the caller passes ORG_B. The
    // .eq('organization_id', ORG_B) chain must filter the row out —
    // the route never trusts the credentialId alone.
    const cipher = seedCipher({
      shape: 'token',
      token: 'A-only-secret',
    });
    const { client, calls } = makeCacheClient({
      organization_registry_credentials: [
        {
          id: CRED_A_ID,
          organization_id: ORG_A,
          ...cipher,
        },
      ],
    });
    await expect(fetchAndDecryptCredential(client, CRED_A_ID, ORG_B)).rejects.toBeInstanceOf(
      CredDecryptError,
    );
    expect(calls[0].eqs).toEqual(
      expect.arrayContaining([
        ['id', CRED_A_ID],
        ['organization_id', ORG_B],
      ]),
    );
  });

  it('throws CredDecryptError when the cred row is missing entirely', async () => {
    const { client } = makeCacheClient({ organization_registry_credentials: [] });
    await expect(
      fetchAndDecryptCredential(client, 'never-existed', ORG_A),
    ).rejects.toBeInstanceOf(CredDecryptError);
  });

  it('listCredentialMetadata never surfaces another org\'s creds', async () => {
    const aCipher = seedCipher({ shape: 'token', token: 'A-secret' });
    const bCipher = seedCipher({ shape: 'token', token: 'B-secret' });
    const { client, calls } = makeCacheClient({
      organization_registry_credentials: [
        {
          id: 'cred-A',
          organization_id: ORG_A,
          registry_type: 'ghcr',
          registry_url: null,
          credential_shape: 'token',
          encryption_key_version: 1,
          ...aCipher,
        },
        {
          id: 'cred-B',
          organization_id: ORG_B,
          registry_type: 'ghcr',
          registry_url: null,
          credential_shape: 'token',
          encryption_key_version: 1,
          ...bCipher,
        },
      ],
    });

    const aOnly = await listCredentialMetadata(client, ORG_A);
    expect(aOnly).toHaveLength(1);
    expect(aOnly[0].id).toBe('cred-A');

    const bOnly = await listCredentialMetadata(client, ORG_B);
    expect(bOnly).toHaveLength(1);
    expect(bOnly[0].id).toBe('cred-B');

    // Both reads chained organization_id; neither leaked the encrypted blob
    // into the metadata projection.
    for (const call of calls) {
      expect(call.eqs.find(([col]) => col === 'organization_id')).toBeDefined();
      expect(call.selectColumns).not.toMatch(/encrypted_credentials/);
    }
  });
});

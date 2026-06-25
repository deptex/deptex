import { fetchOsvVuln, osvVulnToAdvisoryRow } from '../osv-advisory';

describe('osvVulnToAdvisoryRow', () => {
  it('maps details/summary/aliases/dates and leaves PDV-owned fields null', () => {
    const row = osvVulnToAdvisoryRow('dep-1', {
      id: 'GHSA-xxxx',
      summary: 'Sum',
      details: 'Long description',
      aliases: ['CVE-2020-1'],
      published: '2020-01-01T00:00:00Z',
      modified: '2021-01-01T00:00:00Z',
      database_specific: { cwe_ids: ['CWE-79'] },
    });
    expect(row.dependency_id).toBe('dep-1');
    expect(row.osv_id).toBe('GHSA-xxxx');
    expect(row.details).toBe('Long description');
    expect(row.summary).toBe('Sum');
    expect(row.aliases).toEqual(['CVE-2020-1']);
    expect(row.cwe_ids).toEqual(['CWE-79']);
    expect(row.published_at).toBe('2020-01-01T00:00:00Z');
    // Deliberately null so the detail endpoint's `globalVuln?.x ?? vuln.x` falls
    // back to the per-project (PDV) value — an empty [] for fixed_versions would
    // hide the "Fixed in vX" badge.
    expect(row.fixed_versions).toBeNull();
    expect(row.severity).toBeNull();
    expect(row.affected_versions).toBeNull();
  });

  it('adds the requested id to aliases when it is not the canonical osv_id', () => {
    const row = osvVulnToAdvisoryRow('dep-1', { id: 'GHSA-yyyy', details: 'd', aliases: ['CVE-A'] }, 'CVE-B');
    expect(row.aliases).toEqual(expect.arrayContaining(['CVE-A', 'CVE-B']));
  });

  it('nulls empty summary/details rather than storing empty strings', () => {
    const row = osvVulnToAdvisoryRow('dep-1', { id: 'X', summary: '', details: '' });
    expect(row.summary).toBeNull();
    expect(row.details).toBeNull();
  });
});

describe('fetchOsvVuln', () => {
  const realFetch = global.fetch;
  afterEach(() => { global.fetch = realFetch; });

  it('returns the advisory on a direct hit', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true, status: 200, text: async () => JSON.stringify({ id: 'CVE-1', details: 'd' }),
    }) as any;
    const rec = await fetchOsvVuln('CVE-1');
    expect(rec?.id).toBe('CVE-1');
    expect(global.fetch as jest.Mock).toHaveBeenCalledTimes(1);
  });

  it('follows the GHSA alias named in a 404 message', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: false, status: 404, text: async () => JSON.stringify({ code: 5, message: 'Bug not found, but the following aliases were: GHSA-aaaa-bbbb-cccc' }) })
      .mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ id: 'GHSA-aaaa-bbbb-cccc', details: 'd', aliases: ['CVE-1'] }) }) as any;
    const rec = await fetchOsvVuln('CVE-1');
    expect(rec?.id).toBe('GHSA-aaaa-bbbb-cccc');
    expect(global.fetch as jest.Mock).toHaveBeenCalledTimes(2);
  });

  it('returns null when not in OSV and no alias is offered', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false, status: 404, text: async () => JSON.stringify({ code: 5, message: 'Bug not found' }),
    }) as any;
    const rec = await fetchOsvVuln('CVE-unknown');
    expect(rec).toBeNull();
  });
});

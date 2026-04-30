import { validateExternalUrl } from '../url-guard';

// ipaddr.js is real; only DNS is mocked so we can synthesize hostile responses.
jest.mock('dns', () => {
  const actual = jest.requireActual('dns');
  return {
    ...actual,
    promises: {
      lookup: jest.fn(),
    },
  };
});

import { promises as dns } from 'dns';
const dnsLookup = dns.lookup as jest.Mock;

function mockDnsResolves(addresses: { address: string; family: 4 | 6 }[]) {
  dnsLookup.mockResolvedValueOnce(addresses);
}

beforeEach(() => {
  dnsLookup.mockReset();
});

describe('validateExternalUrl — accepted', () => {
  it('accepts an https URL resolving to a public IPv4', async () => {
    mockDnsResolves([{ address: '93.184.216.34', family: 4 }]);
    const r = await validateExternalUrl('https://example.com/');
    expect(r.valid).toBe(true);
  });

  it('accepts an http URL resolving to multiple public addresses', async () => {
    mockDnsResolves([
      { address: '93.184.216.34', family: 4 },
      { address: '2606:2800:220:1:248:1893:25c8:1946', family: 6 },
    ]);
    const r = await validateExternalUrl('http://staging.example.com:8080/health');
    expect(r.valid).toBe(true);
  });
});

describe('validateExternalUrl — input shape', () => {
  it('rejects empty', async () => {
    const r = await validateExternalUrl('');
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/empty/i);
  });

  it('rejects oversize', async () => {
    const r = await validateExternalUrl('https://' + 'a'.repeat(2050) + '.example.com');
    expect(r.valid).toBe(false);
  });

  it('rejects garbage', async () => {
    const r = await validateExternalUrl('not a url');
    expect(r.valid).toBe(false);
  });

  it('rejects file:// scheme', async () => {
    const r = await validateExternalUrl('file:///etc/passwd');
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/scheme/);
  });

  it('rejects gopher:// scheme', async () => {
    const r = await validateExternalUrl('gopher://example.com/');
    expect(r.valid).toBe(false);
  });

  it('rejects javascript: scheme', async () => {
    const r = await validateExternalUrl('javascript:alert(1)');
    expect(r.valid).toBe(false);
  });
});

describe('validateExternalUrl — literal IP rejections (no DNS needed)', () => {
  it('rejects 127.0.0.1', async () => {
    const r = await validateExternalUrl('http://127.0.0.1/');
    expect(r.valid).toBe(false);
    expect(dnsLookup).not.toHaveBeenCalled();
  });

  it('rejects 10.0.0.5', async () => {
    const r = await validateExternalUrl('http://10.0.0.5:3000/');
    expect(r.valid).toBe(false);
  });

  it('rejects 172.16.0.1', async () => {
    const r = await validateExternalUrl('https://172.16.0.1/');
    expect(r.valid).toBe(false);
  });

  it('rejects 172.31.255.255 (top of RFC1918)', async () => {
    const r = await validateExternalUrl('http://172.31.255.255/');
    expect(r.valid).toBe(false);
  });

  it('accepts 172.32.0.1 (just outside RFC1918)', async () => {
    mockDnsResolves([{ address: '172.32.0.1', family: 4 }]);
    const r = await validateExternalUrl('http://172.32.0.1/');
    expect(r.valid).toBe(true);
  });

  it('rejects 192.168.1.1', async () => {
    const r = await validateExternalUrl('http://192.168.1.1/');
    expect(r.valid).toBe(false);
  });

  it('rejects 169.254.169.254 (IMDS)', async () => {
    const r = await validateExternalUrl('http://169.254.169.254/latest/meta-data/');
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/linkLocal|IMDS|169\.254\.169\.254/);
  });

  it('rejects ::1 IPv6 loopback', async () => {
    const r = await validateExternalUrl('http://[::1]/');
    expect(r.valid).toBe(false);
  });

  it('rejects fe80::1 IPv6 link-local', async () => {
    const r = await validateExternalUrl('http://[fe80::1]/');
    expect(r.valid).toBe(false);
  });

  it('rejects fdaa::1 Fly 6PN', async () => {
    const r = await validateExternalUrl('http://[fdaa::1]/');
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/uniqueLocal|Fly 6PN/);
  });

  it('rejects 0.0.0.0', async () => {
    const r = await validateExternalUrl('http://0.0.0.0/');
    expect(r.valid).toBe(false);
  });
});

describe('validateExternalUrl — literal hostname rejections', () => {
  it('rejects bare localhost', async () => {
    const r = await validateExternalUrl('http://localhost/');
    expect(r.valid).toBe(false);
    expect(dnsLookup).not.toHaveBeenCalled();
  });

  it('rejects *.internal', async () => {
    const r = await validateExternalUrl('http://app.internal/');
    expect(r.valid).toBe(false);
    expect(dnsLookup).not.toHaveBeenCalled();
  });

  it('rejects *.fly.dev.internal', async () => {
    const r = await validateExternalUrl('http://service.fly.dev.internal/');
    expect(r.valid).toBe(false);
    expect(dnsLookup).not.toHaveBeenCalled();
  });
});

describe('validateExternalUrl — DNS-resolved attacks', () => {
  it('rejects hostname that resolves to 127.0.0.1 (DNS smuggling)', async () => {
    mockDnsResolves([{ address: '127.0.0.1', family: 4 }]);
    const r = await validateExternalUrl('https://attacker-controlled.example.com/');
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/loopback/i);
  });

  it('rejects hostname that resolves to ANY private address', async () => {
    mockDnsResolves([
      { address: '93.184.216.34', family: 4 },
      { address: '10.0.0.5', family: 4 }, // smuggled internal
    ]);
    const r = await validateExternalUrl('https://multi-resolve.example.com/');
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/private/);
  });

  it('rejects hostname that resolves to IPv6 loopback', async () => {
    mockDnsResolves([{ address: '::1', family: 6 }]);
    const r = await validateExternalUrl('https://v6-attack.example.com/');
    expect(r.valid).toBe(false);
  });

  it('rejects hostname that resolves to IMDS', async () => {
    mockDnsResolves([{ address: '169.254.169.254', family: 4 }]);
    const r = await validateExternalUrl('https://metadata.example.com/');
    expect(r.valid).toBe(false);
  });

  it('rejects when DNS resolution fails entirely', async () => {
    dnsLookup.mockRejectedValueOnce(Object.assign(new Error('not found'), { code: 'ENOTFOUND' }));
    const r = await validateExternalUrl('https://does-not-exist-xyz.example/');
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/DNS resolution failed/);
  });
});

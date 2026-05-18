import {
  redactCredentials,
  parseZapReport,
} from '../dast/runner';

describe('redactCredentials', () => {
  it('redacts JWTs', () => {
    const out = redactCredentials('Authorization: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkw.signature_12345678');
    expect(out).toContain('[REDACTED_JWT]');
    expect(out).not.toContain('eyJ');
  });

  it('redacts AWS access keys', () => {
    expect(redactCredentials('AKIAIOSFODNN7EXAMPLE')).toContain('[REDACTED_AWS_KEY]');
    expect(redactCredentials('ASIAJEXAMPLEACCESSKE')).toContain('[REDACTED_AWS_KEY]');
  });

  it('redacts Bearer tokens', () => {
    expect(redactCredentials('Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456')).toContain('Bearer [REDACTED]');
  });

  it('redacts GitHub tokens', () => {
    expect(redactCredentials('ghp_1234567890abcdefghijklmnopqrstuvwxyz')).toContain('[REDACTED_GHP]');
  });

  it('redacts password assignments', () => {
    expect(redactCredentials('password=hunter2')).toContain('password=[REDACTED]');
    expect(redactCredentials('"password":"secret123"')).toContain('password=[REDACTED]');
  });

  it('redacts API key assignments', () => {
    expect(redactCredentials('api_key=abc123def456ghi789')).toContain('api_key=[REDACTED]');
  });

  it('stops password redaction cleanly at URL / cookie delimiters', () => {
    // Query-string: `&` must terminate the value so neighbouring params survive.
    const url = redactCredentials('https://x.test/login?password=hunter2&user=alice');
    expect(url).toBe('https://x.test/login?password=[REDACTED]&user=alice');
    // Cookie-pair separator (`;`) — the cookie-line redactor doesn't fire here
    // because the input has no `Cookie:` header, so password rule must stop at `;`.
    const pair = redactCredentials('payload=password=hunter2;next=/dash');
    expect(pair).toBe('payload=password=[REDACTED];next=/dash');
    // Fragment / hash separator (`#`).
    const frag = redactCredentials('?password=hunter2#section');
    expect(frag).toBe('?password=[REDACTED]#section');
  });

  it('redacts api_key with base64 padding/special chars without truncating', () => {
    // Base64 `+`, `/`, `=` must be consumed so padding doesn't leak after redaction.
    const padded = redactCredentials('api_key=AbCd+ef/gh==&next=foo');
    expect(padded).toBe('api_key=[REDACTED]&next=foo');
    expect(padded).not.toContain('AbCd');
    expect(padded).not.toContain('==&');
  });

  it('redacts entire Cookie header value (multi-pair)', () => {
    const out = redactCredentials('GET /api/x Cookie: session=fixture-cookie-value-7f3e; csrf=abc123');
    expect(out).toBe('GET /api/x Cookie: [REDACTED]');
    expect(out).not.toContain('fixture-cookie-value-7f3e');
    expect(out).not.toContain('csrf=abc123');
  });

  it('redacts Set-Cookie response headers', () => {
    const out = redactCredentials('Set-Cookie: session=secret123; Path=/; HttpOnly');
    expect(out).toBe('Set-Cookie: [REDACTED]');
    expect(out).not.toContain('secret123');
  });

  it('returns null for null', () => {
    expect(redactCredentials(null)).toBeNull();
    expect(redactCredentials(undefined)).toBeNull();
  });

  it('passes through clean strings', () => {
    expect(redactCredentials('hello world')).toBe('hello world');
  });
});

describe('parseZapReport', () => {
  it('parses a single alert with one instance', () => {
    const report = {
      site: [
        {
          '@name': 'https://target.example.com',
          alerts: [
            {
              alert: 'Cross Site Scripting (Reflected)',
              name: 'Cross Site Scripting (Reflected)',
              riskcode: '3',
              confidence: '2',
              cweid: '79',
              alertRef: '40012-1',
              pluginid: '40012',
              desc: 'XSS reflected',
              instances: [
                {
                  uri: 'https://target.example.com/search?q=1',
                  method: 'GET',
                  attack: '<script>alert(1)</script>',
                  evidence: 'Reflected: <script>alert(1)</script>',
                },
              ],
            },
          ],
        },
      ],
    };
    const findings = parseZapReport(report);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('high');
    expect(findings[0].confidence).toBe('medium');
    expect(findings[0].cwe_id).toBe('79');
    expect(findings[0].owasp_top10_ref).toBe('A03:2021');
    expect(findings[0].rule_id).toBe('40012-1');
    expect(findings[0].http_method).toBe('GET');
    expect(findings[0].endpoint_url).toBe('https://target.example.com/search?q=1');
  });

  it('flattens multiple instances per alert into multiple findings', () => {
    const report = {
      site: [
        {
          '@name': 'https://target.example.com',
          alerts: [
            {
              name: 'X-Frame-Options Header Not Set',
              riskcode: '2',
              confidence: '3',
              cweid: '1021',
              instances: [
                { uri: 'https://target.example.com/a', method: 'GET' },
                { uri: 'https://target.example.com/b', method: 'GET' },
              ],
            },
          ],
        },
      ],
    };
    const findings = parseZapReport(report);
    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.endpoint_url).sort()).toEqual([
      'https://target.example.com/a',
      'https://target.example.com/b',
    ]);
  });

  it('handles alerts with no instances', () => {
    const report = {
      site: [
        {
          '@name': 'https://target.example.com',
          alerts: [
            {
              name: 'Information Disclosure',
              riskcode: '0',
              confidence: '1',
            },
          ],
        },
      ],
    };
    const findings = parseZapReport(report);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('info');
    expect(findings[0].http_method).toBe('GET');
  });

  it('redacts credentials in attack/evidence', () => {
    const report = {
      site: [
        {
          '@name': 'https://target.example.com',
          alerts: [
            {
              name: 'Auth Header Exposure',
              riskcode: '3',
              confidence: '4',
              instances: [
                {
                  uri: '/api/users',
                  method: 'GET',
                  attack: 'Bearer abcdef0123456789abcdef0123456789',
                  evidence: 'AKIAIOSFODNN7EXAMPLE',
                },
              ],
            },
          ],
        },
      ],
    };
    const findings = parseZapReport(report);
    expect(findings[0].payload_redacted).toContain('Bearer [REDACTED]');
    expect(findings[0].response_evidence_redacted).toContain('[REDACTED_AWS_KEY]');
  });

  it('returns empty array on empty report', () => {
    expect(parseZapReport({})).toEqual([]);
    expect(parseZapReport({ site: [] })).toEqual([]);
  });

  it('treats riskcode 4 as critical', () => {
    const report = {
      site: [{ '@name': 'x', alerts: [{ name: 'crit', riskcode: '4', confidence: '4', instances: [{ uri: '/a', method: 'GET' }] }] }],
    };
    expect(parseZapReport(report)[0].severity).toBe('critical');
  });
});

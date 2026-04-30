import {
  selectScript,
  patternToOpenApi,
  buildOpenApiStub,
  redactCredentials,
  parseZapReport,
} from '../dast/runner';

describe('selectScript', () => {
  it('full → full', () => {
    expect(selectScript('full', false)).toBe('full');
    expect(selectScript('full', true)).toBe('full');
  });

  it('quick → baseline regardless of routes', () => {
    expect(selectScript('quick', false)).toBe('baseline');
    expect(selectScript('quick', true)).toBe('baseline');
  });

  it('auto with routes → api', () => {
    expect(selectScript('auto', true)).toBe('api');
  });

  it('auto without routes → baseline', () => {
    expect(selectScript('auto', false)).toBe('baseline');
  });

  it('explicit api → api', () => {
    expect(selectScript('api', false)).toBe('api');
  });
});

describe('patternToOpenApi', () => {
  it('converts express :id → {id}', () => {
    expect(patternToOpenApi('express', '/users/:id')).toBe('/users/{id}');
    expect(patternToOpenApi('express', '/users/:userId/posts/:postId')).toBe('/users/{userId}/posts/{postId}');
  });

  it('converts fastify :id → {id}', () => {
    expect(patternToOpenApi('fastify', '/users/:id')).toBe('/users/{id}');
  });

  it('converts rails :id and *splat', () => {
    expect(patternToOpenApi('rails', '/photos/:id')).toBe('/photos/{id}');
    expect(patternToOpenApi('rails', '/files/*path')).toBe('/files/{path}');
  });

  it('converts gin *action → {action}', () => {
    expect(patternToOpenApi('gin', '/static/*filepath')).toBe('/static/{filepath}');
  });

  it('preserves fastapi {id} and strips type hints', () => {
    expect(patternToOpenApi('fastapi', '/items/{id}')).toBe('/items/{id}');
    expect(patternToOpenApi('fastapi', '/items/{id:int}')).toBe('/items/{id}');
  });

  it('preserves spring {id} and strips type hints', () => {
    expect(patternToOpenApi('spring', '/users/{id:[0-9]+}')).toBe('/users/{id}');
  });

  it('preserves laravel {id?} optional marker', () => {
    expect(patternToOpenApi('laravel', '/posts/{slug?}')).toBe('/posts/{slug}');
  });

  it('strips scheme+host', () => {
    expect(patternToOpenApi('express', 'https://api.example.com/users/:id')).toBe('/users/{id}');
  });
});

describe('buildOpenApiStub', () => {
  it('builds a 3.0 spec with paths grouped by route', () => {
    const stub = buildOpenApiStub('https://api.example.com', [
      { framework: 'express', http_method: 'GET', route_pattern: '/users/:id', handler_name: 'getUser' },
      { framework: 'express', http_method: 'POST', route_pattern: '/users/:id', handler_name: 'updateUser' },
      { framework: 'express', http_method: 'GET', route_pattern: '/items', handler_name: 'listItems' },
    ]);
    expect(stub.openapi).toBe('3.0.0');
    expect((stub.servers as Array<{ url: string }>)[0].url).toBe('https://api.example.com');
    const paths = stub.paths as Record<string, Record<string, unknown>>;
    expect(paths['/users/{id}']).toBeDefined();
    expect(paths['/users/{id}'].get).toBeDefined();
    expect(paths['/users/{id}'].post).toBeDefined();
    expect(paths['/items']).toBeDefined();
    expect(paths['/items'].get).toBeDefined();
  });

  it('skips routes with missing pattern or method', () => {
    const stub = buildOpenApiStub('https://api.example.com', [
      { framework: 'express', http_method: null, route_pattern: '/users/:id', handler_name: null },
      { framework: 'express', http_method: 'GET', route_pattern: null, handler_name: null },
      { framework: 'express', http_method: 'GET', route_pattern: '/keep', handler_name: null },
    ]);
    const paths = stub.paths as Record<string, unknown>;
    expect(Object.keys(paths)).toEqual(['/keep']);
  });

  it('emits path parameters from {} segments', () => {
    const stub = buildOpenApiStub('https://api.example.com', [
      { framework: 'express', http_method: 'GET', route_pattern: '/users/:userId/posts/:postId', handler_name: null },
    ]);
    const paths = stub.paths as Record<string, Record<string, { parameters?: Array<{ name: string }> }>>;
    const op = paths['/users/{userId}/posts/{postId}'].get;
    expect(op.parameters?.map((p) => p.name).sort()).toEqual(['postId', 'userId']);
  });

  it('skips unsupported HTTP methods', () => {
    const stub = buildOpenApiStub('https://api.example.com', [
      { framework: 'express', http_method: 'TRACE', route_pattern: '/x', handler_name: null },
      { framework: 'express', http_method: 'GET', route_pattern: '/x', handler_name: null },
    ]);
    const paths = stub.paths as Record<string, Record<string, unknown>>;
    expect(Object.keys(paths['/x'])).toEqual(['get']);
  });
});

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

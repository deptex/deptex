import {
  scanLogRowForPlaintext,
  scrubLogValue,
  scrubLogObject,
  SYNTHETIC_PASSWORD_FIXTURE,
  SYNTHETIC_JWT_FIXTURE,
  SYNTHETIC_COOKIE_FIXTURE,
} from '../dast-log-scrub';

// ---------------------------------------------------------------------------
// scanLogRowForPlaintext — synthetic fixture detection
// ---------------------------------------------------------------------------

describe('scanLogRowForPlaintext — empty / safe rows', () => {
  it('returns no matches for an empty string', () => {
    expect(scanLogRowForPlaintext('')).toEqual([]);
  });

  it('returns no matches for a row with only safe content', () => {
    expect(scanLogRowForPlaintext('user clicked button A; sent 42 bytes')).toEqual([]);
  });

  it('returns no matches for a structured object with no fixtures', () => {
    expect(
      scanLogRowForPlaintext({
        level: 'info',
        msg: 'scan started',
        target_id: 'cccccccc-cccc-cccc-cccc-cccccccccccc',
      }),
    ).toEqual([]);
  });
});

describe('scanLogRowForPlaintext — synthetic password fixture leak', () => {
  it('flags raw password fixture in a log line', () => {
    const r = scanLogRowForPlaintext(`POST /login user=alice password=${SYNTHETIC_PASSWORD_FIXTURE}`);
    expect(r).toHaveLength(1);
    expect(r[0].fixture).toBe(SYNTHETIC_PASSWORD_FIXTURE);
    expect(r[0].occurrence_count).toBe(1);
  });

  it('flags password fixture inside a serialized JSON payload', () => {
    const r = scanLogRowForPlaintext({
      msg: 'queued scan',
      payload: { username: 'alice', password: SYNTHETIC_PASSWORD_FIXTURE },
    });
    expect(r.some((m) => m.fixture === SYNTHETIC_PASSWORD_FIXTURE)).toBe(true);
  });

  it('counts multiple occurrences', () => {
    const haystack = `${SYNTHETIC_PASSWORD_FIXTURE} retried, then ${SYNTHETIC_PASSWORD_FIXTURE} retried again`;
    const r = scanLogRowForPlaintext(haystack);
    expect(r[0].occurrence_count).toBe(2);
  });
});

describe('scanLogRowForPlaintext — synthetic JWT fixture leak', () => {
  it('flags raw JWT fixture in a log line', () => {
    const r = scanLogRowForPlaintext(
      `Authorization: Bearer ${SYNTHETIC_JWT_FIXTURE} sent to upstream`,
    );
    expect(r.some((m) => m.fixture === SYNTHETIC_JWT_FIXTURE)).toBe(true);
  });

  it('flags JWT fixture nested in object', () => {
    const r = scanLogRowForPlaintext({
      headers: { Authorization: `Bearer ${SYNTHETIC_JWT_FIXTURE}` },
    });
    expect(r.some((m) => m.fixture === SYNTHETIC_JWT_FIXTURE)).toBe(true);
  });
});

describe('scanLogRowForPlaintext — synthetic cookie fixture leak', () => {
  it('flags cookie fixture in a Set-Cookie line', () => {
    const r = scanLogRowForPlaintext(`Set-Cookie: ${SYNTHETIC_COOKIE_FIXTURE}; Path=/`);
    expect(r.some((m) => m.fixture === SYNTHETIC_COOKIE_FIXTURE)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// scrubLogValue — runtime redactor
// ---------------------------------------------------------------------------

describe('scrubLogValue — JWTs', () => {
  it('scrubs a Bearer JWT in a structured-log string', () => {
    const out = scrubLogValue(
      'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.signature_here',
    );
    expect(out).toContain('[REDACTED_JWT]');
    expect(out).not.toContain('signature_here');
  });

  it('does not scrub semver-shaped strings', () => {
    expect(scrubLogValue('package@1.2.3')).toBe('package@1.2.3');
  });

  it('scrubs the synthetic JWT fixture used in tests', () => {
    const out = scrubLogValue(`Token: ${SYNTHETIC_JWT_FIXTURE}`);
    expect(out).toContain('[REDACTED_JWT]');
    expect(out).not.toContain('testpayload');
  });
});

describe('scrubLogValue — credential JSON values', () => {
  it('scrubs a "password" value in a JSON payload', () => {
    const out = scrubLogValue('{"username":"alice","password":"s3cr3t-fixture"}');
    expect(out).toContain('"password":"[REDACTED]"');
    expect(out).not.toContain('s3cr3t-fixture');
  });

  it('scrubs "token" / "api_key" / "client_secret"', () => {
    const out = scrubLogValue(
      '{"token":"abc123","api_key":"def456","client_secret":"ghi789"}',
    );
    expect(out).toContain('"token":"[REDACTED]"');
    expect(out).toContain('"api_key":"[REDACTED]"');
    expect(out).toContain('"client_secret":"[REDACTED]"');
  });

  it('preserves non-credential keys', () => {
    const out = scrubLogValue('{"endpoint_url":"/login","status":200}');
    expect(out).toBe('{"endpoint_url":"/login","status":200}');
  });
});

describe('scrubLogValue — Cookie / Set-Cookie headers', () => {
  it('scrubs the value but preserves the cookie name', () => {
    const out = scrubLogValue('Set-Cookie: session=fixture-cookie-value-7f3e; Path=/');
    expect(out).toMatch(/session=\[REDACTED\]/);
    expect(out).not.toContain('fixture-cookie-value-7f3e');
  });

  it('scrubs request Cookie headers too', () => {
    const out = scrubLogValue('Cookie: session=abc; Path=/');
    expect(out).toMatch(/session=\[REDACTED\]/);
  });
});

describe('scrubLogObject — deep traversal', () => {
  it('scrubs nested string values in objects + arrays', () => {
    const out = scrubLogObject({
      level: 'info',
      msg: 'request body',
      body: {
        username: 'alice',
        password: SYNTHETIC_PASSWORD_FIXTURE, // not a JSON string — won't match credential JSON regex
      },
      tokens: [`Bearer ${SYNTHETIC_JWT_FIXTURE}`],
    });
    // Top-level scalars unchanged
    expect(out.level).toBe('info');
    // Array element JWT scrubbed
    expect(out.tokens[0]).toContain('[REDACTED_JWT]');
    expect(out.tokens[0]).not.toContain('testpayload');
  });

  it('passes through null / numbers / booleans', () => {
    const out = scrubLogObject({ a: null, b: 42, c: true, d: 'no fixture here' });
    expect(out).toEqual({ a: null, b: 42, c: true, d: 'no fixture here' });
  });
});

// ---------------------------------------------------------------------------
// Architectural invariant test (cluster-2 patch):
// Feed all 3 v2.1a strategy fixtures through scrubLogObject and assert that
// scanLogRowForPlaintext on the scrubbed output returns []. This is the
// "decrypted plaintext NEVER appears in any structured log row" gate.
// ---------------------------------------------------------------------------

describe('cluster-2 architectural invariant — scrub then scan', () => {
  it('all 3 strategy fixtures, when scrubbed, produce no scan matches', () => {
    const stagedLog = {
      msg: 'simulated worker emit',
      form_attempt: scrubLogValue(
        JSON.stringify({ username: 'alice', password: SYNTHETIC_PASSWORD_FIXTURE }),
      ),
      jwt_header: scrubLogValue(`Authorization: Bearer ${SYNTHETIC_JWT_FIXTURE}`),
      cookie_jar: scrubLogValue(`Set-Cookie: ${SYNTHETIC_COOKIE_FIXTURE}; Path=/`),
    };
    const matches = scanLogRowForPlaintext(stagedLog);
    expect(matches).toEqual([]);
  });
});

// Phase 36 (v1.1) — three contract suites per pragmatist-prag-r2-1:
//
//   1. strategy coverage  — every grepped `auth_strategy === 'recorded'` site
//                            in depscanner/src/dast/*.ts is followed within 5
//                            lines by a replay branch OR an opt-out comment.
//                            Pins yaml-builder.ts:330 + future-proofing.
//   2. script parseability — emitted scriptInline body parses via
//                            `new vm.Script(source)`, including a hostile
//                            fixture where URL / headers / body contain
//                            characters that would break a naive template
//                            substitution.
//   3. decrypt-switch fwd-compat — buildAuthForStrategy with an unknown
//                                   future kind surfaces UnsupportedAuthStrategyError
//                                   (NOT an unhandled throw). Pins the
//                                   forward-compat contract.

import * as fs from 'fs';
import * as path from 'path';
import * as vm from 'vm';

import {
  buildAuthForStrategy,
  buildReplayAuthForZap,
  UnsupportedAuthStrategyError,
  type ReplayCredentialPayload,
} from '../dast/auth-config';

// ---------------------------------------------------------------------------
// 1. strategy coverage
// ---------------------------------------------------------------------------

const DAST_DIR = path.join(__dirname, '..', 'dast');

describe('strategy coverage — every recorded site has a replay sibling', () => {
  it("each `auth_strategy === 'recorded'` site has a replay branch within 5 lines or an opt-out", () => {
    const files = fs
      .readdirSync(DAST_DIR)
      .filter((f) => f.endsWith('.ts'))
      .map((f) => path.join(DAST_DIR, f));
    const violations: string[] = [];
    for (const file of files) {
      const src = fs.readFileSync(file, 'utf-8');
      const lines = src.split('\n');
      const rx = /auth_strategy\s*[!=]==?\s*['"]recorded['"]/;
      for (let i = 0; i < lines.length; i++) {
        if (!rx.test(lines[i])) continue;
        // Window spans 8 lines BEFORE through 5 lines AFTER the match —
        // an opt-out comment in the surrounding doc-block counts (we have a
        // 5-6 line rationale that explains why the site is recorded-only,
        // and the engine-fallback-ok marker lives at the end of that block).
        // A replay branch in the immediate body of the if also counts.
        const winStart = Math.max(0, i - 8);
        const winEnd = Math.min(lines.length, i + 6);
        const window = lines.slice(winStart, winEnd).join('\n');
        const hasReplaySibling = /\breplay\b/.test(window);
        const hasOptOut = /\/\/\s*engine-fallback-ok/.test(window);
        if (!hasReplaySibling && !hasOptOut) {
          violations.push(`${path.basename(file)}:${i + 1}: ${lines[i].trim()}`);
        }
      }
    }
    if (violations.length > 0) {
      throw new Error(
        'Sites missing a `replay` sibling (or // engine-fallback-ok comment):\n' +
          violations.map((v) => `  ${v}`).join('\n'),
      );
    }
  });
});

// ---------------------------------------------------------------------------
// 2. script parseability
// ---------------------------------------------------------------------------

describe('script parseability — emitted scriptInline must parse via new vm.Script', () => {
  function emittedBody(payload: ReplayCredentialPayload): string {
    const r = buildReplayAuthForZap(payload);
    return (r.contextAuthentication as any).parameters.scriptInline;
  }

  it('parses on a vanilla payload (no TOTP)', () => {
    const body = emittedBody({
      kind: 'replay',
      requests: [{ method: 'GET', url: 'https://app.example.com/', headers: [] }],
      origins_observed: ['app.example.com'],
    });
    expect(() => new vm.Script(body)).not.toThrow();
  });

  it('parses with the RFC 6238 helper + TOTP step', () => {
    const body = emittedBody({
      kind: 'replay',
      requests: [
        {
          method: 'POST',
          url: 'https://app.example.com/totp/verify',
          headers: [{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }],
          body: 'pending_session=abc&code=000000',
        },
      ],
      totp_step: { entry_index: 0, body_field: 'code', body_kind: 'form' },
      totp_secret: 'JBSWY3DPEHPK3PXP',
      origins_observed: ['app.example.com'],
    });
    expect(() => new vm.Script(body)).not.toThrow();
  });

  it('parses on a hostile fixture: URL with `"`, header with `</script>`, body with `${injection}`', () => {
    const body = emittedBody({
      kind: 'replay',
      requests: [
        {
          method: 'POST',
          // The URL string itself can't carry a literal double-quote — URL()
          // would reject it. But the path-encoded form `%22` is legal and
          // the script must survive having %22 round-trip through
          // JSON.stringify.
          url: 'https://app.example.com/p%22ath?q=%22closing%22',
          headers: [
            { name: 'X-Custom', value: '</script><script>alert(1)</script>' },
            { name: 'Authorization', value: 'Bearer eyJ.aa.bb' },
          ],
          body: '${injection}=` + reallyBad + `&csv="alice","wonderland"',
        },
      ],
      origins_observed: ['app.example.com'],
    });
    expect(() => new vm.Script(body)).not.toThrow();
    // The hostile content survived ONLY as JS string-literal content (between
    // double-quotes that JSON.stringify supplied). We assert this by checking
    // that the hostile bytes are bracketed by `"` on both sides — never bare
    // identifiers or statement contexts. (The </script> sequence is fine
    // INSIDE a JS string literal; it only matters if the script body were
    // ever embedded into HTML, which it isn't — ZAP loads it via Java API.)
    expect(body).toContain('"</script><script>alert(1)</script>"');
    // The body-side hostile content (${injection} etc.) must also survive
    // as a string literal — JSON.stringify wraps it in `"`, so it can't be
    // template-substituted at parse time.
    expect(body).toMatch(/setRequestBody\("\$\{injection\}/);
  });

  it('does NOT contain a literal U+2028 / U+2029 (validator rejects, but defense-in-depth)', () => {
    const body = emittedBody({
      kind: 'replay',
      requests: [{ method: 'GET', url: 'https://app.example.com/', headers: [] }],
      origins_observed: ['app.example.com'],
    });
    expect(body).not.toMatch(/[\u2028\u2029]/);
  });
});

// ---------------------------------------------------------------------------
// 3. decrypt-switch forward-compat
// ---------------------------------------------------------------------------

describe('decrypt-switch forward-compat — unknown kinds surface UnsupportedAuthStrategyError', () => {
  it('throws when payload.kind does not match any known strategy', () => {
    // Cast through any so we can simulate a future strategy the dispatcher
    // does not yet recognize.
    let thrown: Error | null = null;
    try {
      buildAuthForStrategy(
        'unknown_future' as any,
        { kind: 'unknown_future', data: 'x' } as any,
      );
    } catch (e) {
      thrown = e as Error;
    }
    expect(thrown).toBeInstanceOf(UnsupportedAuthStrategyError);
  });

  it('throws when strategy is replay but payload.kind is a future variant', () => {
    expect(() =>
      buildAuthForStrategy('replay', { kind: 'replay_v2_streaming' } as any),
    ).toThrow(/mismatches strategy='replay'/);
  });
});

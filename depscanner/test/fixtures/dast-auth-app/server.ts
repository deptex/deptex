// DAST auth-strategy fixture app — three route groups exercise the auth
// shapes the replay strategy (`auth_strategy='replay'`) must handle.
//
// Per `.cursor/plans/dast-har-import.plan.md` M0 step 2 (HARD GATE) and
// OS-NEW-1: this is a PERMANENT test harness — referenced from M0
// validation, M5 e2e (`depscanner/test/e2e/dast-har.ts`), and the dogfood
// runbook (`docs/runbooks/dast-har-import-dogfood.md`).
//
// Route groups:
//   1. /login + /dashboard
//      Plain form-POST that sets an opaque session cookie. Single
//      `Set-Cookie: session=<random>; HttpOnly` on success; /dashboard is
//      403 without the cookie and 200 with text containing "WELCOME, ALICE".
//   2. /hmac-login + /hmac-dashboard
//      Same shape but the session cookie is an HMAC-signed JSON envelope
//      `{userId, expires}`. Validates that scripted auth threads non-opaque
//      session formats correctly. HMAC key fixed at boot.
//   3. /totp/login + /totp/verify + /totp/dashboard
//      Two-step auth: form-POST establishes a "needs OTP" session; POST
//      to /totp/verify with a fresh RFC 6238 code completes it. Verifies
//      Patch A's "fresh code at every ZAP invocation" guarantee — the
//      route accepts any code within ±1 30s window of `now`.
//
// Bind defaults to 0.0.0.0 so the process is reachable from a sibling
// Docker container (ZAP) on a user-defined bridge network. PORT defaults
// to 4500; override via DAST_FIXTURE_PORT.
//
// Started by: `tsx depscanner/test/fixtures/dast-auth-app/server.ts`.
// Stopped by: SIGTERM (clean) or SIGINT.

import { createHmac, randomBytes } from 'crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'http';

import { generateTotpCode } from '../../../src/dast/_helpers/totp-rfc6238';

const PORT = Number(process.env.DAST_FIXTURE_PORT ?? '4500');
const HOST = process.env.DAST_FIXTURE_HOST ?? '0.0.0.0';

// Fixed credentials so tests are deterministic.
const USERNAME = 'alice';
const PASSWORD = 'wonderland';

// RFC 4648 base32 of ASCII "12345678901234567890" (the RFC 6238 §5.1
// reference secret). Verify route accepts any code generated from this
// secret in a ±1 step window.
const TOTP_SECRET_B32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

// HMAC key for the signed-cookie route group. Fixed at process start;
// rotated only by restart.
const HMAC_KEY = randomBytes(32);

// In-memory opaque-session store for /login (route group 1).
const opaqueSessions = new Map<string, { username: string }>();
// In-memory "pending OTP" sessions for /totp/login (route group 3).
const pendingTotpSessions = new Map<string, { username: string; createdAt: number }>();
// Authenticated TOTP sessions (post /totp/verify).
const totpSessions = new Map<string, { username: string }>();

function parseFormBody(req: IncomingMessage): Promise<Record<string, string>> {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      // Soft cap so a fuzzing client can't OOM the fixture.
      if (raw.length > 1024 * 64) {
        reject(new Error('body too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      const params = new URLSearchParams(raw);
      const out: Record<string, string> = {};
      for (const [k, v] of params) out[k] = v;
      resolve(out);
    });
    req.on('error', reject);
  });
}

function parseCookies(header: string | undefined): Record<string, string> {
  if (!header) return {};
  const out: Record<string, string> = {};
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (!k) continue;
    out[k] = decodeURIComponent(v.join('='));
  }
  return out;
}

function signHmacCookie(payload: { userId: string; expires: number }): string {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = createHmac('sha256', HMAC_KEY).update(body).digest('base64url');
  return `${body}.${mac}`;
}

function verifyHmacCookie(token: string): { userId: string; expires: number } | null {
  const [body, mac] = token.split('.');
  if (!body || !mac) return null;
  const expected = createHmac('sha256', HMAC_KEY).update(body).digest('base64url');
  if (expected !== mac) return null;
  try {
    const decoded = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (typeof decoded.userId !== 'string' || typeof decoded.expires !== 'number') return null;
    if (decoded.expires < Date.now() / 1000) return null;
    return decoded;
  } catch {
    return null;
  }
}

function sendText(res: ServerResponse, status: number, body: string, extra: Record<string, string> = {}): void {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', ...extra });
  res.end(body);
}

function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...extra });
  res.end(JSON.stringify(body));
}

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '/', `http://${HOST}:${PORT}`);
  const method = (req.method ?? 'GET').toUpperCase();
  const cookies = parseCookies(req.headers.cookie);

  // ---------------------------------------------------------------- 1. form
  if (method === 'POST' && url.pathname === '/login') {
    const form = await parseFormBody(req);
    if (form.username !== USERNAME || form.password !== PASSWORD) {
      return sendText(res, 401, '<html><body>Invalid credentials</body></html>');
    }
    const sid = randomBytes(16).toString('hex');
    opaqueSessions.set(sid, { username: form.username });
    return sendText(res, 302, '', {
      Location: '/dashboard',
      'Set-Cookie': `session=${sid}; Path=/; HttpOnly; SameSite=Lax`,
    });
  }
  if (method === 'GET' && url.pathname === '/dashboard') {
    const sess = cookies.session ? opaqueSessions.get(cookies.session) : null;
    if (!sess) return sendText(res, 403, '<html><body>You are not logged in.</body></html>');
    return sendText(res, 200, `<html><body><h1>WELCOME, ${sess.username.toUpperCase()}</h1></body></html>`);
  }

  // ----------------------------------------------------------- 2. hmac auth
  if (method === 'POST' && url.pathname === '/hmac-login') {
    const form = await parseFormBody(req);
    if (form.username !== USERNAME || form.password !== PASSWORD) {
      return sendText(res, 401, '<html><body>Invalid credentials</body></html>');
    }
    const token = signHmacCookie({
      userId: form.username,
      expires: Math.floor(Date.now() / 1000) + 3600,
    });
    return sendText(res, 302, '', {
      Location: '/hmac-dashboard',
      'Set-Cookie': `hmac_session=${token}; Path=/; HttpOnly; SameSite=Lax`,
    });
  }
  if (method === 'GET' && url.pathname === '/hmac-dashboard') {
    const verified = cookies.hmac_session ? verifyHmacCookie(cookies.hmac_session) : null;
    if (!verified) return sendText(res, 403, '<html><body>HMAC session invalid.</body></html>');
    return sendText(res, 200, `<html><body><h1>HMAC WELCOME, ${verified.userId.toUpperCase()}</h1></body></html>`);
  }

  // ----------------------------------------------------------- 3. totp auth
  if (method === 'POST' && url.pathname === '/totp/login') {
    const form = await parseFormBody(req);
    if (form.username !== USERNAME || form.password !== PASSWORD) {
      return sendJson(res, 401, { ok: false, reason: 'invalid_credentials' });
    }
    const pendingId = randomBytes(16).toString('hex');
    pendingTotpSessions.set(pendingId, { username: form.username, createdAt: Date.now() });
    return sendJson(
      res,
      200,
      { ok: true, mfa_required: true, pending_session: pendingId },
    );
  }
  if (method === 'POST' && url.pathname === '/totp/verify') {
    const form = await parseFormBody(req);
    const pendingId = form.pending_session;
    const code = form.code;
    // Echo the submitted code so M0 step 6 can grep for two-different-codes
    // proof across consecutive ZAP runs (Patch A freshness assertion).
    process.stdout.write(`[fixture] /totp/verify submitted_code=${code ?? '<missing>'}\n`);
    if (!pendingId || !code) {
      return sendJson(res, 400, { ok: false, reason: 'missing_fields' });
    }
    const pending = pendingTotpSessions.get(pendingId);
    if (!pending) return sendJson(res, 401, { ok: false, reason: 'no_pending_session' });
    if (Date.now() - pending.createdAt > 10 * 60 * 1000) {
      pendingTotpSessions.delete(pendingId);
      return sendJson(res, 401, { ok: false, reason: 'pending_expired' });
    }
    // Accept any code in a ±1 step (30s) window — same tolerance most IdPs
    // ship to absorb clock skew. This is what makes Patch A's freshness
    // guarantee provable: the second-call code only matches if it was
    // regenerated at the new time, not echoed from script-render time.
    const now = Math.floor(Date.now() / 1000);
    const candidates = [
      generateTotpCode(TOTP_SECRET_B32, { time: now - 30 }),
      generateTotpCode(TOTP_SECRET_B32, { time: now }),
      generateTotpCode(TOTP_SECRET_B32, { time: now + 30 }),
    ];
    if (!candidates.includes(code)) {
      return sendJson(res, 401, { ok: false, reason: 'bad_code' }, {});
    }
    pendingTotpSessions.delete(pendingId);
    const sid = randomBytes(16).toString('hex');
    totpSessions.set(sid, { username: pending.username });
    return sendJson(
      res,
      200,
      { ok: true, authenticated: true },
      { 'Set-Cookie': `totp_session=${sid}; Path=/; HttpOnly; SameSite=Lax` },
    );
  }
  if (method === 'GET' && url.pathname === '/totp/dashboard') {
    const sess = cookies.totp_session ? totpSessions.get(cookies.totp_session) : null;
    if (!sess) return sendText(res, 403, '<html><body>You are not logged in.</body></html>');
    return sendText(res, 200, `<html><body><h1>TOTP WELCOME, ${sess.username.toUpperCase()}</h1></body></html>`);
  }

  // ---------------------------------------------------- admin / test helpers
  // Used by M0 step 6 (re-auth cycle): expire a totp_session to force the
  // ZAP `logged_out_indicator` miss path. Returns 200 on success; this
  // endpoint is intentionally unauthenticated because the fixture only
  // exists for tests inside the worker's Docker network.
  if (method === 'POST' && url.pathname === '/__test/expire-totp-session') {
    const sid = url.searchParams.get('session_id');
    if (sid && totpSessions.delete(sid)) {
      return sendJson(res, 200, { ok: true, expired: sid });
    }
    return sendJson(res, 404, { ok: false, reason: 'unknown_session' });
  }

  // Health probe for ZAP "wait until target is up" preflight.
  if (method === 'GET' && url.pathname === '/healthz') {
    return sendJson(res, 200, { ok: true, ts: Date.now() });
  }

  // Landing page — gives the spider a starting link if invoked anonymously.
  if (method === 'GET' && url.pathname === '/') {
    return sendText(
      res,
      200,
      '<html><body><a href="/dashboard">dashboard</a> · <a href="/hmac-dashboard">hmac</a> · <a href="/totp/dashboard">totp</a></body></html>',
    );
  }

  return sendText(res, 404, '<html><body>not found</body></html>');
}

const server = createServer((req, res) => {
  // Request logging — fixture-only, prints METHOD + path + cookie presence.
  // Used by M0 smoke runs to confirm ZAP actually invoked the auth path
  // before reaching the verification probe.
  const cookiePresent = req.headers.cookie ? '+cookie' : '-cookie';
  process.stdout.write(`[fixture] ${req.method} ${req.url} ${cookiePresent}\n`);
  handle(req, res).catch((err) => {
    // Test fixture: log to stderr but never echo body content (matches the
    // backend's privacy posture for any HAR-derived logging).
    process.stderr.write(`[fixture] handler error: ${(err as Error).message}\n`);
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, reason: 'internal' }));
    } else {
      res.end();
    }
  });
});

server.listen(PORT, HOST, () => {
  process.stdout.write(
    `[fixture] dast-auth-app listening at http://${HOST}:${PORT} (totp secret = ${TOTP_SECRET_B32})\n`,
  );
});

process.on('SIGTERM', () => server.close(() => process.exit(0)));
process.on('SIGINT', () => server.close(() => process.exit(0)));

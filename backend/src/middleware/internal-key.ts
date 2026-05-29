import express from 'express';
import crypto from 'crypto';

// Read at call time (not module load) so the value reflects the current env — matters for
// tests that set INTERNAL_API_KEY dynamically, and is harmless in prod where it's set before
// boot. Never log key fragments or lengths.
function configuredKey(): string | undefined {
  return process.env.INTERNAL_API_KEY?.trim();
}

// Constant-time compare; returns false instantly on length mismatch (without leaking
// which side was longer) and otherwise uses timingSafeEqual to hide per-byte timing.
function safeMatch(provided: string | undefined, expected: string | undefined): boolean {
  if (!provided || !expected) return false;
  if (provided.length !== expected.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected));
  } catch {
    return false;
  }
}

function extractKey(req: express.Request): string | undefined {
  const header = req.headers['x-internal-api-key'];
  if (typeof header === 'string') return header.trim();
  const auth = req.headers.authorization;
  if (typeof auth === 'string' && auth.startsWith('Bearer ')) {
    return auth.slice(7).trim();
  }
  return undefined;
}

// Express middleware that gates internal/worker routes on INTERNAL_API_KEY.
// IMPORTANT: never log key fragments or lengths — an attacker with log access
// could derive prefix bytes and combine with a timing oracle.
export function requireInternalKey(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
): void {
  const provided = extractKey(req);
  const configured = configuredKey();
  if (!configured) {
    console.error('[internal-key] INTERNAL_API_KEY is not configured');
    res.status(503).json({ error: 'Internal key not configured' });
    return;
  }
  if (!safeMatch(provided, configured)) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  next();
}

// One-shot helper for routes that gate inside a handler rather than via router.use().
export function isValidInternalKey(provided: string | undefined): boolean {
  return safeMatch(provided, configuredKey());
}

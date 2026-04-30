import crypto from 'crypto';

function getSigningKey(): string {
  const key = process.env.INTERNAL_API_KEY;
  if (!key) {
    throw new Error('INTERNAL_API_KEY is not configured; cannot sign fix approval tokens.');
  }
  return key;
}

function payloadString(fixId: string, orgId: string, generatedAt: string): string {
  return `${fixId}.${orgId}.${generatedAt}`;
}

export function signApprovalToken(
  fixId: string,
  orgId: string,
  generatedAt: string,
): string {
  const hmac = crypto.createHmac('sha256', getSigningKey());
  hmac.update(payloadString(fixId, orgId, generatedAt));
  return hmac.digest('hex');
}

export function verifyApprovalToken(
  token: string,
  fixId: string,
  orgId: string,
  generatedAt: string,
): boolean {
  if (!token) return false;
  const expected = signApprovalToken(fixId, orgId, generatedAt);
  if (token.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(token, 'hex'), Buffer.from(expected, 'hex'));
}

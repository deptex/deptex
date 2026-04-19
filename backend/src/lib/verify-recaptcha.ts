/**
 * Verify Google reCAPTCHA v2 response token.
 * When RECAPTCHA_SECRET_KEY is not set (e.g. local dev), verification is skipped and returns true.
 * Get keys: https://www.google.com/recaptcha/admin
 * Pricing: free for first 10k assessments/month; then paid.
 */

const RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify';

export async function verifyRecaptchaToken(token: string | undefined): Promise<boolean> {
  const secret = process.env.RECAPTCHA_SECRET_KEY;
  if (!secret || !token) {
    if (secret && !token) return false;
    return true;
  }

  try {
    const res = await fetch(RECAPTCHA_VERIFY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret, response: token }),
    });
    const data = (await res.json()) as { success?: boolean; 'error-codes'?: string[] };
    return data.success === true;
  } catch {
    return false;
  }
}

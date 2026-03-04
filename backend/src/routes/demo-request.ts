import { Router } from 'express';
import { supabase } from '../lib/supabase';
import { checkContactRateLimit } from '../lib/contact-rate-limit';
import { verifyRecaptchaToken } from '../lib/verify-recaptcha';

const router = Router();

router.post('/', async (req, res) => {
  const { allowed } = checkContactRateLimit(req, 'demo');
  if (!allowed) {
    return res.status(429).json({ error: 'Too many requests. Please try again later.' });
  }

  if (process.env.RECAPTCHA_SECRET_KEY) {
    const valid = await verifyRecaptchaToken(req.body?.recaptchaToken);
    if (!valid) {
      return res.status(400).json({ error: 'Captcha verification failed. Please try again.' });
    }
  }

  const honeypot = req.body?.website;
  if (honeypot != null && String(honeypot).trim() !== '') {
    return res.status(400).json({ error: 'Invalid request' });
  }

  const { firstName, lastName, email, companyName, details } = req.body ?? {};
  if (
    !firstName ||
    !lastName ||
    !email ||
    typeof firstName !== 'string' ||
    typeof lastName !== 'string' ||
    typeof email !== 'string'
  ) {
    return res.status(400).json({ error: 'Missing or invalid fields: firstName, lastName, email' });
  }

  const trimmed = {
    first_name: firstName.trim().slice(0, 200),
    last_name: lastName.trim().slice(0, 200),
    email: email.trim().toLowerCase().slice(0, 320),
    company_name: (companyName && typeof companyName === 'string') ? companyName.trim().slice(0, 300) : null,
    dev_count: null,
    details: (details && typeof details === 'string') ? details.trim().slice(0, 2000) : null,
  };

  if (!trimmed.first_name || !trimmed.last_name || !trimmed.email) {
    return res.status(400).json({ error: 'First name, last name, and email are required' });
  }

  const { error } = await supabase.from('demo_requests').insert(trimmed);

  if (error) {
    return res.status(500).json({ error: error.message });
  }
  return res.status(201).json({ ok: true });
});

export default router;

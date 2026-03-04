import { Router } from 'express';
import { supabase } from '../lib/supabase';
import { checkContactRateLimit } from '../lib/contact-rate-limit';
import { verifyRecaptchaToken } from '../lib/verify-recaptcha';

const router = Router();

router.post('/', async (req, res) => {
  const { allowed } = checkContactRateLimit(req, 'enterprise');
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

  const {
    companyName,
    firstName,
    lastName,
    email,
    companySize,
    phone,
    additionalDetails,
  } = req.body ?? {};

  if (
    !firstName ||
    !lastName ||
    !email ||
    typeof firstName !== 'string' ||
    typeof lastName !== 'string' ||
    typeof email !== 'string'
  ) {
    return res.status(400).json({ error: 'Missing or invalid fields: first name, last name, business email' });
  }

  const trimmed = {
    first_name: firstName.trim().slice(0, 200),
    last_name: lastName.trim().slice(0, 200),
    email: email.trim().toLowerCase().slice(0, 320),
    company_name: companyName && typeof companyName === 'string' ? companyName.trim().slice(0, 300) : null,
    dev_count: null,
    details: JSON.stringify({
      source: 'enterprise',
      companySize: companySize && typeof companySize === 'string' ? companySize.trim().slice(0, 100) : null,
      phone: phone && typeof phone === 'string' ? phone.trim().slice(0, 50) : null,
      additionalDetails: additionalDetails && typeof additionalDetails === 'string' ? additionalDetails.trim().slice(0, 2000) : null,
    }),
  };

  if (!trimmed.first_name || !trimmed.last_name || !trimmed.email) {
    return res.status(400).json({ error: 'First name, last name, and business email are required' });
  }

  const { error } = await supabase.from('demo_requests').insert({
    first_name: trimmed.first_name,
    last_name: trimmed.last_name,
    email: trimmed.email,
    company_name: trimmed.company_name ?? '',
    dev_count: trimmed.dev_count ?? '',
    details: trimmed.details,
  });

  if (error) {
    return res.status(500).json({ error: error.message });
  }
  return res.status(201).json({ ok: true });
});

export default router;
